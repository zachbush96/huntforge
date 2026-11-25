"""Build one consistent static website and versioned public API snapshot."""

import argparse
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from .collect import CATALOG, HUNTS, PROFILE_CATALOG, REPORT
from .indicator_query import build_indicator_query
from .sources import ROOT, canonical, digest, read_json, write_json

DIST = ROOT / "dist"
RELEASE_ID = re.compile(r"^hf-\d{8}-[0-9a-f]{12}$")


def json_index(release, items):
    return {"schema_version": 1, "release_id": release, "count": len(items), "items": items}


def make_search(records, hunts, indicators, reference):
    result = []
    for kind, items in (
        ("intelligence", records), ("hunt", hunts), ("indicator", indicators),
        ("technique", [x for x in reference if x["type"] == "attack-pattern"]),
        ("adversary", [x for x in reference if x["type"] != "attack-pattern"]),
    ):
        for item in items:
            title = item.get("title", item.get("display"))
            terms = [title, item.get("summary"), item.get("description"), item.get("value"), item.get("source"), item["id"]]
            terms.extend(term for field in ("cves", "tags", "techniques", "aliases", "software", "actors") for term in item.get(field, []))
            if kind == "hunt":
                terms.extend(ref.get("claim") for ref in item["evidence"])
                terms.extend(variant["queries"][str(item["lookback"])]["table"] for variant in item["variants"].values())
            result.append({"kind": kind, "id": item["id"], "title": title,
                           "text": " ".join(dict.fromkeys(v.lower() for v in terms if isinstance(v, str)))})
    return result


def release_files(catalog, hunts, profiles, report, commit):
    release_hash = digest(canonical({"catalog": catalog, "hunts": hunts, "profiles": profiles, "report": report, "commit": commit}))
    release = "hf-" + catalog["window"]["through"].replace("-", "") + "-" + release_hash[:12]
    records = sorted(catalog["records"], key=lambda row: (row["published"], row["source"], row["id"]), reverse=True)
    indicators = catalog["indicators"]
    reference = catalog["reference"]["items"]
    shared = defaultdict(list)
    for row in records:
        for cve in row["cves"]:
            shared[cve].append(row["id"])
    hunts_for_record = defaultdict(list)
    hunts_for_cve = defaultdict(list)
    for hunt in hunts:
        for identifier in hunt["source_ids"]:
            hunts_for_record[identifier].append(hunt["id"])
        for cve in hunt.get("cves", []):
            hunts_for_cve[cve].append(hunt["id"])
    records = [{**row, "related": sorted({linked for cve in row["cves"] for linked in shared[cve] if linked != row["id"]}),
                "exploitation_hunts": sorted({identifier for cve in row["cves"] for identifier in hunts_for_cve[cve]}) if row["kind"] == "Vulnerability" else [],
                "hunts": hunts_for_record[row["id"]], "epss": catalog["epss"].get(row["source_id"], [])} for row in records]
    indicator_query = build_indicator_query(indicators, records, profiles, catalog["window"]["through"])
    file_map = {
        "intelligence/index.json": canonical(json_index(release, [{k: v for k, v in row.items() if k != "epss"} for row in records])),
        "hunts/index.json": canonical(json_index(release, [{k: v for k, v in row.items() if k != "variants"} for row in hunts])),
        "indicators/index.json": canonical(json_index(release, indicators)),
        "indicators/bulk-query.json": canonical({**indicator_query, "schema_version": 1, "release_id": release}),
        "profiles/index.json": canonical(json_index(release, profiles)),
        "reference/index.json": canonical({**json_index(release, reference), "version": catalog["reference"].get("collection"),
                                            "license": catalog["reference"].get("license")}),
        "search.json": canonical(json_index(release, make_search(records, hunts, indicators, reference))),
        "changes.json": canonical({**json_index(release, catalog["changes"]), "tombstones": catalog["tombstones"]}),
        "report.json": canonical({**report, "release_id": release}),
    }
    for kind, rows in (("intelligence", records), ("hunts", hunts), ("indicators", indicators), ("profiles", profiles)):
        for row in rows:
            file_map[f"{kind}/{row['id']}.json"] = canonical({**row, "release_id": release})
    for hunt in hunts:
        for profile_id, variant in hunt["variants"].items():
            filename = f"downloads/{hunt['id']}-r{hunt['revision']}-{profile_id}.kql"
            file_map[filename] = variant["queries"][str(hunt["lookback"])]["table"].encode()
    for schema in sorted((ROOT / "schemas").glob("*.json")):
        file_map[f"schemas/{schema.name}"] = schema.read_bytes()
    counts = Counter(row["type"] for row in reference)
    manifest = {
        "schema_version": 1, "release_id": release, "created": report["finished"], "window": catalog["window"],
        "source_commit": commit, "snapshot": f"releases/{release}/manifest.json",
        "counts": {"intelligence": len(records), "in_window": sum(row["in_window"] for row in records),
                   "hunts": len(hunts), "indicators": len(indicators), "profiles": len(profiles),
                   "sources": len(catalog["sources"]), "techniques": counts["attack-pattern"]},
        "files": {path: {"sha256": digest(contents), "bytes": len(contents)} for path, contents in sorted(file_map.items())},
    }
    file_map["manifest.json"] = canonical(manifest)
    return manifest, file_map


def collect_commit():
    if os.environ.get("HUNTFORGE_SOURCE_COMMIT"):
        return os.environ["HUNTFORGE_SOURCE_COMMIT"]
    process = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    return process.stdout.strip() if process.returncode == 0 else None


def build(archive=None):
    catalog, hunts, profiles, report = [read_json(path) for path in (CATALOG, HUNTS, PROFILE_CATALOG, REPORT)]
    if not all((catalog, hunts, profiles, report)):
        raise ValueError("Collect and validate data before building.")
    manifest, files = release_files(catalog, hunts, profiles, report, collect_commit())
    shutil.copytree(ROOT / "website", DIST, dirs_exist_ok=True)
    api = DIST / "api" / "v1"
    releases = api / "releases"
    if archive and archive.exists():
        for saved in archive.iterdir():
            if saved.is_dir() and RELEASE_ID.fullmatch(saved.name):
                shutil.copytree(saved, releases / saved.name, dirs_exist_ok=True)
    folder = releases / manifest["release_id"]
    for relative, body in files.items():
        path = folder / relative
        if path.exists() and path.read_bytes() != body:
            raise ValueError(f"Immutable release file changed: {relative}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    previous = [{"release_id": path.parent.name, "created": read_json(path)["created"]} for path in releases.glob("*/manifest.json")]
    write_json(api / "history.json", json_index(manifest["release_id"], sorted(previous, key=lambda v: v["created"], reverse=True)))
    write_json(api / "latest.json", {k: v for k, v in manifest.items() if k != "files"})
    (DIST / ".nojekyll").touch()
    print(manifest["release_id"])
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    build(parser.parse_args().archive)


if __name__ == "__main__":
    main()
