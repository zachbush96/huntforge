"""Update the public canonical dataset from a bounded historical window."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from .queries import generate_hunts, reviewed
from .sources import ROOT, advisory, attack, canonical, digest, epss, kev, read_json, utc_now, write_json

CATALOG = ROOT / "data/catalog.json"
HUNTS = ROOT / "hunts/catalog.json"
PROFILE_CATALOG = ROOT / "profiles/catalog.json"
REPORT = ROOT / "reports/latest.json"
SOURCE_NAMES = {"cisa-kev": "CISA KEV", "first-epss": "FIRST EPSS", "cisa-advisories": "CISA Advisories",
                "microsoft": "Microsoft Security", "ncsc": "UK NCSC", "mitre": "MITRE ATT&CK®"}


def collection(start, end, previous, stamp):
    status = {}
    earliest = start.isoformat()
    record_inputs = {}
    old = {item["id"]: item for item in previous.get("records", [])}
    old_sources = {item["id"]: item for item in previous.get("sources", [])}

    def obtain(source, future, fallback):
        try:
            data, details = future.result()
            count = len(data["items"]) if source == "mitre" else len(data)
            if source == "cisa-kev":
                count = sum(item["in_window"] for item in data)
            status[source] = {"id": source, "name": SOURCE_NAMES[source], "state": "live", "retrieved": stamp,
                              "count": count, **details}
            return data
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, StopIteration, SyntaxError) as error:
            print(f"{source}: {type(error).__name__}: {error}")
            status[source] = {**old_sources.get(source, {}), "id": source, "name": SOURCE_NAMES[source],
                              "state": "cached" if fallback else "failed", "attempted": stamp,
                              "coverage": "unavailable", "error": type(error).__name__}
            return fallback

    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = {source: pool.submit(advisory, source, start, end) for source in ("cisa-advisories", "microsoft", "ncsc")}
        jobs["cisa-kev"] = pool.submit(kev, start, end)
        jobs["mitre"] = pool.submit(attack)
        record_inputs["cisa-kev"] = obtain("cisa-kev", jobs["cisa-kev"], [x for x in old.values() if x["source"] == "cisa-kev"])
        cves = sorted({cve for row in record_inputs["cisa-kev"] if earliest <= row["published"] <= end.isoformat() for cve in row["cves"]})
        score_job = pool.submit(epss, start, end, cves)
        for source in ("cisa-advisories", "microsoft", "ncsc"):
            record_inputs[source] = obtain(source, jobs[source], [x for x in old.values() if x["source"] == source])
        references = obtain("mitre", jobs["mitre"], previous.get("reference", {"items": []}) if previous else {})
        scores = obtain("first-epss", score_job, previous.get("epss", {}))
    if not any(status[key]["state"] == "live" for key in record_inputs):
        raise RuntimeError("No live intelligence source succeeded. Retaining the previous release.")
    curated, indicators, reviewed_ids = reviewed()
    records = dict(old)
    for source, inputs in record_inputs.items():
        for row in inputs:
            if row["published"] >= earliest or row["id"] in old:
                records[row["id"]] = row
    for row in curated:
        records[row["id"]] = row
    released = []
    changes = []
    volatile = {"in_window", "revision", "signature", "updated", "retrieved", "first_retrieved"}
    for identifier, row in sorted(records.items()):
        prior = old.get(identifier, {})
        signature = digest(canonical({k: v for k, v in row.items() if k not in volatile}))
        changed = prior.get("signature") != signature
        retrieved = status[row["source"]].get("retrieved")
        if row["id"] in reviewed_ids.values() and not prior:
            retrieved = stamp
        if status[row["source"]]["state"] != "live":
            retrieved = prior.get("retrieved", retrieved)
        row = {**row, "signature": signature, "revision": prior.get("revision", 0) + changed,
               "first_retrieved": prior.get("first_retrieved", retrieved), "retrieved": retrieved,
               "updated": stamp if changed else prior.get("updated"), "in_window": earliest <= row["published"] <= end.isoformat()}
        if changed:
            changes.append({"id": identifier, "type": "intelligence", "action": "updated" if prior else "created",
                            "revision": row["revision"], "title": row["title"]})
        released.append(row)
    return {"schema_version": 1, "updated": stamp, "window": {"from": earliest, "through": end.isoformat()},
            "records": released, "indicators": indicators, "epss": scores, "reference": references,
            "sources": sorted(status.values(), key=lambda x: list(SOURCE_NAMES).index(x["id"]))}, changes, reviewed_ids


def material_changes(hunts, previous):
    prior = {row["id"]: row for row in previous}
    current = {row["id"] for row in hunts}
    changes = [{"id": row["id"], "type": "hunt", "action": "retired", "revision": row["revision"], "title": row["title"]}
               for row in previous if row["id"] not in current]
    for row in hunts:
        old = prior.get(row["id"])
        if old and old["signature"] == row["signature"]:
            continue
        changes.append({"id": row["id"], "type": "hunt", "action": "updated" if old else "created",
                        "revision": row["revision"], "title": row["title"]})
    return changes


def update(as_of, initial_release=False):
    started = utc_now()
    previous = read_json(CATALOG, {})
    prior_hunts = read_json(HUNTS, [])
    start = as_of - timedelta(days=30)
    catalog, changes, reviewed_ids = collection(start, as_of, previous, started)
    profiles = read_json(PROFILE_CATALOG)
    hunts, rejected = generate_hunts(catalog["records"], catalog["indicators"], reviewed_ids, profiles,
                                    catalog.get("reference", {}).get("items", []), prior_hunts, started)
    if not hunts:
        raise RuntimeError("No hunt passed mandatory validation. Retaining the previous release.")
    changes.extend(material_changes(hunts, prior_hunts))
    if initial_release:
        changes = [{"id": row["id"], "type": kind, "action": "created", "revision": row["revision"], "title": row["title"]}
                   for kind, rows in (("intelligence", catalog["records"]), ("hunt", hunts)) for row in rows]
    tombstones = {row["id"]: row for row in previous.get("tombstones", [])}
    for row in changes:
        if row["action"] == "retired":
            tombstones[row["id"]] = {**row, "retired_at": started}
        else:
            tombstones.pop(row["id"], None)
    catalog["changes"] = sorted(changes, key=lambda x: (x["type"], x["id"]))
    catalog["tombstones"] = sorted(tombstones.values(), key=lambda x: x["id"])
    report = {"schema_version": 1, "started": started, "finished": utc_now(), "accepted": len(hunts),
              "quarantined": rejected, "sources": catalog["sources"], "window": catalog["window"],
              "engine": {"type": "deterministic reviewed rules", "models": [], "calls": 0, "tokens": 0,
                         "cost_usd": 0, "daily_budget_usd": 0, "monthly_budget_usd": 0},
              "changes": len(changes), "status": "partial" if any(x["state"] != "live" for x in catalog["sources"]) else "passed"}
    # Queries and evidence are rendered from the same accepted, analyzed inputs.
    write_json(HUNTS, hunts)
    for hunt in hunts:
        for profile_id, variant in hunt["variants"].items():
            file = ROOT / "hunts" / "queries" / hunt["id"] / f"{profile_id}.kql"
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(variant["queries"][str(hunt["lookback"])]["table"].encode())
    write_json(CATALOG, catalog)
    write_json(REPORT, report)
    print(f"{start} through {as_of}: {sum(x['in_window'] for x in catalog['records'])} in-window records, {len(hunts)} hunts, {len(rejected)} quarantined")
    for source in catalog["sources"]:
        print(f"{source['name']}: {source['state']} / {source['coverage']} / {source.get('count', 0)}")
    for item in rejected:
        print(f"Quarantined {item['id']}: {item['reason']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--as-of", type=date.fromisoformat)
    parser.add_argument("--initial-release", action="store_true")
    args = parser.parse_args()
    day = args.as_of or datetime.now(ZoneInfo("America/New_York")).date()
    update(day, args.initial_release)


if __name__ == "__main__":
    main()
