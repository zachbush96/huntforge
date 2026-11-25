"""Verify one complete release locally or check the served public API."""

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .build import DIST, RELEASE_ID
from .sources import digest, read_json


def verify_local(root):
    api = root / "api/v1"
    latest = read_json(api / "latest.json")
    assert RELEASE_ID.fullmatch(latest["release_id"]), "Invalid release identifier"
    for instance in read_json(api / "history.json")["items"]:
        release = instance["release_id"]
        assert RELEASE_ID.fullmatch(release), "Invalid archived release identifier"
        base = api / "releases" / release
        manifest = read_json(base / "manifest.json")
        assert manifest["release_id"] == release
        for filename, expected in manifest["files"].items():
            path = (base / filename).resolve()
            assert path.is_relative_to(base.resolve()), "Path escapes snapshot"
            body = path.read_bytes()
            assert len(body) == expected["bytes"] and digest(body) == expected["sha256"], f"Hash mismatch: {filename}"
        if release == latest["release_id"]:
            assert {k:v for k,v in manifest.items() if k != "files"} == latest
    main = api / "releases" / latest["release_id"]
    assert (main / "manifest.json").is_file()
    for name in ("intelligence","indicators","hunts","profiles"):
        index = read_json(main / name / "index.json")
        assert index["release_id"] == latest["release_id"]
        assert index["count"] == len(index["items"]) == latest["counts"][name]
        for row in index["items"]:
            assert read_json(main / name / f"{row['id']}.json")["release_id"] == latest["release_id"]
    print("Verified release", latest["release_id"])


def verify_http(url, expected):
    base = url.rstrip("/") + "/"
    parsed = urlsplit(base)
    if parsed.scheme != "https" or parsed.netloc != "zachbush96.github.io" or parsed.path != "/huntforge/":
        raise ValueError("Public verification uses the configured GitHub Pages URL")

    def get(path, json_type=False):
        req = Request(base + path, headers={"User-Agent": "HuntForge-Smoke/1", "Origin": "https://example.org", "Cache-Control": "no-cache"})
        with urlopen(req, timeout=20) as response:
            if json_type:
                assert response.headers.get_content_type() == "application/json"
            return response.read(), response.headers

    landing, _ = get("")
    assert b"HuntForge" in landing
    latest_raw, headers = get(f"api/v1/latest.json?smoke={expected}", True)
    latest = json.loads(latest_raw)
    assert latest["release_id"] == expected, f"Served {latest['release_id']} instead of {expected}"
    uri = f"api/v1/releases/{expected}/"
    manifest = json.loads(get(uri + "manifest.json", True)[0])
    assert manifest["release_id"] == expected
    example_kql = next(path for path in manifest["files"] if path.startswith("downloads/HF-2025-0001-") and path.endswith(".kql"))
    required = ["hunts/HF-2025-0001.json", "intelligence/index.json", example_kql]
    if "indicators/bulk-query.json" in manifest["files"]:
        required.append("indicators/bulk-query.json")
    with ThreadPoolExecutor(max_workers=3) as pool:
        checks = [pool.submit(get, uri + path, path.endswith(".json")) for path in required]
        for path, result in zip(required, checks):
            contents, _ = result.result()
            assert digest(contents) == manifest["files"][path]["sha256"], f"Served hash mismatch: {path}"
    print(f"Served {expected}; latest Cache-Control={headers.get('Cache-Control')}; CORS={headers.get('Access-Control-Allow-Origin')}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=DIST)
    parser.add_argument("--url")
    parser.add_argument("--release")
    args = parser.parse_args()
    if args.url:
        if not args.release or not RELEASE_ID.fullmatch(args.release):
            parser.error("--url requires a valid --release")
        verify_http(args.url,args.release)
    else:
        verify_local(args.dist)


if __name__ == "__main__":
    main()
