"""Render a single KQL query, optionally using a local private profile."""

import argparse
import sys
from pathlib import Path

from .collect import CATALOG, HUNTS, PROFILE_CATALOG
from .queries import DAYS, render_query, run_validator, static_pass, variant
from .sources import ROOT, read_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hunt")
    parser.add_argument("--profile")
    parser.add_argument("--local-profile", type=Path)
    parser.add_argument("--days", default=7, choices=DAYS, type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    hunt = next((row for row in read_json(HUNTS, []) if row["id"] == args.hunt), None)
    if not hunt:
        parser.error("Unknown accepted hunt ID")
    if args.local_profile:
        if args.profile or args.local_profile.is_relative_to(ROOT / "website"):
            parser.error("Use one profile option and keep private profiles outside the site")
        profile = read_json(args.local_profile.resolve())
        if not profile:
            parser.error("The local profile could not be loaded")
        if hunt["research"] != "outage-phishing" or any(x["capability"] != "web" for x in profile["tables"].values()):
            parser.error("Local mapping currently supports the web destination hunt")
        indicators = [row for row in read_json(CATALOG)["indicators"] if row["id"] in hunt["indicator_ids"]]
        table, schema, parts = variant(hunt, profile, indicators)
        query = render_query(table, schema, parts, args.days, args.json)
        result = run_validator([{"table": table, "columns": schema["columns"], "query": query}])[0]
        if result["syntax"] or result["errors"] or not result["tabular"] or not static_pass(query):
            parser.error("The local query failed mandatory Kusto validation")
    else:
        profile_id = args.profile or hunt["profiles"][0]
        if profile_id not in hunt["variants"]:
            ids = ", ".join(item["id"] for item in read_json(PROFILE_CATALOG) if item["id"] in hunt["profiles"])
            parser.error(f"Incompatible profile. Choose {ids}.")
        query = hunt["variants"][profile_id]["queries"][str(args.days)]["json" if args.json else "table"]
    sys.stdout.buffer.write(query.encode())


if __name__ == "__main__":
    main()
