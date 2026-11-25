import io
import unittest
import zipfile
from datetime import date
from unittest.mock import patch

from pipeline.build import release_files, zip_snapshot
from pipeline.collect import CATALOG, HUNTS, PROFILE_CATALOG, REPORT, collection
from pipeline.queries import DAYS, JSON_SUFFIX, render_query, run_validator, static_pass, validate_profile, variant
from pipeline.sources import CisaListing, ROOT, plain, read_json, stable


class CollectorTests(unittest.TestCase):
    def test_source_markup_stays_inert(self):
        self.assertEqual(plain('<img src=x onerror=alert(1)>Hello<script>bad()</script> world'), 'Hello world')
        self.assertEqual(plain('&#x202e; safe <b>title</b>'), 'safe title')
        self.assertEqual(stable('HF-INT', 'CVE-2026-1000'), stable('HF-INT', 'CVE-2026-1000'))

    def test_cisa_html_parser(self):
        parser = CisaListing()
        parser.feed('<article><time datetime="2026-11-19T12:00Z"></time><h3 class="c-teaser__title">'
                    '<a href="/news-events/ics-advisories/test">A &amp; B</a></h3></article>')
        self.assertEqual(parser.entries, [(date(2026,11,19), "/news-events/ics-advisories/test", "A & B")])

    def test_partial_outage_retains_cisa_records(self):
        previous = read_json(CATALOG)
        start, end = map(date.fromisoformat, [previous["window"]["from"], previous["window"]["through"]])
        rows = [row for row in previous["records"] if row["source"] == "ncsc"]
        reference = previous["reference"]
        def inputs(source, *_):
            if source == "ncsc":
                return rows, {"coverage":"full"}
            raise TimeoutError("fixture source unavailable")
        with patch("pipeline.collect.kev", side_effect=TimeoutError), patch("pipeline.collect.epss", side_effect=TimeoutError), \
                patch("pipeline.collect.advisory", side_effect=inputs), patch("pipeline.collect.attack", return_value=(reference,{"coverage":"reference"})):
            after, changes, _ = collection(start,end,previous,"2026-11-26T12:00:00Z")
        self.assertEqual([x["state"] for x in after["sources"] if x["id"] == "cisa-kev"], ["cached"])
        self.assertEqual(set(x["id"] for x in previous["records"]), set(x["id"] for x in after["records"]))
        self.assertEqual(changes, [])


class QueriesTests(unittest.TestCase):
    def test_lookback_and_json_output(self):
        hunts = read_json(HUNTS)
        for hunt in hunts:
            for values in hunt["variants"].values():
                for days in DAYS:
                    query = values["queries"][str(days)]
                    self.assertTrue(static_pass(query["table"]))
                    self.assertEqual(query["json"], query["table"] + JSON_SUFFIX + "\n")
                    self.assertEqual(query["json"].count(JSON_SUFFIX), 1)
        self.assertRaises(ValueError, render_query, "A", {"timestamp":"T"}, [], 50)

    def test_parser_rejects_syntax_and_schema_errors(self):
        common = {"table":"Sample","columns":{"Timestamp":"datetime","Value":"string"}}
        good, bad_syntax, missing, wrong_type = run_validator([
            {**common,"query":"Sample | project Value"},
            {**common,"query":"Sample | project ("},
            {**common,"query":"Sample | project Missing"},
            {**common,"query":"Sample | where Value > ago(1d)"},
        ])
        self.assertEqual(good, {"syntax":[],"errors":[],"tabular":True})
        self.assertTrue(bad_syntax["syntax"])
        self.assertTrue(missing["errors"])
        self.assertTrue(wrong_type["errors"])

    def test_custom_profile_requires_valid_columns_and_capability(self):
        profiles = read_json(PROFILE_CATALOG)
        rules = read_json(ROOT / "hunts/rules.json")
        ps = next(row for row in rules if row["research"] == "powershell-download")
        web = next(row for row in profiles if row["id"] == "custom-proxy")
        self.assertRaises(ValueError, variant, ps, web, [])
        web["tables"]["CustomWeb_CL"]["columns"]["TimeGenerated"] = "string"
        self.assertRaises(ValueError, validate_profile, web)

    def test_published_hunts_default_to_sentinel(self):
        profiles = {row["id"]: row for row in read_json(PROFILE_CATALOG)}
        hunts = read_json(HUNTS)
        for hunt in hunts:
            with self.subTest(hunt=hunt["id"]):
                profile_id = hunt["profiles"][0]
                self.assertEqual(profiles[profile_id]["target"], "Microsoft Sentinel Logs")
                self.assertEqual(hunt["primary_table"], hunt["variants"][profile_id]["table"])
                self.assertIn("| where TimeGenerated >", hunt["variants"][profile_id]["queries"][str(hunt["lookback"])]["table"])

    def test_all_techniques_have_descriptions_and_sentinel_alert_pivots(self):
        items = read_json(CATALOG)["reference"]["items"]
        techniques = [row for row in items if row["type"] == "attack-pattern"]
        self.assertTrue(techniques)
        for row in techniques:
            with self.subTest(technique=row["id"]):
                self.assertTrue(row["description"])
                self.assertTrue(row["alert_query"].startswith("SecurityAlert\n| where TimeGenerated > ago(30d)"))
                self.assertIn(row["id"].replace(".", r"\."), row["alert_query"])
                self.assertTrue(static_pass(row["alert_query"]))


class ReleaseTests(unittest.TestCase):
    def test_pack_carries_individual_queries_and_provenance(self):
        hunts = read_json(HUNTS)
        with zipfile.ZipFile(io.BytesIO(zip_snapshot(hunts,"test"))) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn(b'"evidence"',archive.read("manifest.json"))
            for hunt in hunts:
                for profile in hunt["variants"]:
                    path = f"{hunt['id']}-r{hunt['revision']}-{profile}.kql"
                    self.assertEqual(archive.read(path).decode(),hunt["variants"][profile]["queries"][str(hunt["lookback"])]["table"])

    def test_release_build_is_deterministic_and_has_real_provenance(self):
        inputs = [read_json(path) for path in (CATALOG,HUNTS,PROFILE_CATALOG,REPORT)]
        manifest, files = release_files(*inputs,"a" * 40)
        self.assertEqual((manifest,files),release_files(*inputs,"a" * 40))
        self.assertTrue(manifest["counts"]["in_window"] > 0)
        self.assertTrue(manifest["source_commit"] == "a" * 40)
        self.assertTrue(all(item["evidence"] for item in inputs[0]["records"]))


if __name__ == "__main__":
    unittest.main()
