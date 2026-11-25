import json
import unittest
from datetime import date, timedelta
from unittest.mock import call, patch
from xml.sax.saxutils import escape

from pipeline.build import release_files
from pipeline.collect import CATALOG, HUNTS, PROFILE_CATALOG, REPORT, collection
from pipeline.queries import DAYS, JSON_SUFFIX, render_query, run_validator, static_pass, validate_profile, variant
from pipeline.sources import (
    ADVISORY_FEEDS, SHADOWSERVER, TALOS_BLOG, TALOS_SPOTLIGHT, CisaListing, ROOT,
    advisory, fetch, plain, read_json, shadowserver, stable,
)


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

    def test_publisher_feed_metadata_and_window(self):
        sources = [
            ("cert-fr", "https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1250/", "", "CERTFR-2026-AVI-1250", "Advisory"),
            ("unit-42", "https://unit42.paloaltonetworks.com/example/", "https://unit42.paloaltonetworks.com/?p=42", "42", "Research"),
            ("cisco-talos", "https://blog.talosintelligence.com/example/", "0123456789abcdef01234567", "0123456789abcdef01234567", "Advisory"),
            ("fbi-flash", "https://www.ic3.gov/CSA/2026/261124.pdf", "261124", "261124", "Advisory"),
            ("google-threat-intelligence", "https://cloud.google.com/blog/topics/threat-intelligence/example/", "", None, "Research"),
            ("securelist", "https://securelist.com/example/12345/", "", "12345", "Research"),
            ("dfir-report", "https://thedfirreport.com/2026/11/24/example/", "https://thedfirreport.com/?p=42", "42", "Research"),
            ("greynoise", "https://viz.greynoise.io/articles/12345678-1234-1234-1234-123456789abc",
             "12345678-1234-1234-1234-123456789abc", "12345678-1234-1234-1234-123456789abc", "Research"),
        ]
        title = escape("An <em>example</em> finding about CVE-2026-12345")

        def entry(url, guid, published):
            return (f"<item><link>{escape(url)}</link><guid>{escape(guid)}</guid><title>{title}</title>"
                    f"<pubDate>{published}</pubDate><description>An excerpt from the publisher.</description></item>")

        start, end = date(2026, 10, 25), date(2026, 11, 24)
        for source, url, guid, identifier, kind in sources:
            with self.subTest(source=source):
                body = ("<rss><channel>" + entry(url + "?tracking=example#section", guid, "Tue, 24 Nov 2026 18:00:00 +0000")
                        + entry("https://other.example/advisory", guid, "Fri, 23 Oct 2026 18:00:00 +0000")
                        + entry(url, guid, "invalid")
                        + entry(url, guid, "Wed, 25 Nov 2026 18:00:00 +0000")
                        + "</channel></rss>").encode()
                with patch("pipeline.sources.fetch", return_value=body) as retrieve:
                    rows, status = advisory(source, start, end)
                endpoint = ADVISORY_FEEDS[source][0]
                extra = {"cisco-talos": [TALOS_BLOG, TALOS_SPOTLIGHT],
                         "securelist": [endpoint + "?paged=2", endpoint + "?paged=3"]}
                self.assertEqual(retrieve.call_args_list, [call(url) for url in [endpoint, *extra.get(source, [])]])
                self.assertEqual(status["coverage"], "partial")
                self.assertEqual(status["first_available"], end.isoformat())
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row["source_id"], f"{source}:{identifier}" if identifier else url)
                self.assertEqual(row["id"], stable("HF-INT", row["source_id"]))
                self.assertEqual(row["published"], end.isoformat())
                self.assertEqual(row["evidence"][0]["url"], url)
                self.assertEqual(row["title"], "An example finding about CVE-2026-12345")
                self.assertEqual(row["cves"], ["CVE-2026-12345"])
                self.assertEqual(row["kind"], kind)
                self.assertEqual(row["severity"], "unrated")
                self.assertNotIn("An excerpt from the publisher", row["summary"])
                self.assertIsNone(row["evidence"][0]["observation_date"])
                self.assertIsNone(row["evidence"][0]["modified"])

    def test_new_feed_paths_and_parameters_are_fixed(self):
        sources = ("cert-fr", "unit-42", "cisco-talos", "fbi-flash", "google-threat-intelligence",
                   "securelist", "dfir-report", "greynoise")
        endpoints = [ADVISORY_FEEDS[source][0] for source in sources] + [SHADOWSERVER, TALOS_BLOG, TALOS_SPOTLIGHT]
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint), patch("pipeline.sources.socket.getaddrinfo") as dns:
                for url in (endpoint + "unregistered/", endpoint + "?page=2"):
                    with self.assertRaisesRegex(ValueError, "outside the source registry"):
                        fetch(url)
                dns.assert_not_called()

    def test_shadowserver_listing_keeps_only_dated_threat_publications(self):
        def item(path, title):
            return (f'<div class="article-content"><h4><a href="{path}">{title}</a></h4>'
                    '<div class="the-date">November 24, 2026</div><div class="excerpt">Body</div></div>')

        body = (item("/news/example/", "Malware &amp; attack research")
                + item("https://untrusted.example/news/", "Malware")
                + item("/news/announcement/", "Organizational announcement")).encode()
        with patch("pipeline.sources.fetch", return_value=body) as retrieve:
            rows, status = shadowserver(date(2026, 10, 26), date(2026, 11, 25))
        retrieve.assert_called_once_with(SHADOWSERVER)
        self.assertEqual(status["coverage"], "partial")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "Malware & attack research")
        self.assertEqual(rows[0]["evidence"][0]["url"], "https://www.shadowserver.org/news/example/")

    def test_dfir_window_does_not_relabel_historical_publication(self):
        body = b"""<rss><channel><item><link>https://thedfirreport.com/example/</link>
            <guid>https://thedfirreport.com/?p=42</guid><title>Incident report</title>
            <pubDate>Mon, 24 Aug 2026 14:00:00 +0000</pubDate></item></channel></rss>"""
        with patch("pipeline.sources.fetch", return_value=body):
            rows, status = advisory("dfir-report", date(2026, 10, 26), date(2026, 11, 25))
        self.assertEqual(status["historical_count"], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["published"], "2026-08-24")
        self.assertFalse(rows[0]["in_window"])

    def test_partial_outage_retains_published_and_new_seed_records(self):
        previous = read_json(CATALOG)
        start, end = map(date.fromisoformat, [previous["window"]["from"], previous["window"]["through"]])
        rows = [row for row in previous["records"] if row["source"] == "ncsc"]
        reference = previous["reference"]
        existing = next(row for row in previous["records"] if row["source"] == "cisa-kev")
        added = {**existing, "id": stable("HF-INT", "fixture-new-seed"), "revision": 7,
                 "published": (start - timedelta(days=1)).isoformat()}
        future = {**added, "id": stable("HF-INT", "fixture-future-seed"),
                  "published": (end + timedelta(days=1)).isoformat()}
        seed = {"records": [added, future, {**existing, "title": "Seed must yield to the publication"}]}

        def inputs(source, *_):
            if source == "ncsc":
                return rows, {"coverage":"full"}
            raise TimeoutError("fixture source unavailable")

        with patch("pipeline.collect.kev", side_effect=TimeoutError), patch("pipeline.collect.epss", side_effect=TimeoutError), \
                patch("pipeline.collect.advisory", side_effect=inputs), patch("pipeline.collect.shadowserver", side_effect=TimeoutError), \
                patch("pipeline.collect.attack", return_value=(reference,{"coverage":"reference"})):
            after, changes, _ = collection(start, end, previous, "2026-11-26T12:00:00Z", seed)
        self.assertEqual([x["state"] for x in after["sources"] if x["id"] == "cisa-kev"], ["cached"])
        for source in ("cert-fr", "unit-42", "cisco-talos"):
            if source in {row["source"] for row in previous["records"]}:
                self.assertEqual([x["state"] for x in after["sources"] if x["id"] == source], ["cached"])
        records = {row["id"]: row for row in after["records"]}
        self.assertEqual(set(records), {row["id"] for row in previous["records"]} | {added["id"]})
        self.assertEqual(records[existing["id"]]["title"], existing["title"])
        backfill = records[added["id"]]
        self.assertFalse(backfill["in_window"])
        self.assertEqual(backfill["first_retrieved"], added["first_retrieved"])
        self.assertEqual(backfill["retrieved"], added["retrieved"])
        self.assertEqual([(row["id"], row["action"], row["revision"]) for row in changes], [(added["id"], "created", 1)])


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
    def test_release_build_is_deterministic_and_has_real_provenance(self):
        inputs = [read_json(path) for path in (CATALOG,HUNTS,PROFILE_CATALOG,REPORT)]
        manifest, files = release_files(*inputs,"a" * 40)
        self.assertEqual((manifest,files),release_files(*inputs,"a" * 40))
        self.assertTrue(manifest["counts"]["in_window"] > 0)
        self.assertTrue(manifest["source_commit"] == "a" * 40)
        self.assertTrue(all(item["evidence"] for item in inputs[0]["records"]))
        self.assertIn("indicators/bulk-query.json", manifest["files"])
        self.assertFalse(any(path.endswith(".zip") for path in files))
        for hunt in inputs[1]:
            for profile, variant in hunt["variants"].items():
                path = f"downloads/{hunt['id']}-r{hunt['revision']}-{profile}.kql"
                self.assertEqual(files[path].decode(), variant["queries"][str(hunt["lookback"])]["table"])

    def test_vulnerability_hunts_link_through_reviewed_cves(self):
        catalog, hunts, profiles, report = [read_json(path) for path in (CATALOG,HUNTS,PROFILE_CATALOG,REPORT)]
        _, files = release_files(catalog, hunts, profiles, report, "a" * 40)
        index = json.loads(files["intelligence/index.json"])["items"]
        vulnerabilities = [row for row in index if row["kind"] == "Vulnerability"]
        covered = [row for row in vulnerabilities if row["exploitation_hunts"]]
        self.assertGreaterEqual(len(covered), 9)
        for row in covered:
            for hunt_id in row["exploitation_hunts"]:
                hunt = json.loads(files[f"hunts/{hunt_id}.json"])
                self.assertTrue(set(hunt["cves"]).intersection(row["cves"]))
                self.assertTrue(hunt["profiles"][0].startswith("sentinel-"))
                self.assertTrue(hunt["evidence"])


if __name__ == "__main__":
    unittest.main()
