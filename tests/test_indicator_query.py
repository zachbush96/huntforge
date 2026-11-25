import json
import re
import unittest
from copy import deepcopy
from datetime import date
from unittest.mock import patch

from pipeline.collect import CATALOG, PROFILE_CATALOG
from pipeline.indicator_query import build_indicator_query
from pipeline.queries import DAYS
from pipeline.sources import read_json


def inline_indicators(query):
    literal = query.split("HfIndicatorCatalog = dynamic(", 1)[1].split(")\n| extend HfMatch0", 1)[0]
    return json.loads(literal)


def projected_aliases(query):
    projection = query.split("| project ", 1)[1].split("\n| order by", 1)[0]
    return re.findall(r"\b([A-Za-z_]+) = ", projection)


class IndicatorQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = read_json(CATALOG)
        cls.profiles = read_json(PROFILE_CATALOG)
        cls.as_of = cls.catalog["window"]["through"]

    def compile(self, indicators):
        return build_indicator_query(indicators, self.catalog["records"], self.profiles, self.as_of)

    def test_current_release_has_one_query_per_lookback_with_lookup_provenance(self):
        result = self.compile(self.catalog["indicators"])
        self.assertEqual(result["table"], "CommonSecurityLog")
        self.assertEqual(result["as_of"], self.as_of)
        self.assertEqual(set(result["queries"]), {str(days) for days in DAYS})
        self.assertEqual(result["indicator_count"], sum(result["counts_by_type"].values()))
        self.assertEqual(result["validation"]["workspace"], "not_run")
        self.assertTrue(result["validation"]["static"])
        self.assertEqual(set(result["match_fields"]),
                         {"SourceIP", "DestinationIP", "DestinationHostName", "SourceHostName", "RequestURL.Host", "RequestURL"})
        for days, query in result["queries"].items():
            self.assertTrue(query.startswith(f"CommonSecurityLog\n| where TimeGenerated > ago({days}d)\n"))
            self.assertIn("LogTable", query)
            self.assertIn("MatchedField", query)
            self.assertIn("MatchedSide", query)
            self.assertIn("IntelRecordId", query)
            self.assertIn("EvidenceURLs", query)
            self.assertIn("LogExternalId", query)
            self.assertLess(query.index("| where isnotnull(HfMatch0)"), query.index("| mv-expand"))
        inline = inline_indicators(result["queries"]["30"])
        self.assertEqual(len(inline), result["indicator_count"])
        for key, items in inline.items():
            for indicator in items:
                self.assertTrue(key.startswith(indicator["Type"] + ":"))
                self.assertTrue(indicator["IntelRecordId"])
                self.assertTrue(indicator["IntelTitle"])
                self.assertTrue(indicator["Context"])
                self.assertTrue(indicator["EvidenceSources"])
                self.assertTrue(indicator["EvidenceURLs"])

    def test_sentinel_endpoint_keeps_similar_context_and_requires_a_full_url_for_path_matching(self):
        result = self.compile(self.catalog["indicators"])
        endpoint, = result["alternate_targets"]
        self.assertEqual(endpoint["table"], "DeviceNetworkEvents")
        self.assertEqual(endpoint["profile_id"], "sentinel-endpoint")
        self.assertEqual(set(endpoint["queries"]), set(result["queries"]))
        self.assertEqual(endpoint["validation"], result["validation"])
        self.assertEqual(endpoint["match_fields"], ["LocalIP", "RemoteIP", "RemoteUrl.Host", "RemoteUrl"])
        self.assertIn("require an absolute RemoteUrl", endpoint["scope_note"])

        cef_query = result["queries"]["30"]
        endpoint_query = endpoint["queries"]["30"]
        self.assertTrue(endpoint_query.startswith("DeviceNetworkEvents\n| where TimeGenerated > ago(30d)\n"))
        self.assertEqual(inline_indicators(endpoint_query), inline_indicators(cef_query))
        self.assertEqual(projected_aliases(endpoint_query), projected_aliases(cef_query))
        self.assertIn("iff(isempty(HfUrlAuthority), HfRawUrl, tostring(parse_url(HfRawUrl).Host))", endpoint_query)
        self.assertIn('iff(isempty(HfUrlAuthority), "", strcat(tolower(HfUrlAuthority)', endpoint_query)
        self.assertIn('strcat("domain:", HfNormalizedUrlHost)', endpoint_query)
        self.assertIn('strcat("ipv4:", HfNormalizedUrlHost)', endpoint_query)
        self.assertIn('strcat("url:", HfNormalizedUrl)', endpoint_query)
        self.assertNotIn('strcat("url:", HfNormalizedUrlHost)', endpoint_query)
        self.assertIn('TrafficDirection = "Unknown"', endpoint_query)
        self.assertIn('LogExternalId = tostring(column_ifexists("ReportId", long(null)))', endpoint_query)
        self.assertIn("LogInitiatingProcess = InitiatingProcessFileName", endpoint_query)

    def test_scope_excludes_expired_review_due_and_future_rows(self):
        prototype = deepcopy(self.catalog["indicators"][0])
        prototype.update(reported="2026-11-01", aging_review="2026-11-25", source_expires=None)
        variants = [
            prototype,
            {**prototype, "id": "expired", "source_expires": "2026-11-24"},
            {**prototype, "id": "review-due", "aging_review": "2026-11-24"},
            {**prototype, "id": "future", "reported": "2026-11-25"},
        ]
        result = build_indicator_query(variants, self.catalog["records"], self.profiles, date(2026, 11, 24))
        self.assertEqual(result["indicator_count"], 1)
        self.assertEqual(result["exclusion_count"], 3)
        self.assertEqual(result["exclusion_counts"], {"expired": 1, "review_due": 1, "not_reported": 1})
        self.assertEqual(len(next(iter(inline_indicators(result["queries"]["30"]).values()))), 1)

    def test_exact_url_case_and_multiple_provenance_records(self):
        original = deepcopy(next(row for row in self.catalog["indicators"] if row["type"] == "url"))
        original.update(value="HTTPS://EXAMPLE.ORG/Case?Token=AbC", reported="2026-11-01", aging_review="2026-12-31")
        another = {**original, "record_id": self.catalog["records"][1]["id"]}
        first = self.compile([original, another, original])
        second = self.compile([another, original])
        self.assertEqual(first, second)
        amended = {**original, "context": "An independent observation tied to the same intel record"}
        self.assertEqual(self.compile([amended, original]), self.compile([original, amended]))
        url = "url:https://example.org/Case?Token=AbC"
        query = first["queries"]["30"]
        self.assertIn('strcat("url:", HfNormalizedUrl)', query)
        self.assertNotIn('strcat("url:", HfNormalizedUrlHost)', query)
        self.assertIn('strcat(tolower(HfUrlAuthority), substring(HfRawUrl, strlen(HfUrlAuthority)))', query)
        matches = inline_indicators(query)
        self.assertEqual(list(matches), [url])
        self.assertEqual({row["IntelRecordId"] for row in matches[url]}, {original["record_id"], another["record_id"]})

    def test_text_stays_in_the_data_literal_and_zero_rows_skip_validation(self):
        indicator = deepcopy(self.catalog["indicators"][0])
        context = 'Example "text"; quoted Unicode and newline:\n| take 1 // \N{GREEK SMALL LETTER PI}'
        indicator["context"] = context
        result = self.compile([indicator])
        query = result["queries"]["30"]
        metadata = next(iter(inline_indicators(query).values()))[0]
        self.assertEqual(metadata["Context"], context)
        self.assertNotIn("\n| take 1", query)
        with patch("pipeline.indicator_query.run_validator", side_effect=AssertionError("unexpected analyzer call")):
            empty = self.compile([])
        self.assertEqual(empty["indicator_count"], 0)
        self.assertEqual(empty["queries"], {})
        self.assertEqual(empty["alternate_targets"][0]["queries"], {})


if __name__ == "__main__":
    unittest.main()
