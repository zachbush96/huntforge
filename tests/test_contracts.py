import unittest

from jsonschema import Draft202012Validator

from pipeline.build import release_files
from pipeline.collect import CATALOG, HUNTS, PROFILE_CATALOG, REPORT
from pipeline.sources import ROOT, read_json


class Contracts(unittest.TestCase):
    def test_release_and_canonical_records(self):
        intelligence, hunts, profiles, report = [read_json(path) for path in (CATALOG,HUNTS,PROFILE_CATALOG,REPORT)]
        manifest, _ = release_files(intelligence,hunts,profiles,report,"0"*40)
        for schema, records in [("release",[manifest]),("intelligence",intelligence["records"]),("hunt",hunts),
                                ("profile",profiles),("indicator",intelligence["indicators"])]:
            definition = read_json(ROOT / "schemas" / (schema + ".v1.json"))
            Draft202012Validator.check_schema(definition)
            validator = Draft202012Validator(definition)
            for record in records:
                validator.validate(record)
