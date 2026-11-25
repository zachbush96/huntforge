# Publication quality

| State | Requirements |
| --- | --- |
| Validated | Evidence, syntax, schema, static checks and actual KQL engine testing pass against the declared scope. |
| Partially validated | Mandatory checks pass. Engine execution is pending or unavailable. |
| Unvalidated | One or more required checks have yet to run. Excluded from production hunt catalogs. |
| Rejected | A mandatory check failed. Kept in the sanitized run report and excluded from published hunts. |

The current Kusto.Language analyzer checks both output formats and all five lookback choices for every compatible profile. It analyzes names, types, functions and the tabular result. The static check requires an early time filter and excludes unsupported constructs. These checks are tied to the query and profile revisions.

Tests use representative parser, schema, outage, markup and UI fixtures. They do not execute KQL. Engine, workspace, per-rule synthetic telemetry and analyst execution fields record `not_run`.

The Brief labels KEV entries high based on CISA's exploitation criterion. Other publishers' records generally stay unrated. EPSS estimates probability and remains a separate attributed signal. Correlation among advisory records uses shared CVE IDs and does not establish independent corroboration. Analyst effort should follow the explicit evidence and confidence fields.
