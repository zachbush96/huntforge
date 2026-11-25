# API v1

The public root is [api/v1/latest.json](https://zachbush96.github.io/huntforge/api/v1/latest.json). Its `snapshot` path resolves relative to `api/v1/`. Each release snapshot has an ID, creation time, collection window, source commit, counts and hashes.

Fetch `releases/<release-id>/manifest.json`, then use these relative paths.

| Path | Contents |
| --- | --- |
| `intelligence/index.json` | Intelligence listing and reviewed metadata. |
| `intelligence/<id>.json` | Record provenance, evidence, correlations and EPSS history where available. |
| `hunts/index.json` | Accepted Hunt Cards. |
| `hunts/<id>.json` | Complete prevalidated queries by profile, lookback and output mode. |
| `indicators/index.json` | Source observations and lifecycle fields. |
| `profiles/index.json` | Versioned public and synthetic Environment Profiles. |
| `reference/index.json` | Current MITRE ATT&CK® Enterprise reference and original license. |
| `changes.json` | Release delta and current tombstones. |
| `report.json` | Latest collection and validation summary for this release. |
| `search.json` | Browser search terms for client-side indexes. |
| `indicators/bulk-query.json` | A single Sentinel IOC correlation statement per telemetry table and lookback, with snapshot date, counts and validation. |
| `downloads/{hunt-id}-r{revision}-{profile-id}.kql` | An individually executable KQL download for a Hunt Card profile at its suggested lookback. |
| `schemas/*.v1.json` | JSON Schema 2020-12 records. |

`api/v1/history.json` lists retained snapshots. Sort and filter locally. There are no server-side search parameters or pagination. Release items are immutable once issued. The Pages host controls HTTP cache and CORS headers. Consumers that need freshness should revalidate the latest pointer.

Source commits and archived files remain on GitHub. The current release includes one index per entity class and individual record files. Older archived endpoints may be removed from hosting when the site reaches its capacity, while Git retains the published data.
