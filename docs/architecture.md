# Architecture

The Python collector retrieves only registered publisher endpoints. It uses conditional requests, bounded retries and local untracked caches. Published records contain extracted facts, reviewed evidence and official source links. The site escapes source text and only renders approved publisher links. Raw dumps are not included in the release.

The collector joins records by stable publisher ID, correlates CVE references and stores EPSS data separately. Reviewed evidence can enrich an existing record by canonical URL. Curated behavioral rules can generate KQL only from enabled public profiles and verified facts. Unsupported candidates remain outside the hunt index.

The static builder snapshots canonical inputs and reports. Every API file is hashed. The browser resolves the current release once and loads revision-pinned indexes, records and query variants. The version pointer, website and API are served from one Pages artifact.

The GitHub workflow validates candidates under read-only credentials. It deploys one Pages artifact, verifies its served ID and key hashes, then archives the accepted site and data in `codex/publications`. A rejected candidate leaves the existing deployment in place. If post-deployment verification fails, the workflow redeploys the archived previous site when present.

## Recovery

Inspect the failed job and latest public manifest. Fix the failure in a source branch and dispatch `release.yml` on main. The next run reloads the last accepted catalog. To restore a prior site after a platform incident, stage the `site/` tree from a selected commit on the publication branch and deploy it using the Pages artifact workflow. Smoke-check the matching release ID afterward.

GitHub Pages has a total site-size limit. Monitor the publication branch and archive older snapshot folders outside the served artifact before approaching the limit. Restore immutable files by their original hashes.
