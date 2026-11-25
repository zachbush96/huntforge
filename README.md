# HuntForge

HuntForge publishes public threat intelligence and evidence-backed KQL for Microsoft Sentinel and Defender XDR. Browse [the website](https://zachbush96.github.io/huntforge/), resolve [the latest API release](https://zachbush96.github.io/huntforge/api/v1/latest.json), or download KQL from [the publication branch](https://github.com/zachbush96/huntforge/tree/codex/publications/hunts/queries).

The initial collection spans **October 25–November 24, 2026**, inclusive. CISA KEV, CISA Advisories, FIRST EPSS, Microsoft Security, and UK NCSC provide dated coverage within their documented scopes. MITRE ATT&CK® Enterprise is a separate reference snapshot. See the run report for individual coverage and failures.

## Run locally

Install Python 3.11 or later and the .NET 9 SDK. The static site needs no package manager or JavaScript build step.

```text
python -m pip install -r requirements-dev.txt
dotnet restore validator --locked-mode
dotnet build validator --configuration Release --no-restore
python -m pipeline.build
python -m pipeline.verify
python -m http.server 8765 --bind 127.0.0.1 --directory dist
```

Open [the local preview](http://127.0.0.1:8765/). The tracked canonical files seed a fresh checkout. The live publisher reads the latest accepted data from the publication branch.

```text
python -m pipeline.collect
python -m unittest discover -s tests -v
python -m pipeline.build
python -m pipeline.verify
python -m playwright install chromium
python tests/browser_check.py http://127.0.0.1:8765
python -m pipeline.render HF-2025-0001 --days 14 --json
```

Run the collector with `--as-of 2026-11-24` to scope the dates for the initial window. Feed buffers still reflect what a publisher currently exposes.

## Project reference

- [API and retention](docs/api.md)
- [Profiles and local query rendering](docs/profiles.md)
- [Architecture and recovery](docs/architecture.md)
- [Schedules and operating commands](docs/automation.md)
- [Validation definitions](QUALITY.md)
- [Sources and coverage policy](SOURCES.yaml)
- [Roadmap](ROADMAP.md)
- [Contribution instructions](CONTRIBUTING.md)

HuntForge code is [MIT licensed](LICENSE). Upstream publications and catalog data retain their own terms and attribution. The release carries MITRE's license with its reference data. [Data rights](docs/rights.md)
