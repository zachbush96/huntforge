# HuntForge

HuntForge publishes public threat intelligence and evidence-backed KQL for Microsoft Sentinel and Defender XDR. Browse [the website](https://zachbush96.github.io/huntforge/), resolve [the latest API release](https://zachbush96.github.io/huntforge/api/v1/latest.json), or download KQL from [the publication branch](https://github.com/zachbush96/huntforge/tree/codex/publications/hunts/queries).

Hunts default to Microsoft Sentinel Logs. Filter by source date, actor or topic. Each technique includes a definition and a Sentinel alert pivot using ATT&CK tags, plus behavioral KQL when HuntForge covers the technique.

Vulnerability records link to CVE-specific exploitation hunts when reviewed evidence supports a query. Use the exploitation coverage filter to find these records. From Indicators, copy a single Sentinel KQL statement for the current release's full eligible indicator set. Select CEF or endpoint telemetry and a lookback. Results identify the matched field, event context, indicator and source evidence.

On a Hunt Card, select **Explain the results to me** to analyze redacted results with an endpoint you control. Enter the full URL, model and API format. The form supports Ollama native chat and Chat Completions-compatible servers. The endpoint must allow browser requests from the HuntForge origin. Requests go directly to your endpoint, and results and API keys are kept in the form for the current visit.

Use **Feedback** in the site header to send suggestions to the maintainer's private Google Forms inbox. Maintainers review the **Responses** tab in the form editor. Keep editor access restricted and respondent summaries disabled. Treat messages and suggested URLs as untrusted text. Verify a source before proposing it through the normal source review process.

The initial collection spans **October 25 to November 24, 2026**, inclusive. Pushes to `main` start collection and publishing through GitHub Actions. The collector refreshes the active entries in [the source registry](SOURCES.yaml). Open **System Status** for the latest coverage and use the **Source** filter in Intelligence to browse by publisher. The DFIR Report also contributes historical intrusion research from its public feed. MITRE ATT&CK® Enterprise is a reference snapshot.

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
