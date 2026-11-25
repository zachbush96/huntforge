"""Render constrained defensive hunts and require Microsoft Kusto analysis."""

import ipaddress
import json
import os
import re
import subprocess
from datetime import date, timedelta
from urllib.parse import urlsplit

from .sources import ROOT, digest, evidence, read_json, record, stable

DAYS = (1, 3, 7, 14, 30)
JSON_SUFFIX = "| summarize Results = make_list(pack_all())\n| project JSON = tostring(Results)"
VALIDATOR = ROOT / "validator/bin/Release/net9.0/HuntForge.Validator.dll"
VALIDATOR_VERSION = "Microsoft.Azure.Kusto.Language 12.4.1"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
TABLES = {"powershell-download": "DeviceNetworkEvents", "gsocket": "DeviceProcessEvents",
          "quick-assist": "DeviceProcessEvents", "outage-phishing": "DeviceNetworkEvents",
          "service-principal": "AADServicePrincipalSignInLogs"}


def kql_string(value):
    return json.dumps(value, ensure_ascii=True)


def defang(value):
    return value.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def reviewed():
    records, indicators, by_key = [], [], {}
    for item in read_json(ROOT / "data/reviewed-evidence.json"):
        url = item["url"]
        parts = urlsplit(url)
        if parts[:2] != ("https", "www.microsoft.com") or not parts.path.startswith("/en-us/security/blog/"):
            raise ValueError("Reviewed evidence must reference the approved publisher")
        ref = evidence("microsoft", url, url, item["date"], item["location"], item["claim"])
        ref["observation_date"] = item.get("observation_date")
        row = record("microsoft", url, item["date"], item["title"], item["claim"], "Research", "unrated",
                     [ref], cves=[], tags=item["tags"], techniques=item["techniques"], software=item.get("software", []),
                     **({"actors": item["actors"]} if item.get("actors") else {}))
        by_key[item["key"]] = row["id"]
        row["indicators"] = []
        for kind, original, context in item.get("indicators", []):
            value = original.lower().replace("[.]", ".").replace("hxxps://", "https://")
            if kind == "domain" and not DOMAIN.fullmatch(value):
                raise ValueError("Invalid domain indicator")
            if kind == "ipv4" and not ipaddress.IPv4Address(value).is_global:
                raise ValueError("Invalid public IPv4 indicator")
            if kind == "url" and (urlsplit(value).scheme != "https" or not DOMAIN.fullmatch(urlsplit(value).netloc)):
                raise ValueError("Invalid HTTPS indicator")
            if kind not in {"domain", "ipv4", "url"}:
                raise ValueError("Unsupported indicator type")
            identifier = stable("HF-IOC", kind + "\n" + value)
            row["indicators"].append(identifier)
            indicators.append({
                "schema_version": 1, "revision": 1, "id": identifier, "type": kind, "value": value,
                "original": original, "display": defang(value), "context": context, "record_id": row["id"],
                "evidence": [ref], "reported": row["published"], "first_observed": item.get("observation_date"),
                "last_observed": None, "source_expires": None,
                "aging_review": (date.fromisoformat(row["published"]) + timedelta(days=45)).isoformat(),
            })
        records.append(row)
    return records, indicators, by_key


def validate_profile(profile):
    allowed_types = {"datetime", "string", "int", "long", "bool", "dynamic", "real"}
    for table, data in profile["tables"].items():
        columns = data["columns"]
        if not IDENT.fullmatch(table) or len(columns) > 80 or columns.get(data["timestamp"]) != "datetime":
            raise ValueError("Invalid telemetry table or timestamp")
        if not all(IDENT.fullmatch(key) and value in allowed_types for key, value in columns.items()):
            raise ValueError("Invalid telemetry column names or types")
        if not all(column in columns for column in data["mappings"].values()):
            raise ValueError("Mapping references an undeclared column")


def render_query(table, schema, statements, days, json_output=False):
    if days not in DAYS:
        raise ValueError("Unsupported lookback")
    query = "\n".join([table, f"| where {schema['timestamp']} > ago({days}d)", *statements])
    return query + ("\n" + JSON_SUFFIX if json_output else "") + "\n"


def variant(rule, profile, indicators):
    validate_profile(profile)
    key = rule["research"]
    template = rule.get("query")
    if template:
        table = template["table"]
        schema = profile["tables"][table]
        statements = []
        for statement in template["statements"]:
            statement = statement.replace("{time}", schema["timestamp"])
            for kind in ("domain", "ipv4"):
                marker = "{" + kind + "}"
                if marker in statement:
                    literals = ", ".join(kql_string(x["value"]) for x in indicators if x["type"] == kind)
                    if not literals:
                        raise ValueError(f"Missing reviewed {kind} indicators for {rule['id']}")
                    statement = statement.replace(marker, literals)
            statements.append(statement)
        return table, schema, statements
    if profile["id"] == "sentinel-windows" and key in {"powershell-download", "quick-assist"}:
        if key == "powershell-download":
            table = "WindowsEvent"
            statements = [
                '| where Channel == "Microsoft-Windows-Sysmon/Operational" and EventID == 3',
                '| extend Image = tostring(EventData.Image), DestinationIP = tostring(EventData.DestinationIp)',
                r'| where Image endswith @"\powershell.exe" or Image endswith @"\pwsh.exe"',
                '| where isnotempty(DestinationIP)',
                '| project TimeGenerated, Computer, Image, DestinationIP, DestinationPort = tostring(EventData.DestinationPort),',
                '          ProcessGuid = tostring(EventData.ProcessGuid), User = tostring(EventData.User)',
                '| order by TimeGenerated desc',
            ]
        else:
            table = "SecurityEvent"
            statements = [
                r'| where EventID == 4688 and NewProcessName endswith @"\QuickAssist.exe"',
                '| project TimeGenerated, Computer, Account, NewProcessName, CommandLine',
                '| order by TimeGenerated desc',
            ]
        return table, profile["tables"][table], statements
    table = TABLES[key]
    if key == "outage-phishing" and table not in profile["tables"]:
        table = next((name for name, item in profile["tables"].items() if item["capability"] == "web"), "")
    if table not in profile["tables"]:
        raise ValueError("Required telemetry capability is missing")
    schema = profile["tables"][table]
    columns = schema["mappings"]
    timestamp = schema["timestamp"]
    if key == "powershell-download":
        statements = [
            '| where InitiatingProcessFileName in~ (',
            '    "powershell.exe",',
            '    "pwsh.exe"',
            ')',
            "| where isnotempty(RemoteIP)",
            f"| project {timestamp}, DeviceName, RemoteIP, RemotePort, RemoteUrl,",
            "          InitiatingProcessCommandLine", f"| order by {timestamp} desc"]
    elif key == "gsocket":
        statements = [
            '| where FileName in~ ("gs-netcat", "gsocket", "gsnetcat")',
            '     or ProcessCommandLine contains "gs-netcat"',
            f"| project {timestamp}, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName",
            f"| order by {timestamp} desc"]
    elif key == "quick-assist":
        statements = [
            '| where FileName =~ "QuickAssist.exe"',
            f"| project {timestamp}, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName",
            f"| order by {timestamp} desc"]
    elif key == "service-principal":
        literals = ", ".join(kql_string(x["value"]) for x in indicators if x["type"] == "ipv4")
        if not literals:
            raise ValueError("Missing reviewed service-principal address")
        statements = [
            f'| where ResultType == "0" and IPAddress in ({literals})',
            "| project TimeGenerated, ServicePrincipalName, ServicePrincipalId, IPAddress, ResourceDisplayName, ResultType",
            "| order by TimeGenerated desc"]
    else:
        literals = ", ".join(kql_string(x["value"]) for x in indicators if x["type"] == "domain")
        if not literals:
            raise ValueError("Missing reviewed downstream destinations")
        url = columns["Destination URL"]
        raw_host = columns.get("Hostname", url)
        host = f'iff({raw_host} contains "://", tostring(parse_url({raw_host}).Host), {raw_host})'
        fallback = f'tostring(parse_url({url}).Host)'
        projection = list(dict.fromkeys([timestamp, *[columns[name] for name in
            ("Device", "User", "Source IP", "Destination IP", "Destination URL", "Action") if name in columns], "HuntDestinationHost"]))
        statements = [
            f"| extend HuntDestinationHost = tolower(trim_end(@\"\\.+\", coalesce({host}, {fallback})))",
            f"| where HuntDestinationHost in ({literals})",
            f"| project {', '.join(projection)}", f"| order by {timestamp} desc"]
    return table, schema, statements


def run_validator(requests):
    result = subprocess.run(["dotnet", str(VALIDATOR)], input=json.dumps(requests).encode(), capture_output=True,
                            timeout=120, check=True, cwd=ROOT)
    diagnostics = json.loads(result.stdout)
    if len(diagnostics) != len(requests):
        raise ValueError("Kusto analyzer did not return one result per query")
    return diagnostics


def static_pass(query):
    return (
        len(query) < 5000
        and bool(re.search(r"^\| where \w+ > ago\((1|3|7|14|30)d\)$", query, re.M))
        and not re.search(r"\b(externaldata|evaluate|notruncation|invoke|union|join)\b|;", query, re.I)
    )


def add_technique_pivots(items, profiles):
    profile = next(row for row in profiles if row["id"] == "sentinel-alerts")
    validate_profile(profile)
    schema = profile["tables"]["SecurityAlert"]
    techniques = [row for row in items if row["type"] == "attack-pattern"]
    jobs = []
    for row in techniques:
        identifier = row["id"]
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", identifier):
            raise ValueError(f"Unexpected technique identifier: {identifier}")
        pattern = r"(?i)(?:^|[^a-z0-9.])" + re.escape(identifier) + r"(?:$|[^a-z0-9.])"
        statements = [
            f'| where strcat(Techniques, " ", SubTechniques) matches regex @"{pattern}"',
            "| project TimeGenerated, AlertName, AlertSeverity, ProductName, CompromisedEntity, SystemAlertId",
            "| order by TimeGenerated desc",
        ]
        jobs.append({"table": "SecurityAlert", "columns": schema["columns"], "query": render_query("SecurityAlert", schema, statements, 30)})
    for row, job, result in zip(techniques, jobs, run_validator(jobs) if jobs else []):
        if result["syntax"] or result["errors"] or not result["tabular"] or not static_pass(job["query"]):
            raise ValueError(f"Technique alert pivot failed validation: {row['id']}")
        row["alert_query"] = job["query"]


def generate_hunts(records, indicators, by_key, profiles, techniques, previous, today):
    ids = {x["id"] for x in techniques}
    jobs, checks, candidates, rejected = [], {}, [], []
    records_by_id = {x["id"]: x for x in records}
    for rule in read_json(ROOT / "hunts/rules.json"):
        source = records_by_id[by_key[rule["research"]]]
        if rule["technique"] not in ids or not source["evidence"] or rule["technique"] not in source["techniques"]:
            rejected.append({"id": rule["id"], "reason": "Missing reviewed behavioral evidence or ATT&CK reference"})
            continue
        metadata = {key: value for key, value in rule.items() if key != "query"}
        candidate = {**metadata, "schema_version": 1, "status": "partially_validated", "source_ids": [source["id"]],
                     "source_published": source["published"], "tags": source["tags"],
                     "evidence": source["evidence"], "indicator_ids": source.get("indicators", []),
                     "variants": {}, "expected_output": rule.get("expected_output", "One row per matching event in tabular mode. A match supports triage."),
                     "performance": "Time filter first, then table-specific predicates and a narrow projection.",
                     "scope": "Evidence review, static checks, Microsoft Kusto syntax and schema analysis. Engine and workspace execution not run."}
        for profile_id in rule["profiles"]:
            profile = next(row for row in profiles if row["id"] == profile_id)
            table, schema, statements = variant(rule, profile, [x for x in indicators if x["id"] in candidate["indicator_ids"]])
            rendered = {}
            for days in DAYS:
                table_modes = rendered[str(days)] = {}
                for is_json in (False, True):
                    mode = "json" if is_json else "table"
                    query = render_query(table, schema, statements, days, is_json)
                    table_modes[mode] = query
                    jobs.append({"table": table, "columns": schema["columns"], "query": query})
                    checks.setdefault(rule["id"], []).append((len(jobs) - 1, profile_id, days, mode))
            candidate["variants"][profile_id] = {
                "table": table, "queries": rendered, "profile_revision": profile["revision"],
                "validation": {"evidence":"pass", "syntax":"pass", "schema":"pass", "static":"pass",
                               "synthetic_fixture":"not_run", "engine":"not_run", "workspace":"not_run", "analyst":"not_run"},
            }
        candidate["primary_table"] = candidate["variants"][rule["profiles"][0]]["table"]
        candidates.append(candidate)
    diagnostics = run_validator(jobs) if jobs else []
    accepted = []
    prior = {x["id"]: x for x in previous or []}
    for candidate in candidates:
        identifier = candidate["id"]
        failures = []
        for idx, profile_id, days, mode in checks[identifier]:
            result = diagnostics[idx]
            if result["syntax"] or result["errors"] or not result["tabular"] or not static_pass(jobs[idx]["query"]):
                failures.append({"profile": profile_id, "days": days, "mode": mode, "diagnostics": result})
        if failures:
            rejected.append({"id": identifier, "reason": "Mandatory syntax, schema, or static checks failed", "checks": failures})
            continue
        old = prior.get(identifier, {})
        signature = digest(json.dumps({**candidate, "validator": VALIDATOR_VERSION}, sort_keys=True).encode())
        changed = old.get("signature") != signature
        revision = old.get("revision", 0) + changed
        history = old.get("history", [])
        if changed:
            summary = "Created evidence-backed hunt and validated all supported variants."
            if old:
                changed_fields = [name for name in candidate if candidate[name] != old.get(name)]
                summary = "Revalidated after changes to " + ", ".join(changed_fields or ["validator version"]) + "."
            history = [*history, {"revision": revision, "date": today, "change": "Updated" if old else "Created", "summary": summary}]
        accepted.append({**candidate, "revision": revision, "signature": signature, "history": history,
                         "published": old.get("published", today), "updated": history[-1]["date"],
                         "validation": {"date": history[-1]["date"], "validator": VALIDATOR_VERSION,
                                        "variants_checked": len(checks[identifier])}})
    return accepted, rejected
