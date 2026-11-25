"""Build a single Sentinel correlation statement from the accepted indicator set."""

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date

from .queries import DAYS, VALIDATOR_VERSION, kql_string, render_query, run_validator, validate_profile


TYPE_NAMES = ("ipv4", "domain", "url")
URL_AUTHORITY = r"(?i)^(https?://[^/?#]+)"
EVENT_COLUMNS = {
    "LogComputer": '""',
    "LogExternalId": '""',
    "LogAction": '""',
    "LogActivity": '""',
    "LogVendor": '""',
    "LogProduct": '""',
    "LogProtocol": '""',
    "LogSourceIP": '""',
    "LogSourceHost": '""',
    "LogDestinationIP": '""',
    "LogDestinationHost": '""',
    "LogDestinationPort": "int(null)",
    "LogLocalIP": '""',
    "LogRemoteIP": '""',
    "LogRemotePort": "int(null)",
    "LogURL": '""',
    "LogInitiatingProcess": '""',
    "LogInitiatingCommandLine": '""',
}


@dataclass(frozen=True)
class TelemetryTarget:
    table: str
    profile_id: str
    url_column: str
    bare_url_host: bool
    aliases: dict[str, str]
    match_fields: tuple[tuple[str, str, str, str, str], ...]
    event_columns: dict[str, str]
    traffic_direction: str
    scope_note: str


CEF = TelemetryTarget(
    table="CommonSecurityLog",
    profile_id="sentinel-cef",
    url_column="RequestURL",
    bare_url_host=False,
    aliases={"HfSourceHost": 'column_ifexists("SourceHostName", "")',
             "HfDirection": 'column_ifexists("CommunicationDirection", "")'},
    match_fields=(
        ("ipv4", "SourceIP", "source", "SourceIP", r'trim(@"\s+", SourceIP)'),
        ("ipv4", "DestinationIP", "destination", "DestinationIP", r'trim(@"\s+", DestinationIP)'),
        ("domain", "SourceHostName", "source", "HfSourceHost", r'tolower(trim_end(@"\.+", trim(@"\s+", HfSourceHost)))'),
        ("domain", "DestinationHostName", "destination", "DestinationHostName",
         r'tolower(trim_end(@"\.+", trim(@"\s+", DestinationHostName)))'),
        ("domain", "RequestURL.Host", "destination", "HfUrlHost", "HfNormalizedUrlHost"),
        ("ipv4", "RequestURL.Host", "destination", "HfUrlHost", "HfNormalizedUrlHost"),
        ("url", "RequestURL", "destination", "RequestURL", "HfNormalizedUrl"),
    ),
    event_columns={
        "LogComputer": 'column_ifexists("Computer", "")',
        "LogExternalId": 'column_ifexists("ExternalID", "")',
        "LogAction": "DeviceAction",
        "LogActivity": "Activity",
        "LogVendor": "DeviceVendor",
        "LogProduct": "DeviceProduct",
        "LogProtocol": 'column_ifexists("Protocol", "")',
        "LogSourceIP": "SourceIP",
        "LogSourceHost": "HfSourceHost",
        "LogDestinationIP": "DestinationIP",
        "LogDestinationHost": "DestinationHostName",
        "LogDestinationPort": "DestinationPort",
        "LogURL": "RequestURL",
    },
    traffic_direction=(
        'case(HfDirection in~ ("0", "inbound"), "Inbound", '
        'HfDirection in~ ("1", "outbound"), "Outbound", "Unknown")'
    ),
    scope_note=(
        "Matches source and destination IPs and hostnames, the host in RequestURL, and exact full RequestURL values. "
        "Field coverage depends on how the CEF connector maps the event."
    ),
)

ENDPOINT = TelemetryTarget(
    table="DeviceNetworkEvents",
    profile_id="sentinel-endpoint",
    url_column="RemoteUrl",
    bare_url_host=True,
    aliases={"HfLocalIP": 'column_ifexists("LocalIP", "")'},
    match_fields=(
        ("ipv4", "LocalIP", "local", "HfLocalIP", r'trim(@"\s+", HfLocalIP)'),
        ("ipv4", "RemoteIP", "remote", "RemoteIP", r'trim(@"\s+", RemoteIP)'),
        ("domain", "RemoteUrl.Host", "remote", "HfUrlHost", "HfNormalizedUrlHost"),
        ("ipv4", "RemoteUrl.Host", "remote", "HfUrlHost", "HfNormalizedUrlHost"),
        ("url", "RemoteUrl", "remote", "RemoteUrl", "HfNormalizedUrl"),
    ),
    event_columns={
        "LogComputer": "DeviceName",
        "LogExternalId": 'tostring(column_ifexists("ReportId", long(null)))',
        "LogAction": "ActionType",
        "LogProtocol": 'column_ifexists("Protocol", "")',
        "LogLocalIP": "HfLocalIP",
        "LogRemoteIP": "RemoteIP",
        "LogRemotePort": "RemotePort",
        "LogURL": "RemoteUrl",
        "LogInitiatingProcess": "InitiatingProcessFileName",
        "LogInitiatingCommandLine": "InitiatingProcessCommandLine",
    },
    traffic_direction='"Unknown"',
    scope_note=(
        "Matches local and remote IPs and RemoteUrl hostnames. Full URL indicators require an absolute RemoteUrl. "
        "A hostname-only event can match a domain or IP. Local and remote describe the device's view of the event."
    ),
)


def _date(value):
    return date.fromisoformat(value[:10]) if isinstance(value, str) else value


def _excluded(indicator, as_of):
    if _date(indicator["reported"]) > as_of:
        return "not_reported"
    expires = indicator.get("source_expires")
    if expires and _date(expires) <= as_of:
        return "expired"
    if _date(indicator["aging_review"]) <= as_of:
        return "review_due"
    return None


def _match_value(kind, value):
    value = value.strip()
    if kind == "domain":
        return value.lower().rstrip(".")
    if kind == "url":
        authority = re.match(URL_AUTHORITY, value)
        if not authority:
            raise ValueError("Expected an absolute HTTP or HTTPS indicator URL")
        return authority[1].lower() + value[authority.end():]
    return value


def _metadata(indicator, records_by_id):
    record_id = indicator.get("record_id", "")
    record = records_by_id.get(record_id, {})
    sources = {item["source"] for item in indicator["evidence"]}
    return {
        "Id": indicator["id"],
        "Type": indicator["type"],
        "Value": indicator["value"],
        "Context": indicator.get("context", ""),
        "IntelRecordId": record_id,
        "IntelTitle": record.get("title", ""),
        "IntelTags": record.get("tags", []),
        "IntelActors": record.get("actors", []),
        "Cves": record.get("cves", []),
        "EvidenceSources": sorted("Microsoft" if name == "microsoft" else name for name in sources),
        "EvidenceURLs": sorted({item["url"] for item in indicator["evidence"]}),
        "Reported": indicator["reported"],
        "FirstObserved": indicator.get("first_observed"),
        "LastObserved": indicator.get("last_observed"),
        "ReviewBy": indicator["aging_review"],
        "SourceExpires": indicator.get("source_expires"),
    }


def _lookup_catalog(indicators, records, as_of):
    records_by_id = {record["id"]: record for record in records}
    lookup = defaultdict(list)
    exclusions = Counter(dict.fromkeys(("not_reported", "review_due", "expired"), 0))
    for indicator in sorted(indicators, key=lambda item: (item["id"], item.get("record_id", ""))):
        reason = _excluded(indicator, as_of)
        if reason:
            exclusions[reason] += 1
            continue
        kind = indicator["type"]
        if kind not in TYPE_NAMES:
            raise ValueError(f"Unsupported indicator type: {kind}")
        key = f"{kind}:{_match_value(kind, indicator['value'])}"
        metadata = _metadata(indicator, records_by_id)
        if metadata not in lookup[key]:
            lookup[key].append(metadata)
    return lookup, exclusions


def _encode_lookup(lookup):
    entries = []
    for key, items in sorted(lookup.items()):
        records = sorted(json.dumps(item, ensure_ascii=True, sort_keys=True, separators=(",", ":")) for item in items)
        entries.append(f"{kql_string(key)}: [{','.join(records)}]")
    return "{\n    " + ",\n    ".join(entries) + "\n}"


def _statements(target, encoded, as_of):
    input_aliases = [rf'HfRawUrl = trim(@"\s+", {target.url_column})']
    input_aliases.extend(f"{name} = {expression}" for name, expression in target.aliases.items())
    parsed_host = "tostring(parse_url(HfRawUrl).Host)"
    host_without_scheme = "HfRawUrl" if target.bare_url_host else '""'
    event_columns = EVENT_COLUMNS | target.event_columns
    statements = [
        "| extend " + ",\n         ".join(input_aliases),
        f'| extend HfUrlAuthority = extract(@"{URL_AUTHORITY}", 1, HfRawUrl)',
        f"| extend HfUrlHost = iff(isempty(HfUrlAuthority), {host_without_scheme}, {parsed_host})",
        r'| extend HfNormalizedUrlHost = tolower(trim_end(@"\.+", HfUrlHost)),',
        '         HfNormalizedUrl = iff(isempty(HfUrlAuthority), "", strcat(tolower(HfUrlAuthority), substring(HfRawUrl, strlen(HfUrlAuthority))))',
        f"| extend HfIndicatorCatalog = dynamic({encoded})",
    ]
    matches, candidates = [], []
    for index, (kind, field, side, raw, normalized) in enumerate(target.match_fields):
        alias = f"HfMatch{index}"
        matches.append(alias)
        statements.append(f'| extend {alias} = HfIndicatorCatalog[strcat("{kind}:", {normalized})]')
        candidates.append(f'bag_pack("Records", {alias}, "Field", "{field}", "Side", "{side}", "Raw", {raw})')
    statements.extend([
        "| where " + " or ".join(f"isnotnull({alias})" for alias in matches),
        "| extend HfCandidates = pack_array(" + ",\n    ".join(candidates) + ")",
        "| mv-expand HfCandidate = HfCandidates",
        "| where isnotnull(HfCandidate.Records)",
        "| mv-expand HfIndicator = HfCandidate.Records",
        f'| project TimeGenerated, LogTable = "{target.table}", IndicatorSetAsOf = {kql_string(as_of.isoformat())},',
        '          MatchedField = tostring(HfCandidate.Field), MatchedSide = tostring(HfCandidate.Side),',
        '          MatchedValue = tostring(HfCandidate.Raw),',
        f"          TrafficDirection = {target.traffic_direction},",
        '          IndicatorId = tostring(HfIndicator.Id), IndicatorType = tostring(HfIndicator.Type), IndicatorValue = tostring(HfIndicator.Value),',
        '          IntelRecordId = tostring(HfIndicator.IntelRecordId), IntelTitle = tostring(HfIndicator.IntelTitle),',
        '          IndicatorContext = tostring(HfIndicator.Context), Actors = HfIndicator.IntelActors, Tags = HfIndicator.IntelTags, CVEs = HfIndicator.Cves,',
        '          IndicatorReported = tostring(HfIndicator.Reported), IndicatorFirstObserved = tostring(HfIndicator.FirstObserved),',
        '          IndicatorLastObserved = tostring(HfIndicator.LastObserved),',
        '          IndicatorReviewBy = tostring(HfIndicator.ReviewBy), IndicatorSourceExpires = tostring(HfIndicator.SourceExpires),',
        '          EvidenceSources = HfIndicator.EvidenceSources, EvidenceURLs = HfIndicator.EvidenceURLs,',
        "          " + ",\n          ".join(f"{name} = {value}" for name, value in event_columns.items()),
        "| order by TimeGenerated desc",
    ])
    return statements


def _build_target(target, profile, encoded, as_of):
    queries = {}
    if encoded:
        if not profile:
            raise ValueError(f"Missing Sentinel profile for indicator correlation: {target.profile_id}")
        validate_profile(profile)
        schema = profile["tables"][target.table]
        statements = _statements(target, encoded, as_of)
        queries = {str(days): render_query(target.table, schema, statements, days) for days in DAYS}
        jobs = [{"table": target.table, "columns": schema["columns"], "query": query} for query in queries.values()]
        for days, result in zip(queries, run_validator(jobs)):
            if result["syntax"] or result["errors"] or not result["tabular"]:
                problems = list(dict.fromkeys(result["syntax"] + result["errors"]))
                raise ValueError(
                    f"Indicator correlation failed Kusto validation ({target.table}, {days} days): {', '.join(problems)}"
                )
    return {
        "table": target.table,
        "profile_id": target.profile_id,
        "scope_note": target.scope_note,
        "match_fields": list(dict.fromkeys(field for _, field, *_ in target.match_fields)),
        "validation": {"validator": VALIDATOR_VERSION, "static": bool(queries), "workspace": "not_run"},
        "queries": queries,
    }


def build_indicator_query(indicators, records, profiles, as_of):
    """Return statically validated Sentinel correlation queries for each target and lookback."""
    as_of = _date(as_of)
    lookup, exclusions = _lookup_catalog(indicators, records, as_of)
    counts = Counter(dict.fromkeys(TYPE_NAMES, 0))
    counts.update(key.split(":", 1)[0] for key in lookup)
    profiles_by_id = {profile["id"]: profile for profile in profiles}
    encoded = _encode_lookup(lookup) if lookup else ""
    default_target = _build_target(CEF, profiles_by_id.get(CEF.profile_id), encoded, as_of)
    alternate_targets = [
        _build_target(target, profiles_by_id[target.profile_id], encoded, as_of)
        for target in (ENDPOINT,)
        if target.profile_id in profiles_by_id
    ]
    return {
        **default_target,
        "as_of": as_of.isoformat(),
        "indicator_count": len(lookup),
        "counts_by_type": dict(counts),
        "exclusion_count": sum(exclusions.values()),
        "exclusion_counts": dict(exclusions),
        "alternate_targets": alternate_targets,
    }
