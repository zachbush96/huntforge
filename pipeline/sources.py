"""Retrieve registered public publisher endpoints and normalize their metadata."""

import hashlib
import html
import ipaddress
import json
import re
import socket
import time
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache"
KEV = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
ATTACK = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ATTACK_LICENSE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt"
EPSS = "https://api.first.org/data/v1/epss"
CISA = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
CISA_ARCHIVE = "https://www.cisa.gov/news-events/cybersecurity-advisories"
MS = "https://www.microsoft.com/en-us/security/blog/feed/"
NCSC = "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"
CERT_FR = "https://cert.cyber.gouv.fr/avis/feed/"
UNIT_42 = "https://unit42.paloaltonetworks.com/category/threat-research/feed/"
TALOS = "https://blog.talosintelligence.com/category/threat-advisory/rss/"
TALOS_BLOG = "https://blog.talosintelligence.com/rss/"
TALOS_SPOTLIGHT = "https://blog.talosintelligence.com/category/threat-spotlight/rss/"
IC3 = "https://www.ic3.gov/CSA/rss"
GOOGLE_TI = "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v"
SECURELIST = "https://securelist.com/feed/"
DFIR_REPORT = "https://thedfirreport.com/feed/"
GREYNOISE = "https://api.greynoise.io/v3/articles/rss"
SHADOWSERVER = "https://www.shadowserver.org/news-insights/"
ADVISORY_FEEDS = {
    "cisa-advisories": (CISA, 1, "Advisory"),
    "microsoft": (MS, 6, "Research"),
    "ncsc": (NCSC, 1, "Research"),
    "cert-fr": (CERT_FR, 1, "Advisory"),
    "unit-42": (UNIT_42, 1, "Research"),
    "cisco-talos": (TALOS, 1, "Advisory"),
    "fbi-flash": (IC3, 1, "Advisory"),
    "google-threat-intelligence": (GOOGLE_TI, 1, "Research"),
    "securelist": (SECURELIST, 3, "Research"),
    "dfir-report": (DFIR_REPORT, 1, "Research"),
    "greynoise": (GREYNOISE, 1, "Research"),
}
FIXED_FEED_PATHS = {urlsplit(url)[:3] for url in (CERT_FR, UNIT_42, TALOS, TALOS_BLOG, TALOS_SPOTLIGHT, IC3,
                                                GOOGLE_TI, DFIR_REPORT, GREYNOISE, SHADOWSERVER)}
FETCH_PATHS = {urlsplit(url)[:3] for url in (KEV, ATTACK, ATTACK_LICENSE, EPSS, CISA_ARCHIVE)} | FIXED_FEED_PATHS
FETCH_PATHS.update(urlsplit(url)[:3] for url, _, _ in ADVISORY_FEEDS.values())
SOURCE_HOSTS = {
    "cisa-advisories": {"www.cisa.gov", "cisa.gov"},
    "microsoft": {"www.microsoft.com"},
    "ncsc": {"www.ncsc.gov.uk"},
    "cert-fr": {"cert.cyber.gouv.fr", "www.cert.cyber.gouv.fr"},
    "unit-42": {"unit42.paloaltonetworks.com"},
    "cisco-talos": {"blog.talosintelligence.com"},
    "fbi-flash": {"www.ic3.gov"},
    "google-threat-intelligence": {"cloud.google.com"},
    "securelist": {"securelist.com"},
    "dfir-report": {"thedfirreport.com"},
    "greynoise": {"www.greynoise.io", "viz.greynoise.io"},
}
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
LIMIT = 64 * 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(canonical(obj))
    temp.replace(path)


def read_json(path, default=None):
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else default


def digest(value):
    return hashlib.sha256(value).hexdigest()


class DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Source redirect needs a registry update")


def fetch(url):
    parts = urlsplit(url)
    target = parts[:3]
    if (target not in FETCH_PATHS or parts.username or parts.password or parts.fragment
            or (parts.query and target in FIXED_FEED_PATHS)
            or (target == urlsplit(SECURELIST)[:3] and parts.query not in {"", "paged=2", "paged=3"})):
        raise ValueError("Endpoint is outside the source registry")
    addresses = socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError("Source DNS returned a non-public address")
    CACHE.mkdir(exist_ok=True)
    key = CACHE / digest(url.encode())
    meta = read_json(key.with_suffix(".json"), {})
    headers = {"User-Agent": "HuntForge/0.1 (+https://github.com/zachbush96/huntforge)", "Accept-Encoding": "identity"}
    if key.exists() and meta.get("etag"):
        headers["If-None-Match"] = meta["etag"]
    if key.exists() and meta.get("last_modified"):
        headers["If-Modified-Since"] = meta["last_modified"]
    opener = build_opener(ProxyHandler({}), DenyRedirect())
    for attempt in range(3):
        try:
            with opener.open(Request(url, headers=headers), timeout=15) as res:
                data = res.read(LIMIT + 1)
                if len(data) > LIMIT:
                    raise ValueError("Source response exceeded byte limit")
                key.write_bytes(data)
                write_json(key.with_suffix(".json"), {"etag": res.headers.get("ETag"), "last_modified": res.headers.get("Last-Modified")})
                return data
        except HTTPError as exc:
            if exc.code == 304 and key.exists():
                return key.read_bytes()
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)
    raise RuntimeError("Retry loop exhausted")


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def plain(value, limit=240):
    parser = PlainText()
    parser.feed(html.unescape(value or ""))
    value = re.sub(r"[\x00-\x1f\u200b\u200e\u200f\u202a-\u202e\u2066-\u2069]", " ", " ".join(parser.parts))
    return " ".join(value.split())[:limit]


def stable(prefix, value):
    return prefix + "-" + digest(value.encode())[:14].upper()


def evidence(source, url, source_id, published, location, claim):
    return {"source": source, "url": url, "source_id": source_id, "published": published,
            "observation_date": None, "modified": None, "location": location, "claim": claim}


def record(source, source_id, date_value, title, summary, kind, severity, refs, **metadata):
    return {"schema_version": 1, "id": stable("HF-INT", source_id), "source_id": source_id,
            "source": source, "published": date_value, "title": title, "summary": summary, "kind": kind,
            "severity": severity, "confidence": "Publisher-reported", "status": "active",
            "evidence": refs, **metadata}


def kev(start, end):
    catalog = json.loads(fetch(KEV))
    if len(catalog["vulnerabilities"]) != catalog["count"]:
        raise ValueError("Incomplete KEV catalog")
    output = []
    for row in catalog["vulnerabilities"]:
        added = date.fromisoformat(row["dateAdded"])
        cve = row["cveID"]
        if not CVE.fullmatch(cve) or added > end:
            continue
        vendor = plain(row["vendorProject"])
        product = plain(row["product"])
        name = plain(row["vulnerabilityName"], 180)
        summary = f"CISA added {cve} to the Known Exploited Vulnerabilities catalog based on evidence of exploitation in the wild."
        if row.get("dueDate"):
            summary += f" Federal remediation due {row['dueDate']}."
        ransomware = row.get("knownRansomwareCampaignUse") == "Known"
        url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + cve
        refs = [evidence("cisa-kev", url, cve, added.isoformat(), "KEV catalog entry",
                         "CISA listed this vulnerability based on evidence of exploitation in the wild.")]
        output.append(record("cisa-kev", cve, added.isoformat(), name, summary, "Vulnerability", "high",
                             refs, cves=[cve], tags=["Exploitation"] + (["Ransomware"] if ransomware else []),
                             vendor=vendor, product=product, remediation_due=row.get("dueDate"),
                             ransomware_use="known" if ransomware else "unknown", in_window=added >= start))
    return output, {"snapshot": catalog["dateReleased"], "coverage": "full", "first_available": min(row["published"] for row in output)}


def epss(start, end, cves):
    scores = {}
    dates = set()
    for i in range(0, len(cves), 35):
        batch = cves[i:i+35]
        params = {"cve": ",".join(batch), "scope": "time-series", "limit": str(len(batch))}
        doc = json.loads(fetch(EPSS + "?" + urlencode(params)))
        if doc.get("status") != "OK" or doc.get("total") != len(doc["data"]):
            raise ValueError("Unexpected EPSS response")
        for row in doc["data"]:
            series = {}
            for point in [row, *row.get("time-series", [])]:
                day = date.fromisoformat(point["date"])
                score, percentile = float(point["epss"]), float(point["percentile"])
                if start <= day <= end and 0 <= score <= 1 and 0 <= percentile <= 1:
                    series[day.isoformat()] = {key: point[key] for key in ("date", "epss", "percentile")}
                    dates.add(day.isoformat())
            if series:
                scores[row["cve"]] = [series[key] for key in sorted(series, reverse=True)]
        if i + len(batch) < len(cves):
            time.sleep(1)
    if not dates:
        raise ValueError("No EPSS observations in the requested window")
    return scores, {"first_available": min(dates), "snapshot": max(dates), "score_days": len(dates),
                    "coverage": "full" if len(dates) == (end - start).days + 1 else "partial",
                    "coverage_note": f"Scoped to {len(scores)} CVEs with available KEV-linked scores."}


def attack():
    doc = json.loads(fetch(ATTACK))
    license_text = fetch(ATTACK_LICENSE).decode()
    if "MITRE" not in license_text:
        raise ValueError("Missing MITRE attribution")
    collection = next(row for row in doc["objects"] if row["type"] == "x-mitre-collection")
    items = []
    for row in doc["objects"]:
        if row["type"] not in {"attack-pattern", "intrusion-set", "malware"} or row.get("revoked") or row.get("x_mitre_deprecated"):
            continue
        ref = next((x for x in row.get("external_references", []) if x.get("source_name") == "mitre-attack"), None)
        if ref and re.fullmatch(r"[TGS]\d{4}(?:\.\d{3})?", ref["external_id"]) and ref["url"].startswith("https://attack.mitre.org/"):
            items.append({"schema_version": 1, "id": ref["external_id"], "type": row["type"], "title": plain(row["name"]),
                          "url": ref["url"], "modified": row["modified"],
                          "aliases": [plain(alias) for alias in row.get("aliases", [])],
                          "tactics": [p["phase_name"] for p in row.get("kill_chain_phases", [])]})
            if row["type"] == "attack-pattern":
                opening = row.get("description", "").split("\n\n", 1)[0]
                opening = re.sub(r"\[([^\]]+)\]\([^)]+\)|\(Citation:[^)]+\)", lambda match: match[1] or "", opening)
                items[-1]["description"] = plain(opening, 680)
    return {"collection": collection.get("x_mitre_version"), "license": license_text, "items": sorted(items, key=lambda x: x["id"])}, {
        "snapshot": collection["modified"], "coverage": "reference", "coverage_note": "Current Enterprise snapshot."}


TOPICS = {
    "Ransomware": ("ransomware", "ransom"),
    "Phishing": ("phishing", "social engineering", "impersonation"),
    "Identity": ("sign-in", "oauth", "credential", "identity", "authentication", "active directory"),
    "Supply Chain": ("supply chain", "supply-chain", "third-party compromise"),
    "Agentic AI": ("agentic", "ai agent", "coding agent"),
    "APT Activity": ("north korean", "nation-state", "intrusions", "espionage", "apt "),
    "LOLBins": ("powershell", "mshta", "rundll32"),
    "Insider Threat": ("insider threat", "malicious insider"),
    "Exploitation": ("vulnerability", "exploitation", "vulnerabilities", "cve-"),
}


def publisher_record(source, source_id, link, published, title, kind, text, location="Publisher feed entry"):
    cves = sorted({match.group().upper() for match in CVE.finditer(text)})
    topics = TOPICS
    if source in {"fbi-flash", "google-threat-intelligence", "securelist", "dfir-report", "greynoise", "shadowserver"}:
        topics = {**TOPICS, "Malware": ("malware", "infostealer", "botnet", "backdoor", "loader"),
                  "Exposure": ("internet-facing", "internet-exposed", "honeypot", "exposed devices")}
    lower = text.lower()
    tags = [topic for topic, terms in topics.items() if any(term in lower for term in terms)]
    summary = "Publisher security advisory." if kind == "Advisory" else "Publisher research and guidance."
    if source == "cert-fr":
        summary = "CERT-FR security advisory. The publisher lists affected products and mitigations."
        tags = ["Vulnerability management"]
    elif tags:
        summary += " Topics include " + ", ".join(tags).lower() + "."
    if cves:
        summary += " References " + ", ".join(cves[:5]) + "."
    ref = evidence(source, link, source_id, published.isoformat(), location, title)
    return record(source, source_id, published.isoformat(), title, summary, kind, "unrated",
                  [ref], cves=cves, tags=tags)


def rss_records(source, url, max_pages, kind, start, end):
    observed = {}
    dates = []
    for page in range(1, max_pages + 1):
        raw = fetch(url if page == 1 else f"{url}?paged={page}")
        if b"\0" in raw or re.search(br"<!DOCTYPE|<!ENTITY", raw, re.I):
            raise ValueError("Feed must use a single-byte or UTF-8 encoding without DTD declarations")
        for item in ET.fromstring(raw).findall("./channel/item"):
            try:
                link = urlsplit(item.findtext("link", "").strip())
                published = parsedate_to_datetime(item.findtext("pubDate")).date()
            except (TypeError, ValueError, OverflowError):
                continue
            if link.scheme != "https" or link.netloc not in SOURCE_HOSTS[source]:
                continue
            link = link._replace(query="", fragment="")
            source_id = advisory_id(source, item, link)
            title = plain(item.findtext("title"), 200)
            if not source_id or not title:
                continue
            dates.append(published)
            if published > end or (published < start and source != "dfir-report"):
                continue
            excerpt = plain(item.findtext("description"), 600)
            categories = {plain(row.text).lower() for row in item.findall("category")}
            text = title + " " + excerpt
            if source in {"unit-42", "securelist", "cisco-talos"}:
                text += " " + " ".join(sorted(categories))
            microsoft_security = {"linux", "malware", "incident response", "lateral movement", "frontier ai models",
                                  "vulnerability", "credential theft", "token theft", "supply chain attack"}
            row_kind = kind
            if source == "cisco-talos" and url != TALOS:
                research = {"threat advisory", "threat spotlight", "threats", "on the radar",
                            "talos ir trends", "patch tuesday"}
                if not categories & research:
                    continue
                row_kind = "Advisory" if "threat advisory" in categories else "Research"
            row = publisher_record(source, source_id, link.geturl(), published, title, row_kind, text)
            if source == "microsoft" and (not row["tags"] and not categories & microsoft_security or
                                          "/gartner-" in link.path or "/idc-" in link.path):
                continue
            observed[source_id] = {**row, "in_window": start <= published}
        if dates and min(dates) <= start:
            break
    return observed, dates


def advisory(source, start, end):
    observed, dates = rss_records(source, *ADVISORY_FEEDS[source], start, end)
    archive_note = ""
    coverage_floor = min(dates) if dates else None
    incomplete = False
    if source == "cisco-talos" and dates:
        for endpoint in (TALOS_BLOG, TALOS_SPOTLIGHT):
            try:
                more, available = rss_records(source, endpoint, 1, "Research", start, end)
                if not available:
                    raise ValueError("No usable entries in supplemental RSS feed")
                coverage_floor = max(coverage_floor, min(available))
                dates.extend(available)
                observed = {**more, **observed}
            except (OSError, ValueError, ET.ParseError):
                incomplete = True
        archive_note = (" Supplemental Talos RSS coverage is incomplete." if incomplete
                        else " Includes Threat Advisories, Threat Spotlights and security research from the main Talos feed.")
    if source == "cisa-advisories" and (not dates or min(dates) > start):
        try:
            for page in range(5):
                parser = CisaListing()
                parser.feed(fetch(CISA_ARCHIVE + f"?page={page}").decode())
                if not parser.entries:
                    raise ValueError("No advisory entries matched the listing")
                for published, path, title in parser.entries:
                    dates.append(published)
                    url = "https://www.cisa.gov" + path
                    if not start <= published <= end or url in observed:
                        continue
                    summary = "Publisher security advisory indexed in the CISA advisory archive."
                    ref = evidence(source, url, url, published.isoformat(), "CISA advisory archive", title)
                    cves = sorted(set(m.group().upper() for m in CVE.finditer(title)))
                    observed[url] = record(source, url, published.isoformat(), title, summary, "Advisory", "unrated",
                                           [ref], cves=cves, tags=["Exploitation"] if cves else [], in_window=True)
                if min(dates) <= start:
                    break
            archive_note = " Includes the paginated CISA advisory archive."
        except (OSError, ValueError) as error:
            archive_note = f" Archive retrieval incomplete ({type(error).__name__})."
        coverage_floor = min(dates) if dates else None
    if not dates:
        raise ValueError("Feed did not contain usable entries")
    details = {"first_available": min(dates).isoformat(),
               "coverage": "full" if coverage_floor <= start and not incomplete else "partial",
               "coverage_note": "Coverage reflects available publisher feed entries." + archive_note}
    if source == "dfir-report":
        details["historical_count"] = sum(not row["in_window"] for row in observed.values())
        details["coverage_note"] += " Older reports in the feed are retained as historical research."
    return list(observed.values()), details


def advisory_id(source, item, link):
    guid = item.findtext("guid", "").strip()
    if source == "cert-fr":
        match = re.fullmatch(r"/avis/(CERTFR-\d{4}-AVI-\d+)/", link.path)
    elif source == "unit-42":
        match = re.fullmatch(r"https://unit42\.paloaltonetworks\.com/\?p=(\d+)", guid)
    elif source == "cisco-talos":
        match = re.fullmatch(r"([0-9a-f]{24})", guid)
    elif source == "fbi-flash":
        match = re.fullmatch(r"(\d{6}(?:-\d+)?)", guid) if link.path.startswith("/CSA/") else None
    elif source == "securelist":
        match = re.search(r"/(\d+)/?$", link.path)
    elif source == "dfir-report":
        match = re.fullmatch(r"https://thedfirreport\.com/\?p=(\d+)", guid)
    elif source == "greynoise":
        match = re.fullmatch(r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", guid)
    elif source == "google-threat-intelligence":
        return link.geturl() if link.path.startswith("/blog/topics/threat-intelligence/") else None
    else:
        return link.geturl()
    return f"{source}:{match[1]}" if match else None


def shadowserver(start, end):
    parser = ShadowserverListing()
    parser.feed(fetch(SHADOWSERVER).decode("utf-8"))
    parser.close()
    if not parser.entries:
        raise ValueError("No entries matched the Shadowserver public listing")
    records = {}
    report_terms = ("attack", "infection", "ransomware", "malware", "vulnerab", "exploitation",
                    "compromis", "botnet", "credential", "scann", "exposure", "honeypot", "remediation",
                    "abuse", "threat", "incident", "ddos", "security advisory")
    for published, path, title in parser.entries:
        if not start <= published <= end or not any(word in title.lower() for word in report_terms):
            continue
        link = "https://www.shadowserver.org" + path
        row = publisher_record("shadowserver", link, link, published, title, "Research", title,
                               "Shadowserver public News & Insights listing")
        records[row["id"]] = row
    oldest = min(entry[0] for entry in parser.entries)
    return list(records.values()), {
        "first_available": oldest.isoformat(), "coverage": "full" if oldest <= start else "partial",
        "coverage_note": "Coverage reflects threat and exposure publications on the public News & Insights listing.",
    }


class ShadowserverListing(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.entries = []
        self.depth = 0
        self.heading = False
        self.date_depth = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "div":
            if self.depth:
                self.depth += 1
                if "the-date" in (attrs.get("class") or "").split():
                    self.date_depth = self.depth
            elif "article-content" in (attrs.get("class") or "").split():
                self.depth = 1
                self.path, self.title, self.published = None, [], []
        elif self.depth and tag == "h4":
            self.heading = True
        elif self.heading and tag == "a":
            path = attrs.get("href") or ""
            if re.fullmatch(r"/news/[a-zA-Z0-9_-]+/", path):
                self.path = path

    def handle_data(self, data):
        if self.heading and self.path:
            self.title.append(data)
        elif self.date_depth:
            self.published.append(data)

    def handle_endtag(self, tag):
        if tag == "h4":
            self.heading = False
        elif tag == "div" and self.depth:
            if self.depth == self.date_depth:
                self.date_depth = None
            self.depth -= 1
            if self.depth == 0 and self.path:
                title = plain(html.escape(" ".join(self.title)), 200)
                try:
                    published = datetime.strptime(" ".join(self.published).strip(), "%B %d, %Y").date()
                except ValueError:
                    return
                if title:
                    self.entries.append((published, self.path, title))


class CisaListing(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.entries = []
        self.publication = None
        self.title_heading = False
        self.link = None
        self.text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "article":
            self.publication = None
        elif tag == "time" and "datetime" in attrs:
            self.publication = date.fromisoformat(attrs["datetime"][:10])
        elif tag == "h3" and "c-teaser__title" in attrs.get("class", ""):
            self.title_heading = True
        elif tag == "a" and self.title_heading:
            link = attrs.get("href", "")
            if re.fullmatch(r"/news-events/(?:alerts|ics-advisories|cybersecurity-advisories)/[a-zA-Z0-9/_-]+", link):
                self.link, self.text = link, []

    def handle_data(self, data):
        if self.link:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.link:
            if self.publication:
                self.entries.append((self.publication, self.link, plain("".join(self.text), 200)))
            self.link = None
        elif tag == "h3":
            self.title_heading = False
