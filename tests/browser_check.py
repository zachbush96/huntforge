"""Exercise the built site in Chromium, including browser-generated downloads."""

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

from playwright.sync_api import expect, sync_playwright


def drilldowns(page, base):
    def metric(label):
        control = page.get_by_role("link", name=re.compile(label, re.I))
        return control, int(control.locator("b").inner_text())

    def result_count(text, count):
        label = f"of {count} {text}" if count else f"0 {text}"
        expect(page.get_by_role("navigation", name="Results pages").get_by_text(label, exact=False)).to_be_visible()

    new_findings, count = metric("new findings")
    new_findings.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", name="Intelligence", exact=True)).to_be_visible()
    assert page.get_by_label("From", exact=True).input_value()
    assert page.get_by_label("From", exact=True).input_value() == page.get_by_label("Through", exact=True).input_value()
    result_count("records", count)
    page.go_back()
    high, count = metric("high severity")
    high.click()
    expect(page.get_by_label("Severity",exact=True)).to_have_value("high")
    result_count("records", count)
    page.reload()
    expect(page.get_by_label("Severity",exact=True)).to_have_value("high")
    page.get_by_role("button", name="Clear", exact=True).click()
    expect(page).to_have_url(re.compile(r"#/intelligence$"))
    page.go_back()
    hunts, count = metric("new hunts")
    hunts.click()
    expect(page.get_by_label("Release change", exact=True)).to_have_value("created")
    result_count("hunts", count)
    page.go_back()
    sources, count = metric("source updates")
    sources.click()
    expect(page.get_by_label("Collection state")).to_have_value("live")
    sources_table = page.get_by_role("table").filter(has=page.get_by_role("columnheader", name="Coverage", exact=True))
    if count:
        expect(sources_table.locator("tbody tr")).to_have_count(count)
    else:
        expect(page.get_by_text("No sources match these filters.")).to_be_visible()
    page.go_back()
    cve_link = page.locator(".finding a.chip").filter(has_text=re.compile(r"^CVE-")).first
    cve = cve_link.inner_text()
    cve_link.click()
    expect(page.get_by_role("heading", name="Vulnerabilities", exact=True)).to_be_visible()
    expect(page.get_by_label("CVE", exact=True)).to_have_value(cve)
    page.locator(".finding h3 a").first.click()
    expect(page.get_by_role("heading", name="Record provenance")).to_be_visible()
    page.go_back()
    expect(page.get_by_label("CVE", exact=True)).to_have_value(cve)

    page.goto(base+"#/hunts/HF-2026-0003")
    expect(page.get_by_role("heading",name="Microsoft 365 Outage Phishing Destinations")).to_be_visible()
    page.locator(".hunt-facts").get_by_role("link", name="Partially validated").click()
    expect(page.get_by_role("heading", name="Reviewed source evidence")).to_be_visible()
    page.reload()
    expect(page.get_by_role("tab", name="Intelligence", exact=True)).to_have_attribute("aria-selected","true")
    page.locator(".hunt-facts div").filter(has_text="REQUIRED TELEMETRY").get_by_role("link").click()
    expect(page.get_by_role("link",name="Browse hunts using this profile")).to_be_visible()
    page.get_by_role("button", name=re.compile("Use suggested lookback")).click()
    expect(page.get_by_label("Lookback",exact=True)).to_have_value("7")
    related = page.get_by_role("link", name=re.compile(r"Reported indicators \(\d+\)"))
    count = int(re.search(r"\((\d+)\)",related.inner_text())[1])
    related.click()
    expect(page.get_by_label("Related hunt",exact=True)).to_have_value("HF-2026-0003")
    expect(page.locator(".catalog-card")).to_have_count(count)
    page.locator(".catalog-card .meta a").first.click()
    assert page.get_by_label("Indicator type",exact=True).input_value()

    page.goto(base+"#/techniques/T1059.001")
    expect(page.get_by_role("heading",name="PowerShell",exact=True)).to_be_visible()
    page.get_by_role("link",name="Execution",exact=True).click()
    expect(page.get_by_label("Tactic",exact=True)).to_have_value("execution")
    page.goto(base+"#/adversaries")
    page.locator(".catalog-card .meta a").first.click()
    assert page.get_by_label("Entity type",exact=True).input_value()
    page.goto(base+"#/research")
    page.locator(".finding h3 a").first.click()
    expect(page.get_by_text("HuntForge / Research",exact=True)).to_be_visible()
    page.get_by_role("link",name="Browse research",exact=True).click()
    expect(page.get_by_role("heading",name="Research",exact=True)).to_be_visible()

    page.goto(base+"#/status?panel=validation")
    page.get_by_role("link",name=re.compile(r"^Partially validated")).click()
    expect(page.get_by_label("Validation",exact=True)).to_have_value("partially_validated")
    page.goto(base+"#/changelog")
    page.get_by_label("Change",exact=True).select_option("updated")
    expect(page).to_have_url(re.compile(r"#/changelog\?change=updated$"))
    page.goto(base+"#/developers")
    page.get_by_role("button",name="Copy URL for Latest release pointer").click()
    expect(page.get_by_text("API URL copied.",exact=True)).to_have_text("API URL copied.")
    assert page.evaluate("navigator.clipboard.readText()") == base+"api/v1/latest.json"
    page.get_by_role("link",name="Intelligence index",exact=True).click()
    expect(page.get_by_role("heading",name="Intelligence",exact=True)).to_be_visible()


def sentinel_catalog(page, base):
    page.goto(base+"#/hunts")
    page.get_by_role("link",name=re.compile("hunts from the latest 30-day window")).click()
    expect(page.get_by_label("Source date",exact=True)).to_have_value("recent")
    assert page.locator(".catalog-card").count() > 5
    page.get_by_role("link",name="ARTEX and agentic AI").click()
    expect(page.get_by_role("searchbox",name="Search",exact=True)).to_have_value("ARTEX")
    expect(page.get_by_role("heading",name="ARTEX and WISP Infrastructure in CEF Logs")).to_be_visible()
    page.get_by_role("link",name="Nation-state",exact=True).click()
    expect(page.get_by_label("Topic",exact=True)).to_have_value("Nation-State")
    page.get_by_label("Actor",exact=True).select_option("North Korea")
    expect(page.get_by_role("heading",name="North Korea · Jasper Sleet Sign-in Alerts")).to_be_visible()
    page.goto(base+"#/techniques/T1059.001")
    expect(page.get_by_role("heading",name="What this technique means")).to_be_visible()
    expect(page.get_by_role("heading",name="How to hunt in Sentinel")).to_be_visible()
    query = page.locator(".technique-query").filter(has_text="Suspicious PowerShell Network Activity")
    query.locator("summary").click()
    expect(query.locator("pre")).to_contain_text("WindowsEvent")
    query.get_by_role("button",name="Copy KQL").click()
    expect(page.get_by_text("KQL copied.",exact=True)).to_have_text("KQL copied.")
    assert "TimeGenerated" in page.evaluate("navigator.clipboard.readText()")
    page.goto(base+"#/techniques/T1001")
    expect(page.get_by_role("heading",name="What this technique means")).to_be_visible()
    pivot = page.locator(".technique-query").filter(has_text="Look up alerts tagged T1001")
    pivot.locator("summary").click()
    expect(pivot.locator("pre")).to_contain_text("SecurityAlert")
    expect(pivot.locator("pre")).to_contain_text("T1001")


def results_explanation(page, base):
    requests = []
    endpoint = "https://model.example.test"
    headers = {
        "Access-Control-Allow-Origin":"*",
        "Access-Control-Allow-Headers":"content-type, authorization",
        "Access-Control-Allow-Methods":"POST, OPTIONS",
    }

    def model_response(route):
        request = route.request
        if request.method == "OPTIONS":
            route.fulfill(status=204,headers=headers)
            return
        payload = request.post_data_json
        requests.append((request.url,request.all_headers(),payload))
        if payload["model"] == "simulated-error":
            route.fulfill(status=401,headers=headers,json={"error":"example"})
        elif request.url.endswith("/api/chat"):
            route.fulfill(headers=headers,json={"message":{"content":"Ollama synthetic explanation."}})
        else:
            route.fulfill(headers=headers,json={"choices":[{"message":{"content":"Synthetic explanation. <script>fixture()</script>"}}]})

    page.route(endpoint+"/**",model_response)
    try:
        page.goto(base+"#/hunts/HF-2025-0001")
        page.get_by_role("link",name="Explain the results to me",exact=True).click()
        expect(page.get_by_role("heading",name="Explain the results to me",exact=True)).to_be_visible()
        page.get_by_label("Hunt results",exact=True).fill('{"Computer":"synthetic-workstation"}')
        page.get_by_label("Endpoint URL",exact=True).fill(endpoint+"/v1/chat/completions")
        page.get_by_label("Model",exact=True).fill("synthetic-test-model")
        page.get_by_label("API key (optional)",exact=True).fill("fixture-access-token")
        page.get_by_text("System prompt and generation settings",exact=True).click()
        page.get_by_label("System prompt",exact=True).fill("Use a short SOC summary.")
        page.get_by_label("Temperature",exact=True).fill("0.4")
        page.get_by_label("Max output tokens",exact=True).fill("512")
        assert not requests
        page.get_by_role("button",name="Send and explain").click()
        expect(page.locator(".explain-status")).to_have_text("Explanation ready.")
        assert len(requests) == 1
        _, sent_headers, body = requests[-1]
        assert sent_headers["authorization"] == "Bearer fixture-access-token"
        assert body["model"] == "synthetic-test-model" and body["max_tokens"] == 512 and body["temperature"] == 0.4
        assert "Use a short SOC summary" in body["messages"][0]["content"]
        assert "untrusted evidence" in body["messages"][0]["content"]
        evidence = json.loads(body["messages"][1]["content"])
        assert "synthetic-workstation" in evidence["results"] and evidence["hunt"]["table"] == "WindowsEvent"
        expect(page.locator(".explain-response pre")).to_contain_text("<script>fixture()</script>")
        assert page.locator(".explain-response script").count() == 0
        assert "fixture-access-token" not in page.evaluate("JSON.stringify(localStorage)")
        assert "synthetic-workstation" not in page.evaluate("JSON.stringify(localStorage)")

        page.get_by_label("API format",exact=True).select_option("ollama")
        page.get_by_label("Endpoint URL",exact=True).fill(endpoint+"/api/chat")
        page.get_by_label("API key (optional)",exact=True).fill("")
        page.get_by_role("button",name="Send and explain").click()
        expect(page.locator(".explain-response pre")).to_have_text("Ollama synthetic explanation.")
        assert requests[-1][2]["options"] == {"temperature":0.4,"num_predict":512}
        page.get_by_label("Model",exact=True).fill("simulated-error")
        page.get_by_role("button",name="Send and explain").click()
        expect(page.locator(".explain-status")).to_contain_text("HTTP 401")
        page.get_by_label("Endpoint URL",exact=True).fill("http://insecure.example.test/chat")
        page.get_by_role("button",name="Send and explain").click()
        expect(page.locator(".explain-status")).to_contain_text("Use HTTPS")
        assert len(requests) == 3
    finally:
        page.unroute(endpoint+"/**",model_response)


def catalog_controls(page, base):
    page.set_viewport_size({"width":1586,"height":992})
    page.goto(base)
    page.reload()
    search = page.locator(".topbar").get_by_role("button",name="Search",exact=True)
    expect(search).to_be_visible()
    search.click()
    expect(page.get_by_role("searchbox",name="Search public release")).to_be_focused()
    page.keyboard.press("Escape")

    page.goto(base+"#/techniques")
    page_size = page.get_by_label("Results per page",exact=True).first
    cards = page.locator(".catalog-card")
    expect(page_size).to_have_value("12")
    expect(cards).to_have_count(12)
    page_size.select_option("24")
    expect(cards).to_have_count(24)
    pager = page.get_by_role("navigation",name="Results pages").last
    pager.get_by_label("Next page",exact=True).click()
    expect(pager.get_by_text("Showing 25–48",exact=False)).to_be_visible()
    params = parse_qs(urlsplit(page.url).fragment.partition("?")[2])
    assert params.get("size") == ["24"] and params.get("page") == ["2"],page.url
    page.reload()
    expect(page_size).to_have_value("24")
    expect(pager.get_by_text("Showing 25–48",exact=False)).to_be_visible()

    card_destination = cards.first.get_by_role("heading").get_by_role("link").get_attribute("href")
    assert card_destination
    cards.first.click(position={"x":8,"y":8})
    expect(page).to_have_url(urljoin(base,card_destination))
    expect(page.get_by_role("heading",name="What this technique means")).to_be_visible()
    page.go_back()
    expect(pager.get_by_text("Showing 25–48",exact=False)).to_be_visible()

    tactic = cards.locator('a[href*="tactic="]').first
    tactic_href = tactic.get_attribute("href")
    assert tactic_href
    target_tactic = parse_qs(urlsplit(tactic_href).fragment.partition("?")[2])["tactic"][0]
    tactic.click()
    expect(page.get_by_label("Tactic",exact=True)).to_have_value(target_tactic)
    assert urlsplit(page.url).fragment.partition("?")[0] == "/techniques"
    page.goto(base+"#/techniques")
    page_size.select_option("48")
    expect(cards).to_have_count(48)

    page.goto(base+"#/hunts")
    expect(page.get_by_role("heading",name="Hunts",exact=True)).to_be_visible()
    expect(page.get_by_role("link",name=re.compile("hunt pack",re.I))).to_have_count(0)
    expect(page.get_by_role("button",name=re.compile("download selected",re.I))).to_have_count(0)
    expect(page.get_by_label("Include in ZIP pack",exact=True)).to_have_count(0)

    page.set_viewport_size({"width":390,"height":844})
    page.goto(base+"#/developers")
    expect(page.get_by_role("heading",name="Developers",exact=True)).to_be_visible()
    active_link = page.get_by_role("navigation",name="Main navigation").get_by_role("link",name="Developers",exact=True)
    expect(active_link).to_have_attribute("aria-current","page")
    expect(active_link).to_be_in_viewport(ratio=0.5)
    assert page.evaluate("document.documentElement.scrollWidth") == 390


def defender_queries(page, base):
    def copy_query(control, table, days):
        control.click()
        heading = f"{table}\n| where TimeGenerated > ago({days}d)"
        page.wait_for_function("""heading => navigator.clipboard.readText().then(text =>
            text.replaceAll('\\r\\n', '\\n').startsWith(heading))""", arg=heading, timeout=5000)
        return page.evaluate("navigator.clipboard.readText()").replace("\r\n", "\n")

    page.goto(base+"#/vulnerabilities")
    coverage = page.get_by_label("Exploitation hunt coverage", exact=True)
    coverage.select_option(label="With exploitation hunts")
    assert parse_qs(urlsplit(page.url).fragment.partition("?")[2])["exploitCoverage"] == ["covered"]
    cve = "CVE-2026-132165"
    page.get_by_label("CVE", exact=True).fill(cve)
    record = page.locator(".finding").filter(has=page.get_by_role("link", name=cve, exact=True)).first
    record.get_by_role("heading").get_by_role("link").click()
    section = page.get_by_role("region", name="Exploitation hunts", exact=True)
    vulnerability_query = copy_query(section.get_by_role("button", name="Copy KQL", exact=True), "DeviceFileEvents", 30)
    assert "settings.php" in vulnerability_query
    hunt_link = section.get_by_role("link", name="Open Hunt Card", exact=True)
    expect(hunt_link).to_have_attribute("href", "#/hunts/HF-2026-0036")
    hunt_link.click()
    expect(page.get_by_role("heading", name="Microsoft Sentinel Logs KQL")).to_be_visible()
    expect(page.locator(".code-line").first).to_have_text("DeviceFileEvents")
    expect(page.locator(".code-line").filter(has_text="settings.php").first).to_be_visible()

    page.goto(base+"#/indicators")
    lookback = page.get_by_label("Indicator lookback", exact=True)
    copy = page.get_by_role("button", name="Copy all current indicators as KQL", exact=True)
    expect(lookback).to_have_value("30")
    expect(copy).to_be_enabled()
    default_query = copy_query(copy, "CommonSecurityLog", 30)
    assert "RequestURL" in default_query
    for field in ("MatchedField", "MatchedSide", "TrafficDirection", "LogComputer", "IntelRecordId",
                  "IndicatorContext", "EvidenceURLs"):
        assert field in default_query, field
    lookback.select_option("14")
    shorter_query = copy_query(copy, "CommonSecurityLog", 14)
    assert "ago(30d)" not in shorter_query
    assert re.search(r"\bdynamic\(\{", shorter_query)
    page.get_by_label("Indicator telemetry", exact=True).select_option(label="DeviceNetworkEvents")
    endpoint_query = copy_query(copy, "DeviceNetworkEvents", 14)
    assert "RemoteIP" in endpoint_query and "RemoteUrl" in endpoint_query


def feedback_entry(page, base, screenshots):
    page.goto(base + "#/changelog")
    feedback = page.get_by_role("link", name="Feedback", exact=True)
    expect(feedback).to_be_visible()
    feedback.click()
    expect(page).to_have_url(base + "feedback.html")
    expect(page.get_by_role("heading", name="Feedback", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Where your feedback goes")).to_be_visible()
    form = page.get_by_role("link", name="Open feedback form on Google")
    target = urlsplit(form.get_attribute("href"))
    assert target.scheme == "https" and target.netloc == "docs.google.com"
    assert re.fullmatch(r"/forms/d/e/[\w-]+/viewform", target.path)
    expect(form).to_have_attribute("rel", "noreferrer")
    assert page.locator("iframe, form").count() == 0
    if screenshots:
        page.screenshot(path=str(screenshots / "feedback.png"), full_page=True)
    page.get_by_role("link", name="HuntForge home").click()
    expect(page.get_by_role("heading", name="Daily Threat Brief")).to_be_visible()


def check(base, channel, screenshots):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel=channel, headless=True)
        context = browser.new_context(viewport={"width": 1586, "height": 992}, accept_downloads=True)
        context.grant_permissions(["clipboard-read", "clipboard-write"])
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(base)
        expect(page.get_by_role("heading", name="Daily Threat Brief")).to_be_visible()
        page.evaluate("""localStorage.setItem('huntforge:preferences',JSON.stringify({
            profiles:{'HF-2025-0001':'defender-xdr'}
        }))""")
        page.reload()
        expect(page.get_by_role("heading", name="Daily Threat Brief")).to_be_visible()
        drilldowns(page,base)
        sentinel_catalog(page,base)
        results_explanation(page,base)
        defender_queries(page,base)
        feedback_entry(page,base,screenshots)
        page.goto(base)
        expect(page.get_by_role("heading", name="Daily Threat Brief")).to_be_visible()
        if screenshots:
            page.screenshot(path=str(screenshots / "brief.png"), full_page=True)
        page.get_by_label("Page 2",exact=True).click()
        expect(page.get_by_text("Showing 5–8",exact=False)).to_be_visible()
        page.keyboard.press("/")
        search = page.get_by_role("searchbox",name="Search public release")
        for term in ["DeviceNetworkEvents","T1059.001","reallifeaccounting.com"]:
            search.fill(term)
            expect(page.locator("#global-results a").first).to_be_visible()
        cve = page.evaluate("""async () => {
            const latest = await (await fetch('api/v1/latest.json')).json();
            const data = await (await fetch('api/v1/releases/'+latest.release_id+'/intelligence/index.json')).json();
            return data.items.find(row=>row.cves.length).cves[0];
        }""")
        search.fill(cve)
        expect(page.locator("#global-results a").first).to_be_visible()
        search.fill("Suspicious PowerShell")
        page.locator("#global-results").get_by_text("Suspicious PowerShell Network Activity").click()
        expect(page.get_by_role("heading", name="Suspicious PowerShell Network Activity")).to_be_visible()
        if screenshots:
            page.screenshot(path=str(screenshots / "hunt.png"), full_page=True)
        expect(page.locator(".code-line").first).to_have_text("WindowsEvent")
        expect(page.get_by_role("heading",name="Microsoft Sentinel Logs KQL")).to_be_visible()
        expect(page.get_by_role("complementary", name="Environment profile and schema")).to_have_count(0)
        page.get_by_label("Lookback",exact=True).select_option("14")
        expect(page.get_by_text("ago(14d)",exact=False)).to_be_visible()
        json_toggle = page.get_by_label("Single-row JSON output")
        json_toggle.check()
        expect(page.get_by_text("project JSON = tostring(Results)",exact=False)).to_be_visible()
        json_toggle.uncheck()
        expect(page.get_by_text("project JSON = tostring(Results)",exact=False)).to_have_count(0)
        json_toggle.check()
        page.get_by_role("button",name="Copy KQL").click()
        expect(page.get_by_text("KQL copied.",exact=True)).to_have_text("KQL copied.")
        copied = page.evaluate("navigator.clipboard.readText()").replace("\r\n","\n")
        assert copied.startswith("WindowsEvent\n") and copied.count("make_list(pack_all())") == 1
        with page.expect_download() as download:
            page.get_by_role("button",name="KQL (.kql)").click()
        assert download.value.suggested_filename.endswith(".kql")
        assert download.value.path().read_bytes().decode()==copied
        expect(page.get_by_role("button",name="Hunt Pack (.zip)")).to_have_count(0)
        page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('fixture denied')); }")
        page.locator("[data-action=copy-query]").click()
        expect(page.get_by_role("dialog",name="KQL")).to_be_visible()
        expect(page.get_by_role("textbox",name="KQL")).to_have_value(copied)
        page.keyboard.press("Escape")
        page.get_by_label("Query profile",exact=True).select_option("defender-xdr")
        expect(page.locator(".code-line").first).to_have_text("DeviceNetworkEvents")
        expect(page.get_by_text("where Timestamp >",exact=False)).to_be_visible()
        page.get_by_label("Query profile",exact=True).select_option("sentinel-endpoint")
        expect(page.get_by_text("where TimeGenerated >",exact=False)).to_be_visible()
        page.goto(base+"#/hunts/HF-2026-0003")
        expect(page.get_by_role("heading",name="Microsoft 365 Outage Phishing Destinations")).to_be_visible()
        expect(page.get_by_label("Query profile",exact=True)).to_have_value("sentinel-cef")
        expect(page.locator(".code-line").first).to_have_text("CommonSecurityLog")
        page.get_by_label("Query profile",exact=True).select_option("custom-proxy")
        expect(page.locator(".code-line").first).to_have_text("CustomWeb_CL")
        expect(page.get_by_label("Single-row JSON output")).to_be_checked()
        page.get_by_role("tab",name="Investigation").click()
        expect(page.get_by_role("heading",name="Hunt hypothesis")).to_be_visible()
        page.keyboard.press("ArrowRight")
        expect(page.get_by_role("heading",name="Reviewed source evidence")).to_be_visible()
        page.goto(base+"#/hunts")
        expect(page.get_by_role("heading",name="Hunts",exact=True)).to_be_visible()
        page.get_by_role("searchbox",name="Search",exact=True).fill("Microsoft 365 Outage Phishing Destinations")
        page.get_by_label("Profile",exact=True).select_option("sentinel-cef")
        expect(page.get_by_role("heading",name="Microsoft 365 Outage Phishing Destinations")).to_be_visible()
        expect(page.get_by_role("heading",name="Suspicious PowerShell Network Activity")).to_have_count(0)
        page.goto(base+"#/intelligence")
        page.get_by_role("searchbox",name="Search",exact=True).fill("zz-no-fixture-result")
        expect(page.get_by_text("No records match these filters.")).to_be_visible()
        page.get_by_role("button",name="Clear",exact=True).click()
        page.get_by_label("Severity",exact=True).select_option("high")
        expect(page.locator(".finding").first).to_be_visible()
        if page.locator(".finding .unrated").count():
            raise AssertionError("Severity filter retained unrated items")
        page.set_viewport_size({"width":390,"height":844})
        page.evaluate("localStorage.removeItem('huntforge:preferences')")
        page.goto(base)
        page.get_by_role("link",name=re.compile("high severity",re.I)).click()
        severity = page.get_by_label("Severity",exact=True)
        if not severity.is_visible():
            page.get_by_text(re.compile(r"^More filters\b")).click()
        expect(severity).to_be_visible()
        expect(severity).to_have_value("high")
        assert page.evaluate("document.documentElement.scrollWidth") == 390
        for path,title,name in [("","Daily Threat Brief","brief-mobile"),
            ("#/hunts/HF-2025-0001","Suspicious PowerShell Network Activity","hunt-mobile")]:
            page.goto(base+path)
            expect(page.get_by_role("heading",name=title)).to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth") == 390
            if screenshots:
                page.screenshot(path=str(screenshots / (name+".png")), full_page=True)
        catalog_controls(page,base)
        for width in (320, 741, 1024):
            page.set_viewport_size({"width":width,"height":844})
            for path, heading in [("#/brief","Daily Threat Brief"),("#/indicators","Indicators")]:
                page.goto(base+path)
                expect(page.get_by_role("heading",name=heading,exact=True)).to_be_visible()
                expect(page.get_by_role("link",name="Feedback",exact=True)).to_be_visible()
                assert page.evaluate("document.documentElement.scrollWidth") == width
        assert not errors,errors
        context.close()
        browser.close()
        print("Browser QA passed at desktop, tablet, and mobile sizes.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("--channel",default=os.environ.get("PLAYWRIGHT_CHANNEL"))
    parser.add_argument("--screenshots",type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True,exist_ok=True)
    check(args.base.rstrip("/")+"/",args.channel,args.screenshots)


if __name__ == "__main__":
    main()
