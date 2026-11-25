"""Exercise the built site in Chromium, including browser-generated downloads."""

import argparse
import json
import os
import re
import zipfile
from pathlib import Path

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
        drilldowns(page,base)
        page.goto(base)
        expect(page.get_by_role("heading", name="Daily Threat Brief")).to_be_visible()
        if screenshots:
            page.screenshot(path=str(screenshots / "brief.png"), full_page=True)
        page.get_by_role("button", name="Page 2", exact=True).click()
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
        expect(page.get_by_text("InitiatingProcessFileName in~",exact=False)).to_be_visible()
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
        assert copied.startswith("DeviceNetworkEvents\n") and copied.count("make_list(pack_all())") == 1
        with page.expect_download() as download:
            page.get_by_role("button",name="KQL (.kql)").click()
        assert download.value.path().read_bytes().decode()==copied
        with page.expect_download() as download:
            page.get_by_role("button",name="Hunt Pack (.zip)").click()
        with zipfile.ZipFile(download.value.path()) as archive:
            item = json.loads(archive.read("manifest.json"))["queries"][0]
            assert item["output"] == "json" and item["lookback_days"] == 14 and item["evidence"]
            assert archive.read(item["file"]).decode() == copied
        page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('fixture denied')); }")
        page.locator("[data-action=copy-query]").click()
        expect(page.get_by_role("dialog",name="KQL")).to_be_visible()
        expect(page.get_by_role("textbox",name="KQL")).to_have_value(copied)
        page.keyboard.press("Escape")
        page.get_by_label("Environment Profile",exact=True).select_option("custom-menlo")
        expect(page.get_by_role("button",name="Copy KQL")).to_be_disabled()
        expect(page.get_by_text("This profile cannot supply",exact=False)).to_be_visible()
        page.goto(base+"#/hunts/HF-2026-0003")
        expect(page.get_by_role("heading",name="Microsoft 365 Outage Phishing Destinations")).to_be_visible()
        page.get_by_label("Environment Profile",exact=True).select_option("custom-proxy")
        expect(page.locator(".code-line").first).to_have_text("CustomWeb_CL")
        expect(page.get_by_label("Single-row JSON output")).to_be_checked()
        page.get_by_role("tab",name="Investigation").click()
        expect(page.get_by_role("heading",name="Hunt hypothesis")).to_be_visible()
        page.keyboard.press("ArrowRight")
        expect(page.get_by_role("heading",name="Reviewed source evidence")).to_be_visible()
        page.goto(base+"#/hunts")
        expect(page.get_by_role("heading",name="Hunts",exact=True)).to_be_visible()
        page.get_by_label("Profile",exact=True).select_option("sentinel-cef")
        expect(page.get_by_role("heading",name="Microsoft 365 Outage Phishing Destinations")).to_be_visible()
        expect(page.get_by_role("heading",name="Suspicious PowerShell Network Activity")).to_have_count(0)
        page.get_by_label("Include in ZIP pack").check()
        with page.expect_download() as download:
            page.get_by_role("button",name="Download selected (1)").click()
        with zipfile.ZipFile(download.value.path()) as archive:
            assert archive.testzip() is None
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
        expect(page.get_by_label("Severity",exact=True)).to_have_value("high")
        assert page.evaluate("document.documentElement.scrollWidth") == 390
        for path,title,name in [("","Daily Threat Brief","brief-mobile"),
            ("#/hunts/HF-2025-0001","Suspicious PowerShell Network Activity","hunt-mobile")]:
            page.goto(base+path)
            expect(page.get_by_role("heading",name=title)).to_be_visible()
            assert page.evaluate("document.documentElement.scrollWidth") == 390
            if screenshots:
                page.screenshot(path=str(screenshots / (name+".png")), full_page=True)
        assert not errors,errors
        context.close()
        browser.close()
        print("Browser QA passed at 1586×992 and 390×844.")


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
