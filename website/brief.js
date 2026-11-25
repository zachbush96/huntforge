import { badge, bars, day, escape, hoursAgo, icon, neutral, pagination, route, sourceNames, table, utc } from "./ui.js";

export function finding(record) {
  return `<article class="finding">
    <div class="finding-level">${badge(record.severity.toUpperCase(), "severity " + record.severity)}<span class="finding-id">${escape(record.id)}</span></div>
    <div class="finding-body"><div class="finding-action">
      ${record.hunts?.length ? `<a class="stamp" href="${route("hunts", record.hunts[0])}">${icon("check")} PARTIALLY VALIDATED</a>` :
        `<a class="stamp" href="${route("intelligence", record.id)}">${icon("file")} SOURCE EVIDENCE</a>`}</div>
      <h3><a href="${route("intelligence", record.id)}">${neutral(record.title)}</a></h3>
      <p>${neutral(record.summary)}</p>
      <div class="chips">${[...record.cves, ...(record.techniques || []), ...record.tags].slice(0, 7).map(tag => badge(tag)).join("") || badge(record.kind)}</div>
    </div>
    <div class="finding-foot"><span><b>CONFIDENCE</b> ${neutral(record.confidence.toUpperCase())}</span>
      <span><b>SOURCE</b> ${escape(sourceNames[record.source] || record.source)}</span>
      <span><b>PUBLISHED</b> ${day(record.published)}</span></div></article>`;
}

export function isFresh(row) {
  return row.state === "live" && Date.now() - Date.parse(row.retrieved) < 48 * 60 * 60 * 1000;
}

export function sourceState(row) {
  return row.state === "live" && !isFresh(row) ? "stale" : row.state;
}

function recentFindings(records) {
  const inWindow = records.filter(row => row.in_window);
  const selected = [];
  const take = row => row && !selected.includes(row) && selected.push(row);
  take(inWindow.find(row => row.source === "cisa-kev"));
  take(inWindow.find(row => row.source === "ncsc" && row.tags.includes("Agentic AI")));
  take(inWindow.find(row => row.source === "cisa-kev" && row.id !== selected.at(0)?.id));
  take(inWindow.find(row => row.hunts?.length && row.tags.includes("Phishing")));
  return [...selected, ...inWindow.filter(row => !selected.includes(row))];
}

export function briefMain(data, state) {
  const {manifest, report} = data;
  const records = recentFindings(data.records);
  const daily = records.filter(row => row.published === manifest.window.through);
  const newly = data.changes.items.filter(x => x.type === "hunt" && x.action === "created").length;
  const stats = [[daily.length,"NEW FINDINGS",true], [daily.filter(x => x.severity === "high").length,"HIGH SEVERITY",true],
    [newly,"NEW HUNTS",true], [report.sources.filter(x => x.state === "live").length,"SOURCE UPDATES",true]];
  const visible = records.slice(state.page*4, state.page*4+4);
  return `<main id="main" class="brief-main" tabindex="-1">
    <section class="brief-hero"><div class="globe-art" aria-hidden="true"></div><p class="eyebrow">The Brief / Daily Threat Overview</p>
      <h1>Daily Threat Brief</h1>
      <p class="brief-intro">A concise, actionable summary of significant public threat intelligence,<br class="hero-break"> with Microsoft Sentinel hunting guidance.</p>
      <div class="metrics">${stats.map(([number,label]) => `<div class="metric"><b>${number}</b><span>${label}</span><small>+${number}</small></div>`).join("")}</div>
      <p class="run-line"><span>REPORT DATE: ${day(manifest.window.through)}</span><span>COVERAGE: ${day(manifest.window.from)}–${day(manifest.window.through)}</span>
       <span>SOURCES: ${manifest.counts.sources}</span><span>HUNTS AVAILABLE: ${manifest.counts.hunts}</span></p>
    </section>
    <section class="developments">${bars("TOP DEVELOPMENTS")}${visible.map(finding).join("") || '<p class="empty">No findings in this collection window.</p>'}
      ${pagination(records.length, state.page, 4, "findings")}
      <div class="brief-actions"><a class="changes-link" href="#/changelog">What changed since my last visit?</a>
      <button class="btn" type="button" data-action="search">${icon("search")} Search release</button></div>
    </section></main>`;
}

export function briefAside(data) {
  const sources = data.report.sources;
  const fresh = sources.filter(isFresh).length;
  const counts = data.hunts.reduce((out, row) => ({...out, [row.status]: (out[row.status] || 0)+1}), {});
  const created = data.manifest.created;
  const stages = [
    ["Intelligence Ingestion", data.report.status === "passed" ? "Complete" : "Partial"],
    ["Normalization & Correlation", "Complete"],
    ["Detection Generation (KQL)", `${data.hunts.length} accepted`],
    ["Validation & Testing", "Static checks"],
    ["Publication (GitHub + Site)", "Snapshot loaded"]
  ];
  const freshnessRows = sources.map(row => [escape(row.name), escape(row.id === "microsoft" || row.id === "ncsc" || row.id === "cisa-advisories" ? "Feed" : row.id === "mitre" ? "STIX" : "API"),
    escape(isFresh(row) ? hoursAgo(row.retrieved) : sourceState(row))]);
  const runtime = Math.max(0, Math.round((Date.parse(data.report.finished)-Date.parse(data.report.started))/1000));
  return `<aside class="brief-aside" aria-label="Operational summary">
    <section>${bars("PIPELINE HEALTH", `<span>● ${data.report.status === "passed" && fresh === sources.length ? "OPERATIONAL" : "CHECK SOURCES"}</span>`)}
      <div class="panel-body status-rows">${stages.map(([stage,result]) => `<div class="status-row">${icon("checked")}<span>${escape(stage)}</span><span>✓ ${escape(result)}</span></div>`).join("")}</div>
    </section>
    <section>${bars("SOURCE FRESHNESS", `<span>${fresh} / ${sources.length} FRESH</span>`)}
      <div class="panel-body">${table(["Source","Type","Last update"], freshnessRows)}
      <p class="aside-foot"><a href="#/status">View collection coverage →</a></p></div>
    </section>
    <section>${bars("VALIDATION STATISTICS")}
      <div class="panel-body validation-grid"><div>${[[counts.validated || 0, "Engine<br>Validated"],
        [counts.partially_validated || 0,"Partially<br>Validated"],[counts.unvalidated || 0,"Unvalidated"]].map(([count,label]) =>
        `<div class="validation-tally"><b>${count}</b><span>${label}</span></div>`).join("")}</div>
      ${table([],[[data.hunts.length ? "<strong>100%</strong>" : "—","Syntax checked"],
        [data.hunts.length ? "<strong>100%</strong>" : "—","Schema checked"],
        ["<strong>—</strong>","Engine execution"],[`<strong>${data.report.quarantined.length}</strong>`,"Quarantined"]])}</div>
    </section>
    <section>${bars("COLLECTION ENGINE", "<span>● DAILY / 06:17 ET</span>")}
      <div class="panel-body">${table([],[
        ["<b>Last run</b>", utc(created)], ["<b>Duration</b>", `${runtime}s`],
        ["<b>Generation</b>", "Reviewed KQL rules"], ["<b>Hunts accepted</b>", data.hunts.length],
        ["<b>Model calls</b>", data.report.engine.calls], ["<b>Model cost</b>", "$" + data.report.engine.cost_usd.toFixed(2)],
        ["<b>Release</b>", `<a href="#/developers">${escape(data.manifest.release_id)}</a>`]
      ])}</div>
    </section></aside>`;
}
