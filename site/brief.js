import { badge, bars, day, escape, hoursAgo, icon, link, neutral, pagination, resultWindow, resultsToolbar, route, sourceNames, table, utc } from "./ui.js";

export function findingTags(data, record, limit) {
  const cves = record.cves.map(cve => {
    const section = data.records.some(row => row.kind === "Vulnerability" && row.cves.includes(cve)) ? "vulnerabilities" : "intelligence";
    return link(cve,route(section,null,{cve}),"chip");
  });
  const techniques = (record.techniques || []).map(technique => link(technique,route("techniques",technique),"chip"));
  const tags = record.tags.map(tag => link(tag,route("intelligence",null,{tag}),"chip"));
  return [...cves,...techniques,...tags].slice(0,limit).join("") || badge(record.kind);
}

export function finding(data, record, section = "intelligence") {
  const detail = route(section,record.id);
  const date = day(record.published);
  return `<article class="finding" data-record-card>
    <div class="finding-level">${link(record.severity.toUpperCase(),route(section,null,{severity:record.severity}),"severity " + record.severity)}<span class="finding-id">${escape(record.id)}</span></div>
    <div class="finding-body"><div class="finding-action">
      ${record.exploitation_hunts?.length ? `<a class="stamp" href="${route("vulnerabilities",record.id)}">${icon("crosshair")} ${record.exploitation_hunts.length} EXPLOITATION HUNT${record.exploitation_hunts.length > 1 ? "S" : ""}</a>` :
      record.hunts?.length ? `<a class="stamp" href="${route("hunts", record.hunts[0])}">${icon("check")} PARTIALLY VALIDATED</a>` :
        `<a class="stamp" href="${detail}">${icon("file")} SOURCE EVIDENCE</a>`}</div>
      <h3>${link(record.title,detail)}</h3>
      <p>${neutral(record.summary)}</p>
      <div class="chips">${findingTags(data,record,7)}</div>
    </div>
    <div class="finding-foot"><span><b>CONFIDENCE</b> ${neutral(record.confidence.toUpperCase())}</span>
      <span><b>SOURCE</b> ${link(sourceNames[record.source] || record.source,route(section,null,{source:record.source}))}</span>
      <span><b>PUBLISHED</b> ${link(date,route(section,null,{start:date,through:date}))}</span></div></article>`;
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
  const {from,through} = manifest.window;
  const daily = records.filter(row => row.published === through);
  const onDate = {start:through,through};
  const newly = data.changes.items.filter(x => x.type === "hunt" && x.action === "created").length;
  const stats = [
    [daily.length,"NEW FINDINGS",route("intelligence",null,onDate)],
    [daily.filter(x => x.severity === "high").length,"HIGH SEVERITY",route("intelligence",null,{...onDate,severity:"high"})],
    [newly,"NEW HUNTS",route("hunts",null,{change:"created"})],
    [report.sources.filter(x => x.state === "live").length,"SOURCE UPDATES",route("status",null,{sourceState:"live"})]
  ];
  const changes = state.previousVisit !== manifest.release_id && data.history.some(row=>row.release_id===state.previousVisit)
    ? route("changelog","since-last-visit") : route("changelog");
  const {start,end,page,size} = resultWindow(records.length,state);
  const visible = records.slice(start,end);
  return `<main id="main" class="brief-main" tabindex="-1">
    <section class="brief-hero"><div class="globe-art" aria-hidden="true"></div><p class="eyebrow">The Brief / Daily Threat Overview</p>
      <h1>Daily Threat Brief</h1>
      <p class="brief-intro">A concise, actionable summary of significant public threat intelligence,<br class="hero-break"> with Microsoft Sentinel hunting guidance.</p>
      <div class="metrics">${stats.map(([number,label,href]) => `<a class="metric" href="${escape(href)}" aria-label="${label}, ${number}"><b>${number}</b><span>${label}</span><small aria-hidden="true">${icon("chevron")}</small></a>`).join("")}</div>
      <p class="run-line"><span>${link("REPORT DATE: " + day(through),route("intelligence",null,onDate))}</span>
       <span>${link(`COVERAGE: ${day(from)}–${day(through)}`,route("intelligence",null,{start:from,through}))}</span>
       <span>${link("SOURCES: " + manifest.counts.sources,route("status"))}</span><span>${link("HUNTS AVAILABLE: " + manifest.counts.hunts,route("hunts"))}</span></p>
    </section>
    <section class="developments">${bars("TOP DEVELOPMENTS")}${resultsToolbar(records.length,"findings",state)}
      ${visible.map(row=>finding(data,row)).join("") || '<p class="empty">No findings in this collection window.</p>'}
      ${pagination(records.length, page, size, "findings")}
      <div class="brief-actions">${link("What changed since my last visit?",changes,"changes-link")}
      <button class="btn" type="button" data-action="search">${icon("search")} Search release</button></div>
    </section></main>`;
}

export function briefAside(data) {
  const sources = data.report.sources;
  const fresh = sources.filter(isFresh).length;
  const counts = data.hunts.reduce((out, row) => ({...out, [row.status]: (out[row.status] || 0)+1}), {});
  const created = data.manifest.created;
  const validation = route("status",null,{panel:"validation"});
  const stages = [
    ["Intelligence Ingestion", data.report.status === "passed" ? "Complete" : "Partial",route("status")],
    ["Normalization & Correlation","Complete",route("intelligence")],
    ["Detection Generation (KQL)",`${data.hunts.length} accepted`,route("hunts")],
    ["Validation & Testing","Static checks",validation],
    ["Publication (GitHub + Site)","Snapshot loaded",route("developers")]
  ];
  const freshnessRows = sources.map(row => [link(row.name,route("status",null,{source:row.id})), escape(row.id === "microsoft" || row.id === "ncsc" || row.id === "cisa-advisories" ? "Feed" : row.id === "mitre" ? "STIX" : "API"),
    escape(isFresh(row) ? hoursAgo(row.retrieved) : sourceState(row))]);
  const runtime = Math.max(0, Math.round((Date.parse(data.report.finished)-Date.parse(data.report.started))/1000));
  return `<aside class="brief-aside" aria-label="Operational summary">
    <section>${bars("PIPELINE HEALTH", `<span>● ${data.report.status === "passed" && fresh === sources.length ? "OPERATIONAL" : "CHECK SOURCES"}</span>`)}
      <div class="panel-body status-rows">${stages.map(([stage,result,href]) => `<a class="status-row" href="${escape(href)}">${icon("checked")}<span>${escape(stage)}</span><span>✓ ${escape(result)}</span></a>`).join("")}</div>
    </section>
    <section>${bars("SOURCE FRESHNESS", `<span>${fresh} / ${sources.length} FRESH</span>`)}
      <div class="panel-body">${table(["Source","Type","Last update"], freshnessRows)}
      <p class="aside-foot"><a href="#/status">View collection coverage →</a></p></div>
    </section>
    <section>${bars("VALIDATION STATISTICS")}
      <div class="panel-body validation-grid"><div>${[["validated","Engine<br>Validated"],
        ["partially_validated","Partially<br>Validated"],["unvalidated","Unvalidated"]].map(([status,label]) =>
        `<a class="validation-tally" href="${route("hunts",null,{validation:status})}"><b>${counts[status] || 0}</b><span>${label}</span></a>`).join("")}</div>
      ${table([],[[data.hunts.length ? "<strong>100%</strong>" : "—",link("Syntax checked",validation)],
        [data.hunts.length ? "<strong>100%</strong>" : "—",link("Schema checked",validation)],
        ["<strong>—</strong>",link("Engine execution",validation)],[`<strong>${data.report.quarantined.length}</strong>`,link("Quarantined",validation)]])}</div>
    </section>
    <section>${bars("COLLECTION ENGINE", "<span>● DAILY / 06:17 ET</span>")}
      <div class="panel-body">${table([],[
        ["<b>Last run</b>",link(utc(created),route("status"))], ["<b>Duration</b>", `${runtime}s`],
        ["<b>Generation</b>", "Reviewed KQL rules"], ["<b>Hunts accepted</b>",link(data.hunts.length,route("hunts"))],
        ["<b>Model calls</b>", data.report.engine.calls], ["<b>Model cost</b>", "$" + data.report.engine.cost_usd.toFixed(2)],
        ["<b>Release</b>", `<a href="#/developers">${escape(data.manifest.release_id)}</a>`]
      ])}</div>
    </section></aside>`;
}
