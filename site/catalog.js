import { finding, isFresh, sourceState } from "./brief.js";
import { anchor, badge, button, day, escape, external, icon, neutral, options, pagination, repo, route, section, sourceNames, table, utc } from "./ui.js";

const pages = {
  intelligence:["Intelligence","Search published findings, source evidence and linked Hunt Cards."],
  hunts:["Hunts","Choose a telemetry profile and build a self-contained KQL query for your investigation."],
  adversaries:["Adversaries","Browse groups and software from the current MITRE ATT&CK® Enterprise reference."],
  vulnerabilities:["Vulnerabilities","Explore CISA’s known-exploited vulnerabilities and associated EPSS data."],
  indicators:["Indicators","Review attributed observations and their context. Values are defanged here."],
  techniques:["Techniques","Browse MITRE ATT&CK® techniques and their linked HuntForge hunts."],
  research:["Research","Read reported behaviors, publisher evidence and public detection guidance."],
  changelog:["Changelog","Track new, updated and retired records across releases."],
  developers:["Developers","Read the release API, download schemas and work with versioned KQL."],
  status:["System Status","Inspect source coverage, pipeline health and query validation."]
};

function shell(id, content, title, intro) {
  const [name, text] = pages[id] || ["Page unavailable", ""];
  return `<main id="main" tabindex="-1"><div class="page-shell"><p class="eyebrow">HuntForge / ${escape(name)}</p>
    <h1>${neutral(title || name)}</h1>${intro ?? `<p class="intro">${escape(text)}</p>`}${content}</div></main>`;
}

function filtered(data, state, rows) {
  const {q, severity, source, start, through, technique, malware, validation, profile, freshness, category} = state.filters;
  const tokens = (q || "").toLowerCase().trim().split(/\s+/).filter(Boolean);
  return rows.filter(row => {
    const blob = data.text.get(row.id) || JSON.stringify(row).toLowerCase();
    return tokens.every(token => blob.includes(token)) &&
      (!severity || row.severity === severity) &&
      (!source || row.source === source || row.evidence?.some(ref => ref.source === source)) &&
      (!start || (row.published || row.reported || row.modified || "").slice(0,10) >= start) &&
      (!through || (row.published || row.reported || row.modified || "").slice(0,10) <= through) &&
      (!technique || [row.technique,...(row.techniques || [])].includes(technique)) &&
      (!malware || (row.software || []).includes(malware)) &&
      (!validation || row.status === validation) &&
      (!profile || row.profiles?.includes(profile)) &&
      (!freshness || indicatorState(row) === freshness) &&
      (!category || row.type === category);
  });
}

function dropdown(name, label, rows, active) {
  return `<label>${label}<select aria-label="${label}" data-filter="${name}">${options([["","All"],...rows],active||"")}</select></label>`;
}

function filters(data,state,kind) {
  const f = state.filters;
  const dateRange = `<label>From<input type="date" data-filter="start" value="${escape(f.start || "")}"></label><label>Through<input type="date" data-filter="through" value="${escape(f.through || "")}"></label>`;
  const source = dropdown("source","Source",Object.entries(sourceNames),f.source);
  const technique = dropdown("technique","Technique",[...new Set(data.hunts.map(x=>x.technique).concat(data.records.flatMap(x=>x.techniques || [])))].sort().map(x=>[x,x]),f.technique);
  const extras = kind === "hunts" ? [source, technique,
    dropdown("profile","Profile",data.profiles.map(x=>[x.id,x.short]),f.profile),
    dropdown("validation","Validation",[["validated","Validated"],["partially_validated","Partially validated"],["unvalidated","Unvalidated"]], f.validation), dateRange] :
    kind === "indicators" ? [source, dropdown("freshness","Freshness",[["current","Current"],["review","Review due"],["expired","Source expired"]], f.freshness),dateRange] :
    kind === "adversaries" ? [dropdown("category","Entity type",[["intrusion-set","Group"],["malware","Software"]],f.category)] :
    kind === "techniques" ? [] : [dropdown("severity","Severity",[["high","High"],["unrated","Unrated"]],f.severity), source, dateRange, technique,
      dropdown("malware","Software", [...new Set(data.records.flatMap(x=>x.software || []))].map(x=>[x,x]),f.malware)];
  return `<form class="filters" aria-label="Filter results"><label>Search<input type="search" data-filter="q" value="${escape(f.q || "")}" placeholder="Search ${escape(pages[kind][0].toLowerCase())}"></label>
    ${extras.join("")}${button("Clear","clear-filters")}</form>`;
}

function indicatorState(row) {
  const today = new Date().toISOString().slice(0,10);
  if (row.source_expires && row.source_expires <= today) return "expired";
  return row.aging_review <= today ? "review" : "current";
}

function huntCard(row, state) {
  const label = state.preferences.followed.includes(row.id) ? "Following · " : "";
  return `<article class="catalog-card">
    <div class="meta">${escape(label+row.id)} · REV ${row.revision}</div>
    <h2><a href="${route("hunts",row.id)}">${neutral(row.title)}</a></h2><p>${neutral(row.description)}</p>
    <p class="chips">${badge(row.technique)}${badge(row.tactic)}${badge("Partially validated")}</p>
    <label class="checkbox"><input type="checkbox" data-pack-id="${escape(row.id)}"${state.pack.has(row.id) ? " checked" : ""}> Include in ZIP pack</label>
  </article>`;
}

function entityCard(kind,row) {
  if (kind === "indicators") return `<article class="catalog-card"><div class="meta">${escape(row.type.toUpperCase())} · ${escape(indicatorState(row))} · ${day(row.reported)}</div>
    <h2><a href="${route(kind,row.id)}">${escape(row.display)}</a></h2><p>${neutral(row.context)}</p></article>`;
  return `<article class="catalog-card"><div class="meta">${escape(row.id)} · ${escape(row.type === "intrusion-set" ? "GROUP" : row.type === "malware" ? "SOFTWARE" : "TECHNIQUE")}</div>
    <h2><a href="${route(kind,row.id)}">${neutral(row.title)}</a></h2>${row.aliases?.length > 1 ? `<p>${neutral(row.aliases.slice(1,6).join(", "))}</p>` : ""}</article>`;
}

export function catalog(data, state) {
  const kind = state.section;
  const isHunts = kind === "hunts";
  const entities = ["indicators","adversaries","techniques"].includes(kind);
  const limit = isHunts || entities ? 12 : 10;
  const source = isHunts ? data.hunts : kind === "indicators" ? data.indicators :
    kind === "adversaries" ? data.reference.filter(x=>x.type !== "attack-pattern") :
    kind === "techniques" ? data.reference.filter(x=>x.type === "attack-pattern") :
    kind === "vulnerabilities" ? data.records.filter(x=>x.kind==="Vulnerability") :
    kind === "research" ? data.records.filter(x=>x.kind==="Research") : data.records;
  const rows = filtered(data,state,source);
  const visible = rows.slice(state.page*limit, state.page*limit+limit);
  let contents = filters(data,state,kind);
  if (isHunts) {
    contents += `<div class="detail-links">${button(`Download selected (${state.pack.size})`, "pack-selected","download","inverted")}
      ${anchor("Default hunt pack (.zip)",data.base+"downloads/hunt-pack.zip","file")}${button("Output preferences","settings","settings")}</div>`;
  }
  if (visible.length) {
    const markup = visible.map(row => isHunts ? huntCard(row,state) : entities ? entityCard(kind,row) : finding(row)).join("");
    contents += isHunts || entities ? `<div class="catalog-grid">${markup}</div>` : markup;
  } else contents += '<p class="empty">No records match these filters.</p>';
  contents += pagination(rows.length,state.page,limit,isHunts ? "hunts" : "records");
  return shell(kind,contents);
}

function evidenceList(refs) {
  return `<div class="catalog-grid">${refs.map(ref=>`<article class="catalog-card"><p class="meta">${escape(sourceNames[ref.source])} · ${day(ref.published)}</p>
    <h3>${neutral(ref.location)}</h3><p>${neutral(ref.claim)}</p>
    ${ref.observation_date ? `<p>Source observation ${day(ref.observation_date)}</p>` : ""}${external("Open publisher source",ref.url)}</article>`).join("")}</div>`;
}

export function intelligenceDetail(data,state) {
  const row = state.detail;
  const scores = row.epss || [];
  const contents = `<p class="detail-links">${[...row.cves,...(row.techniques||[]),...row.tags].map(x=>badge(x)).join("")}</p>
    <section class="detail-section">${section("Record provenance","file")}${table(["Attribute","Value"],[
      ["ID",escape(row.id)],["Revision",row.revision],["Source",escape(sourceNames[row.source])],["Source publication",day(row.published)],
      ["HuntForge first retrieved",utc(row.first_retrieved)],["Latest source retrieval",utc(row.retrieved)],["HuntForge updated",utc(row.updated)],
      ["Evidence confidence",escape(row.confidence)],["HuntForge severity",escape(row.severity)]
    ])}</section>
    <section class="detail-section">${section("Source evidence","link")}${evidenceList(row.evidence)}</section>
    ${row.hunts.length || row.related.length || row.indicators?.length ? `<section class="detail-section">${section("Related records","network")}
      <div class="detail-links">${row.hunts.map(id=>anchor(data.hunts.find(x=>x.id===id)?.title||id,route("hunts",id),"crosshair")).join("")}
      ${row.related.map(id=>anchor(data.records.find(x=>x.id===id)?.title||id,route("intelligence",id),"file")).join("")}
      ${(row.indicators||[]).map(id=>anchor(data.indicators.find(x=>x.id===id)?.display||id,route("indicators",id),"database")).join("")}</div></section>`:""}
    ${scores.length ? `<section class="detail-section">${section("FIRST EPSS","pulse")}<p>EPSS estimates exploitation probability over the next 30 days. CISA’s listing separately records evidence of exploitation.</p>
      <details class="mapping" open><summary>${scores.length} daily scores from FIRST</summary>${table(["Score date","Probability","Percentile"],
        scores.map(point=>[day(point.date),`${(Number(point.epss)*100).toFixed(2)}%`,`${(Number(point.percentile)*100).toFixed(2)}%`]))}</details></section>`:""}
    <p class="detail-links">${anchor("Record JSON",data.base+`intelligence/${row.id}.json`,"code")}${anchor("Back to intelligence",route("intelligence"))}</p>`;
  return shell("intelligence",contents,row.title,`<p class="intro">${neutral(row.summary)}</p>`);
}

export function entityDetail(data,state) {
  const row = state.detail;
  const kind = state.section;
  if (kind === "indicators") {
    return shell(kind,`<p class="detail-links">${button("Copy canonical value","copy-indicator","copy")}${anchor("Indicator JSON",data.base+`indicators/${row.id}.json`,"code")}${anchor("Related intelligence",route("intelligence",row.record_id),"file")}</p>
      <section class="detail-section">${section("Indicator lifecycle","history")}${table(["Attribute","Value"],[
        ["Type",escape(row.type)],["Publisher report",day(row.reported)],["First observation",day(row.first_observed)],
        ["Last observation",day(row.last_observed)],["Publisher expiration",day(row.source_expires)],["HuntForge review date",day(row.aging_review)],
        ["Freshness",escape(indicatorState(row))]
      ])}</section><section class="detail-section">${section("Source evidence","link")}${evidenceList(row.evidence)}</section>`,row.display,`<p class="intro">${neutral(row.context)}</p>`);
  }
  const hunts = data.hunts.filter(hunt=>hunt.technique===row.id);
  const related = data.records.filter(rec=>rec.techniques?.includes(row.id));
  return shell(kind,`<p>${external("Open MITRE ATT&CK reference",row.url)}</p><div class="chips">${row.tactics?.map(x=>badge(x)).join("") || ""}</div>
    <p class="mono">Modified ${day(row.modified)} · Enterprise ATT&CK ${escape(data.referenceVersion)}</p>
    ${row.aliases?.length ? `<p>Aliases ${neutral(row.aliases.join(", "))}</p>` : ""}
    ${hunts.length ? `<section class="detail-section">${section("Related hunts","crosshair")}
      <div class="detail-links">${hunts.map(x=>anchor(x.title,route("hunts",x.id))).join("")}</div></section>` : ""}
    ${related.length ? `<section class="detail-section">${section("Related intelligence","file")}${related.map(finding).join("")}</section>`:""}`,row.title,
    `<p class="intro">${escape(row.id)} · Current MITRE ATT&CK® Enterprise reference entry.</p>`);
}

export function systemStatus(data) {
  const {report, manifest} = data;
  const sourceRows = report.sources.map(row=>[escape(row.name), escape(sourceState(row)), escape(row.coverage), day(row.first_available),
    utc(row.retrieved), row.count??"—",escape(row.coverage_note||"")]);
  const fields = [["Latest release",escape(manifest.release_id)],["Collection start",utc(report.started)],["Collection end",utc(report.finished)],
    ["Historical window",`${day(report.window.from)} through ${day(report.window.through)}`],["Fresh sources",`${report.sources.filter(isFresh).length} of ${report.sources.length}`],
    ["Accepted hunts",report.accepted],["Quarantined hunts",report.quarantined.length],
    ["Analyzer",escape(data.hunts[0]?.validation?.validator||"Unavailable")],["Workspace execution","Not run"],
    ["Scheduled collection","Daily at 06:17 America/New_York through GitHub Actions"],
    ["Models / model calls","Deterministic collection and generation / " + report.engine.calls],["Model expenditure","$" + report.engine.cost_usd.toFixed(2)]];
  return shell("status",`<section class="detail-section">${section("Latest collection run","pulse")}${table(["Field","Value"],fields)}</section>
    <section class="detail-section">${section("Source health & historical coverage","database")}<div class="table-scroll">
    ${table(["Source","State","Coverage","Earliest available","Retrieved","Records","Scope"],sourceRows)}</div></section>
    <p class="detail-links">${anchor("Release report JSON",data.base+"report.json","code")} ${anchor("GitHub Actions",repo+"/actions","github")}</p>`);
}

export function changelog(data,state) {
  const selected = state.detail || data.changes;
  const label = state.detail ? `Release ${escape(selected.release_id)}` : "Current accepted release";
  const prior = state.previousVisit;
  const links = data.history.map(row=>anchor(row.release_id,route("changelog",row.release_id),"history")).join("");
  const matching = selected.items.slice(state.page*25,state.page*25+25);
  return shell("changelog",`<div class="notice">${prior && prior !== data.manifest.release_id ?
    `Last viewed ${escape(prior)}. ${anchor("Changes since that release",route("changelog","since-last-visit"),"history")}` :
    prior ? "Your last visit used the current release." : "This is your first recorded visit."}</div>
    <p class="detail-links">${links}${anchor("Release history JSON","api/v1/history.json","code")}</p>
    <section class="detail-section">${section(label,"history")}
    ${matching.length ? `<div class="table-scroll">${table(["Change","Type","ID","Title","Revision"],matching.map(row=>[
      badge(row.action),escape(row.type),escape(row.id),row.action==="retired" ? neutral(row.title) :
      `<a href="${route(row.type === "hunt" ? "hunts" : "intelligence",row.id)}">${neutral(row.title)}</a>`,row.revision]))}</div>
      ${pagination(selected.items.length,state.page,25,"changes")}` : '<p class="empty">No material changes were recorded for this comparison.</p>'}</section>`);
}

export function developers(data) {
  const first = data.hunts[0]?.id;
  const paths = [
    ["Latest release pointer","api/v1/latest.json"],["Release manifest",data.base+"manifest.json"],["Intelligence index",data.base+"intelligence/index.json"],
    ["Hunt index",data.base+"hunts/index.json"],["Example Hunt Card",data.base+`hunts/${first}.json`],["Indicators",data.base+"indicators/index.json"],
    ["Profiles",data.base+"profiles/index.json"],["Search index",data.base+"search.json"],
    ["Release changes",data.base+"changes.json"],["Hunt pack (.zip)",data.base+"downloads/hunt-pack.zip"],
    ...Object.keys(data.manifest.files).filter(name=>name.startsWith("schemas/")).map(name=>["JSON schema",data.base+name])
  ];
  return shell("developers",`<p class="notice">Use <code>latest.json</code> to resolve a release. Pin that snapshot for a consistent set of files. The public API uses static JSON with generated indexes.</p>
    <div class="table-scroll">${table(["Resource","Location"],paths.map(([name,path])=>[escape(name),`<a href="${escape(path)}"><code>${escape(path)}</code></a>`]))}</div>
    <p class="detail-links">${anchor("API documentation",repo+"/blob/main/docs/api.md","book")} ${anchor("MITRE ATT&CK attribution",data.base+"reference/index.json","file")}</p>`);
}

export function missing(data,state) {
  const retired = data.changes.tombstones?.find(row=>row.id===state.id);
  return shell(state.section,`<p class="empty">${retired ? `This record was retired on ${day(retired.retired_at)}. Earlier snapshots remain in release history.` :
    state.error ? "The release file could not be loaded. Try again from the catalog." : "This address has no matching record in the current release."}</p><p>${anchor("Return to The Brief",route("brief"))}</p>`,retired ? retired.title : "Record unavailable","");
}
