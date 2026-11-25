import { finding, findingTags, isFresh, sourceState } from "./brief.js";
import { anchor, button, day, escape, external, icon, link, neutral, options, pagination, repo, route, section,
  sourceNames, table, tacticKey, tacticName, utc, validationNames } from "./ui.js";

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
  const {q, severity, source, start, through, cve, tag, technique, tactic, malware, validation, profile,
    freshness, category, indicatorType, hunt, change, following} = state.filters;
  const tokens = (q || "").toLowerCase().trim().split(/\s+/).filter(Boolean);
  const changedHunts = change ? new Set(data.changes.items.filter(row=>row.type==="hunt" && row.action===change).map(row=>row.id)) : null;
  const huntIndicators = hunt ? data.hunts.find(row=>row.id===hunt)?.indicator_ids || [] : null;
  return rows.filter(row => {
    const blob = data.text.get(row.id) || JSON.stringify(row).toLowerCase();
    return tokens.every(token => blob.includes(token)) &&
      (!severity || row.severity === severity) &&
      (!source || row.source === source || row.evidence?.some(ref => ref.source === source)) &&
      (!start || (row.published || row.reported || row.modified || "").slice(0,10) >= start) &&
      (!through || (row.published || row.reported || row.modified || "").slice(0,10) <= through) &&
      (!cve || row.cves?.includes(cve.toUpperCase())) &&
      (!tag || row.tags?.includes(tag)) &&
      (!technique || [row.technique,...(row.techniques || [])].includes(technique)) &&
      (!tactic || (row.tactic ? tacticKey(row.tactic) === tactic : row.tactics?.includes(tactic))) &&
      (!malware || (row.software || []).includes(malware)) &&
      (!validation || row.status === validation) &&
      (!profile || row.profiles?.includes(profile)) &&
      (!freshness || indicatorState(row) === freshness) &&
      (!indicatorType || row.type === indicatorType) &&
      (!huntIndicators || huntIndicators.includes(row.id)) &&
      (!changedHunts || changedHunts.has(row.id)) &&
      (!following || state.preferences.followed.includes(row.id)) &&
      (!category || row.type === category);
  });
}

function dropdown(name, label, rows, active) {
  return `<label>${label}<select aria-label="${label}" data-filter="${name}">${options([["","All"],...rows],active||"")}</select></label>`;
}

function namedValues(values, label = value=>value) {
  return [...new Set(values)].sort().map(value=>[value,label(value)]);
}

const changeOptions = [["created","New in this release"],["updated","Updated in this release"],["retired","Retired"]];
const entityTypes = {"intrusion-set":"Group", malware:"Software", "attack-pattern":"Technique"};

function filters(data,state,kind) {
  const f = state.filters;
  const dateRange = `<label>From<input type="date" data-filter="start" value="${escape(f.start || "")}"></label><label>Through<input type="date" data-filter="through" value="${escape(f.through || "")}"></label>`;
  const source = dropdown("source","Source",Object.entries(sourceNames),f.source);
  const technique = dropdown("technique","Technique",[...new Set(data.hunts.map(x=>x.technique).concat(data.records.flatMap(x=>x.techniques || [])))].sort().map(x=>[x,x]),f.technique);
  const tactics = dropdown("tactic","Tactic",namedValues(kind === "hunts" ? data.hunts.map(row=>tacticKey(row.tactic)) :
    data.reference.flatMap(row=>row.tactics || []),tacticName),f.tactic);
  const extras = kind === "hunts" ? [source, technique, tactics,
    dropdown("profile","Profile",data.profiles.map(x=>[x.id,x.short]),f.profile),
    dropdown("validation","Validation",Object.entries(validationNames), f.validation),
    dropdown("change","Release change",changeOptions.slice(0,2),f.change),
    dropdown("following","Followed hunts",[["1","Following"]],f.following),dateRange] :
    kind === "indicators" ? [source, dropdown("freshness","Freshness",[["current","Current"],["review","Review due"],["expired","Source expired"]], f.freshness),
      dropdown("indicatorType","Indicator type",namedValues(data.indicators.map(row=>row.type),value=>value.toUpperCase()),f.indicatorType),
      dropdown("hunt","Related hunt",data.hunts.filter(row=>row.indicator_ids?.length).map(row=>[row.id,row.title]),f.hunt),dateRange] :
    kind === "adversaries" ? [dropdown("category","Entity type",[["intrusion-set","Group"],["malware","Software"]],f.category)] :
    kind === "techniques" ? [tactics] : [dropdown("severity","Severity",[["high","High"],["medium","Medium"],["low","Low"],["unrated","Unrated"]],f.severity), source, dateRange, technique,
      dropdown("tag","Topic",namedValues(data.records.flatMap(row=>row.tags)),f.tag),
      dropdown("malware","Software",namedValues(data.records.flatMap(row=>row.software || [])),f.malware),
      `<label>CVE<input type="search" data-filter="cve" value="${escape(f.cve || "")}" placeholder="CVE identifier"></label>`];
  return `<form class="filters" aria-label="Filter results"><label>Search<input type="search" data-filter="q" value="${escape(f.q || "")}" placeholder="Search ${escape(pages[kind][0].toLowerCase())}"></label>
    ${extras.join("")}${button("Clear","clear-filters")}</form>`;
}

function indicatorState(row) {
  const today = new Date().toISOString().slice(0,10);
  if (row.source_expires && row.source_expires <= today) return "expired";
  return row.aging_review <= today ? "review" : "current";
}

function huntCard(row, state) {
  const following = state.preferences.followed.includes(row.id) ? link("Following",route("hunts",null,{following:"1"})) + " · " : "";
  return `<article class="catalog-card">
    <div class="meta">${following}${escape(row.id)} · ${link("REV " + row.revision,route("hunts",row.id,{tab:"revisions"}))}</div>
    <h2><a href="${route("hunts",row.id)}">${neutral(row.title)}</a></h2><p>${neutral(row.description)}</p>
    <p class="chips">${link(row.technique,route("techniques",row.technique),"chip")}${link(row.tactic,route("hunts",null,{tactic:tacticKey(row.tactic)}),"chip")}
    ${link(validationNames[row.status] || row.status,route("hunts",null,{validation:row.status}),"chip")}</p>
    <label class="checkbox"><input type="checkbox" data-pack-id="${escape(row.id)}"${state.pack.has(row.id) ? " checked" : ""}> Include in ZIP pack</label>
  </article>`;
}

function entityCard(kind,row) {
  if (kind === "indicators") return `<article class="catalog-card"><div class="meta">${link(row.type.toUpperCase(),route(kind,null,{indicatorType:row.type}))} ·
    ${link(indicatorState(row),route(kind,null,{freshness:indicatorState(row)}))} · ${day(row.reported)}</div>
    <h2><a href="${route(kind,row.id)}">${escape(row.display)}</a></h2><p>${neutral(row.context)}</p></article>`;
  const type = entityTypes[row.type];
  return `<article class="catalog-card"><div class="meta">${escape(row.id)} · ${kind === "adversaries" ?
    link(type.toUpperCase(),route(kind,null,{category:row.type})) : escape(type.toUpperCase())}</div>
    <h2><a href="${route(kind,row.id)}">${neutral(row.title)}</a></h2>${row.aliases?.length > 1 ? `<p>${neutral(row.aliases.slice(1,6).join(", "))}</p>` : ""}
    ${row.tactics?.length ? `<div class="chips">${row.tactics.map(tactic=>link(tacticName(tactic),route("techniques",null,{tactic}),"chip")).join("")}</div>` : ""}</article>`;
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
      ${anchor("Default hunt pack (.zip)",data.base+"downloads/hunt-pack.zip","file")}${anchor("Followed hunts",route("hunts",null,{following:"1"}),"star")}
      ${button("Output preferences","settings","settings")}</div>`;
  }
  if (visible.length) {
    const markup = visible.map(row => isHunts ? huntCard(row,state) : entities ? entityCard(kind,row) : finding(data,row,kind)).join("");
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
  const kind = state.section;
  const contents = `<p class="detail-links">${findingTags(data,row)}</p>
    <section class="detail-section">${section("Record provenance","file")}${table(["Attribute","Value"],[
      ["ID",escape(row.id)],["Revision",row.revision],["Source",link(sourceNames[row.source],route(kind,null,{source:row.source}))],
      ["Source publication",link(day(row.published),route(kind,null,{start:row.published,through:row.published}))],
      ["HuntForge first retrieved",utc(row.first_retrieved)],["Latest source retrieval",utc(row.retrieved)],["HuntForge updated",utc(row.updated)],
      ["Evidence confidence",escape(row.confidence)],["HuntForge severity",link(row.severity,route(kind,null,{severity:row.severity}))]
    ])}</section>
    <section class="detail-section">${section("Source evidence","link")}${evidenceList(row.evidence)}</section>
    ${row.hunts.length || row.related.length || row.indicators?.length ? `<section class="detail-section">${section("Related records","network")}
      <div class="detail-links">${row.hunts.map(id=>anchor(data.hunts.find(x=>x.id===id)?.title||id,route("hunts",id),"crosshair")).join("")}
      ${row.related.map(id=>anchor(data.records.find(x=>x.id===id)?.title||id,route("intelligence",id),"file")).join("")}
      ${(row.indicators||[]).map(id=>anchor(data.indicators.find(x=>x.id===id)?.display||id,route("indicators",id),"database")).join("")}</div></section>`:""}
    ${scores.length ? `<section class="detail-section">${section("FIRST EPSS","pulse")}<p>EPSS estimates exploitation probability over the next 30 days. CISA’s listing separately records evidence of exploitation.</p>
      <details class="mapping" open><summary>${scores.length} daily scores from FIRST</summary>${table(["Score date","Probability","Percentile"],
        scores.map(point=>[day(point.date),`${(Number(point.epss)*100).toFixed(2)}%`,`${(Number(point.percentile)*100).toFixed(2)}%`]))}</details></section>`:""}
    <p class="detail-links">${anchor("Record JSON",data.base+`intelligence/${row.id}.json`,"code")}${anchor("Browse " + pages[kind][0].toLowerCase(),route(kind))}</p>`;
  return shell(kind,contents,row.title,`<p class="intro">${neutral(row.summary)}</p>`);
}

export function entityDetail(data,state) {
  const row = state.detail;
  const kind = state.section;
  if (kind === "indicators") {
    return shell(kind,`<p class="detail-links">${button("Copy canonical value","copy-indicator","copy")}${anchor("Indicator JSON",data.base+`indicators/${row.id}.json`,"code")}${anchor("Related intelligence",route("intelligence",row.record_id),"file")}</p>
      <section class="detail-section">${section("Indicator lifecycle","history")}${table(["Attribute","Value"],[
        ["Type",link(row.type,route(kind,null,{indicatorType:row.type}))],["Publisher report",day(row.reported)],["First observation",day(row.first_observed)],
        ["Last observation",day(row.last_observed)],["Publisher expiration",day(row.source_expires)],["HuntForge review date",day(row.aging_review)],
        ["Freshness",link(indicatorState(row),route(kind,null,{freshness:indicatorState(row)}))]
      ])}</section><section class="detail-section">${section("Source evidence","link")}${evidenceList(row.evidence)}</section>
      <p>${anchor("Browse indicators",route(kind))}</p>`,row.display,`<p class="intro">${neutral(row.context)}</p>`);
  }
  const hunts = data.hunts.filter(hunt=>hunt.technique===row.id);
  const related = data.records.filter(rec=>rec.techniques?.includes(row.id));
  return shell(kind,`<p>${external("Open MITRE ATT&CK reference",row.url)}</p><div class="chips">${row.tactics?.map(tactic=>
    link(tacticName(tactic),route("techniques",null,{tactic}),"chip")).join("") || ""}</div>
    <p class="mono">Modified ${day(row.modified)} · Enterprise ATT&CK ${escape(data.referenceVersion)}</p>
    ${row.aliases?.length ? `<p>Aliases ${neutral(row.aliases.join(", "))}</p>` : ""}
    ${hunts.length ? `<section class="detail-section">${section("Related hunts","crosshair")}
      <div class="detail-links">${hunts.map(x=>anchor(x.title,route("hunts",x.id))).join("")}</div></section>` : ""}
    ${related.length ? `<section class="detail-section">${section("Related intelligence","file")}${related.map(record=>finding(data,record)).join("")}</section>`:""}
    <p class="detail-links">${anchor("Browse " + pages[kind][0].toLowerCase(),route(kind,null,kind === "adversaries" ? {category:row.type} : {}))}
      ${anchor("Search intelligence",route("intelligence",null,kind === "techniques" ? {technique:row.id} : {q:row.title}),"search")}</p>`,row.title,
    `<p class="intro">${escape(row.id)} · Current MITRE ATT&CK® Enterprise reference entry.</p>`);
}

export function systemStatus(data,state) {
  const {report, manifest} = data;
  const {source,sourceState:selectedState,panel} = state.filters;
  const validation = route("status",null,{panel:"validation"});
  const sourceRows = report.sources.filter(row=>(!source || row.id===source) &&
    (!selectedState || (selectedState==="fresh" ? isFresh(row) : row.state===selectedState))).map(row=>{
      const browse = row.id==="mitre" ? link("Browse techniques",route("techniques")) :
        row.id==="first-epss" ? link("Browse vulnerabilities",route("vulnerabilities")) :
        data.records.some(record=>record.source===row.id) ? link("Browse findings",route("intelligence",null,{source:row.id})) : "";
      return [link(row.name,route("status",null,{source:row.id})),escape(sourceState(row)),escape(row.coverage),day(row.first_available),
        utc(row.retrieved), row.count??"—",escape(row.coverage_note||""),browse];
    });
  const fields = [["Latest release",link(manifest.release_id,route("changelog",manifest.release_id))],["Collection start",utc(report.started)],["Collection end",utc(report.finished)],
    ["Historical window",link(`${day(report.window.from)} through ${day(report.window.through)}`,route("intelligence",null,{start:report.window.from,through:report.window.through}))],
    ["Fresh sources",link(`${report.sources.filter(isFresh).length} of ${report.sources.length}`,route("status",null,{sourceState:"fresh"}))],
    ["Accepted hunts",link(report.accepted,route("hunts"))],["Quarantined hunts",link(report.quarantined.length,validation)],
    ["Analyzer",link(data.hunts[0]?.validation?.validator||"Unavailable",validation)],["Workspace execution","Not run"],
    ["Scheduled collection","Daily at 06:17 America/New_York through GitHub Actions"],
    ["Models / model calls","Deterministic collection and generation / " + report.engine.calls],["Model expenditure","$" + report.engine.cost_usd.toFixed(2)]];
  const navigation = `<nav class="detail-links" aria-label="Status views">${anchor("Source health",route("status"),"database",panel==="validation" ? "" : "inverted")}
    ${anchor("Hunt validation",validation,"checked",panel==="validation" ? "inverted" : "")}</nav>`;
  const hunts = panel==="validation" ? `<section class="detail-section">${section("Hunt validation","checked")}
    <p>Accepted hunts include their validation scope and evidence. KQL engine and workspace execution have yet to be run.</p>
    <div class="detail-links">${Object.entries(validationNames).map(([key,name])=>anchor(
      `${name} (${data.hunts.filter(row=>row.status===key).length})`,route("hunts",null,{validation:key}))).join("")}</div>
    <h3>Quarantined hunts</h3>${report.quarantined.length ? table(["Hunt","Reason"],report.quarantined.map(row=>[escape(row.id),neutral(row.reason)])) :
      '<p class="empty">No hunts were quarantined in this release.</p>'}</section>` : "";
  const sources = `<section class="detail-section">${section("Source health & historical coverage","database")}
    <form class="filters" aria-label="Filter sources">
      ${dropdown("source","Source",report.sources.map(row=>[row.id,row.name]),source)}
      ${dropdown("sourceState","Collection state",[["live","Retrieved live"],["fresh","Fresh"],["cached","Cached"],["failed","Failed"]],selectedState)}
      ${button("Clear","clear-filters")}
    </form>${sourceRows.length ? `<div class="table-scroll">${table(["Source","State","Coverage","Earliest available","Retrieved","Records","Scope","Browse"],sourceRows)}</div>` :
      '<p class="empty">No sources match these filters.</p>'}</section>`;
  const run = `<section class="detail-section">${section("Latest collection run","pulse")}${table(["Field","Value"],fields)}</section>`;
  return shell("status",`${navigation}${panel==="validation" ? hunts : source || selectedState ? sources+run : run+sources}
    <p class="detail-links">${anchor("Release report JSON",data.base+"report.json","code")} ${anchor("GitHub Actions",repo+"/actions","github")}</p>`);
}

export function changelog(data,state) {
  const selected = state.detail || data.changes;
  const label = state.id === "since-last-visit" ? "Changes since your last visit" : state.detail ? `Release ${selected.release_id}` : "Current accepted release";
  const prior = state.previousVisit;
  const links = data.history.map(row=>anchor(row.release_id,route("changelog",row.release_id),"history",state.id===row.release_id ? "inverted" : "")).join("");
  const {q,change,recordType} = state.filters;
  const rows = selected.items.filter(row=>(!change || row.action===change) && (!recordType || row.type===recordType) &&
    (!q || `${row.id} ${row.title}`.toLowerCase().includes(q.trim().toLowerCase())));
  const matching = rows.slice(state.page*25,state.page*25+25);
  return shell("changelog",`<div class="notice">${prior && prior !== data.manifest.release_id ?
    `Last viewed ${escape(prior)}. ${anchor("Changes since that release",route("changelog","since-last-visit"),"history")}` :
    prior ? "Your last visit used the current release." : "This is your first recorded visit."}</div>
    <p class="detail-links">${anchor("Current release",route("changelog"),"history",state.id ? "" : "inverted")}
      ${links}${anchor("Release history JSON","api/v1/history.json","code")}</p>
    <section class="detail-section">${section(label,"history")}
    <form class="filters" aria-label="Filter release changes">
      <label>Search changes<input type="search" data-filter="q" value="${escape(q || "")}"></label>
      ${dropdown("change","Change",changeOptions,change)}
      ${dropdown("recordType","Record type",[["hunt","Hunt"],["intelligence","Intelligence"]],recordType)}
      ${button("Clear","clear-filters")}
    </form>
    ${matching.length ? `<div class="table-scroll">${table(["Change","Type","ID","Title","Revision"],matching.map(row=>[
      link(row.action,route("changelog",state.id,{...state.filters,change:row.action}),"chip"),
      link(row.type,route("changelog",state.id,{...state.filters,recordType:row.type})),escape(row.id),row.action==="retired" ? neutral(row.title) :
      `<a href="${route(row.type === "hunt" ? "hunts" : "intelligence",row.id)}">${neutral(row.title)}</a>`,row.revision]))}</div>
      ${pagination(rows.length,state.page,25,"changes")}` : `<p class="empty">${change || recordType || q ?
        "No release changes match these filters." : "No material changes were recorded for this comparison."}</p>`}</section>`);
}

export function developers(data) {
  const first = data.hunts[0]?.id;
  const paths = [
    ["Latest release pointer","api/v1/latest.json",route("changelog")],["Release manifest",data.base+"manifest.json",route("status")],
    ["Intelligence index",data.base+"intelligence/index.json",route("intelligence")],["Hunt index",data.base+"hunts/index.json",route("hunts")],
    ...(first ? [["Example Hunt Card",data.base+`hunts/${first}.json`,route("hunts",first)]] : []),
    ["Indicators",data.base+"indicators/index.json",route("indicators")],
    ["Profiles",data.base+"profiles/index.json"],["Search index",data.base+"search.json"],
    ["Release changes",data.base+"changes.json",route("changelog")],["Hunt pack (.zip)",data.base+"downloads/hunt-pack.zip"],
    ...Object.keys(data.manifest.files).filter(name=>name.startsWith("schemas/")).map(name=>["JSON schema",data.base+name])
  ];
  return shell("developers",`<p class="notice">Use <code>latest.json</code> to resolve a release. Pin that snapshot for a consistent set of files. The public API uses static JSON with generated indexes.</p>
    <div class="table-scroll">${table(["Resource","Location","Actions"],paths.map(([name,path,view])=>[
      view ? link(name,view) : escape(name),`<a href="${escape(path)}"><code>${escape(path)}</code></a>`,
      `<button type="button" class="btn" data-copy-url="${escape(path)}" aria-label="Copy URL for ${escape(name)}">${icon("copy")} Copy URL</button>`
    ]))}</div>
    <p class="detail-links">${anchor("API documentation",repo+"/blob/main/docs/api.md","book")} ${anchor("MITRE ATT&CK attribution",data.base+"reference/index.json","file")}</p>`);
}

export function missing(data,state) {
  const retired = data.changes.tombstones?.find(row=>row.id===state.id);
  return shell(state.section,`<p class="empty">${retired ? `This record was retired on ${day(retired.retired_at)}. Earlier snapshots remain in release history.` :
    state.error ? "The release file could not be loaded. Try again from the catalog." : "This address has no matching record in the current release."}</p><p>${anchor("Return to The Brief",route("brief"))}</p>`,retired ? retired.title : "Record unavailable","");
}
