import { finding, findingTags, isFresh, sourceState } from "./brief.js";
import { anchor, button, day, escape, external, icon, link, neutral, options, pagination, profileBy, recentHunts, repo, resultWindow, resultsToolbar, route,
  section, sourceNames, table, tacticKey, tacticName, utc, validationNames } from "./ui.js";

const pages = {
  intelligence:["Intelligence","Search published findings, source evidence and linked Hunt Cards."],
  hunts:["Hunts","Browse evidence-backed KQL for Microsoft Sentinel. Each Hunt Card lists the workspace table and connector it needs."],
  adversaries:["Adversaries","Browse groups and software from the current MITRE ATT&CK® Enterprise reference."],
  vulnerabilities:["Vulnerabilities","Explore CISA’s known-exploited vulnerabilities and associated EPSS data."],
  indicators:["Indicators","Review attributed observations and their context. Values are defanged here."],
  techniques:["Techniques","Learn what each MITRE ATT&CK® technique means, then explore the Sentinel queries available for it."],
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

function evidenceInWindow(data,row) {
  const date = row.source_published || row.evidence?.[0]?.published || "";
  return date >= data.manifest.window.from && date <= data.manifest.window.through;
}

function filtered(data, state, rows) {
  const {q, severity, source, start, through, cve, tag, technique, tactic, malware, validation, profile,
    freshness, category, indicatorType, hunt, change, following, evidenceRange, actor, coverage, exploitCoverage} = state.filters;
  const tokens = (q || "").toLowerCase().trim().split(/\s+/).filter(Boolean);
  const changedHunts = change ? new Set(data.changes.items.filter(row=>row.type==="hunt" && row.action===change).map(row=>row.id)) : null;
  const huntIndicators = hunt ? data.hunts.find(row=>row.id===hunt)?.indicator_ids || [] : null;
  const mappedTechniques = coverage ? new Set(data.hunts.map(row=>row.technique)) : null;
  return rows.filter(row => {
    const blob = data.text.get(row.id) || JSON.stringify(row).toLowerCase();
    return tokens.every(token => blob.includes(token)) &&
      (!severity || row.severity === severity) &&
      (!source || row.source === source || row.evidence?.some(ref => ref.source === source)) &&
      (!start || (row.source_published || row.published || row.reported || row.modified || "").slice(0,10) >= start) &&
      (!through || (row.source_published || row.published || row.reported || row.modified || "").slice(0,10) <= through) &&
      (!cve || row.cves?.includes(cve.toUpperCase())) &&
      (!tag || row.tags?.includes(tag)) &&
      (!technique || [row.technique,...(row.techniques || [])].includes(technique)) &&
      (!tactic || (row.tactic ? tacticKey(row.tactic) === tactic : row.tactics?.includes(tactic))) &&
      (!malware || (row.software || []).includes(malware)) &&
      (!validation || row.status === validation) &&
      (!profile || row.profiles?.includes(profile)) &&
      (!freshness || indicatorState(data,row) === freshness) &&
      (!indicatorType || row.type === indicatorType) &&
      (!huntIndicators || huntIndicators.includes(row.id)) &&
      (!changedHunts || changedHunts.has(row.id)) &&
      (!following || state.preferences.followed.includes(row.id)) &&
      (!evidenceRange || evidenceInWindow(data,row) === (evidenceRange === "recent")) &&
      (!actor || row.actors?.includes(actor)) &&
      (!mappedTechniques || mappedTechniques.has(row.id)) &&
      (!exploitCoverage || Boolean(row.exploitation_hunts?.length) === (exploitCoverage === "covered")) &&
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
    dropdown("evidenceRange","Source date",[["recent","Release window"],["older","Older reporting"]],f.evidenceRange),
    dropdown("actor","Actor",namedValues(data.hunts.flatMap(row=>row.actors || [])),f.actor),
    dropdown("tag","Topic",namedValues(data.hunts.flatMap(row=>row.tags || [])),f.tag),
    dropdown("profile","Profile",data.profiles.map(x=>[x.id,x.short]),f.profile),
    dropdown("validation","Validation",Object.entries(validationNames), f.validation),
    dropdown("change","Release change",changeOptions.slice(0,2),f.change),
    dropdown("following","Followed hunts",[["1","Following"]],f.following),dateRange] :
    kind === "indicators" ? [source, dropdown("freshness","Freshness",[["current","Current"],["review","Review due"],["expired","Source expired"]], f.freshness),
      dropdown("indicatorType","Indicator type",namedValues(data.indicators.map(row=>row.type),value=>value.toUpperCase()),f.indicatorType),
      dropdown("hunt","Related hunt",data.hunts.filter(row=>row.indicator_ids?.length).map(row=>[row.id,row.title]),f.hunt),dateRange] :
    kind === "adversaries" ? [dropdown("category","Entity type",[["intrusion-set","Group"],["malware","Software"]],f.category)] :
    kind === "techniques" ? [tactics,dropdown("coverage","Query coverage",[["sentinel","With behavioral hunts"]],f.coverage)] : [dropdown("severity","Severity",[["high","High"],["medium","Medium"],["low","Low"],["unrated","Unrated"]],f.severity), source, dateRange, technique,
      dropdown("tag","Topic",namedValues(data.records.flatMap(row=>row.tags)),f.tag),
      dropdown("malware","Software",namedValues(data.records.flatMap(row=>row.software || [])),f.malware),
      `<label>CVE<input type="search" data-filter="cve" value="${escape(f.cve || "")}" placeholder="CVE identifier"></label>`,
      kind === "vulnerabilities" ? dropdown("exploitCoverage","Exploitation hunt coverage",[["covered","With exploitation hunts"],["uncovered","Without exploitation hunts"]],f.exploitCoverage) : ""];
  const labels = {evidenceRange:f.evidenceRange === "recent" ? "Release window" : "Older reporting",
    following:"Following", coverage:"With behavioral hunts",
    exploitCoverage:f.exploitCoverage === "covered" ? "With exploitation hunts" : "Without exploitation hunts",
    change:changeOptions.find(([value])=>value===f.change)?.[1], category:entityTypes[f.category],
    validation:validationNames[f.validation], tactic:f.tactic && tacticName(f.tactic), source:sourceNames[f.source],
    profile:profileBy(data,f.profile)?.short, hunt:data.hunts.find(row=>row.id===f.hunt)?.title};
  const applied = Object.entries(f).filter(([name])=>name!=="q" && name!=="sort");
  return `<form class="filters catalog-filters" aria-label="Filter results">
    <div class="filter-primary"><label>Search<input type="search" data-filter="q" value="${escape(f.q || "")}" placeholder="Search ${escape(pages[kind][0].toLowerCase())}"></label>
    ${Object.keys(f).length ? button("Clear","clear-filters") : ""}</div>
    <details data-filter-panel${state.filtersExpanded ? " open" : ""}><summary>More filters</summary><div class="filter-fields">${extras.join("")}</div></details>
    ${applied.length ? `<div class="chips" aria-label="Applied filters">${applied.map(([name,value])=>
      `<button type="button" class="chip" data-remove-filter="${escape(name)}" aria-label="Remove filter: ${escape(labels[name] || value)}">${neutral(labels[name] || value)} ×</button>`).join("")}</div>` : ""}</form>`;
}

function indicatorState(data,row) {
  const today = data.manifest.window.through;
  if (row.source_expires && row.source_expires <= today) return "expired";
  return row.reported > today || row.aging_review <= today ? "review" : "current";
}

function huntCard(data, row, state) {
  const following = state.preferences.followed.includes(row.id) ? link("Following",route("hunts",null,{following:"1"})) + " · " : "";
  const primary = profileBy(data,row.profiles[0]);
  return `<article class="catalog-card" data-record-card>
    <div class="meta">${following}${escape(row.id)} · ${link("REV " + row.revision,route("hunts",row.id,{tab:"revisions"}))}</div>
    <p class="meta">Source: ${day(row.source_published || row.evidence[0]?.published)} · ${escape(primary.short)}${row.primary_table ? ` · <code>${escape(row.primary_table)}</code>` : ""}</p>
    <h2><a href="${route("hunts",row.id)}">${neutral(row.title)}</a></h2><p>${neutral(row.description)}</p>
    <p class="chips">${link(row.technique,route("techniques",row.technique),"chip")}${link(row.tactic,route("hunts",null,{tactic:tacticKey(row.tactic)}),"chip")}
    ${(row.cves || []).map(cve=>link(cve,route("vulnerabilities",null,{cve}),"chip")).join("")}
    ${(row.actors || []).map(actor=>link(actor,route("hunts",null,{actor}),"chip")).join("")}
    ${link(validationNames[row.status] || row.status,route("hunts",null,{validation:row.status}),"chip")}</p>
  </article>`;
}

function entityCard(data,kind,row) {
  if (kind === "indicators") return `<article class="catalog-card" data-record-card><div class="meta">${link(row.type.toUpperCase(),route(kind,null,{indicatorType:row.type}))} ·
    ${link(indicatorState(data,row),route(kind,null,{freshness:indicatorState(data,row)}))} · ${day(row.reported)}</div>
    <h2><a href="${route(kind,row.id)}">${escape(row.display)}</a></h2><p>${neutral(row.context)}</p></article>`;
  const type = entityTypes[row.type];
  const matches = kind === "techniques" ? data.hunts.filter(hunt=>hunt.technique===row.id).length : 0;
  return `<article class="catalog-card" data-record-card><div class="meta">${escape(row.id)} · ${kind === "adversaries" ?
    link(type.toUpperCase(),route(kind,null,{category:row.type})) : escape(type.toUpperCase())}</div>
    <h2><a href="${route(kind,row.id)}">${neutral(row.title)}</a></h2>${row.aliases?.length > 1 ? `<p>${neutral(row.aliases.slice(1,6).join(", "))}</p>` : ""}
    ${row.description ? `<p class="technique-summary">${neutral(row.description)}</p>` : ""}
    <div class="chips">${(row.tactics || []).map(tactic=>link(tacticName(tactic),route("techniques",null,{tactic}),"chip")).join("")}
    ${matches ? link(`${matches} behavioral ${matches === 1 ? "hunt" : "hunts"}`,route("techniques",row.id),"chip") :
      row.alert_query ? link("Alert pivot",route("techniques",row.id),"chip") : ""}</div></article>`;
}

function indicatorTargets(data) {
  const bulk = data.indicatorQuery;
  return bulk ? [bulk,...(bulk.alternate_targets || [])] : [];
}

export function indicatorQueryTarget(data,state) {
  const targets = indicatorTargets(data);
  return targets.find(target=>target.profile_id === state.indicatorTarget) || targets[0];
}

function bulkIndicators(data,state) {
  const bulk = data.indicatorQuery;
  const target = indicatorQueryTarget(data,state);
  if (!bulk) return "";
  const query = target.queries[String(state.indicatorDays)];
  const counts = Object.entries(bulk.counts_by_type).map(([type,count])=>`${count} ${type.toUpperCase()}`).join(" · ");
  return `<section class="detail-section bulk-indicators">${section("Hunt across current indicators","crosshair")}
    <p>${bulk.indicator_count} current indicators as of ${day(bulk.as_of)}${counts ? ` · ${escape(counts)}` : ""}.
      ${bulk.exclusion_count ? `${bulk.exclusion_count} excluded by age, expiration or eligibility.` : ""}</p>
    ${query ? `<div class="detail-links">
      ${button("Copy all current indicators as KQL","copy-bulk-indicators","copy","inverted")}
      ${indicatorTargets(data).length > 1 ? `<label>Telemetry <select data-indicator-target aria-label="Indicator telemetry">${options(indicatorTargets(data).map(item=>[item.profile_id,item.table]),target.profile_id)}</select></label>` : ""}
      <label>Lookback <select data-indicator-days aria-label="Indicator lookback">${options(Object.keys(target.queries).map(value=>[Number(value),value+" days"]),state.indicatorDays)}</select></label>
      </div><p>Microsoft Sentinel · <code>${escape(target.table)}</code>. Each row identifies the matching log field, device and network context, indicator, and source intelligence. One event can generate multiple matches.</p>
      <p>${escape(target.scope_note || "Matches only fields populated by your connector.")}</p>
      <details class="mapping" data-indicator-preview${state.indicatorPreview ? " open" : ""}><summary>Preview indicator KQL</summary>
        <div class="code-surface"><pre tabindex="0"><code>${escape(query)}</code></pre></div></details>` :
      "<p>No current indicators are eligible for a query in this release.</p>"}</section>`;
}

export function catalog(data, state) {
  const kind = state.section;
  const isHunts = kind === "hunts";
  const entities = ["indicators","adversaries","techniques"].includes(kind);
  const source = isHunts ? recentHunts(data.hunts) : kind === "indicators" ? data.indicators :
    kind === "adversaries" ? data.reference.filter(x=>x.type !== "attack-pattern") :
    kind === "techniques" ? data.reference.filter(x=>x.type === "attack-pattern") :
    kind === "vulnerabilities" ? data.records.filter(x=>x.kind==="Vulnerability") :
    kind === "research" ? data.records.filter(x=>x.kind==="Research") : data.records;
  const rows = filtered(data,state,source);
  const date = row => row.source_published || row.published || row.reported || row.modified || "";
  const sort = state.filters.sort;
  if (sort === "title") rows.sort((a,b)=>(a.title || a.display).localeCompare(b.title || b.display));
  if (sort === "newest") rows.sort((a,b)=>date(b).localeCompare(date(a)));
  if (sort === "oldest") rows.sort((a,b)=>date(a).localeCompare(date(b)));
  const {start,end,page,size} = resultWindow(rows.length,state);
  const visible = rows.slice(start,end);
  let contents = "";
  if (isHunts) {
    const recent = data.hunts.filter(row=>evidenceInWindow(data,row)).length;
    contents += `<nav class="detail-links" aria-label="Hunt collections">
      ${anchor(`${recent} hunts from the latest 30-day window`,route("hunts",null,{evidenceRange:"recent"}),"history")}
      ${anchor("ARTEX and agentic AI",route("hunts",null,{q:"ARTEX"}),"search")}
      ${anchor("Nation-state",route("hunts",null,{tag:"Nation-State"}),"users")}
      ${anchor("All hunts",route("hunts"),"crosshair")}
    </nav>`;
  }
  if (kind === "indicators") contents += bulkIndicators(data,state);
  contents += filters(data,state,kind);
  if (isHunts) {
    contents += `<div class="detail-links">${anchor("Followed hunts",route("hunts",null,{following:"1"}),"star")}
      ${button("Output preferences","settings","settings")}</div>`;
  }
  contents += resultsToolbar(rows.length,isHunts ? "hunts" : "records",state,true);
  if (visible.length) {
    const markup = visible.map(row => isHunts ? huntCard(data,row,state) : entities ? entityCard(data,kind,row) : finding(data,row,kind)).join("");
    contents += isHunts || entities ? `<div class="catalog-grid">${markup}</div>` : markup;
  } else contents += '<p class="empty">No records match these filters.</p>';
  contents += pagination(rows.length,page,size,isHunts ? "hunts" : "records");
  return shell(kind,contents);
}

function evidenceList(refs) {
  return `<div class="catalog-grid">${refs.map(ref=>`<article class="catalog-card"><p class="meta">${escape(sourceNames[ref.source])} · ${day(ref.published)}</p>
    <h3>${neutral(ref.location)}</h3><p>${neutral(ref.claim)}</p>
    ${ref.observation_date ? `<p>Source observation ${day(ref.observation_date)}</p>` : ""}
    ${ref.modified ? `<p>Publisher updated ${day(ref.modified)}</p>` : ""}${external("Open publisher source",ref.url)}</article>`).join("")}</div>`;
}

function exploitationHunts(data,row) {
  const cards = row.huntCards || [];
  return `<section class="detail-section" aria-labelledby="exploitation-hunts"><h2 id="exploitation-hunts">Exploitation hunts</h2>
    ${cards.length ? `<div class="catalog-grid">${cards.map(card=>{
      const profile = profileBy(data,card.profiles[0]);
      const query = card.variants[profile.id].queries[String(card.lookback)].table;
      return `<article class="catalog-card">
        <p class="meta">${escape(profile.target)} · <code>${escape(card.primary_table)}</code> · ${card.lookback}-day lookback</p>
        <h3>${link(card.title,route("hunts",card.id))}</h3><p>${neutral(card.description)}</p>
        <p>${neutral(card.confidence)}</p>
        <div class="detail-links">${anchor("Open Hunt Card",route("hunts",card.id),"crosshair")}
        <button type="button" class="btn" data-copy-technique="${escape(card.id)}">${icon("copy")} Copy KQL</button></div>
        <details class="mapping"><summary>Preview KQL</summary><div class="code-surface"><pre tabindex="0"><code>${escape(query)}</code></pre></div></details>
      </article>`;
    }).join("")}</div>` : `<p>${row.exploitation_hunts?.length ? "The Hunt Cards could not be loaded. Reload this record to try again." :
      "A CVE-specific HuntForge query is not available for this vulnerability yet."}</p>`}</section>`;
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
    ${row.kind === "Vulnerability" ? exploitationHunts(data,row) : ""}
    <section class="detail-section">${section("Source evidence","link")}${evidenceList(row.evidence)}</section>
    ${row.hunts.length || row.related.length || row.indicators?.length ? `<section class="detail-section">${section("Related records","network")}
      <div class="detail-links">${row.hunts.filter(id=>!row.huntCards?.some(card=>card.id===id)).map(id=>anchor(data.hunts.find(x=>x.id===id)?.title||id,route("hunts",id),"crosshair")).join("")}
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
        ["Freshness",link(indicatorState(data,row),route(kind,null,{freshness:indicatorState(data,row)}))]
      ])}</section><section class="detail-section">${section("Source evidence","link")}${evidenceList(row.evidence)}</section>
      <p class="detail-links">${anchor("Browse indicators and copy bulk KQL",route(kind),"crosshair")}</p>`,row.display,`<p class="intro">${neutral(row.context)}</p>`);
  }
  const hunts = data.hunts.filter(hunt=>hunt.technique===row.id);
  const related = data.records.filter(rec=>rec.techniques?.includes(row.id));
  const techniqueContent = kind === "techniques" ? `<section class="detail-section">
    ${section("What this technique means","book")}
    <p>${neutral(row.description || "Read the MITRE ATT&CK reference for the technique definition.")}</p>
    </section><section class="detail-section">${section("How to hunt in Sentinel","crosshair")}
    ${hunts.length ? hunts.map(summary => {
      const card = row.huntCards?.find(hunt=>hunt.id===summary.id);
      if (!card) return `<p>${link(summary.title,route("hunts",summary.id))}</p>`;
      const profile = profileBy(data,card.profiles[0]);
      const variant = card.variants[profile.id];
      return `<details class="mapping technique-query">
        <summary>${neutral(card.title)} · ${escape(variant.table)}</summary>
        <div>
          <p>${neutral(card.hypothesis)}</p>
          <p>${escape(profile.assumptions)}</p>
          <pre class="code-surface" tabindex="0"><code>${escape(variant.queries[card.lookback].table)}</code></pre>
          <div class="detail-links">
            <button type="button" class="btn" data-copy-technique="${escape(card.id)}">${icon("copy")} Copy KQL</button>
            ${anchor("Open Hunt Card",route("hunts",card.id),"crosshair")}
          </div>
        </div>
      </details>`;
    }).join("") : '<p>Behavioral hunt coverage for this technique is pending.</p>'}
    ${row.alert_query ? `<details class="mapping technique-query">
      <summary>Look up alerts tagged ${escape(row.id)} · SecurityAlert</summary>
      <div>
        <p>This pivot finds existing Sentinel alerts tagged with this exact technique ID. It relies on connected products populating the ATT&amp;CK tags.</p>
        <pre class="code-surface" tabindex="0"><code>${escape(row.alert_query)}</code></pre>
        <button type="button" class="btn" data-copy-technique="alert">${icon("copy")} Copy KQL</button>
      </div>
    </details>` : ""}</section>` : "";
  return shell(kind,`<p>${external("Open MITRE ATT&CK reference",row.url)}</p><div class="chips">${row.tactics?.map(tactic=>
    link(tacticName(tactic),route("techniques",null,{tactic}),"chip")).join("") || ""}</div>
    <p class="mono">Modified ${day(row.modified)} · Enterprise ATT&CK ${escape(data.referenceVersion)}</p>
    ${row.aliases?.length ? `<p>Aliases ${neutral(row.aliases.join(", "))}</p>` : ""}
    ${techniqueContent}
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
  const {start,end,page,size} = resultWindow(rows.length,state);
  const matching = rows.slice(start,end);
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
    ${resultsToolbar(rows.length,"changes",state)}
    ${matching.length ? `<div class="table-scroll">${table(["Change","Type","ID","Title","Revision"],matching.map(row=>[
      link(row.action,route("changelog",state.id,{...state.filters,change:row.action}),"chip"),
      link(row.type,route("changelog",state.id,{...state.filters,recordType:row.type})),escape(row.id),row.action==="retired" ? neutral(row.title) :
      `<a href="${route(row.type === "hunt" ? "hunts" : "intelligence",row.id)}">${neutral(row.title)}</a>`,row.revision]))}</div>
      ${pagination(rows.length,page,size,"changes")}` : `<p class="empty">${change || recordType || q ?
        "No release changes match these filters." : "No material changes were recorded for this comparison."}</p>`}</section>`);
}

export function developers(data) {
  const first = data.hunts[0]?.id;
  const paths = [
    ["Latest release pointer","api/v1/latest.json",route("changelog")],["Release manifest",data.base+"manifest.json",route("status")],
    ["Intelligence index",data.base+"intelligence/index.json",route("intelligence")],["Hunt index",data.base+"hunts/index.json",route("hunts")],
    ...(first ? [["Example Hunt Card",data.base+`hunts/${first}.json`,route("hunts",first)]] : []),
    ["Indicators",data.base+"indicators/index.json",route("indicators")],
    ...(data.indicatorQuery ? [["Bulk indicator KQL",data.base+"indicators/bulk-query.json",route("indicators")]] : []),
    ["Profiles",data.base+"profiles/index.json"],["Search index",data.base+"search.json"],
    ["Release changes",data.base+"changes.json",route("changelog")],
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
