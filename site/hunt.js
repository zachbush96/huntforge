import { activeQuery, anchor, badge, day, escape, external, icon, link, neutral, options, profileBy, recentHunts, route, section, sourceNames,
  table, tacticKey, utc, validationNames } from "./ui.js";
import { explainer } from "./explain.js";

export const huntTabs = [["query","Hunting Query"],["environment","Data Requirements"],["investigation","Investigation"],
  ["evidence","Intelligence"],["related","Related"],["revisions","Revision History"],["explain","Explain the Results"]];
const lookbacks = [1, 3, 7, 14, 30];

function profileOptions(data, state) {
  return options(state.hunt.profiles.map(id => [id, profileBy(data,id).name]), state.profile);
}

function tabPanel(data, state, variant) {
  const {hunt, tab, preferences} = state;
  const profile = profileBy(data, state.profile);
  const schema = profile.tables[variant.table];
  if (tab === "explain") return explainer();
  if (tab === "environment") return `<div class="tab-body"><h3>${escape(profile.name)}</h3>
    <p>${escape(profile.assumptions)}</p>
    <p>${escape(profile.target)} · ${schema.documentation ? external(variant.table,schema.documentation) : `<code>${escape(variant.table)}</code>`}</p>
    <div class="detail-links">${anchor("Browse hunts using this profile",route("hunts",null,{profile:profile.id}),"crosshair")}</div></div>`;
  if (tab === "investigation") return `<div class="tab-body"><h3>Hunt hypothesis</h3><p>${escape(hunt.hypothesis)}</p>
    <p>${escape(hunt.expected_output)} ${escape(hunt.performance)}</p><ul>${hunt.considerations.map(x=>`<li>${escape(x)}</li>`).join("")}</ul></div>`;
  if (tab === "evidence") return `<div class="tab-body"><h3>Reviewed source evidence</h3>${hunt.evidence.map(ref =>
    `<p>${external(sourceNames[ref.source], ref.url)} · ${day(ref.published)} · ${neutral(ref.location)}<br>${neutral(ref.claim)}</p>`).join("")}
    <p>${escape(hunt.scope)}</p>${variant ? table(["Check","Result"], Object.entries(variant.validation).map(([key,value])=>[escape(key.replaceAll("_"," ")),escape(value)])) : ""}</div>`;
  if (tab === "related") return `<div class="tab-body">${related(data, hunt)}</div>`;
  if (tab === "revisions") return `<div class="tab-body">${revisionTable(hunt)}</div>`;
  const query = activeQuery(state);
  return `<div class="query-top">
      <div><h2>${escape(profile.target)} KQL</h2><p>${escape(profile.source)} · <code>${escape(variant.table)}</code></p></div>
      <div class="query-tools"><label class="select-wrap"><span class="sr-only">Query profile</span><select aria-label="Query profile" data-setting="profile">${profileOptions(data, state)}</select></label>
        <button class="btn inverted" type="button" data-action="copy-query">${icon("copy")} Copy KQL</button></div></div>
    <p class="query-requirement">${escape(profile.assumptions)} ${link("Data requirements",route("hunts",hunt.id,{tab:"environment"}))}</p>
    ${query ? `<div class="code-surface" aria-label="Complete KQL query"><pre tabindex="0">${query.trimEnd().split("\n").map((line, index) =>
      `<span class="code-line" data-line="${index+1}"><code>${escape(line)}</code></span>`).join("")}</pre></div>` :
      '<div class="empty" role="status">This profile cannot supply the required event fields. Query copy and downloads are unavailable for this selection.</div>'}
    <div class="query-options">
      <label class="select-wrap">Lookback <select aria-label="Lookback" data-setting="days" ${query ? "" : "disabled"}>${options(lookbacks.map(n=>[n,`${n} day${n === 1 ? "" : "s"}`]), preferences.days)}</select></label>
      <label class="checkbox"><input type="checkbox" data-setting="json"${preferences.json ? " checked" : ""}${query ? "" : " disabled"}> Single-row JSON output</label>
    </div>
    ${preferences.json && query ? '<p class="query-note">Aggregation shares engine memory and result-size limits. Your client may limit display of the JSON cell.</p>' : ""}
    <div class="query-bottom">
      <div><h3>Analyze in Sentinel</h3><div class="actions">${anchor("Explain the results to me",route("hunts",hunt.id,{tab:"explain"}),"info")}</div></div>
      <div><h3>Download</h3><div class="actions">
        <button class="btn" type="button" data-action="download-query" ${query ? "" : "disabled"}>${icon("download")} KQL (.kql)</button>
      </div></div></div>`;
}

function related(data, hunt) {
  const records = hunt.source_ids.map(id => data.records.find(row => row.id === id)).filter(Boolean);
  const technique = data.reference.find(x => x.id === hunt.technique);
  const indicators = data.indicators.filter(x => hunt.indicator_ids.includes(x.id));
  const rows = records.map(row => [route("intelligence", row.id), row.title, `Research · ${row.id} · ${row.published}`]);
  if (technique) rows.push([route("techniques", technique.id), technique.title, `Technique · ${technique.id}`]);
  if (indicators.length) rows.push([route("indicators",null,{hunt:hunt.id}), `Reported indicators (${indicators.length})`, "Indicators · Publisher-observed"]);
  const other = data.hunts.find(row => row.id !== hunt.id &&
    (hunt.research === "powershell-download" && row.research === "quick-assist" || row.research === "powershell-download" && hunt.research === "quick-assist"));
  if (other) rows.push([route("hunts", other.id), other.title, `Related hunt · ${other.id}`]);
  return rows.map(([href,title,details])=>`<a class="related-row" href="${href}">${icon("file")}<span>${neutral(title)}<small>${escape(details)}</small></span>${icon("external")}</a>`).join("");
}

function revisionTable(hunt) {
  return table(["Rev.","Date (UTC)","Change","Summary","Author"], [...hunt.history].reverse().map(row =>
    [row.revision, utc(row.date).replace(" UTC",""), badge(row.change), neutral(row.summary), "HuntForge"]), "timeline-table");
}

export function huntMain(data, state) {
  const {hunt} = state;
  const variant = hunt.variants[state.profile];
  const profile = profileBy(data,state.profile);
  const ordered = recentHunts(data.hunts);
  const position = ordered.findIndex(row => row.id === hunt.id);
  const following = state.preferences.followed.includes(hunt.id);
  const previous = ordered[position - 1];
  const next = ordered[position + 1];
  const tabLink = tab => route("hunts",hunt.id,{tab});
  return `<main id="main" tabindex="-1">
    <nav class="breadcrumb" aria-label="Breadcrumb"><a href="#/hunts">Hunts</a>${icon("chevron")}<span>Hunt Card</span>${icon("chevron")}<span>${escape(hunt.id)}</span>
      <span class="right-buttons">${previous ? anchor("← Prev",route("hunts",previous.id)) : '<button class="btn" disabled>← Prev</button>'}
      ${next ? anchor("Next →",route("hunts",next.id)) : '<button class="btn" disabled>Next →</button>'}</span></nav>
    <header class="hunt-hero"><div class="terminal-art" aria-hidden="true">&gt;_</div><div>
      <div class="hunt-meta"><span class="id-tag">HUNTFORGE / ${escape(hunt.id)}</span><span>${link("REV. " + hunt.revision,tabLink("revisions"))}</span>
        <span>PUBLISHED: ${day(hunt.published)}</span><span>UPDATED: ${day(hunt.updated)}</span>
        <span class="right-buttons"><button class="permalink" type="button" data-action="permalink">${icon("link")} Permanent URL</button>
        <button class="btn" type="button" data-action="follow" aria-pressed="${following}">${icon("star")} ${following ? "Following" : "Follow"}</button></span>
      </div><h1>${escape(hunt.title)}</h1><p>${neutral(hunt.description)}</p>
      <div class="chips">${link(hunt.technique,route("techniques",hunt.technique),"chip")}
        ${(hunt.cves || []).map(cve=>link(cve,route("vulnerabilities",null,{cve}),"chip")).join("")}
        ${link(hunt.tactic,route("hunts",null,{tactic:tacticKey(hunt.tactic)}),"chip")}
        ${link(profile.target,tabLink("environment"),"chip")}
        ${link("KQL",route("hunts",hunt.id),"chip")}</div>
    </div></header>
    <section class="hunt-facts" aria-label="Hunt summary">
      <div><span>INTELLIGENCE CONFIDENCE</span><strong>${link(hunt.confidence,tabLink("evidence"))}</strong>
        <small>Source published ${day(hunt.source_published || hunt.evidence[0]?.published)}</small></div>
      <div><span>QUERY VALIDATION</span><strong title="${escape(hunt.scope)}"><a href="${escape(tabLink("evidence"))}">${escape(variant ? validationNames[hunt.status] || hunt.status : "Incompatible")} ${icon("info")}</a></strong></div>
      <div><span>SUGGESTED LOOKBACK</span><strong>${variant ?
        `<button type="button" class="text-button" data-action="use-lookback" aria-label="Use suggested lookback of ${hunt.lookback} days">${hunt.lookback} days</button>` : `${hunt.lookback} days`}</strong></div>
      <div><span>REQUIRED TELEMETRY</span><strong>${link(variant?.table || "Missing capability",tabLink("environment"))}</strong></div>
    </section>
    <section class="query-workspace">
      <div class="tabs" role="tablist" aria-label="Hunt card sections">${huntTabs.map(([id,name]) => `<button type="button" data-tab="${id}" id="tab-${id}" role="tab" aria-selected="${state.tab === id}" aria-controls="hunt-panel" tabindex="${state.tab === id ? 0 : -1}">${name}${id === "revisions" ? ` · ${hunt.history.length}` : ""}</button>`).join("")}</div>
      <div id="hunt-panel" class="query-box" role="tabpanel" aria-labelledby="tab-${state.tab}">${tabPanel(data,state,variant)}</div>
    </section>
    <div class="hunt-context"><section>${section("Analyst Considerations","file")}
      <p>${neutral(hunt.hypothesis)} ${escape(hunt.expected_output)}</p>
      <ul>${hunt.considerations.map(x=>`<li>${neutral(x)}</li>`).join("")}</ul></section>
      <section>${section("Related Intelligence","link")}${related(data,hunt)}</section></div>
    <section class="revision-block"><div class="pager-link">${section("Revision History","history")}<a class="changes-link" href="#/changelog">View full changelog&nbsp; →</a></div>
      <div class="table-scroll">${revisionTable(hunt)}</div></section></main>`;
}
