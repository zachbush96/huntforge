const glyphs = {
  brief:'<path d="m5 12 7-7 7 7M7 10v9h4v-5h2v5h4v-9"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  search:'<circle cx="10" cy="10" r="6.5"/><path d="m15 15 6 6"/>',
  code:'<path d="m8 5-6 7 6 7m8-14 6 7-6 7m-3-15-2 16"/>',
  crosshair:'<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 2v5m0 10v5M2 12h5m10 0h5"/>',
  users:'<circle cx="10" cy="7" r="3"/><path d="M3 20v-2a7 7 0 0 1 14 0v2zm14-10a3 3 0 1 0 0-6m2 10a5 5 0 0 1 3 5v1h-3"/>',
  shield:'<path d="m12 2 9 4v6c0 5-4 8-9 10-5-2-9-5-9-10V6z"/>',
  bolt:'<path d="m14 2-9 12h6l-1 8 9-12h-6z" fill="currentColor" stroke="none"/>',
  database:'<ellipse cx="12" cy="5.5" rx="8" ry="3.5"/><path d="M4 6v12.5c0 2 4 3.5 8 3.5s8-1.5 8-3.5V6M4 12c0 2 4 3.5 8 3.5s8-1.5 8-3.5"/>',
  network:'<circle cx="12" cy="6" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/><path d="m10 9-3.5 6m7.5-6 3.5 6M8 18h8"/>',
  file:'<path d="M5 2h9l5 5v15H5zm9 0v6h5M8 12h8m-8 4h8"/>',
  book:'<path d="M12 5C8 2 4 3 2 4v15c3-1 7-1 10 2 3-3 7-3 10-2V4c-2-1-6-2-10 1v16"/>',
  history:'<path d="M3 10a9 9 0 1 1 1 7m-1-8V4m0 6h5m4-4v6l4 2"/>',
  box:'<path d="m12 2 9 5v10l-9 5-9-5V7zm0 10 9-5M3 7l9 5v10"/>',
  pulse:'<path d="M1 12h5l3-7 4 15 3-8h7"/>',
  layers:'<path d="m2 8 10-5 10 5-10 5zm0 4 10 5 10-5M2 16l10 5 10-5"/>',
  copy:'<rect x="8" y="7" width="12" height="15" rx="1"/><path d="M16 4V2H4v16h2"/>',
  download:'<path d="M12 2v13m-5-5 5 5 5-5M3 15v6h18v-6"/>',
  link:'<path d="m9 15 6-6m-5 9-2 2a4 4 0 0 1-6-6l5-5a4 4 0 0 1 5-.6m2-2 2-2a4 4 0 0 1 6 6l-5 5a4 4 0 0 1-5 .6"/>',
  message:'<path d="M4 3h16a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H9l-5 4v-4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm3 6h10M7 13h6"/>',
  external:'<path d="M12 4H4v16h16v-8M14 3h7v7m0-7L10 14"/>',
  check:'<path d="m4 12 5 5 11-11"/>',
  checked:'<path d="M3 3h18v18H3zm4 9 3 4 7-8"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 10v7m0-11v1"/>',
  star:'<path d="m12 2 3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z"/>',
  settings:'<path d="m9 3 1-2h4l1 2 1 1 3-.2 2 3-1 3v2l2 2-2 4-3-.2-2 1-1 3h-4l-1-3-2-1-3 .2-2-4 2-2v-2L3 7l2-3 3 .2z"/><circle cx="12" cy="11.5" r="3.2"/>',
  github:'<path stroke="none" fill="currentColor" d="M12 1.3a10.9 10.9 0 0 0-3.45 21.25c.55.1.75-.24.75-.53v-2.08c-3.06.64-3.7-1.3-3.7-1.3-.5-1.25-1.2-1.6-1.2-1.6-1-.68.08-.67.08-.67 1.1.08 1.68 1.13 1.68 1.13.98 1.67 2.56 1.2 3.2.91.09-.7.38-1.2.7-1.48-2.45-.28-5.02-1.2-5.02-5.43 0-1.2.43-2.18 1.13-2.95-.12-.28-.5-1.4.11-2.9 0 0 .93-.3 3.02 1.13a10.5 10.5 0 0 1 5.48 0c2.08-1.42 3-1.13 3-1.13.63 1.5.25 2.62.13 2.9.7.77 1.12 1.75 1.12 2.95 0 4.25-2.58 5.15-5.04 5.42.4.35.76 1.02.76 2.05v3.05c0 .29.2.63.76.53A10.9 10.9 0 0 0 12 1.3z"/>'
};

export const repo = "https://github.com/zachbush96/huntforge";
export const sourceNames = {
  "cisa-kev":"CISA KEV", "first-epss":"FIRST EPSS", "cisa-advisories":"CISA Advisories",
  "microsoft":"Microsoft Security", "ncsc":"UK NCSC", "mitre":"MITRE ATT&CK®",
  "cert-fr":"CERT-FR", "unit-42":"Unit 42", "cisco-talos":"Cisco Talos",
  "fbi-flash":"FBI FLASH / IC3", "google-threat-intelligence":"Google Threat Intelligence",
  "securelist":"Securelist", "dfir-report":"The DFIR Report", "shadowserver":"Shadowserver", "greynoise":"GreyNoise",
  "drupal":"Drupal Security Team", "ctir":"CTIR Gov", "gitlab":"GitLab Security", "volexity":"Volexity",
  "aws-security":"AWS Security", "optimizely":"Optimizely", "f6":"F6"
};

export function icon(name) {
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true">${glyphs[name] || glyphs.file}</svg>`;
}

export const anvil = '<svg class="anvil" viewBox="0 0 64 38" aria-hidden="true"><path fill="currentColor" d="M1 8h23V5h38v6l-9 5-12 1-4 6v5l10 4v3H19v-4l9-4v-6l-8-5H9l-8-5z"/></svg>';

export function escape(value = "") {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[char]);
}

export function neutral(value) {
  return escape(String(value ?? "").replace(/https?:\/\/[^\s<>]+/gi, url => url.replace(/^http/i, "hxxp").replaceAll(".", "[.]")));
}

export function safeExternal(value) {
  try {
    const url = new URL(value);
    const allowed = ["cisa.gov","www.cisa.gov","www.microsoft.com","www.ncsc.gov.uk","www.first.org","attack.mitre.org",
      "learn.microsoft.com","github.com","api.first.org","www.drupal.org","www.gov.br","docs.gitlab.com","www.volexity.com",
      "aws.amazon.com","pages.optimizely.com","www.f6.ru"];
    if (url.protocol === "https:" && allowed.includes(url.hostname) && !url.username && !url.password) return escape(url.href);
  } catch { /* Invalid publisher URL. */ }
  return "#";
}

export function hoursAgo(value) {
  if (!value) return "—";
  const minutes = Math.floor((Date.now() - Date.parse(value)) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ${minutes % 60}m ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}

export const day = value => value ? escape(value.slice(0, 10)) : "—";
export const utc = value => value ? escape(value.slice(0, 16).replace("T", " ") + " UTC") : "—";
export function route(section, id = null, filters = {}) {
  const params = new URLSearchParams(Object.entries(filters).filter(([,value]) => value));
  const query = params.toString();
  return `#/${section}${id ? "/" + encodeURIComponent(id) : ""}${query ? "?" + query : ""}`;
}
export const tacticKey = value => value.toLowerCase().replaceAll(" ", "-");
export const tacticName = value => value.split("-").map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(" ");
export const validationNames = {validated:"Validated", partially_validated:"Partially validated", unvalidated:"Unvalidated"};
export const profileBy = (data, id) => data.profiles.find(row => row.id === id);
export const queryMode = state => state.preferences.json ? "json" : "table";
export const activeQuery = state => state.hunt?.variants[state.profile]?.queries[String(state.preferences.days)]?.[queryMode(state)] || "";

export function badge(value, className = "chip") {
  return `<span class="${className}">${neutral(value)}</span>`;
}

export function link(text, href, className = "") {
  return `<a class="${className}" href="${escape(href)}">${neutral(text)}</a>`;
}

export function button(text, action, symbol, extra = "", disabled = false) {
  return `<button type="button" class="btn ${extra}" data-action="${action}"${disabled ? " disabled" : ""}>${symbol ? icon(symbol) : ""}${escape(text)}</button>`;
}

export function anchor(text, href, symbol, extra = "") {
  return `<a class="button ${extra}" href="${escape(href)}">${symbol ? icon(symbol) : ""}${neutral(text)}</a>`;
}

export function external(text, href) {
  const target = safeExternal(href);
  return target === "#" ? neutral(text) : `<a href="${target}" target="_blank" rel="noopener noreferrer">${neutral(text)} ${icon("external")}</a>`;
}

export function options(rows, active) {
  return rows.map(([id, label]) => `<option value="${escape(id)}"${id === active ? " selected" : ""}>${escape(label)}</option>`).join("");
}

export function table(headers, rows, className = "") {
  return `<table class="data-table ${className}">${headers.length ? `<thead><tr>${headers.map(header => `<th scope="col">${escape(header)}</th>`).join("")}</tr></thead>` : ""}<tbody>${rows.map(cells => `<tr>${cells.map(cell => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

export function bars(title, detail = "") {
  return `<h2 class="black-heading">${escape(title)}${detail}</h2>`;
}

export function section(title, symbol) {
  return `<h2 class="section-heading">${icon(symbol)} ${escape(title)}</h2>`;
}

const links = [
  ["brief","The Brief","brief","chevron"],["intelligence","Intelligence","layers","search"],["hunts","Hunts","crosshair","code"],
  ["adversaries","Adversaries","users","users"],["vulnerabilities","Vulnerabilities","bolt","shield"],["indicators","Indicators","database","database"],
  ["techniques","Techniques","network","network"],["research","Research","book","file"],["changelog","Changelog","history","history"],
  ["developers","Developers","code","box"],["status","System Status","pulse","pulse"]
];

export function header(data, brief) {
  return `<header class="topbar${brief ? "" : " compact-header"}">
    <a class="brand" href="#/brief" aria-label="HuntForge home">${brief ? anvil : ""}<span>HuntForge${brief ? "" : "_"}</span></a>
    <span class="brand-slash" aria-hidden="true">${brief ? "/" : "|"}</span>
    <div class="tagline">${brief ? "Autonomous Threat Intelligence<br>&amp; Detection Engineering<br>for Microsoft Sentinel" :
      "Threat Intelligence&nbsp; / &nbsp;Detection Engineering&nbsp; / &nbsp;Microsoft Sentinel"}</div>
    <div class="top-end">
      ${brief ? `<span class="top-box">v0.3.0</span><span class="top-divider"></span><span class="public">PUBLIC</span><span class="top-divider"></span>
        <button type="button" class="top-icon brief-search" aria-label="Search" data-action="search">${icon("search")}</button>` :
        `<button type="button" class="btn search-button" data-action="search" aria-label="Search hunts, actors, CVEs, indicators, techniques">${icon("search")}<span>Search Hunts, Actors, CVEs, Indicators, Techniques...</span><kbd>/</kbd></button><span class="top-divider"></span>`}
      <a class="top-link" href="${repo}" aria-label="GitHub repository">${icon("github")}${brief ? "<span>GitHub</span>" : ""}</a>
      <a class="top-link feedback-link" href="feedback.html" aria-label="Feedback" title="Feedback">${icon("message")}<span>Feedback</span></a>
      ${brief ? `<span class="top-divider"></span>${link("Last Update: " + utc(data.manifest.created), route("changelog"), "header-date")}` :
        '<a class="top-box api-link" href="#/developers">API</a><button type="button" class="top-icon" aria-label="Settings" data-action="settings">' + icon("settings") + "</button>"}
    </div>
  </header>`;
}

export function sidebar(state, data, brief, base = "") {
  const items = data?.changes.items ?? [];
  const huntChanges = items.filter(row => row.type === "hunt");
  return `<aside class="sidebar"><nav aria-label="Main navigation">${links.map(([id, text, glyph, briefGlyph]) =>
    `<a href="${base}${route(id)}"${state?.section === id ? ' aria-current="page"' : ""}>${icon(brief ? briefGlyph : glyph)}<span>${text}</span>
    ${data && !brief && id === "brief" ? `<span class="menu-badge">${data.manifest.counts.in_window}</span>` : ""}</a>`).join("")}</nav><div class="side-rule"></div>
    ${data && !brief ? `<div class="side-update"><strong>LATEST UPDATE</strong><time>${utc(data.manifest.created)}</time><dl>
      <dt>${link("New hunts",route("hunts",null,{change:"created"}))}</dt><dd>${huntChanges.filter(x => x.action === "created").length}</dd>
      <dt>${link("Updated",route("changelog",null,{change:"updated"}))}</dt><dd>${items.filter(x => x.action === "updated").length}</dd>
      <dt>${link("Retired",route("changelog",null,{change:"retired"}))}</dt><dd>${items.filter(x => x.action === "retired").length}</dd></dl>
      <a href="#/changelog">View changelog&nbsp; →</a></div>` : ""}
    <div class="side-art" aria-hidden="true"><i></i></div></aside>`;
}

export function pageSizes(section) {
  if (section === "brief") return [4,8,12,24];
  if (section === "changelog") return [25,50,100];
  return ["hunts","techniques","adversaries","indicators"].includes(section) ? [12,24,48,96] : [10,25,50,100];
}

export function resultWindow(length, state) {
  const size = state.pageSize;
  const page = Math.min(state.page,Math.max(0,Math.ceil(length/size)-1));
  return {page, size, start:page*size, end:(page+1)*size};
}

export function resultsToolbar(length, itemName, state, sort = false) {
  return `<div id="results" class="results-toolbar" tabindex="-1">
    <strong>${length.toLocaleString()} ${escape(itemName)}</strong>
    ${sort ? `<label>Sort by <select data-filter="sort" aria-label="Sort by">${options([
      ["","Default order"],["newest","Newest first"],["oldest","Oldest first"],["title","Name A–Z"]
    ],state.filters.sort || "")}</select></label>` : ""}
    <label>Results per page <select data-page-size aria-label="Results per page">${options(pageSizes(state.section).map(size=>[size,size]),state.pageSize)}</select></label>
  </div>`;
}

export function recentHunts(hunts) {
  return [...hunts].sort((a,b)=>(b.source_published || b.evidence[0]?.published || "").localeCompare(a.source_published || a.evidence[0]?.published || ""));
}

export function pagination(length, page, size, itemName) {
  const pages = Math.max(1, Math.ceil(length / size));
  const numbers = [...new Set([0, page - 1, page, page + 1, pages - 1])].filter(n => n >= 0 && n < pages).sort((a,b) => a-b);
  const pageButtons = numbers.map((n, index) =>
    `${index && n - numbers[index - 1] > 1 ? "…" : ""}<button type="button" data-page="${n}" ${n === page ? 'aria-current="page"' : ""} aria-label="Page ${n + 1}">${n + 1}</button>`).join("");
  return `<nav class="pagination" aria-label="Results pages"><span>${length ? `Showing ${page * size + 1}–${Math.min((page + 1) * size, length)} of ${length} ${itemName}` : `0 ${itemName}`}</span>
    ${page ? `<button type="button" data-page="${page-1}" aria-label="Previous page">‹</button>` : ""}${pageButtons}
    ${page + 1 < pages ? `<button type="button" data-page="${page+1}" aria-label="Next page">›</button>` : ""}</nav>`;
}
