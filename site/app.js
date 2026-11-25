import { briefAside, briefMain } from "./brief.js";
import { catalog, changelog, developers, entityDetail, intelligenceDetail, missing, systemStatus } from "./catalog.js";
import { huntAside, huntMain, huntTabs } from "./hunt.js";
import { activeQuery, escape, header, icon, neutral, queryMode, route, sidebar } from "./ui.js";
import { zip } from "./zip.js";

const app = document.querySelector("#app");
const announcer = document.querySelector("#announcer");
const searchDialog = document.querySelector("#search-dialog");
const settingsDialog = document.querySelector("#settings-dialog");
const copyDialog = document.querySelector("#copy-dialog");
const releaseIdPattern = /^hf-\d{8}-[0-9a-f]{12}$/;
const filterKeys = new Set(["q","severity","source","start","through","cve","tag","technique","tactic","malware",
  "validation","profile","freshness","category","indicatorType","hunt","change","recordType","following","sourceState","panel"]);
let data;
let navigation = 0;

function stored(key, fallback) {
  try { return JSON.parse(localStorage.getItem("huntforge:" + key)) ?? fallback; }
  catch { return fallback; }
}
function save(key,value) {
  try { localStorage.setItem("huntforge:" + key, JSON.stringify(value)); }
  catch { /* Preferences remain active for the browser session. */ }
}
const saved = stored("preferences", {});
const state = {
  section:"brief", id:null, tab:"query", page:0, filters:{}, hunt:null, detail:null, error:false,
  profile:null, pack:new Set(), preferences:{json:saved?.json === true, days:[1,3,7,14,30].includes(saved?.days) ? saved.days : 7,
    profiles:saved?.profiles && typeof saved.profiles === "object" ? saved.profiles : {}, followed:Array.isArray(saved?.followed) ? saved.followed : []},
  previousVisit:stored("last-release", null)
};

async function retrieve(path, expected) {
  const response = await fetch(path, {cache: path.endsWith("/latest.json") ? "no-cache" : "default"});
  if (!response.ok) throw new Error(`Release file returned HTTP ${response.status}`);
  const result = await response.json();
  if (result.schema_version !== 1 || (expected && result.release_id !== expected)) throw new Error("Release metadata differs");
  return result;
}

async function load() {
  const latest = await retrieve("api/v1/latest.json");
  if (!releaseIdPattern.test(latest.release_id)) throw new Error("Invalid release identifier");
  const base = `api/v1/releases/${latest.release_id}/`;
  const get = path => retrieve(base + path, latest.release_id);
  const [manifest,intelligence,hunts,indicators,profiles,reference,search,report,changes,history] = await Promise.all([
    get("manifest.json"),get("intelligence/index.json"),get("hunts/index.json"),get("indicators/index.json"),get("profiles/index.json"),
    get("reference/index.json"),get("search.json"),get("report.json"),get("changes.json"),retrieve("api/v1/history.json")
  ]);
  data = {
    manifest, base, get, records:intelligence.items, hunts:hunts.items, indicators:indicators.items, profiles:profiles.items,
    reference:reference.items, referenceVersion:reference.version, search:search.items, report, changes,
    history:history.items.filter(row => releaseIdPattern.test(row.release_id)), text:new Map(search.items.map(row=>[row.id,row.text])),
    cards:new Map()
  };
  save("last-release", manifest.release_id);
  await navigate();
}

function huntCard(id) {
  if (!data.cards.has(id)) data.cards.set(id,data.get("hunts/" + encodeURIComponent(id) + ".json").catch(error=>{
    data.cards.delete(id);
    throw error;
  }));
  return data.cards.get(id);
}

function readRoute() {
  const url = location.hash.startsWith("#/") ? location.hash.slice(2) : "";
  const split = url.indexOf("?");
  const [section,id] = (split < 0 ? url : url.slice(0,split)).split("/");
  const params = new URLSearchParams(split < 0 ? "" : url.slice(split+1));
  const filters = Object.fromEntries([...params].filter(([key,value]) => filterKeys.has(key) && value));
  const tab = params.get("tab");
  let recordId = null;
  try { recordId = id ? decodeURIComponent(id) : null; }
  catch { /* A malformed ID has no detail route. */ }
  return {section:section || "brief",id:recordId,filters,tab:huntTabs.some(([key])=>key===tab) ? tab : "query"};
}

function stateRoute() {
  const filters = {...state.filters};
  if (state.hunt && state.tab !== "query") filters.tab = state.tab;
  return route(state.section,state.id,filters);
}

function syncRoute() {
  history.replaceState(null,"",stateRoute());
}

async function comparison() {
  const prior = data.history.findIndex(row=>row.release_id===state.previousVisit);
  if (prior < 0) return [];
  const relevant = data.history.slice(0,prior);
  const changes = await Promise.all(relevant.map(row=>row.release_id === data.manifest.release_id ? data.changes :
    retrieve(`api/v1/releases/${row.release_id}/changes.json`,row.release_id)));
  const newest = new Map();
  for (const set of changes) for (const row of set.items) if (!newest.has(row.id)) newest.set(row.id,row);
  return [...newest.values()];
}

async function navigate() {
  if (!data || location.hash === "#main") return;
  const sequence = ++navigation;
  const {section,id,filters,tab} = readRoute();
  Object.assign(state,{section,id,page:0,filters,hunt:null,detail:null,error:false,tab,profile:null});
  let hunt, detail;
  try {
    if (section === "hunts" && id && data.hunts.some(row => row.id === id)) hunt = await huntCard(id);
    if (["intelligence","research","vulnerabilities"].includes(section) && id && data.records.some(row=>row.id===id)) {
      detail = await data.get("intelligence/" + encodeURIComponent(id) + ".json");
    }
    if (section === "indicators" && id) detail = data.indicators.find(x=>x.id===id);
    if (section === "techniques" && id) detail = data.reference.find(x=>x.type==="attack-pattern" && x.id===id);
    if (section === "adversaries" && id) detail = data.reference.find(x=>x.type!=="attack-pattern" && x.id===id);
    if (section === "changelog" && id === "since-last-visit") detail = {release_id: "comparison since last visit",items:await comparison()};
    if (section === "changelog" && data.history.some(row=>row.release_id===id)) {
      detail = await retrieve(`api/v1/releases/${id}/changes.json`,id);
    }
  } catch {
    if (sequence === navigation) state.error = true;
  }
  if (sequence !== navigation) return;
  state.hunt = hunt;
  state.detail = detail;
  if (hunt) {
    const preferred = state.preferences.profiles[hunt.id];
    state.profile = data.profiles.some(row=>row.id===preferred) ? preferred : hunt.profiles[0];
  }
  render();
  if (sequence > 1) {
    window.scrollTo(0,0);
    document.querySelector("#main")?.focus({preventScroll:true});
  }
}

function render(preserve = null) {
  const brief = state.section === "brief";
  let main;
  let aside = "";
  if (brief) {
    main = briefMain(data,state);
    aside = briefAside(data);
  } else if (state.hunt) {
    main = huntMain(data,state);
    aside = huntAside(data,state);
  } else if (state.id && !state.detail) main = missing(data,state);
  else if (["intelligence","research","vulnerabilities"].includes(state.section) && state.detail) main = intelligenceDetail(data,state);
  else if (["indicators","techniques","adversaries"].includes(state.section) && state.detail) main = entityDetail(data,state);
  else if (state.section === "changelog") main = changelog(data,state);
  else if (state.section === "status") main = systemStatus(data,state);
  else if (state.section === "developers") main = developers(data);
  else if (["intelligence","hunts","adversaries","vulnerabilities","indicators","techniques","research"].includes(state.section)) main = catalog(data,state);
  else main = missing(data,state);
  app.innerHTML = header(data,brief) + `<div class="layout${brief ? "" : " compact"}${state.hunt ? " hunt" : ""}">${sidebar(state,data,brief)}${main}${aside}</div>`;
  document.title = `HuntForge — ${app.querySelector("h1")?.textContent || "Threat Intelligence"}`;
  if (preserve) {
    const control = document.querySelector(preserve.selector);
    control?.focus({preventScroll:true});
    if (control?.type === "search" && preserve.cursor != null) control.setSelectionRange(preserve.cursor,preserve.cursor);
  }
}

function setPreference(key,value,selector) {
  if (key === "profile" && state.hunt) {
    state.profile = value;
    state.preferences.profiles[state.hunt.id] = value;
  } else state.preferences[key] = value;
  save("preferences",state.preferences);
  render(selector ? {selector} : null);
}

function announce(message) {
  announcer.textContent = "";
  requestAnimationFrame(()=>{ announcer.textContent = message; });
}

function showSearch() {
  searchDialog.innerHTML = `<form method="dialog"><button class="btn close">Close</button></form><h2 id="search-title">Search HuntForge</h2>
    <label class="sr-only" for="global-search">Search public release</label><input type="search" id="global-search" placeholder="Hunt title, indicator, CVE, technique or KQL…">
    <div id="global-results" class="search-list"></div>`;
  searchDialog.showModal();
  searchDialog.querySelector("input").focus();
  showResults("");
}

function showResults(value) {
  const terms = value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const rows = data.search.filter(row=>terms.every(term=>row.text.includes(term))).sort((a,b)=>{
    const rank = row => (row.kind === "hunt" ? 10 : row.kind === "intelligence" ? 5 : 0) + (terms.length && row.title.toLowerCase().includes(terms[0]) ? 20 : 0);
    return rank(b)-rank(a);
  }).slice(0,12);
  const routes = {hunt:"hunts",intelligence:"intelligence",indicator:"indicators",adversary:"adversaries",technique:"techniques"};
  document.querySelector("#global-results").innerHTML = rows.map(row=>
    `<a href="${route(routes[row.kind],row.id)}"><small>${escape(row.kind)}</small><span>${neutral(row.title)}</span></a>`).join("") ||
    '<p class="empty" role="status">No matching results.</p>';
}

function showSettings() {
  settingsDialog.innerHTML = `<form method="dialog"><button class="btn close">Close</button></form><h2 id="settings-title">Output preferences</h2>
    <p><label class="checkbox"><input type="checkbox" data-setting="json" ${state.preferences.json ? "checked" : ""}> Single-row JSON output</label></p>
    <p>Applies to supported queries, copies and downloads. This preference is stored in this browser.</p>`;
  settingsDialog.showModal();
}

async function copy(value,label) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    announce(`${label} copied.`);
    const focused = document.activeElement;
    if (focused?.matches("[data-action=copy-query], [data-copy-url]") && !focused.hasAttribute("data-copied")) {
      const original = focused.innerHTML;
      focused.setAttribute("data-copied","");
      focused.innerHTML = icon("check") + " Copied";
      setTimeout(()=>{
        if (!focused.isConnected) return;
        focused.innerHTML = original;
        focused.removeAttribute("data-copied");
      },1800);
    }
  } catch {
    copyDialog.innerHTML = `<form method="dialog"><button class="btn close">Close</button></form><h2 id="copy-title">${escape(label)}</h2>
      <p>Manual copy. The complete value is selected below.</p><textarea readonly aria-label="${escape(label)}"></textarea>`;
    const area = copyDialog.querySelector("textarea");
    area.value = value;
    copyDialog.showModal();
    area.select();
  }
}

function download(blob, filename) {
  const href = URL.createObjectURL(blob);
  const element = document.createElement("a");
  element.href = href;
  element.download = filename;
  document.body.append(element);
  element.click();
  element.remove();
  setTimeout(()=>URL.revokeObjectURL(href),2000);
}

function exportName(hunt,profile,days,mode) {
  return `${hunt.id}-r${hunt.revision}-${profile}-${days}d-${mode}.kql`;
}

async function pack(huntIds) {
  if (!huntIds.length) {
    announce("Select a hunt to download.");
    return;
  }
  try {
    const hunts = await Promise.all(huntIds.map(huntCard));
    const files = {"README.txt":"Run each .kql file as a separate query in the documented execution target.\n"};
    const metadata = [];
    const mode = queryMode(state);
    const days = state.preferences.days;
    for (const hunt of hunts) {
      const preferred = state.preferences.profiles[hunt.id];
      const profile = hunt.variants[preferred] ? preferred : hunt.profiles[0];
      const variant = hunt.variants[profile];
      const filename = exportName(hunt,profile,days,mode);
      files[filename] = variant.queries[String(days)][mode];
      metadata.push({id:hunt.id,revision:hunt.revision,profile,lookback_days:days,output:mode,file:filename,
        target:data.profiles.find(row=>row.id===profile).target,evidence:hunt.evidence,validation:variant.validation});
    }
    files["manifest.json"] = JSON.stringify({schema_version:1,release_id:data.manifest.release_id,queries:metadata},null,2)+"\n";
    download(zip(files), `HuntForge-${hunts.length > 1 ? data.manifest.release_id : hunts[0].id}-pack.zip`);
    announce(`Downloaded ${hunts.length} separate KQL quer${hunts.length===1 ? "y" : "ies"}.`);
  } catch { announce("The hunt pack could not be prepared. Try again."); }
}

app.addEventListener("click", event=>{
  const control = event.target.closest("button");
  if (!control || !data) return;
  if (control.dataset.copyUrl) {
    copy(new URL(control.dataset.copyUrl,document.baseURI).href,"API URL");
    return;
  }
  if (control.dataset.page != null) {
    state.page = Number(control.dataset.page);
    render({selector:`[data-page="${state.page}"]`});
  }
  if (control.dataset.tab) {
    state.tab = control.dataset.tab;
    syncRoute();
    render({selector:`[data-tab="${state.tab}"]`});
  }
  if (control.dataset.setProfile) setPreference("profile",control.dataset.setProfile,`[data-set-profile="${control.dataset.setProfile}"]`);
  const actions = {
    search:showSearch, settings:showSettings,
    "clear-filters":()=>{
      state.filters={};
      state.page=0;
      syncRoute();
      render({selector:"[data-filter]"});
    },
    "copy-query":()=>copy(activeQuery(state),"KQL"),
    "copy-indicator":()=>copy(state.detail?.value,"Canonical indicator"),
    permalink:()=>copy(new URL(stateRoute(),location.href).href,"Hunt permalink"),
    "use-lookback":()=>{
      state.tab = "query";
      syncRoute();
      setPreference("days",state.hunt.lookback,"[data-setting=days]");
    },
    follow:()=>{
      const id = state.hunt.id;
      setPreference("followed",state.preferences.followed.includes(id) ? state.preferences.followed.filter(value=>value!==id) :
        [...state.preferences.followed,id],"[data-action=follow]");
    },
    "download-query":()=>{
      const query=activeQuery(state);
      if (query) download(new Blob([query],{type:"text/plain;charset=utf-8"}),exportName(state.hunt,state.profile,state.preferences.days,queryMode(state)));
    },
    "pack-current":()=>pack([state.hunt.id]),"pack-selected":()=>pack([...state.pack]),
    retry:()=>location.reload()
  };
  actions[control.dataset.action]?.();
});

function handleFilter(control) {
  const key = control.dataset.filter;
  state.filters[key] = control.value;
  if (!control.value) delete state.filters[key];
  state.page = 0;
  syncRoute();
  render({selector:`[data-filter="${key}"]`,cursor:control.type === "search" ? control.selectionStart : null});
}
app.addEventListener("input",event=>{
  if (event.target.matches("input[type=search][data-filter]")) handleFilter(event.target);
});
app.addEventListener("change",event=>{
  const control = event.target;
  if (control.matches("[data-filter]:not(input[type=search])")) handleFilter(control);
  if (control.dataset.setting) {
    const key = control.dataset.setting;
    const selector = control.closest("aside") ? `aside [data-setting="${key}"]` : `main [data-setting="${key}"]`;
    const value = key === "json" ? control.checked : key === "days" ? Number(control.value) : control.value;
    setPreference(key,value,selector);
  }
  if (control.dataset.packId) {
    if (control.checked) state.pack.add(control.dataset.packId);
    else state.pack.delete(control.dataset.packId);
    const packButton = app.querySelector("[data-action=pack-selected]");
    if (packButton) packButton.innerHTML = icon("download") + `Download selected (${state.pack.size})`;
  }
});
app.addEventListener("submit",event=>{
  if (event.target.matches(".filters")) event.preventDefault();
});
searchDialog.addEventListener("input",event=>{ if (event.target.type === "search") showResults(event.target.value); });
searchDialog.addEventListener("click",event=>{ if (event.target.closest("a")) searchDialog.close(); });
settingsDialog.addEventListener("change",event=>{ if (event.target.dataset.setting === "json") setPreference("json",event.target.checked); });
document.addEventListener("keydown",event=>{
  if (!data) return;
  if (event.key === "/" && !event.altKey && !event.ctrlKey && !event.metaKey && !document.querySelector("dialog[open]") &&
      !event.target.closest("input,select,textarea,[contenteditable]")) {
    event.preventDefault();
    showSearch();
  }
  if (event.target.matches("[role=tab]") && ["ArrowRight","ArrowLeft","Home","End"].includes(event.key)) {
    const tabs = [...app.querySelectorAll("[role=tab]")];
    const position = tabs.indexOf(event.target);
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 :
      (position + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    event.preventDefault();
    tabs[next].click();
  }
});
document.querySelector(".skip").addEventListener("click",event=>{
  event.preventDefault();
  document.querySelector("#main")?.focus();
});
window.addEventListener("hashchange",navigate);
load().catch(()=>{
  app.innerHTML = '<main id="main" class="loading" tabindex="-1"><strong>HuntForge_</strong><p>The public release could not be loaded.</p><button class="btn" type="button" id="retry">Retry</button></main>';
  app.querySelector("#retry").onclick = ()=>location.reload();
});
