"use strict";
const $ = (s, r = document) => r.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
const CASE = window.__CASE__ || "";
const FOLDER = window.__FOLDER__ || CASE;
const FACE_STRONG = 0.65;
let DATA = null;
let DFSTATUS = {};
let DISPUTED = new Set();

async function boot() {
  if (window.__DATA__) { DATA = window.__DATA__; }
  else {
    try { DATA = await (await fetch(`/api/case/${encodeURIComponent(FOLDER)}`)).json(); }
    catch (e) { document.body.innerHTML = "<p style='padding:20px'>case data could not be loaded.</p>"; return; }
  }
  refreshDeepFace();
  for (const fn of [renderIdentity, renderMap, renderVisual, renderContext]) {
    try { fn(); } catch (e) { console.error(fn.name, e); }
  }
}

// ---- LEFT: identity ----
function renderIdentity() {
  const b = $("#identity .body"); b.innerHTML = "";
  const st = DATA.stats || {};
  const total = (DATA.accounts || []).length;
  const cards = [["accounts", st.accounts || total, ""], ["verified", st.verified, "ok"],
    ["undecided", st.undecided, "warn"], ["missing", st.dead, "bad"]];
  const cw = el("div", "cards");
  cards.forEach(([l, n, c]) => cw.appendChild(el("div", "card " + c, `<div class='n'>${n ?? 0}</div><div class='l'>${l}</div>`)));
  b.appendChild(cw);

  const seeds = DATA.seeds || {};
  const seedLine = ["names", "usernames", "emails", "phones", "domains"]
    .filter(k => (seeds[k] || []).length)
    .map(k => (seeds[k]).map(v => `<span class='tag info' data-seed='${esc(v)}'>${esc(v)}</span>`).join(""))
    .join("");
  if (seedLine) { b.appendChild(el("h3", null, "Search cores")); b.appendChild(el("div", null, seedLine)); }

  b.appendChild(el("h3", null, "Verified accounts"));
  const accts = (DATA.accounts || []).filter(a => a.state === "verified");
  if (!accts.length) b.appendChild(el("p", "mut", "No verified accounts."));
  accts.forEach(a => {
    const row = el("div", "acct");
    const tags = (a.via || []).map(v => `<span class='tag'>${esc(v)}</span>`);
    if (a.photo_group) tags.push(`<span class='tag ${a.photo_tier === "strong" ? "ok" : "warn"}'>photo #${a.photo_group}</span>`);
    if (a.face_group) tags.push(`<span class='tag ok'>face #${a.face_group}</span>`);
    if (a.face_match) tags.push(`<span class='tag ${a.face_match >= FACE_STRONG ? "ok" : "warn"}'>ref face ${a.face_match.toFixed(2)}</span>`);
    const dfs = DFSTATUS[a.url] || a.deepface_status;
    if (dfs) tags.push(dfTag(dfs, a.deepface_models));
    if (dfs === "disputed") row.classList.add("disputed");
    row.innerHTML =
      (a.avatar ? `<img src="${esc(a.avatar)}" alt="">` : `<div class='noav'></div>`) +
      `<div><div class='nm'><a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.display_name || a.site)}</a></div>` +
      `<div class='u'>${esc(a.site)} · @${esc(a.user)}</div></div>` +
      `<div>${tags.join("")}</div>`;
    b.appendChild(row);
  });

  const emails = DATA.email || {};
  if (Object.values(emails).some(r => (r.holehe?.used || []).length)) {
    b.appendChild(el("h3", null, "E-mail registrations"));
    Object.entries(emails).forEach(([e, r]) => {
      const used = r.holehe?.used || [];
      if (used.length) b.appendChild(el("div", null, `<div class='mono'>${esc(e)}</div>` +
        used.map(s => `<span class='tag'>${esc(s)}</span>`).join("")));
    });
  }

  const eg = DATA.opsec?.egress || {};
  b.appendChild(el("h3", null, "OPSEC · your exit"));
  const changed = DATA.opsec?.egress_changed, rotated = DATA.opsec?.egress_rotated;
  // a rotated Tor circuit is normal; only a change of route is a lost exit
  const held = changed ? "<span class='tag bad'>ROUTE CHANGED</span>"
    : rotated ? "<span class='tag ok'>held</span> <span class='mut'>address rotated</span>"
      : "<span class='tag ok'>unchanged</span>";
  b.appendChild(el("div", "kv",
    `<div>Route</div><div><span class='tag ${eg.mullvad || eg.tor ? "ok" : "bad"}'>${eg.mullvad ? "Mullvad" : eg.tor ? "Tor" : "direct"}</span> ${esc(eg.ip || "")}</div>` +
    `<div>Held to end</div><div>${held}</div>` +
    `<div>Kill-switch</div><div>${esc(DATA.opsec?.lockdown ?? "n/a")}</div>`));
}

// ---- MIDDLE: map + feeds ----
let MAP, MARKERS, GIBS;
function renderMap() {
  MAP = L.map("map", { zoomControl: true, attributionControl: false }).setView([39, 35], 3);
  const osm = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19 });
  GIBS = L.tileLayer(gibsUrl($("#gibsdate").value || new Date().toISOString().slice(0, 10)),
    { maxZoom: 9, minZoom: 1, bounds: [[-85, -180], [85, 180]] });
  osm.addTo(MAP);
  L.control.layers({ "OpenStreetMap": osm, "NASA GIBS (satellite, daily)": GIBS }, null, { collapsed: false }).addTo(MAP);
  MARKERS = L.layerGroup().addTo(MAP);
  plotPoints();
  // the layer control keeps its own registry, so swap the URL instead of the layer object
  $("#gibsdate").addEventListener("change", () => GIBS.setUrl(gibsUrl($("#gibsdate").value)));
  $("#sentbtn").addEventListener("click", runSentinel);
}
function gibsUrl(day) {
  return `https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/MODIS_Terra_CorrectedReflectance_TrueColor/default/${day}/GoogleMapsCompatible_Level9/{z}/{y}/{x}.jpg`;
}
function coordPoints() { return (DATA.geo || []).filter(p => p.lat != null && p.lon != null); }
function plotPoints() {
  MARKERS.clearLayers();
  const pts = DATA.geo || [];
  const withCoords = coordPoints();
  withCoords.forEach(p => {
    L.marker([p.lat, p.lon]).addTo(MARKERS)
      .bindPopup(`<b>${esc(p.kind)}</b><br>${esc(p.label)}<br><span class='mut'>${esc(p.when || p.detail || "")}</span><br><span class='mut'>src: ${esc(p.source)}</span>`);
  });
  if (withCoords.length) MAP.fitBounds(withCoords.map(p => [p.lat, p.lon]), { maxZoom: 12, padding: [40, 40] });
  const nonCoord = pts.filter(p => p.lat == null);
  const info = $("#geoinfo"); info.innerHTML = "";
  if (nonCoord.length) info.appendChild(el("div", "note",
    "Country-only (no coordinate): " + nonCoord.map(p => `${esc(p.kind)} ${esc(p.country || p.detail || "")}`).join(" · ")));
  if (!withCoords.length) info.appendChild(el("div", "note",
    "No GPS coordinates in this case. A photo with EXIF GPS (file:) places a precise pin."));
}
async function runSentinel() {
  const pts = coordPoints();
  const c = pts.length ? { lat: pts[0].lat, lon: pts[0].lon } : (() => { const m = MAP.getCenter(); return { lat: m.lat, lon: m.lng }; })();
  const info = $("#geoinfo");
  const box = el("div", "note", `querying Sentinel-2 around ${c.lat.toFixed(3)}, ${c.lon.toFixed(3)}…`);
  info.appendChild(box);
  try {
    const r = await (await fetch(`/api/sentinel?lat=${c.lat}&lon=${c.lon}&days=30`)).json();
    if (r.skipped || r.error) { box.textContent = r.skipped || r.error; return; }
    const items = r.items || [];
    if (!items.length) { box.textContent = "No Sentinel-2 scene with < 40 % cloud in the last 30 days."; return; }
    box.innerHTML = "<b>Sentinel-2 quicklooks</b> (10 m: terrain and buildings, never people)<br>" +
      items.map(i => `<div class='item'>${i.quicklook ? `<a href="${esc(i.quicklook)}" target="_blank" rel="noopener">${esc((i.datetime || "").slice(0, 10))}</a>` : esc((i.datetime || "").slice(0, 10))}` +
        ` <span class='m'>cloud ${i.cloud ?? "?"} % · ${esc(i.id || "")}</span></div>`).join("");
  } catch (e) { box.textContent = "Sentinel request failed."; }
}
async function runGdelt() {
  const q = $("#gq").value.trim(); if (!q) return;
  const box = $("#feed"); box.innerHTML = "<div class='mut'>querying GDELT (one query per 5 s)…</div>";
  try {
    const r = await (await fetch(`/api/gdelt?q=${encodeURIComponent(q)}`)).json();
    box.innerHTML = "";
    if (r.error) { box.innerHTML = `<div class='note'>${esc(r.error)}</div>`; return; }
    const arts = r.articles || [];
    if (!arts.length) { box.innerHTML = "<div class='mut'>No news mentions in the last week. Expected for a private person; useful for an organisation or domain.</div>"; return; }
    arts.slice(0, 25).forEach(a => box.appendChild(el("div", "item",
      `<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.title || a.url)}</a>` +
      `<div class='m'>${esc(a.seendate || "")} · ${esc(a.sourcecountry || "")} · ${esc(a.domain || "")}</div>`)));
  } catch (e) { box.innerHTML = "<div class='mut'>GDELT request failed.</div>"; }
}
async function runTelegram(q = $("#tq").value.trim()) {
  const box = $("#tfeed"); box.innerHTML = "<div class='mut'>querying Telegram…</div>";
  try {
    const r = await (await fetch(`/api/telegram?q=${encodeURIComponent(q)}&case=${encodeURIComponent(FOLDER)}`)).json();
    box.innerHTML = "";
    const hits = r.listener || [];
    if (hits.length) {
      box.appendChild(el("div", "mut", `${hits.length} listener hit(s) in telegram.jsonl`));
      hits.forEach(m => box.appendChild(el("div", "item",
        `<span class='tag warn'>${esc((m.hit || []).join(", "))}</span> ${esc(m.channel)} ${esc((m.text || "").slice(0, 160))}<div class='m'>${esc(m.when || "")}</div>`)));
    }
    if (r.error) { box.appendChild(el("div", "note", esc(r.error))); return; }
    const msgs = r.messages || [];
    if (r.scope) box.appendChild(el("div", "mut", `search scope: ${esc(r.scope.join(", "))}`));
    if (!msgs.length) { box.appendChild(el("div", "mut", "No messages matched.")); return; }
    msgs.slice(0, 25).forEach(m => box.appendChild(el("div", "item",
      (m.link ? `<a href="${esc(m.link)}" target="_blank" rel="noopener">${esc(m.chat)}</a>` : `<b>${esc(m.chat)}</b>`) +
      ` ${esc((m.text || "").slice(0, 160))}<div class='m'>${esc(m.date || "")}</div>`)));
  } catch (e) { box.innerHTML = "<div class='mut'>Telegram request failed.</div>"; }
}

// ---- RIGHT: visual ----
// DeepFace verdicts reach us two ways: baked into the export by a --deepface scan, or as
// deepface_confirms in a sidecar a dashboard run wrote. The sidecar is the fresher of the two.
// Same rule as the scanner: one confirmation anywhere clears a picture, so a photo matched to
// the reference is not marked because some other pairing was refused.
function dfStatusByUrl() {
  const v = DATA.vision || {};
  const confirms = v.deepface_confirms || [];
  const out = {};
  if (confirms.length) {
    // acct:<i> and cover:<i> share a url but are different photographs, so a cover verdict
    // must not decide the avatar's status. Only avatar verdicts are folded here.
    const byKey = {};
    (v.images || []).forEach(i => { if (i.url && /^acct:/.test(i.key)) byKey[i.key] = i.url; });
    const seen = {};
    confirms.forEach(c => [c.a, c.b].forEach(k => {
      const u = byKey[k];
      if (u) (seen[u] || (seen[u] = new Set())).add(c.status);
    }));
    Object.entries(seen).forEach(([u, st]) => {
      out[u] = st.has("confirmed") ? "confirmed" : st.has("disputed") ? "disputed" : "abstained";
    });
  } else {
    (DATA.accounts || []).forEach(a => { if (a.url && a.deepface_status) out[a.url] = a.deepface_status; });
  }
  return out;
}
// A picture the scan already stamped carries the mark inside the JPEG; do not band it twice.
function needsBand(url) {
  const a = (DATA.accounts || []).find(x => x.url === url);
  return !(a && a.deepface_marked);
}
function refreshDeepFace() {
  DFSTATUS = dfStatusByUrl();
  DISPUTED = new Set(Object.entries(DFSTATUS).filter(([, v]) => v === "disputed").map(([u]) => u));
}
function dfTag(status, models) {
  if (status === "confirmed") return `<span class='df ok'>DeepFace confirms</span>`;
  if (status === "abstained") return `<span class='df na'>DeepFace saw no face</span>`;
  if (status !== "disputed") return "";
  const which = (models || []).filter(r => !r.verified).map(r => r.model).join(", ");
  return `<span class='df'>DeepFace does not confirm${which ? " (" + esc(which) + ")" : ""}</span>`;
}
function tierTag(m) {
  const t = m.tier, s = m.score || 0;
  if (t === "strong") return "<span class='tag ok'>byte-identical</span>";
  if (t === "face") return `<span class='tag ${s >= FACE_STRONG ? "ok" : "warn"}'>face ${s.toFixed(2)}</span>`;
  if (t === "similar") return `<span class='tag warn'>CLIP ${s.toFixed(2)}</span>`;
  return "<span class='tag warn'>perceptual</span>";
}
function avatarFor(url) {
  const a = (DATA.accounts || []).find(x => x.url === url);
  return a && a.avatar ? `<img src="${esc(a.avatar)}" alt="">` : "";
}
function renderVisual() {
  const b = $("#visual .body"); b.innerHTML = "";
  const accts = DATA.accounts || [];
  const refs = DATA.target_images || [];

  b.appendChild(el("div", "vis-head", `<h3>1 · Reference images</h3><span class="tag ${refs.length ? "ok" : "info"}">${refs.length} given</span>`));
  if (!refs.length) {
    b.appendChild(el("div", "note", `No reference photo in this case. <a href="/new" style="color:var(--acc)">Start a scan with photos</a> to match them against the profile pictures found.`));
  }
  refs.forEach((ti, idx) => {
    const card = el("div", "group ref");
    const thumb = ti.thumb ? `<img class="th" src="${esc(ti.thumb)}" alt="">` : "";
    const matches = ti.matches || [];
    let body = `<div style="overflow:hidden">${thumb}<div><b>${esc(ti.filename || "reference " + (idx + 1))}</b>` +
      `<div class="mut" style="font-size:11px">${esc(ti.dimensions || "")}${ti.sha256 ? " · sha256 " + esc(ti.sha256.slice(0, 12)) + "…" : ""}</div>` +
      (ti.error ? `<div class="tag bad">${esc(ti.error)}</div>` : "") + `</div></div>`;
    if (matches.length) {
      body += `<div style="margin-top:8px;padding-top:8px;border-top:1px dashed var(--line)"><div class="mut" style="font-size:11px;margin-bottom:4px">matched accounts (${matches.length})</div>` +
        matches.map(m => `<div class="m">${avatarFor(m.url)}<a href="${esc(m.url || "#")}" target="_blank" rel="noopener">${esc(m.site || "?")}</a><span class="mut mono">@${esc(m.user || "")}</span>${tierTag(m)}${dfTag(m.deepface_status || "", m.deepface_models)}` +
          (m.face_score && m.kind !== "face" ? `<span class="mut">face ${m.face_score.toFixed(2)}</span>` : "") +
          (m.clip_score && m.kind !== "clip" ? `<span class="mut">CLIP ${m.clip_score.toFixed(2)}</span>` : "") + `</div>`).join("") + `</div>`;
    } else if (!ti.error) {
      body += `<div class="mut" style="font-size:11px;margin-top:6px">No profile picture matched this photo.</div>`;
    }
    if (ti.reverse_links && ti.reverse_links.length) {
      body += `<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;align-items:center"><span class="mut" style="font-size:11px">reverse search:</span>` +
        ti.reverse_links.map(l => { const [n, u] = Array.isArray(l) ? l : [l.engine, l.url]; return `<a href="${esc(u)}" target="_blank" rel="noopener" class="tag" style="text-decoration:none;color:var(--acc)">${esc(n)} ↗</a>`; }).join("") + `</div>`;
    }
    card.innerHTML = body;
    b.appendChild(card);
  });

  b.appendChild(el("div", "vis-head", `<h3>2 · Captured pictures</h3>`));
  const withPic = accts.filter(a => a.avatar);
  const groups = {};
  accts.forEach(a => { if (a.photo_group) (groups[a.photo_group] ||= []).push(a); });
  if (Object.keys(groups).length) {
    b.appendChild(el("h3", null, "Same-photo groups"));
    Object.entries(groups).forEach(([g, members]) => {
      const tier = members[0].photo_tier || "possible";
      const wrap = el("div", "group");
      wrap.appendChild(el("div", "t", `<span class='tag ${tier === "strong" ? "ok" : "warn"}'>${esc(tier)}</span> ${members.length} accounts share this picture`));
      const pics = el("div", "pics");
      members.forEach(a => pics.appendChild(el("div", "pic g" + (g % 3 + 1),
        (a.avatar ? `<img src="${esc(a.avatar)}">` : "") + `<div class='cap'>${esc(a.site)}</div>`)));
      wrap.appendChild(pics);
      b.appendChild(wrap);
    });
  }
  b.appendChild(el("h3", null, `Profile pictures (${withPic.length})`));
  const pics = el("div", "pics");
  withPic.forEach(a => pics.appendChild(el("div", "pic" + (DISPUTED.has(a.url) && needsBand(a.url) ? " disputed" : ""),
    `<a href="${esc(a.url || '#')}" target="_blank" rel="noopener"><img src="${esc(a.avatar)}" title="${esc(a.site)} · ${esc(a.user || '')}"></a>` +
    `<div class='cap'>${esc(a.site)}</div>`)));
  b.appendChild(pics);
  if (!withPic.length) b.appendChild(el("p", "mut", "No profile picture captured: the pages render with JavaScript or have none."));
  const covers = accts.filter(a => a.cover_thumb);
  if (covers.length) {
    b.appendChild(el("h3", null, "Covers / banners"));
    const cw = el("div", "pics");
    covers.forEach(a => cw.appendChild(el("div", "pic", `<img src="${esc(a.cover_thumb)}" style="aspect-ratio:2">` + `<div class='cap'>${esc(a.site)}</div>`)));
    b.appendChild(cw);
  }
  const exifPics = (DATA.metadata || []).filter(m => m.meta?._thumbnail);
  if (exifPics.length) {
    b.appendChild(el("h3", null, "EXIF previews"));
    const ew = el("div", "pics");
    exifPics.forEach(m => ew.appendChild(el("div", "pic",
      `<img src="${esc(m.meta._thumbnail)}">` + `<div class='cap'>${esc((m.file || "").split("/").pop())}</div>`)));
    b.appendChild(ew);
  }

  b.appendChild(el("div", "vis-head", `<h3>3 · Local vision</h3><span class="tag info">InsightFace · CLIP</span>`));
  const vout = el("div"); b.appendChild(vout);
  renderVision(vout);
  const ctl = el("div", "q", `<button id="facebtn">Run face matching + DeepFace check${refs.length ? " + CLIP" : ""}</button>`);
  b.appendChild(ctl);
  $("#facebtn").addEventListener("click", () => runVision(vout, refs.length > 0));
  const clipq = el("div", "q", `<input id="clipq" placeholder="describe what to look for: 'uniform', 'tattoo', 'glasses'…"><button id="clipbtn">CLIP search</button>`);
  b.appendChild(clipq);
  const cout = el("div"); b.appendChild(cout);
  $("#clipbtn").addEventListener("click", () => runClip($("#clipq").value, cout));
  $("#clipq").addEventListener("keydown", e => { if (e.key === "Enter") runClip($("#clipq").value, cout); });
  if (!DATA.ml_available) b.appendChild(el("div", "note", "The local vision stack is not installed (dashboard/install-ml.sh); the buttons above will say so."));
}
function faceGroups(v) {
  // Clusters of captured pictures that show the same face, built from the pairwise matches.
  const imgs = {}; (v.images || []).forEach(i => imgs[i.key] = i);
  const parent = {}; const find = k => { while ((parent[k] ??= k) !== k) k = parent[k]; return k; };
  const scores = {};
  const isAcct = k => /^(acct|cover):/.test(k);
  (v.face_matches || []).forEach(m => {
    if (!isAcct(m.a) || !isAcct(m.b)) return;
    parent[find(m.a)] = find(m.b);
    scores[m.a] = scores[m.b] = Math.max(scores[m.a] || 0, scores[m.b] || 0, m.score);
  });
  const byRoot = {};
  Object.keys(parent).forEach(k => (byRoot[find(k)] ||= []).push(imgs[k] || { key: k, label: k }));
  return Object.values(byRoot).filter(g => new Set(g.map(i => i.owner)).size > 1)
    .map(g => ({ members: g, score: Math.max(...g.map(i => scores[i.key] || 0)) }));
}
function renderVision(out) {
  out.innerHTML = "";
  const v = DATA.vision || {};
  if (v.status !== "ran") {
    out.appendChild(el("div", "mut", `Not run yet${v.reason ? " — " + esc(v.reason) : ""}. Face embeddings are biometric data: run this only with a lawful basis for the target.`));
    return;
  }
  const eng = Object.entries(v.engine || {}).map(([k, x]) => `${k}: ${esc(x)}`).join(" · ");
  out.appendChild(el("div", "mut", `${v.faces_total || 0} face(s) in ${(v.images || []).length} picture(s), threshold ${v.threshold}` +
    (v.source === "dashboard" ? ` · run from the dashboard ${esc(v.when || "")}` : " · run during the scan") + `<br>${eng}`));
  const groups = (DATA.face_groups && DATA.face_groups.length && v.source !== "dashboard")
    ? DATA.face_groups.map(g => ({ members: g.members.map(m => ({ label: `${m.site} @${m.user}`, url: m.url })), score: g.max_score }))
    : faceGroups(v);
  if (groups.length) {
    out.appendChild(el("h3", null, "Same face across accounts"));
    groups.forEach((g, i) => out.appendChild(el("div", "group",
      `<div class='t'><span class='tag ${g.score >= FACE_STRONG ? "ok" : "warn"}'>face #${i + 1} · ${(g.score || 0).toFixed(2)}</span> ${g.members.length} accounts</div>` +
      `<div class='pair'>${g.members.map(m => `<div class='who'>${avatarFor(m.url)}${esc(m.label)}</div><div></div>`).join("")}</div>`)));
  }
  const refPairs = (v.face_matches || []).filter(m => m.a.startsWith("target") || m.b.startsWith("target"));
  if (refPairs.length) {
    out.appendChild(el("h3", null, "Reference photo ↔ captured face"));
    refPairs.forEach(m => out.appendChild(el("div", "pair",
      `<span class='tag ${m.score >= FACE_STRONG ? "ok" : "warn"}'>${(m.score * 100).toFixed(0)} %</span><div>${esc(m.a_label)} ↔ ${esc(m.b_label)}<div class='bar'><i style='width:${Math.round(m.score * 100)}%'></i></div></div>`)));
  }
  if ((v.clip_similar || []).length) {
    out.appendChild(el("h3", null, "CLIP: reference ↔ captured look alike"));
    v.clip_similar.forEach(m => out.appendChild(el("div", "pair",
      `<span class='tag warn'>${(m.score * 100).toFixed(0)} %</span><div>${esc(m.a_label)} ↔ ${esc(m.b_label)}</div>`)));
  }
  if (!groups.length && !refPairs.length) out.appendChild(el("div", "mut", "No cross-account face match above the threshold."));
  const conf = v.deepface_confirms || [];
  if ((v.ran || {}).deepface) {
    const t = { confirmed: 0, disputed: 0, abstained: 0 };
    conf.forEach(c => { if (c.status in t) t[c.status]++; });
    out.appendChild(el("h3", null, "DeepFace second opinion"));
    out.appendChild(el("div", null,
      `<span class='df ok'>${t.confirmed} confirmed</span><span class='df'>${t.disputed} disputed</span><span class='df na'>${t.abstained} not judged</span>`));
    conf.forEach(c => out.appendChild(el("div", "pair",
      `<span class='df${c.status === "confirmed" ? " ok" : c.status === "abstained" ? " na" : ""}'>${esc(c.status)}</span>` +
      `<div>${esc(c.a_label)} ↔ ${esc(c.b_label)} <span class='mut'>InsightFace ${c.insightface_score ?? "?"}</span>` +
      (c.models || []).map(r => `<div class='m mut' style='font-size:11px'>${esc(r.model)}: ${r.verified ? "agrees" : "refuses"} (${r.distance} vs ${r.threshold})</div>`).join("") +
      `</div>`)));
    out.appendChild(el("div", "note", "DeepFace only re-checks what InsightFace matched; it cannot add a match of its own. A disputed picture is marked so it is not read as evidence."));
  } else if (v.deepface_error) {
    out.appendChild(el("div", "note", "DeepFace did not run: " + esc(v.deepface_error)));
  }
  out.appendChild(el("div", "note", "Cosine similarity, not identity: a high score means the faces look alike. Biometric processing is special-category data (KVKK art. 6 / GDPR art. 9)."));
}
async function runVision(out, withClip) {
  if (!confirm("Face matching processes biometric data locally. Continue only if you have a lawful basis for this target.")) return;
  out.innerHTML = "<div class='mut'>InsightFace embeddings, then the DeepFace re-check on whatever matched (about 30 s to a few minutes)…</div>";
  try {
    const r = await (await fetch(`/api/vision/${encodeURIComponent(FOLDER)}?faces=1&deepface=1${withClip ? "&clip=1" : ""}`, { method: "POST" })).json();
    if (r.error) { out.innerHTML = `<div class='note'>${esc(r.error)}</div>`; return; }
    DATA.vision = r;
    refreshDeepFace();
    renderVision(out);
    try { renderIdentity(); } catch (e) { console.error(e); }
  } catch (e) { out.innerHTML = "<div class='note'>Vision service unavailable.</div>"; }
}
async function runClip(q, out) {
  q = (q || "").trim(); if (!q) return;
  out.innerHTML = "<div class='mut'>encoding the pictures and the query with CLIP…</div>";
  try {
    const r = await (await fetch(`/api/clip/${encodeURIComponent(FOLDER)}?q=${encodeURIComponent(q)}`, { method: "POST" })).json();
    if (r.error) { out.innerHTML = `<div class='note'>${esc(r.error)}</div>`; return; }
    out.innerHTML = "";
    (r.results || []).forEach(x => out.appendChild(el("div", "item",
      `<span class='tag info'>${(x.score * 100).toFixed(0)} %</span> ${esc(x.label)}`)));
    if (!r.results?.length) out.appendChild(el("div", "mut", "No pictures to search."));
    else out.appendChild(el("div", "note", "Ranking by text-image similarity; the scores are relative, not probabilities."));
  } catch (e) { out.innerHTML = "<div class='note'>CLIP service unavailable.</div>"; }
}

// ---- CONTEXT wiring ----
function renderContext() {
  const seeds = DATA.seeds || {};
  const first = (seeds.names || [])[0] || (seeds.usernames || [])[0] || (seeds.domains || [])[0] || "";
  $("#gq").value = first; $("#tq").value = (seeds.usernames || [])[0] || first;
  $("#gbtn").addEventListener("click", runGdelt);
  $("#tbtn").addEventListener("click", runTelegram);
  if (DATA.telegram_listener) runTelegram("");   // listener hits only; the live search waits for the button
  document.body.addEventListener("click", e => {
    const s = e.target.closest("[data-seed]"); if (!s) return;
    $("#gq").value = s.dataset.seed; runGdelt();
  });
}
boot();
