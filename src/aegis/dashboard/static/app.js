// Aegis dashboard - dependency-free vanilla JS.
// SECURITY: every string that came from logs is attacker-controlled (user agents, usernames,
// S3 keys...). It is always inserted with esc() / textContent, never as raw HTML, otherwise an
// attacker could run JavaScript in the analyst's browser (stored XSS through log injection).

const $ = (sel) => document.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
const KILL_CHAIN = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
  "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"];
const LEVEL_COLOR = { LOW: "var(--low)", MEDIUM: "var(--medium)", HIGH: "var(--high)", CRITICAL: "var(--critical)" };
const NODE_COLOR = { user: "#4cc2ff", service_account: "#a78bfa", ip: "#f59e0b", resource: "#34d399", role: "#f472b6",
  access_key: "#ef4766", country: "#94a3b8", host: "#60a5fa" };

const TOKEN = localStorage.getItem("aegisToken");
async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}) };
  const res = await fetch(path, { ...opts, headers });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

let selected = null;
let currentView = "incidents";
let detailTab = "overview";
let lastDetail = null;

// ------------------------------------------------------------------ KPIs
async function loadStats() {
  try {
    const s = await api("/api/stats");
    const lv = s.open_incidents_by_level || {};
    const tiles = [
      ["Events ingested", s.events.toLocaleString()],
      ["Alerts", s.alerts.toLocaleString()],
      ["Critical incidents", lv.CRITICAL || 0, "critical"],
      ["High incidents", lv.HIGH || 0, "high"],
      ["Medium / Low", `${lv.MEDIUM || 0} / ${lv.LOW || 0}`],
      ["Graph", `${s.graph.entities} nodes / ${s.graph.relationships} edges`],
      ["ML model", s.ml_model],
      ["AI investigator", s.llm.enabled ? s.llm.model : "template (offline)"],
    ];
    $("#kpis").innerHTML = tiles.map(([l, v, c]) => `<div class="kpi"><div class="label">${esc(l)}</div><div class="value ${c || ""}" style="${String(v).length > 14 ? "font-size:14px" : ""}">${esc(v)}</div></div>`).join("");
    $("#status").textContent = `${s.mode} mode - last event ${fmtTime(s.last_event_at)}`;
  } catch (e) {
    $("#status").textContent = "API unreachable: " + e.message;
  }
}

// ------------------------------------------------------------------ incident queue
async function loadIncidents() {
  const list = await api(`/api/incidents?min_level=${$("#minLevel").value}`);
  $("#incidentList").innerHTML = list.length ? list.map((i) => `
    <div class="inc ${i.risk_level} ${i.incident_id === selected ? "selected" : ""}" data-id="${i.incident_id}">
      <div class="meta"><span class="badge ${i.risk_level}">${i.risk_level}</span><span>#${i.incident_id}</span>
        <span>risk ${i.risk_score}</span><span>${i.alert_count} alerts</span>${i.has_report ? "<span>report ready</span>" : ""}
        ${i.status !== "open" ? `<span>${esc(i.status)}</span>` : ""}</div>
      <div class="title">${esc(i.title)}</div>
      <div class="meta"><span>${fmtTime(i.first_seen)} - ${fmtTime(i.last_seen)}</span></div>
    </div>`).join("") : `<p class="muted">No incidents at this level yet.</p>`;
  document.querySelectorAll(".inc").forEach((el) => el.addEventListener("click", () => selectIncident(+el.dataset.id)));
}

async function selectIncident(id) {
  selected = id;
  document.querySelectorAll(".inc").forEach((el) => el.classList.toggle("selected", +el.dataset.id === id));
  lastDetail = await api(`/api/incidents/${id}`);
  renderDetail();
}

// ------------------------------------------------------------------ incident detail
function renderDetail() {
  const d = lastDetail;
  if (!d) return;
  const inc = d.incident;
  const color = LEVEL_COLOR[inc.risk_level];
  $("#detail").innerHTML = `
    <div class="detail-head">
      <div class="score" style="border:4px solid ${color};color:${color}">${Math.round(inc.risk_score)}</div>
      <div style="min-width:0;flex:1">
        <div><span class="badge ${inc.risk_level}">${inc.risk_level}</span> <span class="muted">Incident #${inc.incident_id} - ${esc(inc.status)}</span></div>
        <h2>${esc(inc.title)}</h2>
        <div class="muted small">${fmtTime(inc.first_seen)} &rarr; ${fmtTime(inc.last_seen)} - ${d.alerts.length} alerts - ${inc.entities.length} entities</div>
      </div>
      <div class="actions">
        <button class="btn primary" id="btnInvestigate">Investigate with AI</button>
        <select id="statusSel">${["open", "investigating", "closed"].map((s) => `<option ${s === inc.status ? "selected" : ""}>${s}</option>`).join("")}</select>
      </div>
    </div>
    <div class="subtabs" id="subtabs">
      ${["overview", "report", "timeline", "graph", "alerts"].map((t) => `<button data-t="${t}" class="${t === detailTab ? "active" : ""}">${t === "report" ? "AI report" : t[0].toUpperCase() + t.slice(1)}</button>`).join("")}
    </div>
    <div id="tabBody"></div>`;
  $("#subtabs").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { detailTab = b.dataset.t; renderDetail(); }));
  $("#btnInvestigate").addEventListener("click", investigate);
  $("#statusSel").addEventListener("change", async (e) => {
    await api(`/api/incidents/${inc.incident_id}/status`, { method: "POST", body: JSON.stringify({ status: e.target.value }) });
    loadIncidents();
  });
  ({ overview: renderOverview, report: renderReport, timeline: renderTimeline, graph: renderGraph, alerts: renderAlertsTab })[detailTab](d);
}

function renderOverview(d) {
  const inc = d.incident;
  const entities = inc.entities.reduce((acc, e) => ((acc[e.type] = acc[e.type] || []).push(e.value), acc), {});
  $("#tabBody").innerHTML = `
    <h3>ATT&amp;CK kill chain</h3>
    <div class="killchain">${KILL_CHAIN.map((t) => `<span class="${inc.tactics.includes(t) ? "on" : ""}">${t}</span>`).join("")}</div>
    <div class="grid2">
      <div><h3>Why this score</h3><table class="factors">${inc.score_breakdown.map((f) => `<tr><td>+${f.points}</td><td>${esc(f.reason)}</td></tr>`).join("")}</table></div>
      <div><h3>Entities</h3>${Object.entries(entities).map(([t, vs]) => `<div style="margin-bottom:6px"><span class="muted small">${esc(t)}</span><br>${vs.map((v) => `<span class="chip mono">${esc(v)}</span>`).join("")}</div>`).join("")}</div>
    </div>
    <h3>Graph analysis</h3>
    <p class="small">Pivot entity: <span class="chip mono">${esc(d.graph.pivot)}</span></p>
    ${d.graph.attack_paths.length ? `<p class="small">Attack paths (external &rarr; critical asset):</p>${d.graph.attack_paths.map((p) => `<div class="mono small">${p.map(esc).join(" &rarr; ")}</div>`).join("")}` : ""}
    ${d.graph.blast_radius.length ? `<p class="small">Blast radius:</p>${d.graph.blast_radius.map((b) => `<span class="chip mono">${esc(b.relation)}: ${esc(b.entity)}</span>`).join("")}` : ""}
    ${d.report ? `<h3>AI summary</h3><p>${esc(d.report.summary)}</p>` : ""}`;
}

function renderReport(d) {
  const r = d.report;
  if (!r) { $("#tabBody").innerHTML = `<p class="muted">No report yet. Incidents of MEDIUM risk and above are investigated automatically; you can also click "Investigate with AI".</p>`; return; }
  $("#tabBody").innerHTML = `<div class="report">
    <div class="gen">Generated by <b>${esc(r.generated_by)}</b> at ${fmtTime(r.generated_at)} - confidence <b>${esc(r.confidence)}</b></div>
    <h3>Summary</h3><p>${esc(r.summary)}</p>
    <h3>What happened?</h3><p>${esc(r.what_happened)}</p>
    <h3>Which systems were involved?</h3><p>${r.systems_involved.map((s) => `<span class="chip mono">${esc(s)}</span>`).join("")}</p>
    <h3>Why was this flagged?</h3><p>${esc(r.why_flagged)}</p>
    <h3>What evidence supports the finding?</h3><ul class="evidence">${r.evidence.map((e) => `<li>${esc(e.claim)}<br>${e.alert_ids.map((a) => `<span class="chip mono">${esc(a)}</span>`).join("")}${e.event_ids.slice(0, 4).map((a) => `<span class="chip mono">${esc(a)}</span>`).join("")}</li>`).join("")}</ul>
    <h3>What defensive action should an operator consider?</h3><ul class="actions-list">${r.recommended_actions.map((a) => `<li><span class="prio ${esc(a.priority)}">${esc(a.priority)}</span>${esc(a.action)}<div class="muted small">${esc(a.rationale)}</div></li>`).join("")}</ul>
    <h3>MITRE ATT&amp;CK</h3><p>${r.mitre_techniques.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</p>
    <h3>False-positive considerations</h3><p>${esc(r.false_positive_considerations)}</p>
    <h3>Knowledge base references (RAG)</h3><p>${r.references.map((t) => `<span class="chip mono">${esc(t)}</span>`).join("")}</p>
  </div>`;
}

function renderTimeline(d) {
  $("#tabBody").innerHTML = `<div class="timeline">${d.timeline.map((e) => `
    <div class="tl ${e.outcome === "failure" ? "failure" : ""}">
      <div class="t">${fmtTime(e.time)} - ${esc(e.source)}</div>
      <div><b>${esc(e.action)}</b> <span class="muted">${esc(e.outcome)}</span> by <span class="mono">${esc(e.principal || e.src_ip)}</span>
        ${e.src_ip ? `from <span class="mono">${esc(e.src_ip)}</span>${e.country ? ` (${esc(e.country)})` : ""}` : ""}
        ${e.target ? `&rarr; <span class="mono">${esc(e.target)}</span>` : ""}</div>
      <div class="muted small mono">${["role", "policy_arn", "instance_type", "private_ip", "created_access_key", "error_code", "role_ref", "user_agent", "bytes_out"].filter((k) => e[k]).map((k) => `${k}=${esc(e[k])}`).join("  ")}</div>
    </div>`).join("")}</div>`;
}

function renderAlertsTab(d) {
  $("#tabBody").innerHTML = alertsTable(d.alerts);
}

function alertsTable(alerts, withIncident = false) {
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Detector</th><th>Rule</th><th>ATT&amp;CK</th><th>Entities</th>${withIncident ? "<th>Incident</th>" : ""}</tr></thead><tbody>
    ${alerts.map((a) => `<tr><td class="mono">${fmtTime(a.event_time)}</td><td><span class="badge ${a.severity}">${a.severity}</span></td><td>${esc(a.detector)}</td>
      <td><b>${esc(a.rule_id)}</b><br>${esc(a.rule_name)}${a.detector === "ml" && a.evidence.top_features ? `<div class="muted small">${a.evidence.top_features.map((f) => `${esc(f.feature)}=${esc(f.value)}`).join(", ")}</div>` : ""}</td>
      <td>${a.mitre ? `${esc(a.mitre.tactic)}<br><span class="muted small">${esc(a.mitre.technique_id)} ${esc(a.mitre.technique)}</span>` : "-"}</td>
      <td>${a.entities.map((e) => `<span class="chip mono">${esc(e.type)}:${esc(e.value)}</span>`).join("")}</td>
      ${withIncident ? `<td>${a.incident_id ? `#${a.incident_id}` : ""}</td>` : ""}</tr>`).join("")}
  </tbody></table></div>`;
}

// ------------------------------------------------------------------ entity graph (force-directed layout)
function renderGraph(d) {
  const g = d.graph;
  $("#tabBody").innerHTML = `<div class="graph-wrap"><svg id="graphSvg" viewBox="0 0 1000 560"></svg>
    <div class="legend">${Object.entries(NODE_COLOR).map(([t, c]) => `<span><i style="background:${c}"></i>${t}</span>`).join("")}
    <span><i style="background:none;border:2px solid #fff"></i>in incident</span><span style="color:var(--critical)">&#9473; attack path</span></div></div>`;
  const nodes = g.nodes.map((n, i) => ({ ...n, x: 500 + 300 * Math.cos(i), y: 280 + 200 * Math.sin(i * 1.7), vx: 0, vy: 0 }));
  const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
  const links = g.edges.filter((e) => e.source in idx && e.target in idx).map((e) => ({ ...e, s: idx[e.source], t: idx[e.target] }));
  const pathEdges = new Set();
  (g.attack_paths || []).forEach((p) => p.forEach((n, i) => { if (i) { pathEdges.add(p[i - 1] + "|" + n); pathEdges.add(n + "|" + p[i - 1]); } }));

  // Simple physics: every node repels every other node (Coulomb), links act as springs (Hooke),
  // and a weak gravity pulls everything to the centre. 300 iterations is plenty for <200 nodes.
  for (let it = 0; it < 300; it++) {
    const alpha = 1 - it / 300;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y; const dist2 = Math.max(dx * dx + dy * dy, 25);
        const f = 4200 / dist2; dx *= f / Math.sqrt(dist2); dy *= f / Math.sqrt(dist2);
        a.vx += dx; a.vy += dy; b.vx -= dx; b.vy -= dy;
      }
    }
    for (const l of links) {
      const a = nodes[l.s], b = nodes[l.t];
      const dx = b.x - a.x, dy = b.y - a.y, dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (dist - 120) * 0.02;
      a.vx += (dx / dist) * f; a.vy += (dy / dist) * f; b.vx -= (dx / dist) * f; b.vy -= (dy / dist) * f;
    }
    for (const n of nodes) {
      n.vx += (500 - n.x) * 0.004; n.vy += (280 - n.y) * 0.006;
      n.x += Math.max(-20, Math.min(20, n.vx * alpha)); n.y += Math.max(-20, Math.min(20, n.vy * alpha));
      n.vx *= 0.6; n.vy *= 0.6;
      n.x = Math.max(30, Math.min(970, n.x)); n.y = Math.max(25, Math.min(535, n.y));
    }
  }
  const svg = $("#graphSvg");
  const label = (n) => { const v = String(n.value || n.id.split(":").slice(1).join(":")); return v.length > 22 ? v.slice(0, 21) + "..." : v; };
  svg.innerHTML = `<defs><marker id="arrow" viewBox="0 0 10 10" refX="16" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#3b4d63"/></marker></defs>` +
    links.map((l) => { const a = nodes[l.s], b = nodes[l.t]; const hot = pathEdges.has(l.source + "|" + l.target);
      return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${hot ? "#ef4766" : "#2d3e53"}" stroke-width="${hot ? 2.5 : 1.2}" marker-end="url(#arrow)" data-tip="${esc(l.source)} -[${esc(l.type)} x${l.count}]-> ${esc(l.target)}"/>`; }).join("") +
    nodes.map((n) => { const r = n.in_incident ? 9 : 6; const pivot = n.id === g.pivot;
      return `<g data-tip="${esc(n.id)}${n.criticality ? " (criticality: " + esc(n.criticality) + ")" : ""}${n.country ? " - " + esc(n.country) : ""}${n.asn_org ? " - " + esc(n.asn_org) : ""}">
        <circle cx="${n.x}" cy="${n.y}" r="${pivot ? 13 : r}" fill="${NODE_COLOR[n.type] || "#888"}" stroke="${n.in_incident ? "#fff" : "none"}" stroke-width="${pivot ? 3 : 1.5}"/>
        <text x="${n.x + 12}" y="${n.y + 4}" fill="#9fb3c8" font-size="11">${esc(label(n))}</text></g>`; }).join("");
  const tip = $("#tooltip");
  svg.querySelectorAll("[data-tip]").forEach((el) => {
    el.addEventListener("mousemove", (ev) => { tip.textContent = el.dataset.tip; tip.style.left = ev.clientX + 12 + "px"; tip.style.top = ev.clientY + 12 + "px"; tip.classList.remove("hidden"); });
    el.addEventListener("mouseleave", () => tip.classList.add("hidden"));
  });
}

async function investigate() {
  const btn = $("#btnInvestigate");
  btn.disabled = true; btn.textContent = "Investigating...";
  try {
    await api(`/api/incidents/${selected}/investigate`, { method: "POST" });
    detailTab = "report";
    await selectIncident(selected);
  } catch (e) { alert("Investigation failed: " + e.message); }
  finally { btn.disabled = false; btn.textContent = "Investigate with AI"; }
}

// ------------------------------------------------------------------ other views
async function loadScenarios() {
  const list = await api("/api/scenarios");
  $("#scenarioButtons").innerHTML = list.map((s) => `<button title="${esc(s.description)}" data-s="${esc(s.name)}">${esc(s.name.replaceAll("_", " "))}</button>`).join("");
  $("#scenarioButtons").querySelectorAll("button").forEach((b) => b.addEventListener("click", async () => {
    $("#simResult").textContent = `Injecting ${b.dataset.s}...`;
    const r = await api(`/api/simulate/${b.dataset.s}`, { method: "POST" });
    $("#simResult").textContent = r.published_records ? `Published ${r.published_records} synthetic log records to Kafka - incidents appear as the pipeline processes them.` : `Processed ${r.processed_messages} messages.`;
    setTimeout(refresh, 800);
  }));
}

async function loadAlerts() { $("#alertsTable").innerHTML = alertsTable(await api("/api/alerts?limit=300"), true); }
async function loadEvents() {
  const ev = await api("/api/events?limit=200");
  $("#eventsTable").innerHTML = `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Action</th><th>Outcome</th><th>Principal</th><th>Source IP</th><th>Target</th></tr></thead><tbody>
    ${ev.map((e) => `<tr><td class="mono">${fmtTime(e.time)}</td><td>${esc(e.source)}</td><td>${esc(e.action)}</td><td>${esc(e.outcome)}</td><td class="mono">${esc(e.principal)}</td><td class="mono">${esc(e.src_ip)}${e.country ? " " + esc(e.country) : ""}</td><td class="mono">${esc(e.target || e.dst)}</td></tr>`).join("")}</tbody></table></div>`;
}
async function loadEngineering() {
  try {
    const r = await api("/api/ml/report");
    const rows = Object.entries(r.results);
    $("#mlReport").innerHTML = `<p class="muted small">${r.data.test_events.toLocaleString()} test events (${r.data.test_malicious} malicious), ${r.data.features} features. Latency per event, batched.</p>
      <div class="table-wrap"><table><thead><tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>PR-AUC</th><th>Latency (ms)</th></tr></thead><tbody>
      ${rows.map(([n, m]) => `<tr><td><b>${esc(n)}</b></td><td>${m.precision.toFixed(3)}</td><td>${m.recall.toFixed(3)}</td><td>${m.f1.toFixed(3)}</td><td>${m.false_positive_rate.toFixed(4)}</td><td>${m.pr_auc ?? "-"}</td><td>${r.latency_ms[n]?.batched_per_event ?? "-"}</td></tr>`).join("")}
      </tbody></table></div>
      <h3>Novel-attack test: event recall when XGBoost never saw that attack type</h3>
      <div class="table-wrap"><table><thead><tr><th>Scenario</th><th>XGBoost (seen)</th><th>XGBoost (unseen)</th><th>Autoencoder</th><th>Isolation Forest</th><th>Ensemble</th></tr></thead><tbody>
      ${Object.entries(r.novel_attack_recall || {}).map(([s, m]) => `<tr><td>${esc(s)}</td><td>${m.xgboost_seen}</td><td>${m.xgboost_unseen}</td><td>${m.autoencoder}</td><td>${m.isolation_forest}</td><td>${m.ensemble}</td></tr>`).join("")}
      </tbody></table></div>`;
  } catch (e) { $("#mlReport").innerHTML = `<p class="muted">No ML report yet (run <code>aegis train</code>).</p>`; }
  const rules = await api("/api/rules");
  $("#rulesTable").innerHTML = `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Analyzer</th><th>Severity</th><th>ATT&amp;CK</th></tr></thead><tbody>
    ${rules.map((r) => `<tr><td class="mono">${esc(r.id)}</td><td><b>${esc(r.name)}</b><div class="muted small">${esc(r.description)}</div></td><td>${esc(r.type)}</td><td>${esc(r.analyzer)}</td><td><span class="badge ${r.severity}">${r.severity}</span></td><td>${r.mitre ? `${esc(r.mitre.tactic)}<br><span class="muted small">${esc(r.mitre.technique_id)}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

// ------------------------------------------------------------------ wiring
document.querySelectorAll("#mainTabs button").forEach((b) => b.addEventListener("click", () => {
  currentView = b.dataset.view;
  document.querySelectorAll("#mainTabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("hidden", v.id !== `view-${currentView}`));
  refresh();
}));
$("#minLevel").addEventListener("change", loadIncidents);

async function refresh() {
  await loadStats();
  try {
    if (currentView === "incidents") await loadIncidents();
    if (currentView === "alerts") await loadAlerts();
    if (currentView === "events") await loadEvents();
    if (currentView === "engineering") await loadEngineering();
  } catch (e) { console.error(e); }
}

loadScenarios();
refresh();
setInterval(() => { if (currentView !== "engineering") refresh(); }, 5000);
