"use strict";
const SEV = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SEV_COLOR = {INFORMATIONAL: "#8a97a6", LOW: "#3f8f6b", MEDIUM: "#c58f12", HIGH: "#d9622b", CRITICAL: "#b3202e"};
const PALETTE = ["#0f6e8c", "#d9622b", "#3f8f6b", "#c58f12", "#7a5195", "#b3202e", "#4c6a92", "#8a97a6", "#2f9e9e", "#a05a2c"];
const TABS = [["overview", "Overview"], ["threats", "Threat feed"], ["search", "Indicator search"], ["alerts", "Alerts"],
              ["attack", "ATT&CK"], ["vulns", "Vulnerabilities"], ["exec", "Executive summary"]];
const CATS = ["PHISHING","MALWARE","RANSOMWARE","CREDENTIAL THREATS","WEB THREATS","NETWORK THREATS","VULNERABILITY EXPOSURE","SOCIAL ENGINEERING","DATA EXPOSURE","ACCOUNT SECURITY"];
const view = () => clear(document.getElementById("view"));
let charts = [];

function drawChart(parent, title, type, labels, datasets, opts = {}) {
  const canvas = h("canvas", {role: "img", "aria-label": title});
  parent.append(h("div", {class: "panel" + (opts.wide ? " wide" : "")}, h("h3", {}, title), h("div", {class: "chartbox"}, canvas)));
  const horizontal = opts.horizontal;
  charts.push(new Chart(canvas, {type, data: {labels, datasets}, options: {
    responsive: true, maintainAspectRatio: false, indexAxis: horizontal ? "y" : "x",
    plugins: {legend: {display: type === "doughnut" || datasets.length > 1}},
    scales: type === "doughnut" ? {} : {x: {stacked: !!opts.stacked}, y: {stacked: !!opts.stacked, beginAtZero: true}}}}));
}
const one = (label, data, colors) => [{label, data, backgroundColor: colors || PALETTE}];

async function showOverview() {
  const [s, t] = await Promise.all([api("/api/dashboard/stats"), api("/api/dashboard/trends")]);
  document.getElementById("asof").textContent = "Demo data as of " + s.as_of + " (fixed demo clock).";
  const c = s.cards, root = view();
  const items = [["Total threat records", c.total_threat_records], ["Critical threats", c.critical_threats], ["High threats", c.high_threats],
    ["Active indicators", c.active_indicators], ["Open investigations", c.open_investigations],
    ["Average confidence", c.average_confidence], ["Vulnerabilities tracked", c.vulnerabilities_tracked]];
  root.append(h("div", {class: "strip"}, items.map(([l, v]) => h("div", {}, h("b", {}, v), h("span", {}, l)))));
  const help = {OBSERVATION: "seen, unvalidated", INDICATOR: "validated artifact", ALERT: "needs triage", THREAT: "corroborated", INCIDENT: "analyst-confirmed"};
  root.append(h("div", {class: "stages"}, Object.entries(s.by_entity_stage).map(([k, v]) => h("div", {class: "stage"}, h("b", {}, v), k, h("br"), h("small", {}, help[k])))));
  const grid = h("div", {class: "grid"}); root.append(grid);
  charts.forEach(x => x.destroy()); charts = [];
  drawChart(grid, "Threats over time (by first seen)", "bar", t.labels, SEV.map(k => ({label: k, data: t.by_severity[k], backgroundColor: SEV_COLOR[k]})), {stacked: true, wide: true});
  drawChart(grid, "Threats by severity", "doughnut", SEV, one("Threats", SEV.map(k => s.by_severity[k]), SEV.map(k => SEV_COLOR[k])));
  drawChart(grid, "Threats by category", "bar", Object.keys(s.by_category), one("Threats", Object.values(s.by_category)), {horizontal: true});
  drawChart(grid, "IOC type distribution", "doughnut", Object.keys(s.by_indicator_type), one("Indicators", Object.values(s.by_indicator_type)));
  drawChart(grid, "Top ATT&CK tactics (only justified mappings)", "bar", Object.keys(s.top_tactics), one("Records", Object.values(s.top_tactics)), {horizontal: true});
  drawChart(grid, "Risk score distribution", "bar", Object.keys(s.risk_distribution), one("Records", Object.values(s.risk_distribution)));
  drawChart(grid, "Confidence distribution", "bar", Object.keys(s.confidence_distribution), one("Records", Object.values(s.confidence_distribution)));
  drawChart(grid, "Vulnerabilities by severity", "bar", SEV, one("CVEs", SEV.map(k => s.vulnerabilities_by_severity[k]), SEV.map(k => SEV_COLOR[k])));
  drawChart(grid, "Top threat categories", "bar", Object.keys(s.top_categories), one("Threats", Object.values(s.top_categories)));
  drawChart(grid, "Threat status distribution", "doughnut", Object.keys(s.by_status), one("Threats", Object.values(s.by_status)));
}

function sel(id, label, opts) {
  return h("label", {}, label, h("select", {id}, h("option", {value: ""}, "Any"), opts.map(o => h("option", {value: o}, o))));
}
async function showThreats() {
  const root = view();
  const f = (id, label, type = "number", extra = {}) => h("label", {}, label, h("input", Object.assign({id, type}, extra)));
  const form = h("div", {class: "filters"},
    sel("f-severity", "Severity", SEV), sel("f-category", "Category", CATS),
    sel("f-type", "Indicator type", ["IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_DOMAIN", "CVE_ID"]),
    sel("f-status", "Status", ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]),
    sel("f-stage", "Stage", ["OBSERVATION", "INDICATOR", "ALERT", "THREAT", "INCIDENT"]),
    f("f-minrisk", "Min risk", "number", {min: 0, max: 100}), f("f-minconf", "Min confidence", "number", {min: 0, max: 100}),
    f("f-from", "Last seen from", "date"), f("f-to", "Last seen to", "date"), f("f-q", "Search text", "search"),
    h("label", {}, "Sort", h("select", {id: "f-sort"}, [["newest", "Newest"], ["risk", "Highest risk"], ["confidence", "Highest confidence"], ["observed", "Most observed"]].map(([v, l]) => h("option", {value: v}, l)))),
    h("button", {class: "btn", id: "apply"}, "Apply filters"));
  const out = h("div", {id: "tbl"}); root.append(form, out);
  let page = 1;
  async function load() {
    const q = new URLSearchParams({page, per_page: 20, sort: document.getElementById("f-sort").value});
    const map = {"f-severity": "severity", "f-category": "category", "f-type": "indicator_type", "f-status": "status", "f-stage": "entity_stage",
      "f-minrisk": "min_risk", "f-minconf": "min_confidence", "f-from": "date_from", "f-to": "date_to", "f-q": "q"};
    for (const [id, k] of Object.entries(map)) { const v = document.getElementById(id).value; if (v) q.set(k, v); }
    try {
      const d = await api("/api/threats?" + q);
      clear(out).append(
        h("p", {}, d.total + " matching records"),
        table([{label: "Threat ID", key: "threat_id"}, {label: "Threat name", key: "threat_name"}, {label: "Category", key: "category"},
          {label: "Indicator", render: ind}, {label: "Severity", render: r => badge(r.severity)}, {label: "Risk", key: "risk_score"},
          {label: "Confidence", key: "confidence_score"}, {label: "Stage", key: "entity_stage"}, {label: "First seen", key: "first_seen"},
          {label: "Last seen", key: "last_seen"}, {label: "Status", key: "status"}],
          d.items, r => location.href = "threat-details.html?id=" + encodeURIComponent(r.threat_id)),
        h("div", {class: "pager"},
          h("button", {class: "btn ghost", disabled: page <= 1, onclick: () => { page--; load(); }}, "Previous"),
          "Page " + d.page + " of " + Math.max(1, Math.ceil(d.total / d.per_page)),
          h("button", {class: "btn ghost", disabled: page * d.per_page >= d.total, onclick: () => { page++; load(); }}, "Next")));
    } catch (e) { clear(out).append(h("p", {class: "bad"}, e.message)); }
  }
  document.getElementById("apply").addEventListener("click", () => { page = 1; load(); });
  load();
}

async function showSearch() {
  const root = view();
  const input = h("input", {id: "q", type: "search", size: 46, placeholder: "e.g. 198.51.100.25 or login-check.invalid", "aria-label": "Search indicator"});
  const out = h("div", {});
  root.append(h("p", {}, "Supported: IP, domain, URL, file hash, CVE. This is a database lookup only - nothing is ever contacted."),
    h("div", {class: "filters"}, input, h("button", {class: "btn", id: "go"}, "Search indicator")), out);
  async function go() {
    clear(out);
    try {
      const r = await api("/api/indicators/search?q=" + encodeURIComponent(input.value));
      if (!r.valid) { out.append(h("div", {class: "panel bad"}, h("b", {}, "Not a valid indicator. "), r.validation_notes.join(" "))); return; }
      const rows = [["Indicator type", r.indicator_type], ["Indicator", r.indicator_defanged], ["Known in demo dataset", r.known_in_dataset ? "YES" : "NO"]];
      if (r.known_in_dataset) rows.push(["Risk", r.risk_score + "/100"], ["Severity", badge(r.severity)], ["Confidence", r.confidence_score + "%"],
        ["Associated category", r.associated_categories.join(", ")], ["Stage", r.entity_stage], ["First seen", r.first_seen], ["Last seen", r.last_seen], ["Status", r.status],
        ["Source", r.source + " (reliability " + r.source_reliability + ")"],
        ["ATT&CK", r.attack_mappings.length ? r.attack_mappings.map(m => m.technique_id_optional + " " + m.technique).join("; ") : "No mapping (insufficient evidence)"],
        ["Related alerts", r.related_alerts.map(a => a.alert_id + " (" + a.status + ")").join(", ") || "None"],
        ["Related indicators", r.related_indicators.length ? h("span", {}, r.related_indicators.map(x => h("div", {}, h("code", {}, x.indicator_defanged), " risk " + x.risk_score))) : "None"],
        ["Analyst notes", r.analyst_notes.map(n => n.note).join(" | ") || "None"]);
      out.append(h("div", {class: "panel"}, h("dl", {class: "kv"}, rows.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
        h("p", {}, h("b", {}, "Interpretation: "), r.interpretation), r.caution ? h("p", {class: "notice"}, r.caution) : null,
        r.threat_ids ? h("p", {}, r.threat_ids.map(id => h("a", {href: "threat-details.html?id=" + id}, "Open " + id + " "))) : null));
    } catch (e) { out.append(h("p", {class: "bad"}, e.message)); }
  }
  document.getElementById("go").addEventListener("click", go);
  input.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
  input.value = "198.51.100.25"; go();
}

async function showAlerts() {
  const root = view();
  const d = await api("/api/alerts");
  const statuses = ["NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"];
  root.append(h("p", {}, d.total + " correlated alerts (duplicate alerts for the same indicator are merged to reduce alert fatigue). Changing status needs an analyst API key."),
    table([{label: "Alert", key: "alert_id"}, {label: "Threat", render: r => h("a", {href: "threat-details.html?id=" + r.threat_id}, r.threat_id)},
      {label: "Type", key: "alert_type"}, {label: "Severity", render: r => badge(r.severity)}, {label: "Risk", key: "risk_score"},
      {label: "Confidence", key: "confidence_score"}, {label: "Observations", key: "observation_count"}, {label: "Indicator", render: ind},
      {label: "Status", render: r => {
        const s = h("select", {"aria-label": "Status of " + r.alert_id}, statuses.map(x => h("option", {value: x, selected: x === r.status}, x)));
        s.addEventListener("change", async () => { try { await api("/api/alerts/" + r.alert_id + "/status", {method: "PUT", body: JSON.stringify({status: s.value})}); toast(r.alert_id + " set to " + s.value); }
          catch (e) { toast(e.message); s.value = r.status; } });
        return s; }}], d.items));
}

async function showAttack() {
  const root = view();
  const t = await api("/api/dashboard/trends");
  const detail = h("div", {});
  root.append(h("p", {}, "Only records with enough evidence (category + indicator type + confidence of 50 or more) are mapped. Click a technique to see its records."),
    table([{label: "Technique ID", key: "technique_id"}, {label: "Technique", key: "technique"}, {label: "Tactic", key: "tactic"}, {label: "Records", key: "count"}],
      t.technique_frequency, async r => {
        const d = await api("/api/attack/techniques/" + r.technique_id + "/threats");
        clear(detail).append(h("h3", {}, r.technique_id + " " + r.technique + " - " + d.total + " records (top 100)"),
          table([{label: "Threat", render: x => h("a", {href: "threat-details.html?id=" + x.threat_id}, x.threat_id)}, {label: "Indicator", render: ind},
            {label: "Severity", render: x => badge(x.severity)}, {label: "Risk", key: "risk_score"}, {label: "Confidence", key: "confidence_score"}], d.items));
      }), detail);
}

async function showVulns() {
  const root = view();
  const d = await api("/api/vulnerabilities");
  root.append(h("p", {}, "CVSS alone is not patch priority. Priority also weighs asset criticality, exposure, exploitation evidence and business impact. All CVE IDs are fictional (CVE-2099-*)."),
    table([{label: "CVE", key: "cve_id"}, {label: "Product", key: "product_category"}, {label: "CVSS", key: "cvss_score"}, {label: "Severity", render: r => badge(r.severity)},
      {label: "Exposure", key: "exposure"}, {label: "Asset crit.", key: "asset_criticality"}, {label: "Exploitation (demo)", key: "exploitation_status_demo"},
      {label: "Patch", render: r => r.patch_available ? "Available" : "Not yet"}, {label: "Priority", render: r => r.priority_score + " - " + r.priority_label}], d.items));
}

async function showExec() {
  const root = view(), e = await api("/api/dashboard/executive");
  charts.forEach(x => x.destroy()); charts = [];
  const list = items => h("ul", {}, items.map(i => h("li", {}, i)));
  root.append(h("div", {class: "panel wide"}, h("h3", {}, "Threat landscape"), h("p", {}, e.narrative)));
  const grid = h("div", {class: "grid"}); root.append(grid);
  grid.append(h("div", {class: "panel"}, h("h3", {}, "High and critical records: " + e.critical_high_count), h("p", {}, "Most are indicators to monitor, not confirmed attacks."),
    h("h3", {}, "Top threat categories"), list(e.top_threat_categories.map(([k, v]) => k + " (" + v + ")"))));
  grid.append(h("div", {class: "panel"}, h("h3", {}, "Vulnerability areas needing attention"), list(e.top_vulnerability_categories.map(v => v.product_category + " (" + v.count + " urgent/high)")),
    h("h3", {}, "Top awareness weaknesses (quiz averages)"), list(e.top_awareness_weaknesses.map(w => w.category + ": " + w.avg_score + "%"))));
  grid.append(h("div", {class: "panel wide"}, h("h3", {}, "Recommended defensive priorities"), list(e.recommended_priorities)));
  drawChart(grid, "Awareness score trend (monthly average, synthetic + new quiz attempts)", "line", e.awareness_score_trend.map(x => x.month),
    [{label: "Average score", data: e.awareness_score_trend.map(x => x.avg_score), borderColor: "#0f6e8c", backgroundColor: "#0f6e8c"}], {wide: true});
}

const VIEWS = {overview: showOverview, threats: showThreats, search: showSearch, alerts: showAlerts, attack: showAttack, vulns: showVulns, exec: showExec};
function select(name) {
  document.querySelectorAll("#tabs button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  history.replaceState(null, "", "#" + name);
  VIEWS[name]().catch(e => view().append(h("p", {class: "bad"}, "Could not load data: " + e.message + ". Is the backend running?")));
}
document.addEventListener("DOMContentLoaded", () => {
  const tabs = document.getElementById("tabs");
  tabs.append(h("div", {class: "sep"}));
  TABS.forEach(([id, label]) => { const b = h("button", {class: "tab", "data-tab": id, onclick: () => select(id)}, label); tabs.append(b); });
  select(VIEWS[location.hash.slice(1)] ? location.hash.slice(1) : "overview");
});
