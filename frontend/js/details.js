"use strict";
async function load() {
  const root = document.getElementById("detail");
  const id = new URLSearchParams(location.search).get("id") || "";
  try {
    const t = await api("/api/threats/" + encodeURIComponent(id));
    clear(root);
    const kv = rows => h("dl", {class: "kv"}, rows.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
    root.append(h("h2", {}, t.threat_id + " - " + t.threat_name),
      h("p", {class: "sub"}, t.category + " | stage: " + t.entity_stage + " - " + t.stage_explanation),
      h("div", {class: "notice"}, h("b", {}, "Reading the scores: "), t.interpretation + " Risk is how concerning this may be; confidence is how much we trust the intelligence. Neither proves compromise."));
    const grid = h("div", {class: "grid"}); root.append(grid);
    grid.append(h("div", {class: "panel"}, h("h3", {}, "Summary"), kv([
      ["Indicator type", t.indicator_type], ["Indicator", h("code", {}, t.indicator_defanged)], ["Severity", badge(t.severity)],
      ["Risk score", t.risk_score + "/100"], ["Confidence score", t.confidence_score + "/100"],
      ["Source", t.source_name + " (reliability " + t.reliability + " - " + t.reliability_label + ")"],
      ["First seen", t.first_seen], ["Last seen", t.last_seen], ["Observations", t.observation_count], ["Status", t.status], ["Campaign", t.campaign_id || "-"]])));
    grid.append(h("div", {class: "panel"}, h("h3", {}, "Description"), h("p", {}, t.description),
      t.category_info.description ? h("p", {}, h("b", {}, "About this category: "), t.category_info.description) : null,
      h("p", {}, h("b", {}, "Potential impact: "), t.category_info.impact || "-")));
    grid.append(h("div", {class: "panel"}, h("h3", {}, "ATT&CK mapping"),
      t.attack_mappings.length ? t.attack_mappings.map(m => h("p", {}, h("b", {}, m.technique_id_optional + " " + m.technique), h("br"), "Tactic: " + m.tactic, h("br"), h("small", {}, m.rationale)))
        : h("p", {}, "No mapping: there is not enough evidence to justify one (low confidence, false positive, or no fitting technique).")));
    grid.append(h("div", {class: "panel"}, h("h3", {}, "Related indicators (same campaign)"),
      t.related_indicators.length ? table([{label: "Threat", render: r => h("a", {href: "threat-details.html?id=" + r.threat_id}, r.threat_id)}, {label: "Type", key: "indicator_type"},
        {label: "Indicator", render: ind}, {label: "Risk", key: "risk_score"}], t.related_indicators) : h("p", {}, "None. Correlation shows relationship, not attribution.")));
    grid.append(h("div", {class: "panel"}, h("h3", {}, "Related alerts"),
      t.alerts.length ? table([{label: "Alert", key: "alert_id"}, {label: "Type", key: "alert_type"}, {label: "Status", key: "status"}, {label: "Observations", key: "observation_count"}], t.alerts) : h("p", {}, "No alerts.")));
    if (t.cve) grid.append(h("div", {class: "panel"}, h("h3", {}, "CVE association (fictional)"), kv([["CVE", t.cve.cve_id], ["CVSS", t.cve.cvss_score], ["Priority", t.cve.priority_score + " - " + t.cve.priority_label], ["Exposure", t.cve.exposure]])));
    grid.append(h("div", {class: "panel"}, h("h3", {}, "Recommended defensive actions"), h("ul", {}, t.recommended_actions.map(a => h("li", {}, a)))));
    grid.append(h("div", {class: "panel wide"}, h("h3", {}, "Timeline"), h("ul", {class: "timeline"}, t.timeline.map(e => h("li", {}, h("b", {}, e.event), " ", h("small", {}, e.date), e.detail ? h("div", {}, e.detail) : null)))));
    const notes = h("div", {}, t.notes.map(n => h("p", {}, n.note, " ", h("small", {}, "- " + (n.author || "") + ", " + n.created_at.slice(0, 10)))));
    const box = h("textarea", {rows: 3, maxlength: 2000, "aria-label": "New analyst note", placeholder: "Add an analyst note (needs analyst API key)"});
    const btn = h("button", {class: "btn"}, "Save note");
    btn.addEventListener("click", async () => {
      try { const n = await api("/api/threats/" + t.threat_id + "/notes", {method: "POST", body: JSON.stringify({note: box.value})});
        notes.append(h("p", {}, n.note, " ", h("small", {}, "- " + n.author))); box.value = ""; toast("Note saved."); }
      catch (e) { toast(e.message); }
    });
    grid.append(h("div", {class: "panel wide"}, h("h3", {}, "Analyst notes"), notes, box, h("p", {}, btn)));
  } catch (e) { clear(root).append(h("p", {class: "bad"}, e.message)); }
}
document.addEventListener("DOMContentLoaded", load);
