/* Shared helpers. All dynamic text goes through textContent (never innerHTML) to prevent XSS. */
"use strict";
// Served by Flask (port 5000) -> same-origin. Served by `python -m http.server 8000` -> call the backend on 5000.
const BACKEND = (location.port && location.port !== "5000") ? "http://127.0.0.1:5000" : "";

async function api(path, opts = {}) {
  const headers = Object.assign({"Content-Type": "application/json"}, opts.headers || {});
  const key = sessionStorage.getItem("apiKey");
  if (key) headers["X-API-Key"] = key;
  const res = await fetch(BACKEND + path, Object.assign({}, opts, {headers}));
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (!res.ok) throw new Error((data && data.error) || ("Request failed: " + res.status));
  return data;
}
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
function badge(sev) { return h("span", {class: "badge b-" + sev}, sev); }
function toast(msg) { const t = h("div", {class: "toast", role: "status"}, msg); document.body.append(t); setTimeout(() => t.remove(), 3500); }
function table(cols, rows, onRow) {
  const thead = h("thead", {}, h("tr", {}, cols.map(c => h("th", {}, c.label))));
  const tbody = h("tbody", {}, rows.map(r => {
    const tr = h("tr", onRow ? {class: "click", tabindex: "0"} : {}, cols.map(c => h("td", {class: c.wrap ? "wrap" : ""}, c.render ? c.render(r) : r[c.key])));
    if (onRow) { tr.addEventListener("click", () => onRow(r)); tr.addEventListener("keydown", e => { if (e.key === "Enter") onRow(r); }); }
    return tr;
  }));
  return h("div", {class: "tablewrap"}, h("table", {}, thead, tbody));
}
function ind(r) { return h("code", {}, r.indicator_defanged || r.indicator_value); }
function nav(active) {
  const rail = document.getElementById("rail");
  const links = [["index.html", "Home"], ["threat-dashboard.html", "SOC dashboard"], ["awareness.html", "Awareness center"], ["quiz.html", "Awareness quiz"]];
  rail.append(h("h1", {}, "Cyber Awareness & Threat Intelligence"));
  links.forEach(([href, label]) => rail.append(h("a", {href, "aria-current": href === active ? "page" : null}, label)));
  const wrap = h("div", {class: "tabs"}); wrap.id = "tabs"; rail.append(wrap);
  rail.append(h("div", {class: "sep"}));
  const input = h("input", {id: "apikey", type: "password", autocomplete: "off", placeholder: "Only needed to save changes"});
  input.value = sessionStorage.getItem("apiKey") || "";
  input.addEventListener("change", () => { sessionStorage.setItem("apiKey", input.value.trim()); toast("API key kept for this tab only."); });
  rail.append(h("label", {for: "apikey"}, "Analyst API key"), input);
  rail.append(h("p", {class: "sub"}, "Synthetic / demo data only."));
}

document.addEventListener("DOMContentLoaded", () => { if (document.getElementById("rail")) nav(document.body.dataset.page || ""); });
