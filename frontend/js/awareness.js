"use strict";
document.addEventListener("DOMContentLoaded", async () => {
  const pick = document.getElementById("pick"), out = document.getElementById("mod");
  try {
    const mods = await api("/api/awareness/modules");
    mods.forEach(m => pick.append(h("option", {value: m.slug}, m.title)));
    const list = items => h("ul", {}, items.map(i => h("li", {}, i)));
    function render(slug) {
      const m = mods.find(x => x.slug === slug) || mods[0];
      history.replaceState(null, "", "#" + m.slug); pick.value = m.slug;
      clear(out).append(h("div", {class: "panel"}, h("h3", {}, m.title),
        h("p", {}, h("b", {}, "What is it? "), m.what_is_it), h("p", {}, h("b", {}, "Why does it matter? "), m.why_it_matters),
        h("h3", {}, "Warning signs"), list(m.warning_signs), h("h3", {}, "Safe practices"), list(m.safe_practices),
        h("h3", {}, "What to do if something happens"), list(m.if_something_happens),
        m.safe_examples ? [h("h3", {}, "Safe, fictional examples"), m.safe_examples.map(e => h("p", {class: "notice"}, h("b", {}, e.label + ": "), e.text))] : null,
        h("p", {}, h("a", {href: "quiz.html"}, "Test yourself with the quiz"))));
    }
    pick.addEventListener("change", () => render(pick.value));
    render(location.hash.slice(1));
  } catch (e) { out.append(h("p", {class: "bad"}, e.message)); }
});
