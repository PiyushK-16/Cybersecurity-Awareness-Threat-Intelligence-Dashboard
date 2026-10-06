"use strict";
document.addEventListener("DOMContentLoaded", async () => {
  const root = document.getElementById("quiz");
  try {
    const qs = await api("/api/quiz");
    const form = h("div", {});
    qs.forEach((q, i) => {
      form.append(h("fieldset", {class: "panel"}, h("legend", {}, (i + 1) + ". [" + q.category + "] " + q.question),
        h("div", {class: "opts"}, Object.entries(q.options).map(([k, v]) =>
          h("label", {}, h("input", {type: "radio", name: q.id, value: k}), " " + k + ". " + v)))));
    });
    const submit = h("button", {class: "btn"}, "Submit answers");
    root.append(form, h("p", {}, submit));
    submit.addEventListener("click", async () => {
      const answers = {};
      qs.forEach(q => { const c = document.querySelector('input[name="' + q.id + '"]:checked'); if (c) answers[q.id] = c.value; });
      if (!Object.keys(answers).length) { toast("Answer at least one question first."); return; }
      try { show(await api("/api/quiz/submit", {method: "POST", body: JSON.stringify({answers})}), qs); }
      catch (e) { toast(e.message); }
    });
  } catch (e) { root.append(h("p", {class: "bad"}, e.message)); }

  function show(r, qs) {
    clear(root);
    root.append(h("div", {class: "panel"}, h("div", {class: "score"}, r.overall_score + "/100"), h("h3", {}, r.level), h("p", {}, r.disclaimer)));
    const cats = h("div", {class: "panel"}, h("h3", {}, "Category scores"));
    Object.entries(r.category_scores).sort((a, b) => a[1] - b[1]).forEach(([c, s]) =>
      { const fill = h("i"); fill.style.width = s + "%"; cats.append(h("p", {}, c + ": " + s + "%", h("div", {class: "bar"}, fill))); });
    root.append(cats);
    root.append(h("div", {class: "panel"}, h("h3", {}, "Weakest areas"), r.weakest_areas.length ? h("p", {}, r.weakest_areas.join(", ")) : h("p", {}, "None below 75% - nice work."),
      h("h3", {}, "Recommended learning"), h("ul", {}, r.recommendations.map(x => h("li", {}, x.category + " (" + x.score + "%): " + x.recommendation + " ",
        x.module_id && x.score < 75 ? h("a", {href: "awareness.html"}, "Open center") : null)))));
    const det = h("div", {class: "panel"}, h("h3", {}, "Answers explained"));
    r.details.forEach((d, i) => det.append(h("p", {class: d.correct ? "ok" : "bad"}, (i + 1) + ". " + (d.correct ? "Correct. " : "Not quite - correct answer " + d.correct_answer + ". "), d.explanation)));
    root.append(det, h("p", {}, h("button", {class: "btn ghost", onclick: () => location.reload()}, "Retake quiz")));
  }
});
