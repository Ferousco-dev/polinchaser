// Dependency-free SVG charts. Colours come from CSS variables so light/dark
// themes and the palette live in one place (styles.css).
import { h, svg, fmt } from "./lib.js";

const W = 640, H = 220, M = { t: 10, r: 10, b: 24, l: 34 };

function niceMax(v) {
  // The axis has four intervals, so pick a whole-number step: labels stay integers.
  const need = Math.max(1, Math.ceil(v / 4));
  const p = Math.pow(10, Math.floor(Math.log10(need)));
  for (const m of [1, 2, 5, 10]) if (m * p >= need) return 4 * m * p;
  return 4 * need;
}

function frame(data, max, xLabelEvery) {
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  const iw = W - M.l - M.r, ih = H - M.t - M.b;
  for (let i = 0; i <= 4; i++) {
    const y = M.t + ih - (ih * i) / 4;
    root.append(svg("line", { class: "grid-l", x1: M.l, x2: W - M.r, y1: y, y2: y }));
    root.append(svg("text", { x: M.l - 6, y: y + 4, "text-anchor": "end" }, fmt.num(Math.round((max * i) / 4 * 10) / 10)));
  }
  data.forEach((d, i) => {
    if (i % xLabelEvery === 0) root.append(svg("text", { x: M.l + (iw * (i + 0.5)) / data.length, y: H - 6, "text-anchor": "middle" }, d.day.slice(5)));
  });
  return { root, iw, ih };
}

function tooltipFor(box, root, data, series, count) {
  const tip = h("div", { class: "tip", hidden: true });
  box.append(tip);
  const iw = W - M.l - M.r;
  root.addEventListener("pointermove", (e) => {
    const r = root.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * W;
    const i = Math.max(0, Math.min(data.length - 1, Math.floor(((x - M.l) / iw) * data.length)));
    const d = data[i];
    tip.replaceChildren(h("b", {}, d.day), ...series.map((s) => h("div", {}, h("i", { class: "sw", style: null }), `${s.label}: ${count(d, s)}`)));
    tip.querySelectorAll("i").forEach((el, k) => el.setAttribute("class", "sw"));
    tip.querySelectorAll("i").forEach((el, k) => { el.style.background = `var(${series[k].color})`; });
    tip.hidden = false;
    tip.style.left = `${((M.l + (iw * (i + 0.5)) / data.length) / W) * r.width}px`;
    tip.style.top = `${Math.max(30, (e.clientY - r.top))}px`;
  });
  root.addEventListener("pointerleave", () => { tip.hidden = true; });
}

function legend(series) {
  return h("div", { class: "legend" }, series.map((s) => h("span", {}, h("i", { "data-c": s.color }), s.label)));
}

function paintLegend(el, series) {
  el.querySelectorAll("i").forEach((i, k) => { i.style.background = `var(${series[k].color})`; });
  return el;
}

/** Stacked daily bars. series: [{key,label,color:'--c0'}] */
export function stackedBars(data, series) {
  const box = h("div", { class: "chart" });
  const max = niceMax(Math.max(1, ...data.map((d) => series.reduce((a, s) => a + Number(d[s.key] || 0), 0))));
  const { root, iw, ih } = frame(data, max, Math.ceil(data.length / 7));
  const bw = (iw / data.length) * 0.62;
  data.forEach((d, i) => {
    let y = M.t + ih;
    const x = M.l + (iw * (i + 0.5)) / data.length - bw / 2;
    for (const s of series) {
      const v = Number(d[s.key] || 0);
      if (!v) continue;
      const hh = (v / max) * ih;
      y -= hh;
      const r = svg("rect", { x, y, width: bw, height: Math.max(hh - 1, 1), rx: 1.5 });
      r.style.fill = `var(${s.color})`;
      root.append(r);
    }
  });
  box.append(root);
  tooltipFor(box, root, data, series, (d, s) => fmt.num(d[s.key] || 0));
  box.append(paintLegend(legend(series), series));
  return box;
}

/** Multi-series line chart; null values break the line. */
export function lineChart(data, series, unit = "") {
  const box = h("div", { class: "chart" });
  const vals = data.flatMap((d) => series.map((s) => (d[s.key] == null ? 0 : Number(d[s.key]))));
  const max = niceMax(Math.max(1, ...vals));
  const { root, iw, ih } = frame(data, max, Math.ceil(data.length / 7));
  for (const s of series) {
    let dpath = "", pen = false;
    data.forEach((d, i) => {
      if (d[s.key] == null) { pen = false; return; }
      const x = M.l + (iw * (i + 0.5)) / data.length, y = M.t + ih - (Number(d[s.key]) / max) * ih;
      dpath += `${pen ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)} `;
      pen = true;
    });
    const p = svg("path", { d: dpath, fill: "none", "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" });
    p.style.stroke = `var(${s.color})`;
    root.append(p);
    data.forEach((d, i) => {
      if (d[s.key] == null) return;
      const c = svg("circle", { cx: M.l + (iw * (i + 0.5)) / data.length, cy: M.t + ih - (Number(d[s.key]) / max) * ih, r: 2.5 });
      c.style.fill = `var(${s.color})`;
      root.append(c);
    });
  }
  box.append(root);
  tooltipFor(box, root, data, series, (d, s) => (d[s.key] == null ? "no data" : d[s.key] + unit));
  box.append(paintLegend(legend(series), series));
  return box;
}

/** Horizontal bars for ranked categories. items: [{label,value}] */
export function hbars(items, color = "--c0") {
  const max = Math.max(1, ...items.map((i) => i.value));
  return h("div", {}, items.map((i) => {
    const fill = h("div", { class: "fill" });
    fill.style.width = `${(i.value / max) * 100}%`;
    fill.style.background = `var(${i.color || color})`;
    return h("div", { class: "hbar" }, h("span", { class: "trunc" }, i.label), h("div", { class: "track" }, fill), h("span", { class: "n" }, fmt.num(i.value)));
  }));
}
