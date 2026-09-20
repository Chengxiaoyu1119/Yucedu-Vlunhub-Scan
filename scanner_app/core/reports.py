#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分类总结报告生成（公网 Web 靶场 / 内网穿透靶场 共用）

输出四种格式到扫描结果目录：
  report.html  主报告（自带样式、内嵌截图，浏览器直接看）
  report.md    Markdown 版
  report.csv   每行一个开放端口（公网）/ 每行一台主机（内网），便于排序筛选
  report.json  机器可读全量数据
"""

import csv
import datetime
import html
import io
import json
from pathlib import Path

from scanner_app.core.platform_support import GUI_DIR

REPORT_CSS = """
:root { --bg:#f5f5f7; --card:#fff; --card2:#fafafc; --text:#1d1d1f; --text2:#6e6e73;
  --blue:#007aff; --blue-bg:rgba(0,122,255,.1); --green:#248a3d; --green-bg:rgba(52,199,89,.14);
  --red:#c93400; --red-bg:rgba(255,59,48,.12); --sep:rgba(0,0,0,.07);
  --shadow:0 1px 2px rgba(0,0,0,.04),0 4px 14px rgba(0,0,0,.05); }
@media (prefers-color-scheme: dark) {
  :root { --bg:#1e1e22; --card:#2c2c31; --card2:#2a2a30; --text:#f5f5f7; --text2:#98989f;
    --blue:#0a84ff; --blue-bg:rgba(10,132,255,.16); --green:#30d158; --green-bg:rgba(48,209,88,.16);
    --red:#ff453a; --red-bg:rgba(255,69,58,.16); --sep:rgba(255,255,255,.09);
    --shadow:0 1px 2px rgba(0,0,0,.35),0 4px 14px rgba(0,0,0,.3); }
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Helvetica Neue",sans-serif;
  background:var(--bg); color:var(--text); padding:36px 40px 60px; -webkit-font-smoothing:antialiased; }
.wrap { max-width:1100px; margin:0 auto; }
h1 { font-size:26px; letter-spacing:-.4px; }
.meta { margin-top:8px; color:var(--text2); font-size:13px; line-height:1.8; }
.stats { display:flex; gap:12px; margin:26px 0 8px; flex-wrap:wrap; }
.stat { background:var(--card); border-radius:12px; padding:13px 20px 13px 17px; min-width:112px;
  box-shadow:var(--shadow); position:relative; overflow:hidden; }
.stat::before { content:""; position:absolute; left:0; top:10px; bottom:10px; width:3px;
  border-radius:0 2px 2px 0; background:var(--blue); }
.stat b { display:block; font-size:23px; font-weight:700; letter-spacing:-.4px; }
.stat span { font-size:12px; color:var(--text2); }
h2 { font-size:19px; margin:34px 0 12px; letter-spacing:-.3px; }
h2 .tag { font-size:12px; font-weight:600; padding:2px 9px; border-radius:99px;
  vertical-align:2px; margin-left:8px; }
.tag.ok { background:var(--green-bg); color:var(--green); }
.tag.no { background:var(--red-bg); color:var(--red); }
table { width:100%; border-collapse:collapse; background:var(--card); border-radius:12px;
  overflow:hidden; box-shadow:var(--shadow); }
th,td { text-align:left; padding:10px 14px; font-size:13px; border-bottom:1px solid var(--sep); }
th { background:var(--card2); font-weight:600; color:var(--text2); font-size:12px; }
tr:last-child td { border-bottom:none; }
tbody tr:hover { background:rgba(0,122,255,.035); }
code { font-family:"SF Mono",Menlo,monospace; font-size:12px; background:rgba(0,0,0,.05);
  padding:1px 6px; border-radius:5px; }
@media (prefers-color-scheme: dark) { code { background:rgba(255,255,255,.08); } }
.sites { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; margin-top:14px; }
.site { background:var(--card); border-radius:12px; overflow:hidden;
  box-shadow:var(--shadow); transition:box-shadow .15s; }
.site:hover { box-shadow:0 2px 6px rgba(0,0,0,.05),0 10px 28px rgba(0,0,0,.1); }
.site img { width:100%; height:172px; object-fit:cover; object-position:top; display:block;
  background:#2d2e32; }
.site.no-shot img { height:96px; display:flex; align-items:center; justify-content:center;
  color:var(--text2); font-size:12px; }
.site .info { padding:12px 14px; }
.site .t { font-size:14px; font-weight:600; white-space:nowrap; overflow:hidden;
  text-overflow:ellipsis; display:flex; align-items:center; gap:7px; }
.fav { width:17px; height:17px; border-radius:4px; flex-shrink:0; object-fit:cover; }
.fav-dot { width:8px; height:8px; border-radius:50%; background:#c7c7cc; flex-shrink:0; }
.site .u { font-family:"SF Mono",Menlo,monospace; font-size:12px; color:var(--text2); margin-top:2px; }
.site .b { margin-top:8px; font-size:12px; color:var(--text2); }
.badge { font-size:11px; font-weight:600; padding:1px 8px; border-radius:99px;
  background:var(--blue-bg); color:var(--blue); }
.empty { background:var(--card); border-radius:12px; padding:22px; color:var(--text2);
  font-size:13px; box-shadow:var(--shadow); }
.charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; margin:22px 0 6px; }
.chart-box { background:var(--card); border-radius:12px; padding:14px 16px 16px;
  box-shadow:var(--shadow); display:flex; flex-direction:column; }
.chart-box h3 { font-size:12.5px; font-weight:600; color:var(--text2);
  text-align:left; margin-bottom:10px; }
.chart-box .cwrap { flex:1; position:relative; min-height:190px; }
.footnote { margin-top:40px; color:var(--text2); font-size:12px; }
"""

_BASE_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>{title}</title><style>{css}</style></head>
<body><div class="wrap">{body}
<p class="footnote">由靶场扫描助手生成 · 仅用于授权靶场环境的安全教学与测试</p>
</div></body></html>"""


def esc(s):
    return html.escape(str(s if s is not None else ""))


def _stat_html(items):
    cells = "".join(f'<div class="stat"><b>{esc(v)}</b><span>{esc(k)}</span></div>'
                    for k, v in items)
    return f'<div class="stats">{cells}</div>'


def _table(headers, rows):
    thead = "".join(f"<th>{esc(h)}</th>" for h in headers)
    trs = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{trs or ''}</tbody></table>"


# ================= 报告内嵌图表（Chart.js 离线自包含） =================

CHART_JS_PATH = GUI_DIR / "chart.umd.min.js"

# 与 GUI 看板一致的 Apple 调色板
_C = {"blue": "#007aff", "green": "#34c759", "orange": "#ff9500", "red": "#ff3b30",
      "purple": "#af52de", "teal": "#5ac8fa", "pink": "#ff2d55", "gray": "#8e8e93"}

# 图表运行时：遍历 spec 数组建 Chart.js 实例（spec 由 Python 侧聚合并序列化）
_REPORT_CHART_RUNTIME = """
(function () {
  if (typeof Chart === "undefined") return;
  Chart.defaults.font.family = '-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif';
  Chart.defaults.font.size = 11;
  Chart.defaults.color = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches)
    ? "#98989f" : "#86868b";
  Chart.defaults.animation.duration = 600;
  Chart.defaults.animation.easing = "easeOutQuart";
  var centerText = {
    id: "ct",
    afterDraw: function (c) {
      var ctr = c.config.options._center;
      if (!ctr) return;
      var a = c.chartArea, x = (a.left + a.right) / 2, y = (a.top + a.bottom) / 2;
      var ctx = c.ctx;
      ctx.save(); ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.font = "800 22px -apple-system, sans-serif";
      ctx.fillStyle = getComputedStyle(document.body).color;
      ctx.fillText(String(ctr[0]), x, y - 8);
      ctx.font = "500 10.5px -apple-system, sans-serif"; ctx.fillStyle = Chart.defaults.color;
      ctx.fillText(ctr[1], x, y + 12);
      ctx.restore();
    }
  };
  window.__mkReportChart = function (s) {
    var el = document.getElementById(s.id);
    if (!el) return;
    var donut = s.type === "doughnut";
    var total = (s.data || []).reduce(function (a, b) { return a + b; }, 0);
    new Chart(el, {
      type: s.type,
      data: {
        labels: s.labels,
        datasets: [{
          data: s.data,
          backgroundColor: donut ? s.colors : s.colors.map(function (c) { return c + "44"; }),
          borderColor: s.colors,
          borderWidth: donut ? 2 : 1.5,
          borderRadius: donut ? 0 : 6,
          maxBarThickness: 44,
          hoverOffset: donut ? 6 : 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: donut ? "62%" : undefined,
        _center: donut && s.center ? [total, s.center] : null,
        plugins: {
          legend: {
            display: donut, position: "right",
            labels: { usePointStyle: true, boxHeight: 7, font: { size: 10.5 } }
          },
          tooltip: {
            backgroundColor: "rgba(30,30,30,0.88)", cornerRadius: 8, padding: 10,
            callbacks: {
              label: function (ctx) {
                var pct = total ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                return " " + ctx.label + "：" + ctx.parsed + (s.unit || "") + "（" + pct + "%）";
              }
            }
          }
        },
        scales: donut ? undefined : {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: "rgba(0,0,0,0.04)" }, ticks: { precision: 0 } }
        }
      },
      plugins: donut ? [centerText] : []
    });
  };
})();
"""


def _public_chart_specs(results):
    """公网报告：端口分布 / HTTP 状态码 / 各目标端口数 / 服务类型"""
    pairs = [(t["ip"], r) for t in results for r in t["ports"].values()
             if r["state"] == "open"]
    if not pairs:
        return []
    specs = []

    ranges = [("0–999", 0, 999), ("1k–4999", 1000, 4999), ("5k–7999", 5000, 7999),
              ("8k–9999", 8000, 9999), ("10k–19999", 10000, 19999),
              ("20k–65535", 20000, 65535)]
    counts = [0] * len(ranges)
    for _, r in pairs:
        for i, (_, lo, hi) in enumerate(ranges):
            if lo <= r["port"] <= hi:
                counts[i] += 1
                break
    if sum(counts):
        specs.append({"type": "doughnut", "id": "rcPort", "title": "端口分布",
                      "labels": [r[0] for r in ranges], "data": counts,
                      "colors": [_C["blue"], _C["teal"], _C["green"], _C["orange"],
                                 _C["purple"], _C["pink"]],
                      "center": "总端口", "unit": " 个端口"})

    cmap = {"2xx 成功": _C["green"], "3xx 重定向": _C["blue"],
            "4xx 客户端错误": _C["orange"], "5xx 服务端错误": _C["red"]}
    buckets = {}
    for _, r in pairs:
        if not r.get("is_http"):
            continue
        code = r.get("status") or 0
        if 200 <= code < 300:
            lbl = "2xx 成功"
        elif 300 <= code < 400:
            lbl = "3xx 重定向"
        elif 400 <= code < 500:
            lbl = "4xx 客户端错误"
        elif code >= 500:
            lbl = "5xx 服务端错误"
        else:
            lbl = str(code)
        buckets[lbl] = buckets.get(lbl, 0) + 1
    if buckets:
        specs.append({"type": "bar", "id": "rcStatus", "title": "HTTP 状态码",
                      "labels": list(buckets), "data": list(buckets.values()),
                      "colors": [cmap.get(k, _C["gray"]) for k in buckets], "unit": " 个"})

    ip_counts = {}
    for ip, _ in pairs:
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    ranked = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:12]
    shades = ["#007affcc", "#007aff88", "#007aff55"]
    specs.append({"type": "bar", "id": "rcTarget", "title": "各目标端口数",
                  "labels": [k for k, _ in ranked], "data": [v for _, v in ranked],
                  "colors": [shades[min(i, 2)] for i in range(len(ranked))], "unit": " 个"})

    http_n = sum(1 for _, r in pairs if r.get("is_http"))
    https_n = sum(1 for _, r in pairs
                  if r.get("is_http") and r.get("scheme") == "https")
    non_http = len(pairs) - http_n
    http_only = http_n - https_n
    vals, labels, colors = [], [], []
    if http_only:
        vals.append(http_only); labels.append("HTTP"); colors.append(_C["teal"])
    if https_n:
        vals.append(https_n); labels.append("HTTPS"); colors.append(_C["blue"])
    if non_http:
        vals.append(non_http); labels.append("非 HTTP"); colors.append(_C["gray"])
    if vals:
        specs.append({"type": "doughnut", "id": "rcSvc", "title": "服务类型占比",
                      "labels": labels, "data": vals, "colors": colors,
                      "center": "总服务", "unit": " 个"})
    return specs


def _internal_chart_specs(alive_hosts):
    """内网报告：操作系统分布 / 端口开放热度 / 发现方式 / TTL 分布"""
    if not alive_hosts:
        return []
    specs = []

    os_counts = {}
    for h in alive_hosts:
        g = h.get("os_guess", "未知")
        os_counts[g] = os_counts.get(g, 0) + 1
    cmap = {"Linux": _C["green"], "Windows": _C["blue"], "未知": _C["gray"]}
    specs.append({"type": "doughnut", "id": "rcOS", "title": "操作系统分布",
                  "labels": list(os_counts), "data": list(os_counts.values()),
                  "colors": [cmap.get(k, _C["gray"]) for k in os_counts],
                  "center": "总主机", "unit": " 台"})

    port_counts = {}
    for h in alive_hosts:
        for p in h.get("open_ports") or []:
            port_counts[p] = port_counts.get(p, 0) + 1
    ranked = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:12]
    if ranked:
        n = len(alive_hosts)
        colors = []
        for _, v in ranked:
            if v >= n * 0.7:
                colors.append(_C["red"])
            elif v >= n * 0.4:
                colors.append(_C["orange"])
            else:
                colors.append(_C["blue"])
        specs.append({"type": "bar", "id": "rcHeat", "title": "端口开放热度（Top 12）",
                      "labels": [str(k) for k, _ in ranked],
                      "data": [v for _, v in ranked],
                      "colors": colors, "unit": " 台"})

    via = {"ICMP": sum(1 for h in alive_hosts if h.get("via") == "icmp"),
           "TCP 兜底": sum(1 for h in alive_hosts if h.get("via") != "icmp")}
    if sum(via.values()):
        specs.append({"type": "doughnut", "id": "rcVia", "title": "发现方式",
                      "labels": list(via), "data": list(via.values()),
                      "colors": [_C["green"], _C["orange"]],
                      "center": "总发现", "unit": " 台"})

    ttl_buckets = {"≤64": 0, "65–100": 0, "101–128": 0, ">128": 0, "无 TTL": 0}
    for h in alive_hosts:
        t = h.get("ttl")
        if t is None:
            ttl_buckets["无 TTL"] += 1
        elif t <= 64:
            ttl_buckets["≤64"] += 1
        elif t <= 100:
            ttl_buckets["65–100"] += 1
        elif t <= 128:
            ttl_buckets["101–128"] += 1
        else:
            ttl_buckets[">128"] += 1
    tmap = {"≤64": _C["green"], "65–100": _C["teal"], "101–128": _C["blue"],
            ">128": _C["orange"], "无 TTL": _C["gray"]}
    kept = {k: v for k, v in ttl_buckets.items() if v > 0}
    if kept:
        specs.append({"type": "bar", "id": "rcTTL", "title": "TTL 分布",
                      "labels": list(kept), "data": list(kept.values()),
                      "colors": [tmap[k] for k in kept], "unit": " 台"})
    return specs


def _charts_section(specs):
    """内联 Chart.js（离线可用）+ spec 数据 + 初始化脚本；库缺失时静默跳过"""
    if not specs or not CHART_JS_PATH.is_file():
        return ""
    boxes = "".join(
        f'<div class="chart-box"><h3>{esc(s["title"])}</h3>'
        f'<div class="cwrap"><canvas id="{esc(s["id"])}"></canvas></div></div>'
        for s in specs)
    lib = CHART_JS_PATH.read_text(encoding="utf-8")
    spec_json = json.dumps(specs, ensure_ascii=False)
    init = (f'document.addEventListener("DOMContentLoaded",function(){{'
            f'{spec_json}.forEach(__mkReportChart);}});')
    return (f'<div class="charts">{boxes}</div>'
            f'<script>{lib}</script>'
            f'<script>{_REPORT_CHART_RUNTIME}</script>'
            f'<script>{init}</script>')


# ================= 公网 Web 靶场报告 =================

def _qualified_public_results(results):
    """报告层再过滤一次，仅保留具备可展示靶场页面的端口（开放 + HTTP + 有标题）。

    注意：不再要求 ping 存活。域名/子域靶场常禁 ICMP，扫描层已通过
    is_qualified_target(require_ping=False) 完成合格判定并把结果传入本函数，
    这里若再按 ping 过滤会把合法的域名靶场丢弃。端口质量过滤本身已足够
    排除无效目标。
    """
    qualified = []
    for target in results:
        ports = {
            str(key): port
            for key, port in (target.get("ports") or {}).items()
            if port.get("state") == "open"
            and port.get("is_http") is True
            and bool(str(port.get("title") or "").strip())
        }
        if not ports:
            continue
        item = dict(target)
        item["ports"] = ports
        item["open_count"] = len(ports)
        qualified.append(item)
    return qualified

def public_stats(results):
    results = _qualified_public_results(results)
    targets = len(results)
    alive = sum(1 for t in results if t["ping"]["alive"])
    open_ports = sum(t.get("open_count", 0) for t in results)
    sites = sum(1 for t in results for r in t["ports"].values()
                if r["state"] == "open" and r.get("is_http"))
    shots = sum(1 for t in results for r in t["ports"].values() if r.get("screenshot"))
    return {"目标数": targets, "ping 存活": alive, "开放端口": open_ports,
            "网站数": sites, "截图数": shots}


def write_public_report(results, outdir: Path, port_start, port_end, threads, timeout,
                        ports=None, duration=None):
    results = _qualified_public_results(results)
    if not results:
        return
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st = public_stats(results)
    if ports:
        port_desc = f"端口列表（共 {len(ports)} 个）"
    else:
        port_desc = f"端口范围：{esc(port_start)}-{esc(port_end)}（共 {port_end - port_start + 1} 个）"
    dur_desc = f" · 耗时 {esc(duration)}s" if duration is not None else ""

    # ---------- HTML ----------
    body = [f"<h1>靶场扫描报告 · 公网 Web 靶场</h1>",
            f'<div class="meta">扫描时间：{esc(now)}<br>'
            f'目标：{esc("、".join(t["ip"] for t in results))}<br>'
            f'端口：{esc(port_desc)} · '
            f'并发 {esc(threads)} 线程 · 超时 {esc(timeout)}s{dur_desc}</div>',
            _stat_html(st.items()),
            _charts_section(_public_chart_specs(results))]

    for t in results:
        p = t["ping"]
        if p["alive"]:
            ms = f"（{p['latency_ms']:.1f} ms）" if p["latency_ms"] is not None else ""
            ping_html = f'<span class="tag ok">ping 通{esc(ms)}</span>'
        else:
            ping_html = '<span class="tag no">ping 不通（可能禁 ICMP）</span>'
        body.append(f"<h2>{esc(t['ip'])} {ping_html}</h2>")

        open_ports = sorted((r for r in t["ports"].values() if r["state"] == "open"),
                            key=lambda r: r["port"])
        if not open_ports:
            body.append(f'<div class="empty">未发现开放端口（共扫描 {len(t["ports"])} 个端口）</div>')
            continue

        rows = []
        for r in open_ports:
            if r.get("is_http"):
                shot = "✓" if r.get("screenshot") else "-"
                rows.append([r["port"], r["scheme"], r["status"],
                             esc(r["server"] or "-"), esc(r["title"] or "(无)"), shot])
            else:
                rows.append([r["port"], "-", "-", "-", '开放（非 HTTP）', "-"])
        body.append(_table(["端口", "协议", "状态码", "Server", "Title", "截图"],
                           [[f"<code>{c}</code>" if i == 0 else c for i, c in enumerate(row)]
                            for row in rows]))

        site_cards = []
        for r in open_ports:
            if not r.get("is_http"):
                continue
            url = f"{r['scheme']}://{t['ip']}:{r['port']}/"
            shot = r.get("screenshot")
            if shot:
                img = f'<img src="{esc(shot)}" alt="首页截图" loading="lazy">'
                cls = "site"
            else:
                img = '<img alt="">'
                cls = "site no-shot"
            fav = r.get("favicon")
            fav_html = (f'<img class="fav" src="{esc(fav)}" alt="">' if fav
                        else '<span class="fav-dot"></span>')
            site_cards.append(
                f'<div class="{cls}">{img}<div class="info">'
                f'<div class="t" title="{esc(r["title"])}">{fav_html}{esc(r["title"] or "(无标题)")}</div>'
                f'<div class="u">{esc(url)}</div>'
                f'<div class="b"><span class="badge">{esc(r["status"])}</span> '
                f'{esc(r["server"] or "")}</div></div></div>')
        if site_cards:
            body.append(f'<div class="sites">{"".join(site_cards)}</div>')

    html_text = _BASE_HTML.format(title="靶场扫描报告 · 公网 Web 靶场",
                                  css=REPORT_CSS, body="\n".join(body))
    (outdir / "report.html").write_text(html_text, encoding="utf-8")

    # ---------- Markdown ----------
    md = [f"# 靶场扫描报告 · 公网 Web 靶场", "",
          f"- 扫描时间：{now}",
          f"- 目标：{', '.join(t['ip'] for t in results)}",
          f"- 端口：{port_desc}，并发 {threads} 线程，超时 {timeout}s" +
          (f"，耗时 {duration}s" if duration is not None else ""), "",
          f"**统计**：{' · '.join(f'{k} {v}' for k, v in st.items())}", ""]
    for t in results:
        p = t["ping"]
        md.append(f"## {t['ip']}")
        if p["alive"] and p["latency_ms"] is not None:
            md.append(f"- ping：通（{p['latency_ms']:.1f} ms）")
        elif p["alive"]:
            md.append("- ping：通")
        else:
            md.append("- ping：不通（可能禁 ICMP）")
        open_ports = sorted((r for r in t["ports"].values() if r["state"] == "open"),
                            key=lambda r: r["port"])
        if not open_ports:
            md += ["", f"未发现开放端口（共扫描 {len(t['ports'])} 个端口）", ""]
            continue
        md += ["", "| 端口 | 协议 | 状态码 | Server | Title | 截图 |",
               "|------|------|--------|--------|-------|------|"]
        for r in open_ports:
            if r.get("is_http"):
                md.append(f"| {r['port']} | {r['scheme']} | {r['status']} "
                          f"| {(r['server'] or '-').replace('|', chr(92) + '|')} "
                          f"| {(r['title'] or '(无)').replace('|', chr(92) + '|')} "
                          f"| {r.get('screenshot', '-')} |")
            else:
                md.append(f"| {r['port']} | - | - | - | 开放（非 HTTP） | - |")
        md.append("")
        for r in open_ports:
            if r.get("is_http"):
                md.append(f"### {t['ip']}:{r['port']} — {r['title'] or '(无标题)'}")
                md.append(f"`{r['scheme']}://{t['ip']}:{r['port']}/` · "
                          f"状态 {r['status']} · {r['server'] or 'Server 未知'}")
                if r.get("screenshot"):
                    md.append(f"![首页截图]({r['screenshot']})")
                md.append("")
    (outdir / "report.md").write_text("\n".join(md), encoding="utf-8")

    # ---------- CSV ----------
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "ping_ms", "port", "scheme", "status", "server", "title", "screenshot"])
    for t in results:
        for r in sorted((x for x in t["ports"].values() if x["state"] == "open"),
                        key=lambda x: x["port"]):
            w.writerow([t["ip"],
                        f"{t['ping']['latency_ms']:.1f}" if t["ping"]["latency_ms"] is not None else "",
                        r["port"],
                        r.get("scheme", ""),
                        r.get("status", ""),
                        r.get("server", ""),
                        r.get("title", ""),
                        r.get("screenshot", "")])
    (outdir / "report.csv").write_text(buf.getvalue(), encoding="utf-8-sig")  # BOM 便于 Excel 识别中文

    # ---------- JSON ----------
    (outdir / "report.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


# ================= 内网穿透靶场报告 =================

def write_internal_report(hosts, outdir: Path, meta, duration=None):
    """hosts: internal_scanner.run_internal_scan 的返回列表；meta: 含 cidrs/ports 等的字典"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alive_hosts = [h for h in hosts if h["alive"]]
    dur_desc = f" · 耗时 {esc(duration)}s" if duration is not None else ""

    def count(guess):
        return sum(1 for h in alive_hosts if h["os_guess"] == guess)

    counts = {"存活主机": len(alive_hosts), "Linux": count("Linux"),
              "Windows": count("Windows"), "未知": count("未知"),
              "总 IP 数": meta["total_hosts"]}

    # ---------- HTML ----------
    body = [f"<h1>靶场扫描报告 · 内网穿透靶场</h1>",
            f'<div class="meta">扫描时间：{esc(now)}<br>'
            f'网段：{esc("、".join(meta["cidrs"]))}<br>'
            f'探测端口：{esc(", ".join(map(str, meta["ports"])))} · '
            f'并发 {esc(meta["threads"])} 线程 · 超时 {esc(meta["timeout"])}s{dur_desc}<br>'
            f'探测方式：ICMP + TCP 兜底 · 无凭据发现（不做爆破/登录）</div>',
            _stat_html(counts.items()),
            _charts_section(_internal_chart_specs(alive_hosts))]

    if not alive_hosts:
        body.append('<div class="empty">未发现存活主机 —— 请确认向日葵 VPN 已连通、网段配置正确</div>')
    else:
        for guess, title in (("Linux", "Linux 主机"), ("Windows", "Windows 主机"),
                             ("未知", "未识别系统")):
            group = [h for h in alive_hosts if h["os_guess"] == guess]
            if not group:
                continue
            body.append(f"<h2>{title}（{len(group)} 台）</h2>")
            rows = []
            for h in sorted(group, key=lambda x: tuple(map(int, x["ip"].split(".")))):
                via = "ICMP" if h["via"] == "icmp" else "TCP"
                rows.append([f"<code>{esc(h['ip'])}</code>", via,
                             h["ttl"] if h["ttl"] else "-",
                             esc(h.get("mac") or "-"),
                             ", ".join(map(str, h["open_ports"])) or "-",
                             esc(h["ssh_banner"] or h["http_title"] or "-"),
                             esc("；".join(h["reasons"]) or "-")])
            body.append(_table(["IP", "发现方式", "TTL", "MAC 地址", "开放端口",
                                "SSH Banner / Web 标题", "判断依据"], rows))

    html_text = _BASE_HTML.format(title="靶场扫描报告 · 内网穿透靶场",
                                  css=REPORT_CSS, body="\n".join(body))
    (outdir / "report.html").write_text(html_text, encoding="utf-8")

    # ---------- Markdown ----------
    md = [f"# 靶场扫描报告 · 内网穿透靶场", "",
          f"- 扫描时间：{now}",
          f"- 网段：{', '.join(meta['cidrs'])}（共 {meta['total_hosts']} 个 IP）",
          f"- 探测端口：{', '.join(map(str, meta['ports']))}；并发 {meta['threads']} 线程，超时 {meta['timeout']}s" +
          (f"，耗时 {duration}s" if duration is not None else ""),
          f"- 探测方式：ICMP ping + TCP 兜底，无凭据发现", "",
          f"**统计**：{' · '.join(f'{k} {v}' for k, v in counts.items())}", ""]
    if not alive_hosts:
        md.append("未发现存活主机 —— 请确认向日葵 VPN 已连通、网段配置正确")
    for guess, title in (("Linux", "Linux 主机"), ("Windows", "Windows 主机"), ("未知", "未识别系统")):
        group = [h for h in alive_hosts if h["os_guess"] == guess]
        if not group:
            continue
        md.append(f"## {title}（{len(group)} 台）")
        md += ["| IP | 发现方式 | TTL | MAC 地址 | 开放端口 | Banner / 标题 | 判断依据 |",
               "|----|----------|-----|----------|----------|---------------|----------|"]
        for h in sorted(group, key=lambda x: tuple(map(int, x["ip"].split(".")))):
            md.append(f"| {h['ip']} | {'ICMP' if h['via'] == 'icmp' else 'TCP'} "
                      f"| {h['ttl'] or '-'} | {h.get('mac') or '-'} "
                      f"| {', '.join(map(str, h['open_ports'])) or '-'} "
                      f"| {(h['ssh_banner'] or h['http_title'] or '-').replace('|', chr(92) + '|')} "
                      f"| {'；'.join(h['reasons']).replace('|', chr(92) + '|') or '-'} |")
        md.append("")
    (outdir / "report.md").write_text("\n".join(md), encoding="utf-8")

    # ---------- CSV ----------
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "alive", "found_via", "ttl", "mac", "latency_ms", "os_guess",
                "open_ports", "ssh_banner", "http_title", "reasons"])
    for h in hosts:
        w.writerow([h["ip"], h["alive"], h["via"], h["ttl"] or "", h.get("mac") or "",
                    f"{h['latency_ms']:.1f}" if h["latency_ms"] is not None else "",
                    h["os_guess"], " ".join(map(str, h["open_ports"])),
                    h["ssh_banner"], h["http_title"], "；".join(h["reasons"])])
    (outdir / "report.csv").write_text(buf.getvalue(), encoding="utf-8-sig")

    # ---------- JSON ----------
    data = {"mode": "internal", "cidrs": meta["cidrs"], "counts": counts, "hosts": hosts}
    (outdir / "report.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return counts
