#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 report.html 内嵌图表：用模拟数据生成公网/内网报告，Playwright 渲染并截图"""

import asyncio
import json
import unittest
from pathlib import Path

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # Playwright 为可选依赖：CI 安装后运行，本机/沙箱可干净跳过
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False

from scanner_app.core.platform_support import configure_console
from scanner_app.core.reports import write_public_report, write_internal_report

OUT = Path(__file__).resolve().parents[1] / ".artifacts" / "test-shots"
OUT.mkdir(parents=True, exist_ok=True)

PUBLIC_RESULTS = [
    {"ip": "43.139.231.237",
     "ping": {"alive": True, "latency_ms": 32.5},
     "open_count": 6, "total": 100,
     "ports": {
         8000: {"port": 8000, "state": "open", "is_http": True, "scheme": "http",
                 "status": 200, "title": "Web 靶场一", "server": "nginx/1.24",
                 "screenshot": "43.139.231.237_8000.png"},
         8043: {"port": 8043, "state": "open", "is_http": True, "scheme": "https",
                 "status": 200, "title": "安全演练平台", "server": "nginx"},
         8021: {"port": 8021, "state": "open"},
         8080: {"port": 8080, "state": "open", "is_http": True, "scheme": "http",
                 "status": 403, "title": "禁止访问", "server": "Tomcat"},
         8060: {"port": 8060, "state": "open", "is_http": True, "scheme": "http",
                 "status": 500, "title": "报错页", "server": ""},
         33000: {"port": 33000, "state": "open"},
     }},
    {"ip": "43.139.149.11",
     "ping": {"alive": True, "latency_ms": 41.2},
     "open_count": 2, "total": 100,
     "ports": {
         8000: {"port": 8000, "state": "open", "is_http": True, "scheme": "http",
                 "status": 200, "title": "靶场二", "server": "nginx"},
         8080: {"port": 8080, "state": "open", "is_http": True, "scheme": "http",
                 "status": 302, "title": "博客系统", "server": ""},
     }},
]

INTERNAL_HOSTS = [
    {"ip": f"192.168.3.{i}", "alive": True, "via": v, "ttl": t, "mac": None,
     "latency_ms": 1.0, "os_guess": g, "open_ports": p,
     "ssh_banner": "", "http_title": "", "reasons": [f"TTL={t}" if t else "TCP"]}
    for i, v, t, g, p in [
        (10, "icmp", 64, "Linux", [22, 80]),
        (11, "icmp", 64, "Linux", [22, 80, 443]),
        (20, "icmp", 128, "Windows", [135, 139, 445, 3389]),
        (21, "tcp", None, "未知", [8080]),
        (30, "icmp", 63, "Linux", [22, 443, 8080]),
    ]
]


async def main():
    configure_console()
    pub_dir = OUT / "mock_public"
    int_dir = OUT / "mock_internal"
    pub_dir.mkdir(exist_ok=True)
    int_dir.mkdir(exist_ok=True)
    write_public_report(PUBLIC_RESULTS, pub_dir, 8000, 8099, 100, 2)
    write_internal_report(INTERNAL_HOSTS, int_dir,
                          {"cidrs": ["192.168.3.0/24"], "ports": [22, 80, 443, 3389, 8080],
                           "threads": 200, "timeout": 1, "total_hosts": 254})

    checks = {}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page(viewport={"width": 1200, "height": 900})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        for name, d, ids in [
            ("公网", pub_dir, ["rcPort", "rcStatus", "rcTarget", "rcSvc"]),
            ("内网", int_dir, ["rcOS", "rcHeat", "rcVia", "rcTTL"]),
        ]:
            await page.goto((d / "report.html").resolve().as_uri())
            await page.wait_for_timeout(1200)
            n_charts = await page.evaluate("Chart ? Chart.getChart(document.getElementById(ids[0])) ? 1 : 0 : 0"
                                           .replace("ids[0]", f"'{ids[0]}'"))
            counts = []
            for cid in ids:
                c = await page.evaluate(
                    f"(function(){{var c=Chart.getChart(document.getElementById('{cid}'));"
                    f"return c?c.data.datasets[0].data.length:-1;}})()")
                counts.append(c)
            checks[f"{name}报告图表渲染"] = all(n >= 0 for n in counts)
            checks[f"{name}图表数据项 {counts}"] = all(n > 0 for n in counts)
            await page.screenshot(path=str(OUT / f"report_{name}.png"), full_page=True)

        # report.json 仍正常生成
        checks["公网 report.json 存在"] = (pub_dir / "report.json").is_file()
        checks["内网 report.json 存在"] = (int_dir / "report.json").is_file()
        # HTML 内联了 Chart.js（离线自包含）
        html_text = (pub_dir / "report.html").read_text(encoding="utf-8")
        checks["Chart.js 已内联"] = "Chart.register" in html_text or "chart.js" in html_text.lower()
        checks["无页面错误"] = not errors
        if errors:
            print("错误：", errors[:3])
        await browser.close()

    print("=" * 52)
    all_ok = True
    for name, ok in checks.items():
        print(("  ✓ " if ok else "  ✗ ") + name)
        all_ok = all_ok and ok
    print("=" * 52)
    print("报告图表测试：" + ("全部通过 ✓" if all_ok else "存在失败 ✗"))
    return 0 if all_ok else 1


@unittest.skipUnless(PLAYWRIGHT_AVAILABLE, "playwright 未安装，跳过浏览器渲染测试")
class TestReportCharts(unittest.TestCase):
    """report.html 内嵌 Chart.js 图表渲染冒烟测试（需 Playwright + Chromium）。"""

    def test_report_charts_render(self):
        self.assertEqual(asyncio.run(main()), 0)


if __name__ == "__main__":
    if PLAYWRIGHT_AVAILABLE:
        raise SystemExit(asyncio.run(main()))
    print("playwright 未安装，跳过报告图表渲染测试")
    raise SystemExit(0)
