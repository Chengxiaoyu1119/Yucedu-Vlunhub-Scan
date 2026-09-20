#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""图表看板渲染测试：stub pywebview API，模拟扫描事件流，验证 Chart.js 图表生成"""

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

GUI = Path(__file__).resolve().parents[1] / "scanner_app" / "desktop" / "web"
OUT = Path(__file__).resolve().parents[1] / ".artifacts" / "test-shots"
OUT.mkdir(parents=True, exist_ok=True)

PUBLIC_EVENTS = [
    {"type": "scan_start", "targets": ["43.139.231.237", "43.139.149.11"],
     "port_start": 8000, "port_end": 8099, "total_ports": 100, "results_dir": "/tmp/x"},
]
# 模拟不同类型的端口发现事件
for port, http, scheme, status, title, server in [
    (8000, True,  "http",  200, "Web 靶场一", "nginx/1.24"),
    (8080, True,  "http",  302, "管理后台",   "Apache"),
    (8043, True,  "https", 200, "安全演练平台", "nginx"),
    (8021, False, "",      0,   "",           ""),
    (8090, True,  "http",  403, "禁止访问",   "Tomcat"),
    (8060, True,  "http",  500, "报错页",     ""),
]:
    PUBLIC_EVENTS.append({"type": "port_found", "ip": "43.139.231.237", "port": port,
                          "state": "open", "is_http": http, "scheme": scheme,
                          "status": status, "title": title, "server": server})
for port, http, scheme, status, title, server in [
    (8000, True, "http", 200, "靶场二", "nginx"),
    (8080, True, "http", 200, "博客系统", ""),
]:
    PUBLIC_EVENTS.append({"type": "port_found", "ip": "43.139.149.11", "port": port,
                          "state": "open", "is_http": http, "scheme": scheme,
                          "status": status, "title": title, "server": server})
PUBLIC_EVENTS.append({"type": "phase", "phase": "screenshots"})
PUBLIC_EVENTS.append({"type": "scan_done", "results_dir": "/tmp/x", "cancelled": False,
                      "open_total": 8, "screenshot_total": 6})

INTERNAL_EVENTS = [
    {"type": "scan_start", "cidrs": ["192.168.3.0/24", "192.168.4.0/24"],
     "ports": [22, 80, 443, 135, 139, 445, 3389, 8080], "total_hosts": 512,
     "results_dir": "/tmp/y"},
]
for ip, via, ttl, os_g, ports in [
    ("192.168.3.10", "icmp", 64,  "Linux",   [22, 80]),
    ("192.168.3.11", "icmp", 64,  "Linux",   [22, 80, 443]),
    ("192.168.3.20", "icmp", 128, "Windows", [135, 139, 445, 3389]),
    ("192.168.3.21", "tcp",  None, "未知",    [8080]),
    ("192.168.4.30", "icmp", 63,  "Linux",   [22, 80, 443, 8080]),
    ("192.168.4.31", "icmp", 127, "Windows", [445, 3389]),
    ("192.168.4.50", "icmp", 200, "未知",    [80]),
]:
    INTERNAL_EVENTS.append({"type": "host_found", "ip": ip, "via": via, "ttl": ttl,
                            "os_guess": os_g, "open_ports": ports,
                            "reasons": [f"TTL={ttl}" if ttl else "无回包"]})
INTERNAL_EVENTS.append({"type": "mac_resolved", "macs": {"192.168.3.10": "aa:bb:cc:dd:ee:01"}})
INTERNAL_EVENTS.append({"type": "scan_done", "results_dir": "/tmp/y", "cancelled": False,
                        "counts": {"存活主机": 7, "Linux": 3, "Windows": 2, "未知": 2}})

# 历史看板弹窗用的模拟数据（与 get_report_data 返回格式一致）
MOCK_PUBLIC_PORTS = [
  {"ip": "10.0.0.1", "port": 80,  "is_http": True,  "scheme": "http",  "status": 200, "title": "靶场 A", "server": "nginx"},
  {"ip": "10.0.0.1", "port": 443, "is_http": True,  "scheme": "https", "status": 200, "title": "靶场 A", "server": "nginx"},
  {"ip": "10.0.0.1", "port": 8080,"is_http": True,  "scheme": "http",  "status": 302, "title": "管理后台", "server": ""},
  {"ip": "10.0.0.2", "port": 80,  "is_http": True,  "scheme": "http",  "status": 403, "title": "禁止", "server": "Apache"},
  {"ip": "10.0.0.2", "port": 9090,"is_http": False, "scheme": "",      "status": 0,   "title": "",      "server": ""},
]

MOCK_INTERNAL_HOSTS = [
  {"ip": "172.16.1.1", "via": "icmp", "ttl": 64,  "os_guess": "Linux",   "open_ports": [22, 80]},
  {"ip": "172.16.1.2", "via": "icmp", "ttl": 128, "os_guess": "Windows", "open_ports": [445, 3389]},
  {"ip": "172.16.1.3", "via": "tcp",  "ttl": None,"os_guess": "未知",    "open_ports": [8080]},
  {"ip": "172.16.1.4", "via": "icmp", "ttl": 63,  "os_guess": "Linux",   "open_ports": [22, 443, 8080]},
  {"ip": "172.16.1.5", "via": "icmp", "ttl": 127, "os_guess": "Windows", "open_ports": [135, 139, 445, 3389]},
]

STUB = """
window.pywebview = {
  api: {
    get_config: async () => ({targets: "1.1.1.1", port_start: 8000, port_end: 8020, threads: 100, timeout: 2}),
    get_internal_config: async () => ({cidrs: "192.168.3.0/24", ports: "22,80", threads: 200, timeout: 1}),
    poll_events: async () => [],
    screenshot_data: async () => ({error: "no file"}),
    notify: async () => ({ok: true}),
    open_report: async () => ({ok: true}),
    open_url: async () => ({ok: true}),
    open_path: async () => ({ok: true}),
    start_scan: async () => ({ok: true}),
    start_internal_scan: async () => ({ok: true}),
    stop_scan: async () => ({ok: true}),
    get_history: async () => [],
    delete_history: async () => ({ok: true}),
  }
};
"""


async def main():
    configure_console()
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1160, "height": 800})
        # 注入 pywebview stub（在页面脚本执行前）
        await page.add_init_script(STUB)
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        await page.goto((GUI / "index.html").as_uri())
        await page.wait_for_timeout(300)
        # stub 不会自动触发该事件，手动派发以执行 init()
        await page.evaluate("window.dispatchEvent(new Event('pywebviewready'))")
        await page.wait_for_timeout(300)

        # ---- 公网模式 ----
        await page.click("#btnScan")
        # 直接向 handleEvent 注入事件流（绕过轮询）
        await page.evaluate("(evts) => evts.forEach(e => handleEvent(e))", PUBLIC_EVENTS)
        await page.wait_for_timeout(1200)

        checks = {}
        checks["publicDash 可见"] = await page.is_visible("#publicDash")
        for cid in ["chartPortDist", "chartHttpStatus", "chartTargetBar", "chartServiceType"]:
            ok = await page.evaluate(f"!!chartInstances['{cid}']")
            n = await page.evaluate(f"chartInstances['{cid}'] ? chartInstances['{cid}'].data.datasets[0].data.length : -1")
            checks[f"{cid} ({n} 项)"] = ok
        await page.screenshot(path=str(OUT / "public_dash.png"), full_page=True)

        # ---- 历史看板弹窗：公网模式 ----
        # 注入 get_history 返回两条记录
        mock_history = [
            {"path": "/mock/public", "time": "2026-08-19 12:00:00", "kind": "public",
             "report_html": True, "targets": ["10.0.0.1"], "summary": "开放 5 端口"},
            {"path": "/mock/internal", "time": "2026-08-19 11:30:00", "kind": "internal",
             "report_html": True, "targets": ["172.16.1.0/24"], "summary": "存活 5 台"},
        ]
        await page.evaluate(f"window.pywebview.api.get_history = async () => {json.dumps(mock_history)}")

        # 公网看板：stub get_report_data 返回公网端口数据
        public_report_data = json.dumps({"ok": True, "kind": "public", "ports": MOCK_PUBLIC_PORTS})
        internal_report_data = json.dumps({"ok": True, "kind": "internal", "hosts": MOCK_INTERNAL_HOSTS})
        stub_js = (
            "window.pywebview.api.get_report_data = async (p) => {"
            f"  if (p === '/mock/public') return {public_report_data};"
            f"  if (p === '/mock/internal') return {internal_report_data};"
            "  return {ok: false, error: 'not found'};"
            "}"
        )
        await page.evaluate(stub_js)

        # 切到历史页，点击第一个看板按钮
        await page.click('[data-page="history"]')
        await page.wait_for_timeout(300)
        checks["历史页可见"] = await page.is_visible("#page-history")

        # 点击第一个「看板」按钮
        await page.click('.btn-dash')
        await page.wait_for_timeout(800)

        checks["看板弹窗可见"] = await page.is_visible("#dashModal")
        checks["看板类型标签=公网"] = await page.evaluate(
            "document.getElementById('dashModalKind').textContent") == "公网 Web"
        # 验证 modal 内图表已创建
        for cid in ["modal_chartPortDist", "modal_chartHttpStatus", "modal_chartTargetBar", "modal_chartServiceType"]:
            ok = await page.evaluate(f"!!chartInstances['{cid}']")
            checks[f"modal {cid}"] = ok

        await page.screenshot(path=str(OUT / "modal_public_dash.png"))

        # 关闭弹窗
        await page.click("#dashModalClose")
        await page.wait_for_timeout(200)
        checks["弹窗已关闭"] = not await page.is_visible("#dashModal")

        # ---- 历史看板弹窗：内网模式 ----
        # 点击第二个「看板」按钮
        btns = await page.query_selector_all('.btn-dash')
        await btns[1].click()
        await page.wait_for_timeout(800)

        checks["内网看板弹窗可见"] = await page.is_visible("#dashModal")
        checks["看板类型标签=内网"] = await page.evaluate(
            "document.getElementById('dashModalKind').textContent") == "内网穿透"
        for cid in ["modal_chartOSDist", "modal_chartPortHeat", "modal_chartDiscover", "modal_chartTTLDist"]:
            ok = await page.evaluate(f"!!chartInstances['{cid}']")
            checks[f"modal {cid}"] = ok
        # 验证内网 modal 图表数据正确
        modal_os_labels = await page.evaluate("chartInstances['modal_chartOSDist']?.data?.labels")
        checks[f"modal OS 分布 {modal_os_labels}"] = sorted(modal_os_labels or []) == ["Linux", "Windows", "未知"]

        await page.screenshot(path=str(OUT / "modal_internal_dash.png"))
        await page.click("#dashModalClose")
        await page.wait_for_timeout(200)

        # ---- 切到内网模式 ----
        await page.click('[data-page="internal"]')
        await page.click("#btnInternal")
        await page.evaluate("(evts) => evts.forEach(e => handleEvent(e))", INTERNAL_EVENTS)
        await page.wait_for_timeout(1200)

        checks["internalDash 可见"] = await page.is_visible("#internalDash")
        for cid in ["chartOSDist", "chartPortHeat", "chartDiscover", "chartTTLDist"]:
            ok = await page.evaluate(f"!!chartInstances['{cid}']")
            n = await page.evaluate(f"chartInstances['{cid}'] ? chartInstances['{cid}'].data.datasets[0].data.length : -1")
            checks[f"{cid} ({n} 项)"] = ok
        # OS 分布应为 3 类
        os_data = await page.evaluate("chartInstances['chartOSDist'].data.labels")
        checks[f"OS 分布类别 {os_data}"] = sorted(os_data) == ["Linux", "Windows", "未知"]
        await page.screenshot(path=str(OUT / "internal_dash.png"), full_page=True)

        # ---- 公网模式下内网看板应隐藏（反之亦然） ----
        checks["公网页看板不显示内网图"] = not await page.is_visible("#publicDash")

        # ---- Windows 视觉边界：沿用共享主题、隐藏品牌区且最小窗口不横向溢出 ----
        await page.evaluate("document.body.classList.add('windows-shell')")
        windows_layout = await page.evaluate("""() => ({
          brandHidden: (() => {
            const brand = document.querySelector('.brand');
            return !brand || getComputedStyle(brand).display === 'none';
          })(),
          activeNavHasNoLeftAccent: getComputedStyle(document.querySelector('.nav-item.active')).boxShadow === 'none',
          noHorizontalOverflow: document.body.scrollWidth <= window.innerWidth &&
            document.querySelector('.pages').scrollWidth <= document.querySelector('.pages').clientWidth
        })""")
        checks["Windows 左侧不显示品牌区"] = windows_layout["brandHidden"]
        checks["Windows 选中项无左侧蓝边"] = windows_layout["activeNavHasNoLeftAccent"]
        checks["Windows 页面无横向溢出"] = windows_layout["noHorizontalOverflow"]
        await page.screenshot(path=str(OUT / "windows_layout.png"), full_page=True)

        await browser.close()

        print("=" * 52)
        all_ok = True
        for name, ok in checks.items():
            print(("  ✓ " if ok else "  ✗ ") + name)
            all_ok = all_ok and ok
        if errors:
            print(f"  ✗ 页面错误 {len(errors)} 个：")
            for e in errors[:5]:
                print("     ", e[:160])
            all_ok = False
        print("=" * 52)
        print("图表渲染测试：" + ("全部通过 ✓" if all_ok else "存在失败 ✗"))
        return 0 if all_ok else 1


@unittest.skipUnless(PLAYWRIGHT_AVAILABLE, "playwright 未安装，跳过浏览器渲染测试")
class TestDashboardCharts(unittest.TestCase):
    """pywebview 看板 Chart.js 渲染冒烟测试（需 Playwright + Chromium）。"""

    def test_dashboard_charts_render(self):
        self.assertEqual(asyncio.run(main()), 0)


if __name__ == "__main__":
    if PLAYWRIGHT_AVAILABLE:
        raise SystemExit(asyncio.run(main()))
    print("playwright 未安装，跳过图表渲染测试")
    raise SystemExit(0)
