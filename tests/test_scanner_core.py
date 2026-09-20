#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公网结果筛选回归测试。"""

import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner_app.core import scanner_core
from scanner_app.core import reports as reports_mod


def _port(**overrides):
    value = {
        "state": "open",
        "port": 8000,
        "is_http": True,
        "scheme": "http",
        "status": 200,
        "title": "VLUN 靶场",
    }
    value.update(overrides)
    return value


def _target(ip, ping_alive, ports):
    return {
        "ip": ip,
        "ping": {"alive": ping_alive, "latency_ms": 1.0},
        "ports": {str(port["port"]): port for port in ports},
        "open_count": len(ports),
    }


class PublicFilterTests(unittest.TestCase):
    def test_only_http_with_title_is_a_qualified_port(self):
        self.assertTrue(scanner_core.is_qualified_port(_port()))
        self.assertFalse(scanner_core.is_qualified_port(_port(is_http=False)))
        self.assertFalse(scanner_core.is_qualified_port(_port(title="")))
        self.assertFalse(scanner_core.is_qualified_port(_port(state="closed")))

    def test_ping_failure_skips_port_probe(self):
        events = []
        with TemporaryDirectory() as temp:
            with patch.object(
                scanner_core,
                "ping_host",
                return_value={"alive": False, "latency_ms": None},
            ), patch.object(scanner_core, "scan_port") as scan_port:
                result = scanner_core.scan_target(
                    "203.0.113.10",
                    range(8000, 8002),
                    1,
                    2,
                    Path(temp),
                    events.append,
                    threading.Event(),
                )

        scan_port.assert_not_called()
        self.assertEqual(result["ports"], {})
        self.assertEqual(events[-1]["qualified_count"], 0)

    def test_run_scan_returns_only_qualified_targets(self):
        events = []
        scanned = [
            _target("203.0.113.10", False, [_port()]),
            _target("203.0.113.11", True, [_port(title="")]),
            _target("203.0.113.12", True, [_port()]),
        ]
        with TemporaryDirectory() as temp:
            with patch.object(scanner_core, "scan_target", side_effect=scanned), \
                    patch.object(scanner_core, "write_reports") as write_reports:
                result = scanner_core.run_scan(
                    [target["ip"] for target in scanned],
                    ports=[8000],
                    output=temp,
                    screenshots=False,
                    on_event=events.append,
                )

        self.assertEqual([item["ip"] for item in result], ["203.0.113.12"])
        write_reports.assert_called_once()
        finished = next(event for event in events if event["type"] == "scan_done")
        self.assertEqual(finished["qualified_target_total"], 1)
        self.assertEqual(finished["qualified_site_total"], 1)
        self.assertTrue(finished["report_available"])

    def test_domain_target_skips_ping_and_defaults_to_port_80(self):
        """域名目标（非 IPv4 字面量）应放宽 Ping 要求、且未给端口列表时默认只探 80。"""
        captured = {}

        def fake_scan(ip, ports, timeout, threads, outdir, on_event, cancel,
                      require_ping=True):
            captured["ip"] = ip
            captured["ports"] = list(ports)
            captured["require_ping"] = require_ping
            # 返回一个合格结果，使 run_scan 将其纳入 all_results（即便 Ping 失败）
            return {"ip": ip, "ping": {"alive": False},
                    "ports": {"80": _port()}, "open_count": 1}

        with TemporaryDirectory() as temp:
            with patch.object(scanner_core, "scan_target", side_effect=fake_scan), \
                    patch.object(scanner_core, "write_reports"):
                result = scanner_core.run_scan(
                    ["lab-rw2zyp.rzsec.cn"], output=temp,
                    screenshots=False, on_event=lambda e: None,
                )

        self.assertEqual(captured["ip"], "lab-rw2zyp.rzsec.cn")
        self.assertFalse(captured["require_ping"],
                         "域名目标应放宽 Ping（require_ping=False）")
        self.assertEqual(captured["ports"], [80],
                         "未给端口列表时，域名目标应默认只探 80 端口")
        self.assertEqual(len(result), 1,
                         "域名目标即便 Ping 失败也应被纳入结果")

    def test_qualified_public_results_keeps_ping_dead_domain(self):
        """报告层不应因禁 ICMP（ping 不通）而丢弃合法的域名靶场。

        回归保护：reports._qualified_public_results 曾强制要求 ping.alive，
        导致域名靶场即便 HTTP 页面正常也被落盘阶段过滤掉。"""
        target = {
            "ip": "lab-x.rzsec.cn",
            "ping": {"alive": False, "latency_ms": None},
            "ports": {"80": {"state": "open", "is_http": True, "title": "RZSEC Lab"}},
            "open_count": 1,
        }
        out = reports_mod._qualified_public_results([target])
        self.assertEqual(len(out), 1, "禁 ICMP 的域名靶场不应被报告层丢弃")
        self.assertEqual(out[0]["ip"], "lab-x.rzsec.cn")
        self.assertEqual(out[0]["ports"]["80"]["title"], "RZSEC Lab")


    def test_domain_scan_target_captures_live_subdomain_with_final_https(self):
        """已知子域验证：活靶场（80→301→https:443→200 真实标题）应被捕获，
        且端口/协议取最终可达响应（443/https），供截图池抓真实首页。"""
        import scanner_app.core.domain_discovery as dd

        def fake_probe(domain, port, timeout=2.0, **kw):
            # 模拟 rzsec 前端：HTTP 80 统一 301 跳 HTTPS 443，443 返回真实靶场页
            return {
                "domain": domain, "ip": "114.132.123.93", "ok": True, "live": True,
                "status": 200, "title": "upload-labs", "server": "nginx",
                "scheme": "https", "host": domain, "port": 443, "body": b"<title>upload-labs</title>",
            }

        cancel = threading.Event()
        with TemporaryDirectory() as temp:
            out = Path(temp)
            with patch.object(dd, "probe_domain", side_effect=fake_probe):
                res = scanner_core.scan_target(
                    "lab-5n36ys.rzsec.cn", [80], 2.0, 4, out,
                    on_event=lambda e: None, cancel=cancel, require_ping=False)
        self.assertEqual(res["open_count"], 1, "活子域应至少有 1 个开放端口")
        port = res["ports"].get("443")
        self.assertIsNotNone(port, "应使用最终可达端口 443 而非探测端口 80")
        self.assertEqual(port["scheme"], "https")
        self.assertEqual(port["status"], 200)
        self.assertEqual(port["title"], "upload-labs")
        self.assertTrue(scanner_core.is_qualified_target(res, require_ping=False))

    def test_domain_scan_target_excludes_dead_subdomain(self):
        """已知子域验证：死子域（80→301→https:443→404 通用页）不应误判为活靶场。
        回归保护：之前 fetch_http 不跟随跨端口 301 且 is_qualified_port 不过滤通用默认页，
        会把「301 Moved Permanently」默认页误报成活靶场。"""
        import scanner_app.core.domain_discovery as dd

        def fake_probe(domain, port, timeout=2.0, **kw):
            return {
                "domain": domain, "ip": "114.132.123.93", "ok": True, "live": False,
                "status": 404, "title": "", "server": "nginx",
                "scheme": "https", "host": domain, "port": 443, "body": b"404 page not found",
            }

        cancel = threading.Event()
        with TemporaryDirectory() as temp:
            out = Path(temp)
            with patch.object(dd, "probe_domain", side_effect=fake_probe):
                res = scanner_core.scan_target(
                    "lab-5n36ys.rzsec.cn", [80], 2.0, 4, out,
                    on_event=lambda e: None, cancel=cancel, require_ping=False)
        self.assertEqual(res["open_count"], 0, "死子域不应有开放端口")
        self.assertFalse(scanner_core.is_qualified_target(res, require_ping=False),
                         "死子域不应进入公网结果")


if __name__ == "__main__":
    unittest.main()
