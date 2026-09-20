#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""子域发现引擎单元测试 + 本地 HTTP 集成测试。

验证：
  1. 模板解析（parse_template）
  2. 候选空间：sequential 双射、random 是 [0,N) 上的置换（无放回）
  3. 本地 HTTP 服务：活靶场判定（2xx/3xx + 标题非空）
  4. DNS 解析失败时不误判为活靶场
  5. 断点续扫检查点可被后续运行接续
"""

import http.server
import socketserver
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner_app.core import domain_discovery as dd
from scanner_app.core.domain_discovery import (
    CandidateSpace,
    parse_template,
    probe_domain,
    run_discovery,
)


# --------------------------------------------------------------------------- #
# 1. 模板解析
# --------------------------------------------------------------------------- #
class TestParseTemplate(unittest.TestCase):
    def test_wildcard_split(self):
        self.assertEqual(parse_template("lab-??????.rzsec.cn"), ("lab-", ".rzsec.cn", 6))
        self.assertEqual(parse_template("lab-*.rzsec.cn"), ("lab-", ".rzsec.cn", 1))

    def test_no_wildcard(self):
        # 无通配符：视为单个固定域名
        self.assertEqual(parse_template("range.rzsec.cn"), ("", "range.rzsec.cn", 0))

    def test_middle_wildcard(self):
        self.assertEqual(parse_template("pre-??-post"), ("pre-", "-post", 2))


# --------------------------------------------------------------------------- #
# 2. 候选空间
# --------------------------------------------------------------------------- #
class TestCandidateSpace(unittest.TestCase):
    def test_sequential_bijection(self):
        # length=2, charset "ab" -> 4 个组合，sequential 必须恰好覆盖一次
        space = CandidateSpace("", "", 2, "ab", mode="sequential")
        got = [space.candidate_at(k) for k in range(space.total)]
        self.assertEqual(sorted(got), ["aa", "ab", "ba", "bb"])
        self.assertEqual(len(set(got)), space.total)

    def test_random_is_permutation(self):
        # random 模式：相同 seed 下是 [0, total) 的置换（每个组合恰好一次）
        space = CandidateSpace("lab-", ".rzsec.cn", 2, "ab", mode="random", seed=7)
        got = [space.candidate_at(k) for k in range(space.total)]
        self.assertEqual(len(set(got)), space.total)
        self.assertEqual(sorted(got),
                         ["lab-aa.rzsec.cn", "lab-ab.rzsec.cn",
                          "lab-ba.rzsec.cn", "lab-bb.rzsec.cn"])

    def test_same_seed_deterministic(self):
        s1 = CandidateSpace("lab-", ".rzsec.cn", 3, "ab", mode="random", seed=42)
        s2 = CandidateSpace("lab-", ".rzsec.cn", 3, "ab", mode="random", seed=42)
        seq1 = [s1.candidate_at(k) for k in range(s1.total)]
        seq2 = [s2.candidate_at(k) for k in range(s2.total)]
        self.assertEqual(seq1, seq2)

    def test_fixed_domain_length_zero(self):
        space = CandidateSpace("", "example.com", 0)
        self.assertEqual(space.total, 1)
        self.assertEqual(space.candidate_at(0), "example.com")

    def test_charset_dedup(self):
        space = CandidateSpace("x", "y", 1, "aabb")
        self.assertEqual(space.base, 2)  # 去重后只剩 a,b


# --------------------------------------------------------------------------- #
# 3. 探测 + 活靶场判定（本地 HTTP 服务）
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, status, title):
        self.status = status
        self.title = title


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        host = self.headers.get("Host", "")
        resp = self.server.responses.get(host, self.server.default)
        body = "<html><head><title>{}</title></head><body>x</body></html>".format(
            resp.title).encode("utf-8") if resp.title else b"<html><body>nope</body></html>"
        self.send_response(resp.status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    responses = {}
    default = _Resp(200, "")


def _start_server(port, live_host):
    srv = _Server(("127.0.0.1", port), _Handler)
    srv.responses = {live_host: _Resp(200, "Live Range")}
    srv.default = _Resp(200, "")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class TestProbeDomain(unittest.TestCase):
    def test_live_detection(self):
        port = 18099
        live = "lab-a.rzsec.cn"
        srv = _start_server(port, live)
        try:
            with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                r = probe_domain(live, port, timeout=2.0)
            self.assertTrue(r["ok"])
            self.assertTrue(r["live"])
            self.assertEqual(r["status"], 200)
            self.assertIn("Live Range", r["title"])
        finally:
            srv.shutdown()

    def test_not_live_no_title(self):
        port = 18100
        dead = "lab-b.rzsec.cn"
        srv = _start_server(port, "lab-a.rzsec.cn")  # 该域无标题
        try:
            with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                r = probe_domain(dead, port, timeout=2.0)
            self.assertTrue(r["ok"])
            self.assertFalse(r["live"])  # 200 但无标题 -> 非活靶场
        finally:
            srv.shutdown()

    def test_dns_failure(self):
        def boom(_host):
            raise OSError("nxdomain")
        with patch.object(dd.socket, "gethostbyname", side_effect=boom):
            r = probe_domain("lab-zzzzzz.rzsec.cn", 8000, timeout=1.0)
        self.assertFalse(r["ok"])
        self.assertFalse(r["live"])
        self.assertEqual(r["reason"], "dns")


# --------------------------------------------------------------------------- #
# 4. run_discovery 集成
# --------------------------------------------------------------------------- #
class TestRunDiscovery(unittest.TestCase):
    def test_discovers_live_in_small_space(self):
        port = 18101
        live = "lab-a.rzsec.cn"
        srv = _start_server(port, live)
        events = []
        try:
            with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                found = run_discovery(
                    prefix="lab-", suffix=".rzsec.cn", length=1, charset="ab",
                    mode="sequential", port=port, timeout=2.0, threads=4,
                    limit=2, found_limit=1, seed=1, on_event=events.append)
            self.assertEqual(found, [live])
            types = [e["type"] for e in events]
            self.assertIn("discovery_start", types)
            self.assertIn("domain_found", types)
            self.assertIn("discovery_done", types)
            self.assertTrue(any(e["type"] == "domain_found" and e["domain"] == live
                                for e in events))
        finally:
            srv.shutdown()

    def test_resume_checkpoint_written(self):
        port = 18102
        live = "lab-a.rzsec.cn"
        srv = _start_server(port, live)
        try:
            with TemporaryDirectory() as td:
                ck = str(Path(td) / "ckpt.json")
                with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                    run_discovery(
                        prefix="lab-", suffix=".rzsec.cn", length=1, charset="ab",
                        mode="random", port=port, timeout=2.0, threads=4,
                        limit=1, seed=123, resume_path=ck)
                # 检查点应已写入且记录游标 k>=1
                self.assertTrue(Path(ck).exists())
                data = __import__("json").loads(Path(ck).read_text())
                self.assertGreaterEqual(data["k"], 1)

                # 第二次运行接续：resume_from 应等于上次的 k
                events2 = []
                with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                    run_discovery(
                        prefix="lab-", suffix=".rzsec.cn", length=1, charset="ab",
                        mode="random", port=port, timeout=2.0, threads=4,
                        limit=1, seed=123, resume_path=ck, on_event=events2.append,
                        reset=False)
                start = next(e for e in events2 if e["type"] == "discovery_start")
                self.assertGreaterEqual(start["resume_from"], 1)
        finally:
            srv.shutdown()


class TestWildcardFrontendBehavior(unittest.TestCase):
    """回归测试：通配符前端（如 rzsec 的 nginx）对一切子域统一 301->404 时，
    发现引擎不应把 21.8 亿子域全误判为「存活」。

    复现真实结构：前端在 front_port 统一 301 跳转到 back_port；back_port 根据
    Host 返回最终响应（404=未拉起靶场 / 200+真实标题=真实靶场）。
    """

    def _start_front_back(self, front_port, back_port, back_status, back_title):
        loc = "http://127.0.0.1:%d/" % back_port

        class Front(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(301)
                self.send_header("Location", loc)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><head><title>301 Moved Permanently</title></html>")

            def log_message(self, *a):
                pass

        class Back(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(back_status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    ("<html><head><title>%s</title></head><body>x</body></html>" % back_title).encode())

            def log_message(self, *a):
                pass

        front = http.server.HTTPServer(("127.0.0.1", front_port), Front)
        back = http.server.HTTPServer(("127.0.0.1", back_port), Back)
        threading.Thread(target=front.serve_forever, daemon=True).start()
        threading.Thread(target=back.serve_forever, daemon=True).start()
        return front, back

    def test_front_301_then_404_is_not_live(self):
        """前端 301 -> 后端 404（平台未拉起靶场）：必须判为「非存活」，否则全误报。"""
        front, back = self._start_front_back(18201, 18202, 404, "404 page not found")
        try:
            with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                r = dd.probe_domain("lab-xxxxxx.rzsec.cn", 18201, timeout=2.0)
            self.assertTrue(r["ok"])
            self.assertFalse(r["live"], "301->404 的子域不应判为存活（修复前会误报）")
            self.assertEqual(r["status"], 404)
        finally:
            front.shutdown(); back.shutdown()

    def test_front_301_then_200_real_title_is_live(self):
        """前端 301 -> 后端 200 真实标题（真实活靶场）：应判为存活。"""
        front, back = self._start_front_back(18203, 18204, 200, "RZSEC upload-labs 靶场")
        try:
            with patch.object(dd.socket, "gethostbyname", return_value="127.0.0.1"):
                r = dd.probe_domain("lab-xxxxxx.rzsec.cn", 18203, timeout=2.0)
            self.assertTrue(r["live"], "301->200 真实标题应判存活")
            self.assertEqual(r["status"], 200)
            self.assertIn("RZSEC upload-labs", r["title"])
        finally:
            front.shutdown(); back.shutdown()

    def test_generic_title_unit(self):
        for t in ("", "301 Moved Permanently", "404 page not found",
                  "404 Not Found", "nginx", "Index of"):
            self.assertTrue(dd._is_generic_title(t), "应为通用默认标题: %r" % t)
        self.assertFalse(dd._is_generic_title("RZSEC upload-labs 靶场"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
