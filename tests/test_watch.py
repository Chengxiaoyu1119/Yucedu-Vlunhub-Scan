#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""已知子域轮询监控（Api.start_watch / stop_watch）单元测试。

靶场按需随机生成域名、拉起需要时间，盲扫 21.8 亿不现实；对已知 ID 轮询等待
命中率高得多。这里覆盖：

  1. 域名规整（裸随机位 / 完整域名 / 带协议 / 大小写空格）
  2. 入参校验（空输入、非法端口、去重、200 上限）
  3. 事件流：watch_start → watch_probe → watch_round → watch_done
  4. 会话号：同一次监控所有事件同号，两次监控号递增
     —— 旧监控迟到的 watch_done 不能再关掉新监控，前端靠它隔离

全程用假的 probe_domain，不发真实网络请求。
"""

import queue
import time
import unittest
from unittest.mock import patch

from scanner_app.core import domain_discovery
from scanner_app.desktop.gui import Api


def _fake_probe(status=404, live=False):
    """构造假的探测函数，记录被调用的域名。"""
    seen = []

    def _probe(domain, port, **kwargs):
        seen.append((domain, port))
        return {"live": live, "status": status, "title": "", "ip": "127.0.0.1"}

    return _probe, seen


def _drain(api):
    """把事件队列取空，按到达顺序返回。"""
    out = []
    while True:
        try:
            out.append(api.evt_queue.get_nowait())
        except queue.Empty:
            return out


def _wait_stopped(api, timeout=3.0):
    """等监控线程退出，超时返回 False。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not api.is_watching():
            return True
        time.sleep(0.02)
    return False


class TestNormalizeWatchDomain(unittest.TestCase):
    """_normalize_watch_domain：三种写法都要能落到 lab-XXXXXX.rzsec.cn"""

    def test_bare_id_gets_template_applied(self):
        self.assertEqual(Api._normalize_watch_domain("abc123"),
                         "lab-abc123.rzsec.cn")

    def test_full_domain_kept_and_lowered(self):
        self.assertEqual(Api._normalize_watch_domain("lab-XYZ.rzsec.cn"),
                         "lab-xyz.rzsec.cn")

    def test_url_stripped_of_scheme_and_path(self):
        self.assertEqual(Api._normalize_watch_domain("https://lab-xyz.rzsec.cn/"),
                         "lab-xyz.rzsec.cn")

    def test_surrounding_space_and_case(self):
        self.assertEqual(Api._normalize_watch_domain("  Q7X  "),
                         "lab-q7x.rzsec.cn")

    def test_junk_tokens_rejected(self):
        # 无法规整的输入一律返回空串，调用方按假值过滤
        for junk in ("", "   ", "-", "..", "@@", "lab_abc", "http://"):
            self.assertFalse(Api._normalize_watch_domain(junk), junk)


class TestStartWatchValidation(unittest.TestCase):
    def setUp(self):
        self.api = Api()
        self.probe, self.seen = _fake_probe()
        self.patcher = patch.object(domain_discovery, "probe_domain", self.probe)
        self.patcher.start()

    def tearDown(self):
        self.api.stop_watch()
        _wait_stopped(self.api)
        self.patcher.stop()

    def test_empty_input_rejected(self):
        res = self.api.start_watch({"domains": "  ,,\n "})
        self.assertFalse(res["ok"])
        self.assertIn("请至少填写", res["error"])

    def test_bad_port_rejected(self):
        res = self.api.start_watch({"domains": "abc123", "port": 70000})
        self.assertFalse(res["ok"])
        self.assertIn("1-65535", res["error"])

    def test_too_many_domains_rejected(self):
        doms = ",".join(f"d{i:05d}" for i in range(201))
        res = self.api.start_watch({"domains": doms})
        self.assertFalse(res["ok"])
        self.assertIn("最多监控 200", res["error"])

    def test_interval_clamped_to_5_3600(self):
        res = self.api.start_watch({"domains": "abc123", "interval": 1})
        self.assertTrue(res["ok"])
        self.assertEqual(res["interval"], 5)
        self.api.stop_watch()

    def test_duplicates_collapsed(self):
        res = self.api.start_watch({"domains": "abc123\nlab-abc123.rzsec.cn\nabc123"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["domains"], ["lab-abc123.rzsec.cn"])

    def test_second_start_while_running_rejected(self):
        self.api.start_watch({"domains": "abc123", "interval": 5})
        res = self.api.start_watch({"domains": "def456", "interval": 5})
        self.assertFalse(res["ok"])
        self.assertIn("监控已在运行中", res["error"])


class TestWatchEvents(unittest.TestCase):
    def setUp(self):
        self.api = Api()
        self.probe, self.seen = _fake_probe()
        self.patcher = patch.object(domain_discovery, "probe_domain", self.probe)
        self.patcher.start()
        _drain(self.api)

    def tearDown(self):
        self.api.stop_watch()
        _wait_stopped(self.api)
        self.patcher.stop()

    def _start(self, domains="5n36ys\nlab-rw2zyp.rzsec.cn", **kw):
        opts = {"domains": domains, "interval": 5, "port": 443}
        opts.update(kw)
        return self.api.start_watch(opts)

    def test_event_sequence_and_session(self):
        res = self._start()
        self.assertTrue(res["ok"])
        session = res["session"]

        # 第一轮：2 个探测 + 1 个轮次汇总
        deadline = time.time() + 3
        events = []
        while time.time() < deadline and not any(e["type"] == "watch_round" for e in events):
            events += _drain(self.api)
            time.sleep(0.02)

        types = [e["type"] for e in events]
        self.assertEqual(types[0], "watch_start")
        self.assertEqual(types.count("watch_probe"), 2)
        self.assertIn("watch_round", types)

        # 所有事件必须带同一个会话号，前端靠它丢弃旧监控的迟到事件
        for e in events:
            self.assertEqual(e.get("session"), session, e["type"])

        start = events[0]
        self.assertEqual(start["domains"],
                         ["lab-5n36ys.rzsec.cn", "lab-rw2zyp.rzsec.cn"])
        self.assertEqual(start["port"], 443)

        round_evt = next(e for e in events if e["type"] == "watch_round")
        self.assertEqual(round_evt["round"], 1)
        self.assertEqual(round_evt["total"], 2)
        self.assertEqual(round_evt["alive"], 0)

    def test_stop_emits_done_and_ends_thread(self):
        self._start()
        # 等第一轮探测完，确保线程已经跑起来
        time.sleep(0.3)
        self.api.stop_watch()
        self.assertTrue(_wait_stopped(self.api), "停止后线程未退出")

        events = _drain(self.api)
        done = [e for e in events if e["type"] == "watch_done"]
        self.assertEqual(len(done), 1)
        self.assertGreaterEqual(done[0]["rounds"], 1)
        self.assertEqual(done[0]["total"], 2)

    def test_session_increments_between_runs(self):
        first = self._start(domains="aaaaaa")["session"]
        self.api.stop_watch()
        self.assertTrue(_wait_stopped(self.api))
        _drain(self.api)

        second = self._start(domains="bbbbbb")["session"]
        self.assertNotEqual(first, second)
        self.api.stop_watch()

    def test_stop_on_all_up_breaks_immediately(self):
        self.probe_live = True
        probe, _ = _fake_probe(status=200, live=True)
        self.patcher.stop()
        self.patcher = patch.object(domain_discovery, "probe_domain", probe)
        self.patcher.start()

        self._start(domains="aaaaaa\nbbbbbb", stop_on_all_up=True)
        # 全部在线即停，不该等满一个 interval
        deadline = time.time() + 2
        while time.time() < deadline and self.api.is_watching():
            time.sleep(0.02)
        _wait_stopped(self.api)

        events = _drain(self.api)
        self.assertIn("watch_found", [e["type"] for e in events])
        done = [e for e in events if e["type"] == "watch_done"]
        self.assertEqual(done[-1]["alive"], 2)


if __name__ == "__main__":
    unittest.main()
