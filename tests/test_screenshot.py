#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""截图运行时回归测试：确认完整 Chromium 能访问 HTTP 页面并产出 PNG。"""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner_app.core import screenshot


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            b"<html><head><title>Screenshot fixture</title></head>"
            b"<body><h1>VLUN</h1></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@unittest.skipUnless(
    screenshot.SCREENSHOT_AVAILABLE,
    f"截图运行时不可用：{screenshot.SCREENSHOT_UNAVAILABLE_REASON}",
)
class ScreenshotRuntimeTests(unittest.TestCase):
    def test_pool_captures_http_fixture(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            test_root = Path(".artifacts/test-shots")
            test_root.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix="screenshot-", dir=test_root) as temp:
                events = []
                pool = screenshot.ScreenshotPool(events.append, timeout=15, out_dir=Path(temp))
                pool.start()
                pool.submit("127.0.0.1", server.server_port, "http")
                pool.close()

                self.assertEqual(len(events), 1)
                self.assertTrue(events[0]["ok"], events[0])
                output = Path(temp) / f"127.0.0.1_{server.server_port}.png"
                self.assertGreater(output.stat().st_size, 1000)
        finally:
            server.shutdown()
            server.server_close()


class ChromiumExecutableDetectionTests(unittest.TestCase):
    """Chromium 路径识别回归测试。

    新版 Playwright 改了两处命名，旧模式全部漏匹配，导致明明装了 Chromium
    却误报"未找到"、截图功能整体不可用。这里用伪造目录树锁死各种命名，
    不依赖真实浏览器，CI 无浏览器环境也能验证。
    """

    def _touch(self, root: Path, rel: str) -> Path:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"#!/bin/sh\n")
        return target

    def test_detects_modern_macos_chrome_for_testing(self):
        """新版：目录带架构后缀 -x64，App 更名为 Google Chrome for Testing。"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = self._touch(
                root,
                "chromium-1234/chrome-mac-x64/Google Chrome for Testing.app/"
                "Contents/MacOS/Google Chrome for Testing",
            )
            self.assertEqual(screenshot._chromium_executable(root), exe)

    def test_detects_modern_macos_arm64(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = self._touch(
                root,
                "chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/"
                "Contents/MacOS/Google Chrome for Testing",
            )
            self.assertEqual(screenshot._chromium_executable(root), exe)

    def test_prefers_headless_shell_when_both_present(self):
        """headless shell 专为无头场景构建，应优先于完整 Chromium。"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._touch(
                root,
                "chromium-1234/chrome-mac-x64/Google Chrome for Testing.app/"
                "Contents/MacOS/Google Chrome for Testing",
            )
            shell = self._touch(
                root,
                "chromium_headless_shell-1234/chrome-headless-shell-mac-x64/"
                "chrome-headless-shell",
            )
            self.assertEqual(screenshot._chromium_executable(root), shell)

    def test_detects_legacy_macos_chromium_app(self):
        """旧版命名仍需兼容（chrome-mac + Chromium.app）。"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = self._touch(root, "chromium-1105/chrome-mac/Chromium.app/Contents/MacOS/Chromium")
            self.assertEqual(screenshot._chromium_executable(root), exe)

    def test_returns_none_when_no_match(self):
        with TemporaryDirectory() as tmp:
            self.assertIsNone(screenshot._chromium_executable(Path(tmp)))


if __name__ == "__main__":
    unittest.main()
