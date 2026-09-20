#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网站首页截图模块（Playwright 异步 API + Chromium）

设计要点：
  - Python 3.14 的 sync_api 在多线程下事件循环会被关闭，
    因此用 单工作线程 + asyncio + async_playwright 的组合
  - 一个浏览器实例，多页面并发（信号量限 4），不占用端口扫描线程
  - 单站超时 20 秒；失败只记录错误，不影响扫描主流程
  - Playwright 未安装或 Chromium 缺失时自动降级为跳过截图
"""

import asyncio
import os
import queue
import sys
import threading
from pathlib import Path
from urllib.parse import urljoin

from scanner_app.core.platform_support import (
    PLAYWRIGHT_BROWSER_DIR_NAME,
    RESOURCE_ROOT,
    configure_playwright_browser_path,
    hidden_asyncio_subprocesses,
    windows_proactor_event_loop,
)


# 冻结版优先使用 EXE 旁边的外置浏览器目录。
configure_playwright_browser_path()

try:
    from playwright.async_api import async_playwright
    from playwright.async_api import Error as PlaywrightError
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False
    # 未安装 Playwright 时该分支的代码不会执行，这里仅为保持下方 except 元组合法。
    PlaywrightError = Exception


def _browser_search_roots() -> list[Path]:
    """返回 Playwright 可能存放 Chromium 的目录，按优先级去重。"""
    roots = []
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if configured == "0":
        roots.append(RESOURCE_ROOT / "playwright" / "driver" / "package" / ".local-browsers")
    elif configured:
        roots.append(Path(configured).expanduser())

    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent / PLAYWRIGHT_BROWSER_DIR_NAME)
        roots.append(RESOURCE_ROOT / "playwright" / "driver" / "package" / ".local-browsers")
    elif not configured:
        if os.name == "nt":
            roots.append(Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ms-playwright")
        elif sys.platform == "darwin":
            roots.append(Path.home() / "Library" / "Caches" / "ms-playwright")
        else:
            roots.append(Path.home() / ".cache" / "ms-playwright")

    unique = []
    seen = set()
    for root in roots:
        resolved = str(root.expanduser())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(Path(resolved))
    return unique


def _chromium_executable(root: Path) -> Path | None:
    """查找 Chromium 主程序，兼容不同 Playwright 版本的目录命名。

    新版 Playwright 的 macOS 构建改动了两处命名，旧模式会全部漏掉并误报
    "未找到 Chromium"：
      1. 平台目录带架构后缀：chrome-mac-x64 / chrome-mac-arm64（旧假设为 chrome-mac）
      2. App 更名为 "Google Chrome for Testing.app"（旧假设为 Chromium.app）

    因此这里用带通配的模式覆盖新旧命名，并让 headless shell 优先——它专为
    无头场景构建，截图启动更快、占用更小；完整 Chromium 作为兜底。
    """
    if not root.is_dir():
        return None
    patterns = (
        # headless shell（优先：无头截图专用）
        "chromium_headless_shell-*/chrome-headless-shell-mac*/chrome-headless-shell",
        "chromium_headless_shell-*/chrome-headless-shell-linux/chrome-headless-shell",
        "chromium_headless_shell-*/chrome-headless-shell-win*/chrome-headless-shell.exe",
        # 完整 Chromium：macOS 新版命名（架构后缀 + Google Chrome for Testing）
        "chromium-*/chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        # 完整 Chromium：macOS 旧命名
        "chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium",
        # Windows / Linux（目录名可能带 -x64/-arm64 等架构后缀）
        "chromium-*/chrome-win*/chrome.exe",
        "chromium-*/chrome-linux*/chrome",
    )
    for pattern in patterns:
        for candidate in root.glob(pattern):
            if candidate.is_file():
                return candidate
    return None


def _find_chromium_executable(roots=None) -> Path | None:
    """在指定目录列表中查找可用 Chromium；主要供运行时和测试复用。"""
    for root in roots or _browser_search_roots():
        candidate = _chromium_executable(Path(root))
        if candidate is not None:
            return candidate
    return None


CHROMIUM_EXECUTABLE = _find_chromium_executable()
SCREENSHOT_AVAILABLE = PLAYWRIGHT_OK and CHROMIUM_EXECUTABLE is not None
if not PLAYWRIGHT_OK:
    SCREENSHOT_UNAVAILABLE_REASON = "Playwright 未随当前运行环境安装"
elif CHROMIUM_EXECUTABLE is None:
    SCREENSHOT_UNAVAILABLE_REASON = "未找到 Chromium；请将 playwright-browsers 放在 EXE 同目录，或在源码环境执行 playwright install chromium"
else:
    SCREENSHOT_UNAVAILABLE_REASON = ""

VIEWPORT = {"width": 1280, "height": 800}
PAGE_SETTLE_MS = 800   # domcontentloaded 后等待页面渲染的静态时延（提速截图，兼顾页面加载）
CONCURRENCY = 4        # 单浏览器内并发页面数
BROWSER_ARGS = ["--no-proxy-server"] if os.name == "nt" else []


def _img_ext(b: bytes) -> str:
    """按魔数识别图片格式，选对 data URL 的 MIME"""
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if b[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if b[:4] == b"\x00\x00\x01\x00":
        return ".ico"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    head = b[:200].lstrip().lower()
    if head.startswith(b"<svg") or head.startswith(b"<?xml"):
        return ".svg"
    return ".png"


class ScreenshotPool:
    """异步截图池；submit() 入队，close() 等待全部完成后回收浏览器"""

    def __init__(self, on_done, timeout=20, out_dir="."):
        self.on_done = on_done           # 回调：{"ip","port","ok","path"/"error"}
        self.timeout = timeout
        self.out_dir = Path(out_dir)     # 截图保存目录（用绝对路径，避免 CWD 问题）
        self.tasks = queue.Queue()
        self.available = SCREENSHOT_AVAILABLE
        self._launch_error = None
        self._thread = None

    def submit(self, ip: str, port: int, scheme: str):
        if not self.available:
            self.on_done({"ip": ip, "port": port, "ok": False,
                          "error": SCREENSHOT_UNAVAILABLE_REASON or "Playwright/Chromium 不可用，已跳过截图"})
            return
        url = f"{scheme}://{ip}:{port}/"
        self.tasks.put((ip, port, url))

    def start(self):
        if not self.available:
            return
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        # Playwright 会通过 asyncio 启动 Node 驱动和 Chromium。Windows
        # 的窗口版 EXE 没有控制台，但未设置 creationflags 的子进程仍可能
        # 短暂弹出 cmd，因此把隐藏策略限定在这个截图工作线程内。
        with hidden_asyncio_subprocesses(), windows_proactor_event_loop():
            asyncio.run(self._run_all())

    async def _run_all(self):
        browser = None
        if PLAYWRIGHT_OK:
            try:
                self._pw = await async_playwright().start()
                launch_kwargs = {"headless": True, "args": BROWSER_ARGS}
                if CHROMIUM_EXECUTABLE is not None:
                    # Playwright 新版默认的 headless=True 会优先启动
                    # chromium_headless_shell；发行包只带完整 Chromium，
                    # 因此显式指定浏览器主程序，兼容 --no-shell 构建。
                    launch_kwargs["executable_path"] = str(CHROMIUM_EXECUTABLE)
                browser = await self._pw.chromium.launch(**launch_kwargs)
            except (PlaywrightError, OSError, RuntimeError, asyncio.TimeoutError) as e:
                # Chromium 未安装 / 启动超时 / 可执行文件缺失
                self.available = False
                self._launch_error = repr(e)
        else:
            self.available = False

        sem = asyncio.Semaphore(CONCURRENCY)
        pending = []

        async def handle(task):
            ip, port, url = task
            async with sem:
                if browser is None:
                    self.on_done({"ip": ip, "port": port, "ok": False,
                                  "error": f"浏览器启动失败：{self._launch_error or SCREENSHOT_UNAVAILABLE_REASON}"})
                    return
                path = str(self.out_dir / f"{ip}_{port}.png")
                ok, err, fav = await self._shoot(browser, url, path)
                fav_name = None
                if fav is not None:
                    fbytes, fext = fav
                    fav_name = f"{ip}_{port}_icon{fext}"
                    try:
                        (self.out_dir / fav_name).write_bytes(fbytes)
                    except OSError:
                        fav_name = None
                self.on_done({"ip": ip, "port": port, "ok": ok,
                              "path": f"{ip}_{port}.png" if ok else None,
                              "favicon": fav_name, "error": err})

        while True:
            try:
                item = self.tasks.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue
            if item is None:  # close() 的哨兵
                break
            pending.append(asyncio.create_task(handle(item)))

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if browser:
            await browser.close()
        if getattr(self, "_pw", None):
            await self._pw.stop()

    async def _shoot(self, browser, url: str, path: str):
        """截图 + 顺带抓 favicon；返回 (ok, err, favicon(bytes,ext) 或 None)"""
        page = await browser.new_page(viewport=VIEWPORT, ignore_https_errors=True)
        ok, err, fav = False, "", None
        try:
            await page.goto(url, timeout=self.timeout * 1000,
                            wait_until="domcontentloaded")
            await page.wait_for_timeout(PAGE_SETTLE_MS)
            await page.screenshot(path=path, timeout=self.timeout * 1000)
            ok = True
        except (PlaywrightError, OSError, RuntimeError, asyncio.TimeoutError) as e:
            err = f"{type(e).__name__}: {e}"
        if ok:
            fav = await self._grab_favicon(page)
        await page.close()
        return ok, err, fav

    async def _grab_favicon(self, page):
        """按 link[rel*=icon] → /favicon.ico 顺序抓站点图标；返回 (bytes, ext) 或 None"""
        candidates = []
        try:
            el = await page.query_selector('link[rel*="icon"]')
            if el:
                href = await el.get_attribute("href")
                if href:
                    candidates.append(urljoin(page.url, href))
        except (PlaywrightError, OSError, RuntimeError, ValueError):
            pass
        origin = "/".join(page.url.split("/")[:3])
        candidates.append(origin + "/favicon.ico")
        for u in candidates[:3]:
            try:
                resp = await page.request.get(u, fail_on_status_code=False, timeout=6000)
                if resp.ok:
                    body = await resp.body()
                    if body and len(body) < 256 * 1024:
                        return body, _img_ext(body)
            except (PlaywrightError, OSError, RuntimeError, asyncio.TimeoutError):
                continue
        return None

    def close(self):
        """等待队列中所有任务完成（含失败降级路径）"""
        if self._thread is None:
            self._drain_unstarted()
            return
        self.tasks.put(None)
        self._thread.join()
        if not self.available:
            self._drain_unstarted()

    def _drain_unstarted(self):
        while True:
            try:
                ip, port, _ = self.tasks.get_nowait()
            except queue.Empty:
                break
            self.on_done({"ip": ip, "port": port, "ok": False,
                          "error": SCREENSHOT_UNAVAILABLE_REASON or "截图功能不可用，已跳过"})
