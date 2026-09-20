#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨平台支持：项目路径、Ping/ARP 解析和桌面系统联动。

扫描核心只依赖这里暴露的稳定接口，避免把 macOS 命令散落在业务代码中。
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
import sys
import asyncio
from contextlib import contextmanager
from pathlib import Path


APP_NAME = "靶场扫描助手"
# 与 CHANGELOG.md 的最新发行版保持一致；发版时需同步修改两处。
APP_VERSION = "2.2.0"
PLAYWRIGHT_BROWSER_DIR_NAME = "playwright-browsers"
PLAYWRIGHT_RUNTIME_DIR_NAME = "playwright-runtime"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT.parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", SOURCE_ROOT))

if getattr(sys, "frozen", False) and os.name == "nt":
    # 冻结版资源位于 PyInstaller 临时/内部目录，扫描结果必须写入用户可写目录。
    PROJECT_ROOT = Path(sys.executable).resolve().parent
    DATA_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    RESULTS_ROOT = DATA_ROOT / "scan_results"
else:
    PROJECT_ROOT = SOURCE_ROOT
    DATA_ROOT = SOURCE_ROOT / ".artifacts"
    RESULTS_ROOT = DATA_ROOT / "results"

if getattr(sys, "frozen", False):
    GUI_DIR = RESOURCE_ROOT / "scanner_app" / "desktop" / "web"
else:
    GUI_DIR = PACKAGE_ROOT / "desktop" / "web"


def default_results_dir(kind: str = "public") -> Path:
    """返回项目内的默认结果目录，避免依赖启动时的当前工作目录。"""
    prefix = "internal_" if kind == "internal" else ""
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return RESULTS_ROOT / f"{prefix}{stamp}"


def resolve_output_dir(output: str = "", kind: str = "public") -> Path:
    """解析 CLI/GUI 的输出目录；显式相对路径仍相对当前终端目录。"""
    if output:
        path = Path(output).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()
    return default_results_dir(kind)


def user_agent() -> str:
    """返回扫描请求使用的浏览器标识。"""
    if sys.platform == "darwin":
        return ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) RangeScanner/1.0")
    if os.name == "nt":
        return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) RangeScanner/1.0")
    return "Mozilla/5.0 (X11; Linux x86_64) RangeScanner/1.0"


def configure_console() -> None:
    """让 Windows CLI 使用 UTF-8，避免报告依据中的特殊字符导致输出异常。"""
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


def hidden_subprocess_kwargs() -> dict:
    """为 Windows 子进程关闭额外控制台窗口；其它平台不添加参数。"""
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


@contextmanager
def hidden_asyncio_subprocesses():
    """在 Windows 中隐藏 Playwright/asyncio 创建的子进程窗口。

    ping 和 arp 可以直接传入 creationflags，但 Playwright 通过 asyncio
    内部创建 Node 驱动与 Chromium，调用方没有公开的窗口参数入口。因此
    只在截图工作线程的生命周期内拦截 asyncio 的两个创建函数，避免扫描
    时闪出 cmd 窗口，同时不影响其它平台或主进程。
    """
    if os.name != "nt":
        yield
        return

    original_exec = asyncio.create_subprocess_exec
    original_shell = asyncio.create_subprocess_shell

    async def create_hidden_exec(*args, **kwargs):
        kwargs.setdefault("creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return await original_exec(*args, **kwargs)

    async def create_hidden_shell(*args, **kwargs):
        kwargs.setdefault("creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return await original_shell(*args, **kwargs)

    asyncio.create_subprocess_exec = create_hidden_exec
    asyncio.create_subprocess_shell = create_hidden_shell
    try:
        yield
    finally:
        asyncio.create_subprocess_exec = original_exec
        asyncio.create_subprocess_shell = original_shell


@contextmanager
def windows_proactor_event_loop():
    """让 Windows 截图线程使用 Playwright 所需的 Proactor 事件循环。"""
    if os.name != "nt":
        yield
        return

    policy_type = getattr(asyncio, "WindowsProactorEventLoopPolicy", None)
    if policy_type is None:
        yield
        return

    previous_policy = asyncio.get_event_loop_policy()
    asyncio.set_event_loop_policy(policy_type())
    try:
        yield
    finally:
        asyncio.set_event_loop_policy(previous_policy)


def configure_playwright_browser_path() -> None:
    """为冻结版程序选择发行包旁边的外置 Chromium 目录。

    Windows EXE 保持精简体积，Chromium 放在同级
    ``playwright-browsers`` 目录中。
    """
    if not getattr(sys, "frozen", False):
        return

    external_root = Path(sys.executable).resolve().parent / PLAYWRIGHT_BROWSER_DIR_NAME
    if external_root.is_dir() and any(path.is_dir() for path in external_root.glob("chromium-*")):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(external_root)

    external_node = Path(sys.executable).resolve().parent / PLAYWRIGHT_RUNTIME_DIR_NAME / "node.exe"
    if external_node.is_file():
        os.environ["PLAYWRIGHT_NODEJS_PATH"] = str(external_node)


def show_error(title: str, message: str) -> None:
    """在无控制台的冻结版 Windows 程序中显示启动错误。"""
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, str(message), str(title), 0x10)
    except (AttributeError, OSError):
        pass


def ping_command(ip: str, timeout: float) -> list[str]:
    """生成当前系统的单包 Ping 命令。"""
    timeout_ms = max(1, int(timeout * 1000))
    if os.name == "nt":
        # Windows: -n 为次数，-w 为单次等待毫秒数。
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # macOS: -c 为次数，-W 单位为毫秒；Linux 的 -W 单位为秒。
    binary = shutil.which("ping") or ("/sbin/ping" if sys.platform == "darwin" else "ping")
    wait = timeout_ms if sys.platform == "darwin" else max(1, int(timeout))
    return [binary, "-c", "1", "-W", str(wait), ip]


def parse_ping_output(output: str) -> dict:
    """解析 macOS/Linux/Windows Ping 输出中的 TTL 和时延。"""
    ttl_match = re.search(r"\bttl[=:\s]+(\d+)", output or "", re.I)
    # Windows 常见 time<1ms，macOS/Linux 常见 time=0.123 ms。
    latency_match = re.search(r"\btime\s*[=<]\s*([\d.]+)\s*ms", output or "", re.I)
    return {
        "ttl": int(ttl_match.group(1)) if ttl_match else None,
        "latency_ms": float(latency_match.group(1)) if latency_match else None,
    }


def parse_arp_output(output: str) -> dict[str, str]:
    """解析 macOS 与 Windows 的 arp -a 输出并统一为小写冒号 MAC。"""
    result: dict[str, str] = {}

    # macOS: ? (192.168.3.10) at aa:bb:cc:dd:ee:ff on en0
    for ip, mac in re.findall(
        r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
        r"((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})",
        output or "",
    ):
        result[ip] = mac.lower()

    # Windows: 192.168.3.10    aa-bb-cc-dd-ee-ff    dynamic
    for ip, mac in re.findall(
        r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\b",
        output or "",
    ):
        result[ip] = mac.replace("-", ":").lower()
    return result


def open_path(path: Path) -> bool:
    """用系统文件管理器打开目录或文件。"""
    try:
        resolved = str(path.resolve())
        if os.name == "nt":
            os.startfile(resolved)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", resolved], check=False, **hidden_subprocess_kwargs())
        else:
            subprocess.run(["xdg-open", resolved], check=False, **hidden_subprocess_kwargs())
        return True
    except (OSError, ValueError):
        return False


def notify(title: str, message: str) -> bool:
    """发送非阻塞桌面提醒；系统不支持时静默返回 False。"""
    title = str(title).replace('"', "'")[:60]
    message = str(message).replace('"', "'")[:200]
    try:
        if sys.platform == "darwin":
            subprocess.run(
                ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                check=False,
                timeout=5,
                **hidden_subprocess_kwargs(),
            )
            return True
        if os.name == "nt":
            # msg.exe 是 Windows 自带的当前会话提醒，失败时不影响扫描。
            user = os.environ.get("USERNAME") or "*"
            subprocess.Popen(
                ["msg", user, "/TIME:5", f"{title}: {message}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **hidden_subprocess_kwargs(),
            )
            return True
        binary = shutil.which("notify-send")
        if binary:
            subprocess.Popen([binary, title, message], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    return False


def play_sound() -> bool:
    """播放完成提示音；失败时不阻塞主流程。"""
    try:
        if sys.platform == "darwin":
            subprocess.Popen(
                ["afplay", "/System/Library/Sounds/Glass.aiff"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        if os.name == "nt":
            import winsound

            winsound.MessageBeep(winsound.MB_ICONASTERISK)
            return True
    except (ImportError, OSError, ValueError):
        pass
    return False


def delete_path(path: Path) -> tuple[bool, str]:
    """删除历史目录；macOS 优先移入废纸篓，其它平台直接删除。"""
    path = path.resolve()
    try:
        if sys.platform == "darwin":
            escaped = str(path).replace('"', '\\"')
            osa = f'tell application "Finder" to delete (POSIX file "{escaped}" as alias)'
            result = subprocess.run(
                ["osascript", "-e", osa],
                capture_output=True,
                timeout=20,
                **hidden_subprocess_kwargs(),
            )
            if result.returncode == 0 and not path.exists():
                return True, ""

        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
        else:
            return False, "目录不存在或已被删除"
        return True, ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
