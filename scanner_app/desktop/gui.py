#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""靶场扫描 GUI 入口（pywebview，支持 macOS / Windows）双模式版

启动：python3 -m scanner_app.desktop.gui
模式：公网 Web 靶场（端口递增扫描 + 首页截图）/ 内网穿透靶场（存活 + 无凭据 OS 判断）
通信：JS 侧定时轮询 poll_events() 拉取事件，避免跨线程调用问题
"""

import base64
import ipaddress
import json
import queue
import re
import sys
import threading
import traceback
import webbrowser
from pathlib import Path

try:
    import webview
except ImportError:  # 允许 CLI/静态测试在未安装 GUI 依赖时继续导入模块
    webview = None

from scanner_app.core import domain_discovery, internal_scanner, screenshot
from scanner_app.core.platform_support import (
    APP_NAME,
    APP_VERSION,
    GUI_DIR,
    RESULTS_ROOT,
    configure_console,
    delete_path,
    notify as platform_notify,
    open_path as platform_open_path,
    play_sound as platform_play_sound,
    resolve_output_dir,
    show_error,
)
from scanner_app.core import scanner_core

IMG_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".ico": "image/x-icon",
            ".svg": "image/svg+xml", ".gif": "image/gif"}


class Api:
    """暴露给 JS 的接口（JS 侧通过 pywebview.api.xxx() 调用）"""

    def __init__(self):
        self.evt_queue = queue.Queue()
        self.scan_thread = None   # 公网/内网共用一个"当前扫描"槽位
        self.cancel = threading.Event()
        # 已知子域轮询监控：独立线程与取消开关，不占用扫描槽位，可与扫描并存
        self.watch_thread = None
        self.watch_cancel = threading.Event()
        # 每轮监控一个自增会话号，随所有 watch_* 事件下发。
        # 旧监控的 watch_done 可能晚于新监控的 watch_start 才被前端拉走，
        # 没有会话号时它会把新监控的轮询定时器关掉，界面就此卡住。
        self.watch_seq = 0
        self.watch_session = None

    # ---------- 配置 ----------

    def get_config(self):
        return {
            "targets": ", ".join(scanner_core.DEFAULT_TARGETS),
            "port_start": scanner_core.DEFAULT_PUBLIC_PORT_START,
            "port_end": scanner_core.DEFAULT_PUBLIC_PORT_END,
            "threads": 100,
            "timeout": 2.0,
            "screenshots_available": bool(screenshot.SCREENSHOT_AVAILABLE),
            "screenshots_error": screenshot.SCREENSHOT_UNAVAILABLE_REASON,
        }

    def get_internal_config(self):
        return {
            "cidrs": ", ".join(internal_scanner.DEFAULT_CIDRS),
            "ports": ", ".join(map(str, internal_scanner.DEFAULT_PORTS)),
            "threads": internal_scanner.DEFAULT_THREADS,
            "timeout": internal_scanner.DEFAULT_TIMEOUT,
        }

    def get_app_info(self):
        """关于页信息：版本、运行环境、Python 版本、结果目录与截图能力。

        结果目录只用于展示和"打开结果目录"按钮，实际打开仍走 open_path()
        的目录白名单校验，避免这里成为越权入口。
        """
        if sys.platform == "win32":
            platform_name = "windows"
        elif sys.platform == "darwin":
            platform_name = "macos"
        else:
            platform_name = "other"
        return {
            "name": APP_NAME,
            "version": APP_VERSION,
            "platform": platform_name,
            "python": sys.version.split()[0],
            "results_root": str(RESULTS_ROOT),
            "screenshots_available": bool(screenshot.SCREENSHOT_AVAILABLE),
            "screenshots_error": screenshot.SCREENSHOT_UNAVAILABLE_REASON,
        }

    # ---------- 扫描控制 ----------

    def _busy(self):
        return self.scan_thread is not None and self.scan_thread.is_alive()

    def start_scan(self, targets, port_start, port_end, threads, timeout, screenshots=True, ports=None):
        if self._busy():
            return {"ok": False, "error": "扫描正在进行中，请先停止"}
        # 目标解析：支持 IP / hostname / CIDR 网段混合输入（CIDR 展开为 IP 列表）
        ip_list = []
        bad = []
        for t in str(targets).split(","):
            t = t.strip()
            if not t:
                continue
            if "/" in t:
                try:
                    net = ipaddress.ip_network(t, strict=False)
                    ip_list.extend(str(h) for h in net.hosts())
                except ValueError:
                    bad.append(t)
            else:
                ip_list.append(t)
        if bad:
            return {"ok": False, "error": f"网段格式不合法：{', '.join(bad)}"}
        # 去重并保持顺序
        seen = set()
        uniq = []
        for t in ip_list:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        ip_list = uniq
        if not ip_list:
            return {"ok": False, "error": "目标 IP 不能为空"}
        bad = [t for t in ip_list if not re.fullmatch(r"[\w.-]+", t)]
        if bad:
            return {"ok": False, "error": f"目标格式不合法：{', '.join(bad)}"}
        # 端口列表（可选）：显式端口集合，优先级高于范围
        port_list = None
        if ports:
            try:
                port_list = sorted({int(p) for p in re.split(r"[,，\s]+", str(ports)) if p.strip()})
            except ValueError:
                return {"ok": False, "error": "端口列表格式不合法（应为逗号分隔数字）"}

        self.evt_queue = queue.Queue()
        self.cancel = threading.Event()

        def worker():
            try:
                scanner_core.run_scan(
                    targets=ip_list,
                    port_start=int(port_start),
                    port_end=int(port_end),
                    timeout=float(timeout),
                    threads=int(threads),
                    on_event=lambda evt: self.evt_queue.put(evt),
                    cancel=self.cancel,
                    screenshots=bool(screenshots),
                    ports=port_list,
                )
            except Exception as e:
                # 工作线程边界：必须兜住所有异常，否则线程静默退出、界面会永久停在“扫描中”。
                # 因此保留宽泛捕获，但回传完整 traceback，避免只看到 repr(e) 而无从排查。
                self.evt_queue.put({"type": "error", "message": repr(e),
                                    "traceback": traceback.format_exc(), "fatal": True})

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()
        return {"ok": True}

    def start_internal_scan(self, cidrs, ports, threads, timeout):
        if self._busy():
            return {"ok": False, "error": "扫描正在进行中，请先停止"}
        seen = set()
        cidr_list = []
        bad_cidrs = []
        for c in str(cidrs).split(","):
            c = c.strip()
            if not c or c in seen:
                continue
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                bad_cidrs.append(c)
                continue
            seen.add(c)
            cidr_list.append(c)
        if bad_cidrs:
            return {"ok": False, "error": f"网段格式不合法：{', '.join(bad_cidrs)}"}
        if not cidr_list:
            return {"ok": False, "error": "网段不能为空"}
        try:
            port_list = sorted({int(p) for p in re.split(r"[,，\s]+", str(ports)) if p.strip()})
        except ValueError:
            return {"ok": False, "error": "端口列表格式不合法（应为逗号分隔数字）"}

        self.evt_queue = queue.Queue()
        self.cancel = threading.Event()

        def worker():
            try:
                internal_scanner.run_internal_scan(
                    cidrs=cidr_list,
                    ports=port_list,
                    timeout=float(timeout),
                    threads=int(threads),
                    on_event=lambda evt: self.evt_queue.put(evt),
                    cancel=self.cancel,
                )
            except Exception as e:
                # 同 start_scan：工作线程边界保留宽泛捕获，但回传 traceback 便于排查。
                self.evt_queue.put({"type": "error", "message": repr(e),
                                    "traceback": traceback.format_exc(), "fatal": True})

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()
        return {"ok": True}

    def stop_scan(self):
        self.cancel.set()
        return {"ok": True}

    # ---------- 已知子域轮询监控 ----------

    # 合法主机名：点分标签，每个标签字母数字开头结尾、中间可含连字符
    _HOSTNAME_RE = re.compile(
        r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

    @staticmethod
    def _normalize_watch_domain(raw: str) -> str:
        """把输入规整为完整域名，无法规整时返回空串（调用方按假值过滤）。

        支持三种写法：完整域名（lab-abc123.rzsec.cn）、带协议（https://…）、
        以及只给随机位（abc123，自动套用靶场模板 lab-<id>.rzsec.cn）。

        拼完还要过一遍主机名校验：否则 "@@" 会被拼成 lab-@@.rzsec.cn 这种
        无效域名混进监控列表，白占轮询配额。
        """
        d = (raw or "").strip().lower()
        if not d:
            return ""
        d = re.sub(r"^https?://", "", d).strip("/ ")
        if "." not in d:                       # 只给了随机位，套用靶场模板
            d = f"lab-{d}.rzsec.cn"
        return d if Api._HOSTNAME_RE.match(d) else ""

    def start_watch(self, opts):
        """轮询监控已知子域，等待靶场拉起。

        靶场按需随机生成域名、且拉起需要时间，盲扫 21.8 亿不现实；对已知 ID
        轮询等待的命中率要高得多。

        opts：domains（逗号/换行分隔）/ interval（秒）/ port / timeout / stop_on_all_up
        事件：watch_start / watch_probe / watch_found / watch_round / watch_done
        """
        if self.watch_thread and self.watch_thread.is_alive():
            return {"ok": False, "error": "监控已在运行中，请先停止"}
        try:
            opts = opts or {}
            doms, seen = [], set()
            for token in re.split(r"[\s,;]+", str(opts.get("domains") or "")):
                d = self._normalize_watch_domain(token)
                if d and d not in seen:
                    seen.add(d)
                    doms.append(d)
            if not doms:
                return {"ok": False, "error": "请至少填写一个子域或随机位"}
            if len(doms) > 200:
                return {"ok": False, "error": f"最多监控 200 个，当前 {len(doms)} 个"}

            port = int(opts.get("port") or 443)
            if not 1 <= port <= 65535:
                return {"ok": False, "error": "监控端口需在 1-65535 之间"}
            # 限制轮询频率：过快会被平台限流甚至判为滥用
            interval = min(max(float(opts.get("interval") or 30), 5), 3600)
            timeout = float(opts.get("timeout") or 2.0)
            stop_on_all_up = bool(opts.get("stop_on_all_up"))

            self.watch_cancel = threading.Event()
            cancel = self.watch_cancel
            self.watch_seq += 1
            session = str(self.watch_seq)
            self.watch_session = session

            def worker():
                state, rounds = {}, 0
                try:
                    self.evt_queue.put({"type": "watch_start", "session": session,
                                        "domains": list(doms),
                                        "port": port, "interval": interval,
                                        "stop_on_all_up": stop_on_all_up})
                    while not cancel.is_set():
                        rounds += 1
                        alive_cnt = 0
                        for d in doms:
                            if cancel.is_set():
                                break
                            info = domain_discovery.probe_domain(
                                d, port, timeout=timeout,
                                connect_timeout=min(timeout, 1.5),
                                read_timeout=timeout,
                                max_body=domain_discovery.DISCOVER_BODY)
                            live = bool(info.get("live"))
                            if live:
                                alive_cnt += 1
                            self.evt_queue.put({
                                "type": "watch_probe", "session": session,
                                "domain": d, "live": live,
                                "status": info.get("status"), "title": info.get("title"),
                                "round": rounds})
                            # 仅在「未上线/未知 → 已上线」时上报一次，避免每轮刷屏
                            if live and state.get(d) is not True:
                                self.evt_queue.put({
                                    "type": "watch_found", "session": session, "domain": d,
                                    "status": info.get("status"),
                                    "title": info.get("title"), "ip": info.get("ip"),
                                    "port": port, "first": state.get(d) is None})
                            state[d] = live
                        self.evt_queue.put({"type": "watch_round", "session": session,
                                            "round": rounds,
                                            "alive": alive_cnt, "total": len(doms)})
                        if stop_on_all_up and alive_cnt == len(doms):
                            break
                        if cancel.wait(interval):   # 可被 stop_watch 立即唤醒
                            break
                    self.evt_queue.put({"type": "watch_done", "session": session,
                                        "rounds": rounds,
                                        "alive": sum(1 for v in state.values() if v),
                                        "total": len(doms)})
                except Exception as e:
                    # 工作线程边界：保留宽泛捕获，回传 traceback 便于排查
                    self.evt_queue.put({"type": "error", "message": repr(e),
                                        "traceback": traceback.format_exc(), "fatal": False})

            self.watch_thread = threading.Thread(target=worker, daemon=True)
            self.watch_thread.start()
            return {"ok": True, "domains": doms, "interval": interval,
                    "session": session}
        except (OSError, ValueError, TypeError) as e:
            return {"ok": False, "error": repr(e)}

    def stop_watch(self):
        """停止轮询监控（wait 会被立即唤醒，无需等到下个周期）。"""
        self.watch_cancel.set()
        return {"ok": True}

    def is_watching(self):
        return bool(self.watch_thread and self.watch_thread.is_alive())

    def start_discovery(self, opts):
        """子域发现（靶场变为 lab-XXXXXX.rzsec.cn 通配符域名后的搜索优化）。

        opts（JS 字典）：template / charset / port_start / port_end / threads / timeout /
        screenshots / discover_port / discover_threads / limit / found_limit /
        mode / resume

        charset 为空时回退到默认 a-z0-9（36^6≈21.8 亿，穷举不可行）。缩小字符集
        是让发现变可行的唯一手段，例如十六进制仅 16^6≈1677 万。
        复用与 start_scan 相同的事件队列与取消开关；发现的活域名会进入第二阶段
        run_scan（沿用公网结果展示与报告）。
        """
        if self._busy():
            return {"ok": False, "error": "扫描正在进行中，请先停止"}
        try:
            opts = opts or {}
            template = str(opts.get("template") or "").strip() or None
            outdir = resolve_output_dir("", "public")
            outdir.mkdir(parents=True, exist_ok=True)
            resume_path = str(outdir / ".discover_ckpt.json")
            resume = bool(opts.get("resume"))
            self.evt_queue = queue.Queue()
            self.cancel = threading.Event()

            def worker():
                try:
                    scanner_core.run_discovery_scan(
                        template=template,
                        prefix="lab-", suffix=".rzsec.cn", length=6,
                        charset=(str(opts.get("charset") or "").strip() or None),
                        mode=str(opts.get("mode") or "random"),
                        discover_port=int(opts.get("discover_port") or 80),
                        port_start=int(opts.get("port_start") or 80),
                        port_end=int(opts.get("port_end") or 80),
                        timeout=float(opts.get("timeout") or 1.0),
                        connect_timeout=float(opts.get("discover_connect_timeout") or 0.6),
                        read_timeout=float(opts.get("discover_read_timeout") or 1.0),
                        threads=int(opts.get("threads") or 100),
                        discover_threads=int(opts.get("discover_threads") or 300),
                        limit=int(opts.get("limit") or 0) or None,
                        found_limit=int(opts.get("found_limit") or 0) or None,
                        resume_path=resume_path,
                        reset=not resume,
                        fast=bool(opts.get("fast")),
                        output=str(outdir),
                        on_event=lambda evt: self.evt_queue.put(evt),
                        cancel=self.cancel,
                        screenshots=bool(opts.get("screenshots", True)),
                    )
                except Exception as e:
                    # 同 start_scan：工作线程边界保留宽泛捕获，但回传 traceback 便于排查。
                    self.evt_queue.put({"type": "error", "message": repr(e),
                                        "traceback": traceback.format_exc(), "fatal": True})

            self.scan_thread = threading.Thread(target=worker, daemon=True)
            self.scan_thread.start()
            return {"ok": True}
        except (OSError, ValueError, TypeError) as e:
            # 参数解析（int/float）与结果目录创建（mkdir）的预期异常
            return {"ok": False, "error": repr(e)}

    def poll_events(self, limit=60):
        """分批返回事件队列，避免一次回传大量事件导致前端批量渲染卡顿"""
        events = []
        try:
            for _ in range(int(limit)):
                events.append(self.evt_queue.get_nowait())
        except queue.Empty:
            pass
        return events

    def is_scanning(self):
        return {"scanning": self._busy()}

    # ---------- 截图与报告 ----------

    def screenshot_data(self, results_dir, filename):
        """返回 base64 data URL 供界面显示（仅限默认结果目录内的图片）。"""
        try:
            d = Path(results_dir).resolve()
            d.relative_to(RESULTS_ROOT.resolve())
            f = (d / Path(str(filename)).name).resolve()
            f.relative_to(RESULTS_ROOT.resolve())
            mime = IMG_MIME.get(f.suffix.lower())
            if not mime or not f.is_file():
                return {"error": "文件不存在"}
        except (ValueError, OSError):
            return {"error": "路径不合法"}
        b64 = base64.b64encode(f.read_bytes()).decode("ascii")
        return {"data": f"data:{mime};base64,{b64}"}

    def _safe_under_results(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(RESULTS_ROOT.resolve())
            return True
        except (ValueError, OSError):
            return False

    def open_report(self, path):
        """用默认浏览器打开 report.html"""
        f = Path(path)
        if not self._safe_under_results(f) or f.name != "report.html" or not f.is_file():
            return {"ok": False, "error": "报告文件不存在"}
        webbrowser.open(f.resolve().as_uri())
        return {"ok": True}

    # ---------- 系统联动 ----------

    def notify(self, title, message):
        """桌面提醒（macOS 使用通知中心，Windows 使用系统消息）。"""
        platform_notify(title, message)
        return {"ok": True}

    def play_sound(self):
        """扫描完成提示音（静默失败，不阻塞扫描线程）。"""
        platform_play_sound()
        return {"ok": True}

    def open_url(self, url):
        if str(url).startswith(("http://", "https://")):
            webbrowser.open(str(url))
            return {"ok": True}
        return {"ok": False, "error": "仅支持 http/https 链接"}

    def open_path(self, path):
        """在系统文件管理器中打开目录；只允许默认结果目录之内。"""
        if not self._safe_under_results(Path(path)):
            return {"ok": False, "error": "路径不在默认结果目录内"}
        return {"ok": platform_open_path(Path(path))}

    def delete_history(self, path):
        """删除一条历史记录（仅限默认结果目录的直接子目录）。"""
        try:
            p = Path(path).resolve()
            root = RESULTS_ROOT.resolve()
            p.relative_to(root)
            if p.parent != root:
                return {"ok": False, "error": "只能删除默认结果目录下的记录目录"}
            if not p.is_dir():
                return {"ok": False, "error": "目录不存在或已被删除"}
        except (ValueError, OSError):
            return {"ok": False, "error": "路径不合法"}
        ok, error = delete_path(p)
        if not ok:
            return {"ok": False, "error": f"删除失败：{error}"}
        return {"ok": True}

    # ---------- 历史记录 ----------

    def get_report_data(self, path):
        """读取历史记录的 report.json，归一化为前端图表可直接消费的数据"""
        if not self._safe_under_results(Path(path)):
            return {"ok": False, "error": "路径不在默认结果目录内"}
        f = Path(path) / "report.json"
        if not f.is_file():
            return {"ok": False, "error": "report.json 不存在"}
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return {"ok": False, "error": f"读取失败：{e}"}

        if isinstance(data, dict) and data.get("mode") == "internal":
            hosts = [{"ip": h.get("ip"), "via": h.get("via"),
                      "ttl": h.get("ttl"), "os_guess": h.get("os_guess", "未知"),
                      "open_ports": h.get("open_ports", [])}
                     for h in data.get("hosts", []) if h.get("alive")]
            return {"ok": True, "kind": "internal", "hosts": hosts}

        if isinstance(data, list):
            ports = []
            for t in data:
                if not scanner_core.is_qualified_target(t):
                    continue
                for r in (t.get("ports") or {}).values():
                    if scanner_core.is_qualified_port(r):
                        ports.append({"ip": t.get("ip"), "port": r.get("port"),
                                      "is_http": bool(r.get("is_http")),
                                      "scheme": r.get("scheme", ""),
                                      "status": r.get("status", 0),
                                      "title": r.get("title", ""),
                                      "server": r.get("server", "")})
            return {"ok": True, "kind": "public", "ports": ports}

        return {"ok": False, "error": "无法识别的 report.json 格式"}

    def get_history(self):
        items = []
        if RESULTS_ROOT.exists():
            for d in sorted(RESULTS_ROOT.iterdir(), reverse=True):
                if len(items) >= 30:
                    break
                rpt = d / "report.json"
                if not (d.is_dir() and rpt.exists()):
                    continue
                try:
                    data = json.loads(rpt.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                m = re.fullmatch(r"(?:internal_)?(\d{8})_(\d{6})", d.name)
                if m:
                    time_str = (f"{m.group(1)[:4]}-{m.group(1)[4:6]}-{m.group(1)[6:]} "
                                f"{m.group(2)[:2]}:{m.group(2)[2:4]}:{m.group(2)[4:]}")
                else:
                    time_str = d.name
                if isinstance(data, dict) and data.get("mode") == "internal":
                    items.append({
                        "name": d.name, "path": str(d), "time": time_str, "kind": "internal",
                        "targets": data.get("cidrs", []),
                        "summary": (f"存活 {data.get('counts', {}).get('存活主机', 0)} 台 · "
                                    f"Linux {data.get('counts', {}).get('Linux', 0)} · "
                                    f"Windows {data.get('counts', {}).get('Windows', 0)}"),
                        "report_html": (d / "report.html").is_file(),
                    })
                elif isinstance(data, list):
                    valid_data = [t for t in data if scanner_core.is_qualified_target(t)]
                    if not valid_data:
                        continue
                    open_total = sum(
                        sum(1 for r in (t.get("ports") or {}).values()
                            if scanner_core.is_qualified_port(r))
                        for t in valid_data
                    )
                    items.append({
                        "name": d.name, "path": str(d), "time": time_str, "kind": "public",
                        "targets": [t.get("ip", "?") for t in valid_data],
                        "summary": f"开放端口 {open_total} 个",
                        "report_html": (d / "report.html").is_file(),
                    })
        return items


def set_dock_icon():
    """用 pyobjc 设置 macOS Dock 图标（GUI 启动后调用）"""
    if sys.platform != "darwin":
        return
    try:
        from AppKit import NSApplication, NSImage, NSSize
        # 优先使用较小的 dock 专用图标（256x256）；缺失时回退到 1024 原图
        for name in ("app_icon_dock.png", "app_icon.png"):
            img = NSImage.alloc().initWithContentsOfFile_(str(GUI_DIR / name))
            if img is not None:
                # 约束逻辑尺寸为标准 Dock 图标大小，避免在高分屏/非 .app 进程下
                # 被当成超大物理像素图标渲染（Dock 图标显得过大）
                img.setScalesWhenResized_(True)
                img.setSize_(NSSize(128.0, 128.0))
                NSApplication.sharedApplication().setApplicationIconImage_(img)
                break
    except (OSError, ImportError, RuntimeError, AttributeError, ValueError, NameError):
        pass  # 图标设置是纯装饰行为，失败不应影响主功能


def main():
    configure_console()
    if webview is None:
        message = "缺少 pywebview，请重新构建 Windows EXE 或安装项目依赖。"
        if getattr(sys, "frozen", False):
            show_error("靶场扫描助手", message)
        raise SystemExit(message)
    api = Api()
    try:
        webview.create_window(
            title="靶场扫描助手",
            url=str(GUI_DIR / "index.html"),
            js_api=api,
            width=1160,
            height=780,
            min_size=(1000, 660),
            background_color="#f5f5f7",
        )
        webview.start(set_dock_icon)
    except Exception as exc:
        # 程序最外层边界：保留宽泛捕获以便弹出友好提示，随后原样 raise，不吞掉异常。
        message = f"桌面窗口启动失败：{exc!r}"
        if getattr(sys, "frozen", False):
            show_error("靶场扫描助手", message)
        raise


if __name__ == "__main__":
    main()
