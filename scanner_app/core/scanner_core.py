#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""靶场扫描核心逻辑（CLI 与 GUI 共用）

约定：
  - 过程信息一律通过 on_event(dict) 回调发出，本模块自身不做任何 print
  - cancel（threading.Event）置位后尽快停止，未执行的任务被丢弃，
    已在执行的任务最迟约 timeout 秒内自然结束
  - 返回结构化结果列表，并落盘 report.md / report.json / 各站 HTML 快照
  - 公网结果只保留 Ping 存活、HTTP 可访问且页面标题非空的站点

事件类型：
  scan_start      {targets, port_start, port_end, total_ports, results_dir}
  target_start    {ip}
  ping            {ip, alive, latency_ms}
  progress        {ip, done, total}
  port_found      {ip, port, state, is_http, scheme, status, title, server, snapshot, ...}
  phase           {phase}                     # screenshots = 端口扫完等待截图
  screenshot_done {ip, port, ok, path, favicon, error}
  target_done     {ip, open_count, total, cancelled}
  scan_done       {results_dir, cancelled, open_total, screenshot_total,
                   qualified_target_total, qualified_site_total, report_available}
  error           {message}
"""

import concurrent.futures
import html
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from scanner_app.core.platform_support import (
    hidden_subprocess_kwargs,
    parse_ping_output,
    ping_command,
    resolve_output_dir,
    user_agent,
)

UA = user_agent()
MAX_BODY = 512 * 1024  # 首页最多抓取 512KB
DEFAULT_TARGETS = ["43.139.231.237", "43.139.149.11"]
DEFAULT_PUBLIC_PORT_START = 8000
DEFAULT_PUBLIC_PORT_END = 8020
# 复用 SSL 上下文（跳过证书校验，适用于靶场常见自签证书）
_SSL_CTX = ssl._create_unverified_context()
# 直连 opener（禁用系统代理，靶场扫描必须连目标本身；HTTPS 用跳过校验的 context）
_NO_PROXY_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_SSL_CTX),
)


def ping_host(ip: str, timeout: float) -> dict:
    """ICMP 存活探测；命令参数和输出解析由平台适配层处理。"""
    cmd = ping_command(ip, timeout)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 3,
            **hidden_subprocess_kwargs(),
        )
    except subprocess.TimeoutExpired:
        return {"alive": False, "latency_ms": None}
    out = proc.stdout + proc.stderr
    if proc.returncode == 0:
        parsed = parse_ping_output(out)
        return {"alive": True, "latency_ms": parsed["latency_ms"]}
    return {"alive": False, "latency_ms": None}


def decode_body(body: bytes, content_type: str) -> str:
    """按 响应头 charset → meta charset → utf-8 → gbk 的顺序解码"""
    candidates = []
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    if m:
        candidates.append(m.group(1))
    meta = re.search(rb"""<meta[^>]+charset=["']?([\w-]+)""", body[:2048], re.I)
    if meta:
        candidates.append(meta.group(1).decode("ascii", "replace"))
    candidates += ["utf-8", "gbk"]
    for enc in candidates:
        try:
            return body.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


def extract_title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:120]


def _http_result(scheme, status, headers, body, req_url, final_url):
    content_type = (headers.get("Content-Type") or "") if headers else ""
    text = decode_body(body, content_type)
    return {
        "is_http": True,
        "scheme": scheme,
        "status": status,
        "server": (headers.get("Server") or "") if headers else "",
        "content_type": content_type,
        "title": extract_title(text),
        "body_length": len(body),
        "redirected": final_url != req_url,
        "body": body,
    }


def fetch_http(ip: str, port: int, timeout: float) -> dict:
    """对开放端口先试 http 再试 https；非 HTTP 服务返回 is_http=False
    https 二次尝试用递减超时，避免非 HTTP 端口白等满一个完整 timeout；
    必须直连目标（禁用系统代理，否则代理会接管 127.0.0.1 等请求导致误判）"""
    last_err = ""
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
        eff_timeout = timeout if scheme == "http" else max(0.3, timeout * 0.7)
        try:
            # 靶场常用自签证书已通过 HTTPSHandler(context) 跳过校验
            with _NO_PROXY_OPENER.open(req, timeout=eff_timeout) as resp:
                return _http_result(scheme, resp.status, resp.headers,
                                    resp.read(MAX_BODY), url, resp.url)
        except urllib.error.HTTPError as e:  # 4xx/5xx 也说明是 HTTP 服务
            try:
                body = e.read(MAX_BODY)
            except (OSError, ValueError):
                body = b""
            return _http_result(scheme, e.code, e.headers, body, url, url)
        except (urllib.error.URLError, OSError, ssl.SSLError, socket.timeout,
                UnicodeError, ValueError) as e:  # 连不上 / 超时 / 非 HTTP 协议
            last_err = f"{type(e).__name__}: {e}"
    return {"is_http": False, "error": last_err}


def is_qualified_port(result: dict) -> bool:
    """判断公网端口是否具备可展示的靶场页面。"""
    return (
        result.get("state") == "open"
        and result.get("is_http") is True
        and bool(str(result.get("title") or "").strip())
    )


def is_qualified_target(result: dict, require_ping: bool = True) -> bool:
    """判断目标是否应进入公网结果、报告和历史记录。

    require_ping=True（默认，IP 模式）：必须 Ping 存活。
    require_ping=False（域名/子域发现模式）：域名常被禁 ICMP，只要存在可展示
    的 HTTP 端口即算命中，不强制 Ping 存活。
    """
    if require_ping and not (result.get("ping") or {}).get("alive"):
        return False
    return any(is_qualified_port(port) for port in (result.get("ports") or {}).values())


# IPv4 字面量判定：命中则视为 IP 目标，否则（含字母的主机名、[IPv6] 等）按域名处理
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_domain(target: str) -> bool:
    """目标是否为域名/主机名（非纯 IPv4 字面量）。"""
    t = (target or "").strip()
    if not t:
        return False
    if _IPV4_RE.match(t):
        return False
    return True


def scan_port(ip: str, port: int, timeout: float, outdir: Path, cancel: threading.Event) -> dict:
    """单个端口：TCP 连接探测 → 开放则抓首页并保存 HTML 快照"""
    if cancel.is_set():
        return {"state": "cancelled", "port": port}
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except OSError as e:
        return {"state": "closed", "port": port, "detail": type(e).__name__}

    info = fetch_http(ip, port, timeout)
    result = {"state": "open", "port": port, **info}
    if info.get("is_http") and str(info.get("title") or "").strip():
        snap = outdir / f"{ip}_{port}.html"
        snap.write_bytes(info["body"])
        result["snapshot"] = snap.name
    result.pop("body", None)
    return result


def scan_target(ip: str, ports: range, timeout: float, threads: int,
                outdir: Path, on_event, cancel: threading.Event,
                require_ping: bool = True) -> dict:
    on_event({"type": "target_start", "ip": ip})
    is_dom = _is_domain(ip)

    # 域名目标：ICMP 常被云厂商/靶场禁用且对验证无意义，跳过 ping（域名模式 require_ping 恒为 False）
    if is_dom:
        ping = {"alive": False, "skipped": True, "reason": "domain"}
    else:
        ping = ping_host(ip, timeout)
    on_event({"type": "ping", "ip": ip, **ping})

    results = {"ip": ip, "ping": ping, "ports": {}, "open_count": 0}
    total = len(ports)
    cancelled = False
    if require_ping and not ping.get("alive"):
        # 公网结果只展示 Ping 存活的目标；提前结束端口探测，避免生成无效模块。
        on_event({"type": "progress", "ip": ip, "done": total, "total": total})
        on_event({"type": "target_done", "ip": ip, "open_count": 0,
                  "qualified_count": 0, "total": total, "cancelled": False})
        return results

    # ---- 域名目标：走 probe_domain 做已知子域验证 ----
    # 关键：靶场前端对一切子域统一 301→HTTPS、未拉起的靶场统一 404；
    # fetch_http（urllib）不跟随跨端口 301 且 is_qualified_port 不过滤通用默认页，
    # 直接用 scan_port 会把「301 Moved Permanently」默认页误判成活靶场。
    # probe_domain 会跟随 301/302/307/308 到最终 HTTPS 响应，并过滤通用默认页，
    # 返回最终 scheme/port 交给截图池抓真实首页。
    if is_dom:
        from scanner_app.core import domain_discovery
        done = 0
        for port in ports:
            if cancel.is_set():
                cancelled = True
                break
            done += 1
            info = domain_discovery.probe_domain(ip, port, timeout=timeout)
            if not info.get("live"):
                on_event({"type": "progress", "ip": ip, "done": done, "total": total})
                continue
            final_port = info.get("port") or port
            final_scheme = info.get("scheme") or ("https" if final_port == 443 else "http")
            pr = {
                "state": "open",
                "port": final_port,
                "is_http": True,
                "scheme": final_scheme,
                "status": info.get("status"),
                "title": info.get("title") or "",
                "server": info.get("server") or "",
            }
            body = info.get("body")
            if body:
                snap = outdir / f"{ip}_{final_port}.html"
                try:
                    snap.write_bytes(body)
                    pr["snapshot"] = snap.name
                except OSError:
                    pass
            results["ports"][str(final_port)] = pr
            on_event({"type": "port_found", "ip": ip, **pr})
            on_event({"type": "progress", "ip": ip, "done": done, "total": total})
        open_count = sum(1 for r in results["ports"].values() if r["state"] == "open")
        results["open_count"] = open_count
        on_event({"type": "target_done", "ip": ip, "open_count": open_count,
                  "qualified_count": open_count, "total": total, "cancelled": cancelled})
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futmap = {ex.submit(scan_port, ip, p, timeout, outdir, cancel): p for p in ports}
        try:
            for i, fut in enumerate(concurrent.futures.as_completed(futmap), 1):
                if cancel.is_set():
                    cancelled = True
                    break
                port = futmap[fut]
                try:
                    r = fut.result()
                except (OSError, ValueError, TypeError, RuntimeError) as e:
                    r = {"state": "error", "port": port, "error": repr(e)}
                if is_qualified_port(r):
                    results["ports"][str(port)] = r
                    on_event({"type": "port_found", "ip": ip, **r})
                on_event({"type": "progress", "ip": ip, "done": i, "total": total})
        finally:
            if cancelled:
                ex.shutdown(wait=False, cancel_futures=True)

    open_count = sum(1 for r in results["ports"].values() if r["state"] == "open")
    results["open_count"] = open_count
    on_event({"type": "target_done", "ip": ip, "open_count": open_count,
              "qualified_count": open_count, "total": total, "cancelled": cancelled})
    return results


def write_reports(results: list, outdir: Path, port_start: int, port_end: int,
                  threads: int, timeout: float, ports=None, duration=None) -> None:
    """兼容保留：转发到 reports.write_public_report"""
    from scanner_app.core import reports
    reports.write_public_report(results, outdir, port_start, port_end, threads, timeout,
                                ports, duration)


def run_scan(targets, port_start=DEFAULT_PUBLIC_PORT_START,
             port_end=DEFAULT_PUBLIC_PORT_END, timeout=2.0, threads=100,
             output="", on_event=None, cancel=None, screenshots=True, ports=None,
             require_ping=True) -> list:
    """执行一次完整扫描；targets 为 IP 或域名字符串列表。
    支持两种端口模式：ports 列表（显式端口集合）或 port_start/port_end 范围。
    require_ping=True（默认，IP 模式）要求 Ping 存活；域名目标传 False 放宽。"""
    base_on_event = on_event or (lambda evt: None)
    cancel = cancel if cancel is not None else threading.Event()
    scan_t0 = time.time()
    # 去重并保持顺序（先取原参数，再重建，避免生成器迭代到空列表）
    seen = set()
    raw_targets = [t.strip() for t in targets if t.strip()]
    targets = []
    for t in raw_targets:
        if t not in seen:
            seen.add(t)
            targets.append(t)

    outdir = resolve_output_dir(output, "public")
    outdir.mkdir(parents=True, exist_ok=True)
    # 显式端口列表优先；否则按端口范围。域名目标没有显式列表时默认只探 80（靶场首页端口）。
    explicit_ports = None
    if ports:
        explicit_ports = sorted(set(int(p) for p in ports if str(p).strip().isdigit()))

    # 截图池：发现 HTTP 站点后异步截图（顺带抓 favicon），完成经 screenshot_done 事件上报
    shot_map = {}
    fav_map = {}
    pool = None
    if screenshots:
        from scanner_app.core import screenshot as shot_mod
        if shot_mod.SCREENSHOT_AVAILABLE:
            def on_shot_done(info):
                if info["ok"]:
                    shot_map[(info["ip"], info["port"])] = info["path"]
                if info.get("favicon"):
                    fav_map[(info["ip"], info["port"])] = info["favicon"]
                base_on_event({"type": "screenshot_done", **info})

            pool = shot_mod.ScreenshotPool(on_done=on_shot_done, out_dir=outdir)
            pool.start()
        else:
            reason = getattr(
                shot_mod,
                "SCREENSHOT_UNAVAILABLE_REASON",
                "Playwright/Chromium 不可用",
            )
            base_on_event({"type": "error", "message": f"{reason}，本次扫描跳过截图"})

    def wrapped_on_event(evt):
        if evt["type"] == "port_found" and evt.get("is_http") and pool is not None:
            pool.submit(evt["ip"], evt["port"], evt["scheme"])
        base_on_event(evt)

    display_ports = explicit_ports if explicit_ports is not None else list(range(port_start, port_end + 1))
    base_on_event({"type": "scan_start", "targets": targets, "port_start": port_start,
                   "port_end": port_end, "total_ports": len(display_ports),
                   "ports": display_ports,
                   "results_dir": str(outdir)})

    all_results = []
    scanned_results = []
    for ip in targets:
        if cancel.is_set():
            break
        # 域名目标：放宽 Ping 要求；端口优先级：
        #   1) 显式 ports 列表 → 用之
        #   2) 调用方显式端口范围（非 IP 默认 8000–8020，如 GUI 给域名设 80/80 或用户指定 8099/443）→ 用之
        #   3) 域名且无任何端口信息（纯默认）→ 默认只探 80（靶场首页端口）
        #   4) IP 目标 → 用 port_start/port_end 范围
        is_dom = _is_domain(ip)
        if explicit_ports is not None:
            t_ports = explicit_ports
        elif is_dom and (port_start, port_end) == (DEFAULT_PUBLIC_PORT_START, DEFAULT_PUBLIC_PORT_END):
            t_ports = [80]
        else:
            t_ports = range(port_start, port_end + 1)
        t_require_ping = require_ping if not is_dom else False
        try:
            result = scan_target(ip, t_ports, timeout, threads,
                                 outdir, wrapped_on_event, cancel,
                                 require_ping=t_require_ping)
            scanned_results.append(result)
            if is_qualified_target(result, require_ping=t_require_ping):
                all_results.append(result)
        except (OSError, ValueError, TypeError, RuntimeError,
                subprocess.SubprocessError) as e:
            base_on_event({"type": "error", "message": f"扫描 {ip} 时出错：{e!r}"})

    if pool is not None:
        base_on_event({"type": "phase", "phase": "screenshots"})
        pool.close()  # 等待全部截图任务结束

    # 截图结果并入端口数据（截图在端口扫描之后完成，需在此回填）
    for t in all_results:
        for pr in t["ports"].values():
            fn = shot_map.get((t["ip"], pr.get("port")))
            if fn:
                pr["screenshot"] = fn
            fv = fav_map.get((t["ip"], pr.get("port")))
            if fv:
                pr["favicon"] = fv

    if all_results:  # 即使中途取消，也把已拿到的结果落盘
        write_reports(all_results, outdir, port_start, port_end, threads, timeout,
                      ports if isinstance(ports, list) else None,
                      round(time.time() - scan_t0, 1))

    open_total = sum(t["open_count"] for t in all_results)
    ping_alive_total = sum(1 for t in scanned_results if (t.get("ping") or {}).get("alive"))
    base_on_event({"type": "scan_done", "results_dir": str(outdir),
                   "cancelled": cancel.is_set(), "open_total": open_total,
                   "screenshot_total": len(shot_map),
                   "ping_alive_total": ping_alive_total,
                   "qualified_target_total": len(all_results),
                   "qualified_site_total": open_total,
                   "report_available": bool(all_results),
                   "duration": round(time.time() - scan_t0, 1)})
    return all_results


def run_discovery_scan(template: str = None, prefix: str = "", suffix: str = "",
                       length: int = 6, charset: str = None,
                       mode: str = "random", discover_port: int = 80,
                       port_start=DEFAULT_PUBLIC_PORT_START,
                       port_end=DEFAULT_PUBLIC_PORT_END, timeout: float = 1.0,
                       connect_timeout: float = 0.6, read_timeout: float = 1.0,
                       threads: int = 100, discover_threads: int = 300,
                       limit: int = None, found_limit: int = None,
                       resume_path: str = None, reset: bool = False, seed=None,
                       fast: bool = False, output: str = "", on_event=None, cancel=None,
                       screenshots: bool = True) -> list:
    """子域发现 + 全流水线扫描。

    针对靶场改为 lab-XXXXXX.rzsec.cn 通配符域名形式后的搜索优化：
      1) 用 domain_discovery 引擎做 HTTP Host 探测（默认端口 80，域名靶场首页所在端口），
         发现「活的」靶场子域；
      2) 把发现的域名喂入现有 run_scan 流水线，只扫首页所在端口（discover_port，默认 80）
         + 截图 + 报告，域名目标放宽 Ping 要求（require_ping=False）。

    注意：域名靶场页面固定在 80 端口，不再按 IP 模式扫 8000–8020；
    IP 模式的 run_scan 行为完全不变；本函数是其超集。
    """
    from scanner_app.core import domain_discovery

    base_on_event = on_event or (lambda e: None)
    cancel = cancel if cancel is not None else threading.Event()
    charset = charset or domain_discovery.DEFAULT_CHARSET

    found_domains = []
    seen = set()

    def disc_on_event(evt):
        # 透传 discovery_* 事件给 GUI/CLI；同时收集发现的活域名
        if evt.get("type") == "domain_found":
            d = evt["domain"]
            if d not in seen:
                seen.add(d)
                found_domains.append(d)
        base_on_event(evt)

    # 阶段一：发现活靶场子域
    try:
        domain_discovery.run_discovery(
            template=template, prefix=prefix, suffix=suffix, length=length,
            charset=charset, mode=mode, port=discover_port, timeout=timeout,
            connect_timeout=connect_timeout, read_timeout=read_timeout,
            threads=discover_threads, limit=limit, found_limit=found_limit,
            resume_path=resume_path, reset=reset, seed=seed, fast=fast,
            on_event=disc_on_event, cancel=cancel)
    except (OSError, ValueError, TypeError, RuntimeError) as e:
        base_on_event({"type": "error", "message": f"子域发现阶段出错：{e!r}"})
        return []

    if not found_domains:
        base_on_event({"type": "scan_done", "results_dir": "", "cancelled": cancel.is_set(),
                       "open_total": 0, "screenshot_total": 0, "ping_alive_total": 0,
                       "qualified_target_total": 0, "qualified_site_total": 0,
                       "report_available": False, "duration": 0,
                       "note": "未发现活靶场子域"})
        return []

    # 阶段二：对发现的域名做全流水线扫描（只扫首页所在端口 discover_port，放宽 Ping）
    return run_scan(found_domains, port_start=discover_port, port_end=discover_port,
                    timeout=timeout, threads=threads, output=output,
                    on_event=base_on_event, cancel=cancel, screenshots=screenshots,
                    require_ping=False)
