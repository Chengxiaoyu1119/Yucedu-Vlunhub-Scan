#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内网穿透靶场发现模块（向日葵 VPN 场景，默认 192.168.3.0/24 与 192.168.4.0/24）

只做无凭据发现（不做爆破、不登录、不漏洞利用）：
  1. 存活发现：两个网段并发 ICMP ping（子进程方式，无需 root）；
     ping 不通的主机再用常见端口 TCP 探测兜底（防火墙可能禁 ping）
  2. 系统判断：TTL 推断 + 端口指纹 + SSH Banner + HTTP 标题多信号融合，
     结论 Linux / Windows / 未知，并输出判断依据

事件类型：
  scan_start  {cidrs, total_hosts, ports, results_dir}
  progress    {phase, done, total}          phase: ping | detail
  host_found  {ip, alive, via, ttl, latency_ms, open_ports,
               ssh_banner, http_title, os_guess, reasons}
  mac_resolved {macs}                       # ARP 表合并完成后 {ip: mac}
  scan_done   {results_dir, cancelled, counts}
  error       {message}
"""

import concurrent.futures
import ipaddress
import socket
import subprocess
import threading
import time
from pathlib import Path

from scanner_app.core import reports
from scanner_app.core import scanner_core  # 复用 fetch_http
from scanner_app.core.platform_support import (
    hidden_subprocess_kwargs,
    parse_arp_output,
    parse_ping_output,
    ping_command,
    resolve_output_dir,
)

DEFAULT_CIDRS = ["192.168.3.0/24", "192.168.4.0/24"]
DEFAULT_PORTS = [22, 80, 443, 135, 139, 445, 3389, 8080]
DEFAULT_THREADS = 64
DEFAULT_TIMEOUT = 1.0
HTTP_PORTS = (80, 443, 8080)


def arp_table() -> dict:
    """读取本机 ARP 缓存并统一返回 `{ip: mac}`。"""
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
            **hidden_subprocess_kwargs(),
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp_output(out)


def ping_full(ip: str, timeout: float) -> dict:
    """ICMP 探测并解析 TTL（用于 OS 推断）与时延。"""
    cmd = ping_command(ip, timeout)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            **hidden_subprocess_kwargs(),
        )
    except subprocess.TimeoutExpired:
        return {"alive": False, "ttl": None, "latency_ms": None}
    out = proc.stdout + proc.stderr
    if proc.returncode == 0:
        parsed = parse_ping_output(out)
        return {"alive": True,
                "ttl": parsed["ttl"],
                "latency_ms": parsed["latency_ms"]}
    return {"alive": False, "ttl": None, "latency_ms": None}


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_ssh_banner(ip: str, port: int, timeout: float) -> str:
    """SSH 服务端会主动发 banner，直接读即可，无需发送任何数据"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(128)
        return data.decode("utf-8", "replace").strip()
    except OSError:
        return ""


def guess_os(ttl, open_ports, ssh_banner_text):
    """TTL + 端口指纹 + Banner 融合判断；返回 (结论, 依据列表)"""
    reasons = []
    linux_score = win_score = 0

    if ttl is not None:
        if ttl <= 64:
            linux_score += 2
            reasons.append(f"TTL={ttl}（初始 64 − 路由跳数 → Linux/Unix 系）")
        elif ttl <= 128:
            win_score += 2
            reasons.append(f"TTL={ttl}（初始 128 − 路由跳数 → Windows 系）")
        else:
            reasons.append(f"TTL={ttl}（接近初始 255，疑似网络设备）")

    open_set = set(open_ports)
    if 22 in open_set:
        linux_score += 1
        reasons.append("SSH(22) 端口开放")

    win_hit = open_set & {135, 139, 445, 3389}
    if win_hit:
        win_score += 2 if (3389 in win_hit or 445 in win_hit) else 1
        names = {135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP"}
        reasons.append("Windows 特征端口：" +
                       "、".join(f"{names.get(p, p)}({p})" for p in sorted(win_hit)))

    if ssh_banner_text:
        low = ssh_banner_text.lower()
        if "openssh" in low or "dropbear" in low:
            linux_score += 1
            reasons.append(f"SSH Banner：{ssh_banner_text}")

    if linux_score > win_score:
        return "Linux", reasons
    if win_score > linux_score:
        return "Windows", reasons
    return "未知", reasons


def run_internal_scan(cidrs=None, ports=None, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS,
                      output="", on_event=None, cancel=None) -> list:
    """内网发现主流程；返回存活主机列表（已写入报告）"""
    base_on_event = on_event or (lambda evt: None)
    cancel = cancel if cancel is not None else threading.Event()
    scan_t0 = time.time()
    cidrs = list(cidrs or DEFAULT_CIDRS)
    ports = list(ports or DEFAULT_PORTS)

    hosts_ips = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError as e:
            base_on_event({"type": "error", "message": f"网段 {c} 不合法：{e}"})
            return []
        hosts_ips.extend(str(h) for h in net.hosts())
    total = len(hosts_ips)

    outdir = resolve_output_dir(output, "internal")
    outdir.mkdir(parents=True, exist_ok=True)

    base_on_event({"type": "scan_start", "cidrs": cidrs, "total_hosts": total,
                   "ports": ports, "results_dir": str(outdir)})

    # ---------- 阶段 1：ICMP ping 扫（并发限流，避免子进程过多触发系统限制） ----------
    base_on_event({"type": "progress", "phase": "ping", "done": 0, "total": total})
    ping_results = {}
    ping_workers = min(threads, 64)
    with concurrent.futures.ThreadPoolExecutor(max_workers=ping_workers) as ex:
        futmap = {ex.submit(ping_full, ip, timeout): ip for ip in hosts_ips}
        try:
            for i, fut in enumerate(concurrent.futures.as_completed(futmap), 1):
                if cancel.is_set():
                    break
                ip = futmap[fut]
                try:
                    ping_results[ip] = fut.result()
                except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                    ping_results[ip] = {"alive": False, "ttl": None, "latency_ms": None}
                if i % 32 == 0 or i == total:
                    base_on_event({"type": "progress", "phase": "ping", "done": i, "total": total})
        finally:
            if cancel.is_set():
                ex.shutdown(wait=False, cancel_futures=True)

    if cancel.is_set():
        base_on_event({"type": "scan_done", "results_dir": str(outdir),
                       "cancelled": True, "counts": {}})
        return []

    # ---------- 阶段 2A：端口级并发探测（所有主机的所有端口并行） ----------
    # 每台主机 8 端口不再串行：全部 (host, port) 任务直接并发。
    # max_workers 限流到 64，降低 CPU/网络压力并避开 macOS 文件描述符限制。
    scan_tasks = [(ip, p) for ip in hosts_ips for p in ports]
    detail_total = len(scan_tasks)
    base_on_event({"type": "progress", "phase": "detail", "done": 0, "total": detail_total})
    open_map = {}        # ip -> [开放端口]
    done_cnt = 0
    port_workers = min(threads, 64)
    with concurrent.futures.ThreadPoolExecutor(max_workers=port_workers) as ex:
        futmap = {ex.submit(tcp_open, ip, p, timeout): (ip, p) for ip, p in scan_tasks}
        try:
            for fut in concurrent.futures.as_completed(futmap):
                if cancel.is_set():
                    break
                ip, p = futmap[fut]
                try:
                    if fut.result():
                        open_map.setdefault(ip, []).append(p)
                except (OSError, ValueError, TypeError):
                    pass
                done_cnt += 1
                if done_cnt % 64 == 0 or done_cnt == detail_total:
                    base_on_event({"type": "progress", "phase": "detail",
                                   "done": done_cnt, "total": detail_total})
        finally:
            if cancel.is_set():
                ex.shutdown(wait=False, cancel_futures=True)

    if cancel.is_set():
        base_on_event({"type": "scan_done", "results_dir": str(outdir),
                       "cancelled": True, "counts": {}})
        return []

    # ---------- 阶段 2B：对存活主机做 Banner / HTTP / OS 判断 ----------
    def build_host(ip):
        pr = ping_results.get(ip, {"alive": False, "ttl": None, "latency_ms": None})
        ports_open = sorted(open_map.get(ip, []))
        if not (pr["alive"] or ports_open):
            return None
        ssh_banner_text = ""
        if 22 in ports_open and not cancel.is_set():
            ssh_banner_text = grab_ssh_banner(ip, 22, timeout)
        http_title = ""
        http_port = next((p for p in HTTP_PORTS if p in ports_open), None)
        if http_port and not cancel.is_set():
            info = scanner_core.fetch_http(ip, http_port, timeout)
            if info.get("is_http"):
                http_title = info.get("title", "")
        os_guess, reasons = guess_os(pr["ttl"], ports_open, ssh_banner_text)
        return {
            "ip": ip, "alive": True,
            "via": "icmp" if pr["alive"] else "tcp",
            "ttl": pr["ttl"], "latency_ms": pr["latency_ms"],
            "open_ports": ports_open,
            "ssh_banner": ssh_banner_text,
            "http_title": http_title,
            "os_guess": os_guess,
            "reasons": reasons,
        }

    alive_hosts = []
    detail_ips = [ip for ip in hosts_ips
                  if (ping_results.get(ip) or {}).get("alive") or ip in open_map]
    detail_workers = min(threads, 32)
    base_on_event({"type": "progress", "phase": "detail", "done": 0, "total": len(detail_ips)})
    with concurrent.futures.ThreadPoolExecutor(max_workers=detail_workers) as ex:
        futmap = {ex.submit(build_host, ip): ip for ip in detail_ips}
        try:
            for i, fut in enumerate(concurrent.futures.as_completed(futmap), 1):
                if cancel.is_set():
                    break
                try:
                    host = fut.result()
                except (OSError, ValueError, TypeError, RuntimeError,
                        subprocess.SubprocessError) as e:
                    base_on_event({"type": "error", "message": f"探测 {futmap[fut]} 出错：{e!r}"})
                    continue
                if host:
                    alive_hosts.append(host)
                    base_on_event({"type": "host_found", **host})
                if i % 32 == 0 or i == len(detail_ips):
                    base_on_event({"type": "progress", "phase": "detail",
                                   "done": i, "total": len(detail_ips)})
        finally:
            if cancel.is_set():
                ex.shutdown(wait=False, cancel_futures=True)

    # 按IP排序后写报告（附 ARP 表中的 MAC 地址）
    alive_hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    macs = arp_table()
    for h in alive_hosts:
        h["mac"] = macs.get(h["ip"], "")
    base_on_event({"type": "mac_resolved",
                   "macs": {h["ip"]: h["mac"] for h in alive_hosts if h["mac"]}})
    meta = {"cidrs": cidrs, "ports": ports, "threads": threads,
            "timeout": timeout, "total_hosts": total}
    duration = round(time.time() - scan_t0, 1)
    counts = reports.write_internal_report(alive_hosts, outdir, meta, duration)

    base_on_event({"type": "scan_done", "results_dir": str(outdir),
                   "cancelled": cancel.is_set(), "counts": counts,
                   "duration": duration})
    return alive_hosts
