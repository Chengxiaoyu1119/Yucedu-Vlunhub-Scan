#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""靶场扫描 CLI 入口（核心逻辑在 scanner_core.py，GUI 与 CLI 共用）

用法：
  python3 -m scanner_app.cli.public                   # 默认扫描两个靶场 IP 的 8000-8020
  python3 -m scanner_app.cli.public --port-end 8199   # 自定义端口上限
  python3 -m scanner_app.cli.public --targets 1.2.3.4 # 自定义目标 IP
"""

import argparse

from scanner_app.core import scanner_core
from scanner_app.core.platform_support import configure_console, resolve_output_dir


def parse_args():
    p = argparse.ArgumentParser(description="靶场端口扫描 + 网站首页抓取脚本")
    p.add_argument("--targets", default=",".join(scanner_core.DEFAULT_TARGETS),
                   help="目标 IP，逗号分隔（默认：43.139.231.237,43.139.149.11）")
    p.add_argument("--port-start", type=int, default=scanner_core.DEFAULT_PUBLIC_PORT_START,
                   help="起始端口（默认 8000）")
    p.add_argument("--port-end", type=int, default=scanner_core.DEFAULT_PUBLIC_PORT_END,
                   help="结束端口（默认 8020）")
    p.add_argument("--timeout", type=float, default=2.0, help="连接/请求超时秒数（默认 2）")
    p.add_argument("--threads", type=int, default=100, help="并发线程数（默认 100）")
    p.add_argument("--output", default="", help="结果输出目录（默认 .artifacts/results/<时间戳>）")
    p.add_argument("--no-screenshot", action="store_true", help="跳过网站首页截图")

    # ---- 子域发现（靶场改为 lab-XXXXXX.rzsec.cn 通配符域名后的搜索优化）----
    disc = p.add_argument_group("子域发现（可选）",
                                "靶场变为 lab-XXXXXX.rzsec.cn 后，用 HTTP Host 探测发现活靶场子域")
    disc.add_argument("--discover", default=None,
                      help="模板，如 lab-??????.rzsec.cn（? 为随机位）。指定即进入发现模式")
    disc.add_argument("--discover-prefix", default="lab-", help="模板前缀（默认 lab-）")
    disc.add_argument("--discover-suffix", default=".rzsec.cn", help="模板后缀（默认 .rzsec.cn）")
    disc.add_argument("--discover-len", type=int, default=6, help="随机位长度（默认 6）")
    disc.add_argument("--discover-charset", default="", help="候选字符集（默认 a-z0-9）")
    disc.add_argument("--discover-mode", default="random", choices=["random", "sequential"],
                      help="random=随机无放回；sequential=字典序（默认 random）")
    disc.add_argument("--discover-port", type=int, default=80,
                      help="域名靶场首页所在端口（默认 80）")
    disc.add_argument("--discover-limit", type=int, default=None,
                      help="最多探测候选数（默认不限，直至空间耗尽/取消）")
    disc.add_argument("--discover-found-limit", type=int, default=None,
                      help="发现足够活靶场即停止（默认不限）")
    disc.add_argument("--discover-threads", type=int, default=300, help="发现并发线程（默认 300）")
    disc.add_argument("--discover-connect-timeout", type=float, default=0.6,
                      help="发现阶段 TCP 建连超时秒数（默认 0.6，死组合快速失败）")
    disc.add_argument("--discover-read-timeout", type=float, default=1.0,
                      help="发现阶段读取响应超时秒数（默认 1.0）")
    disc.add_argument("--discover-fast", action="store_true",
                      help="快速模式：更激进超时（connect 0.4s/read 0.8s），死组合秒退；并发仍收敛到甜点区 64，不盲目拉高线程")
    disc.add_argument("--discover-resume", default=None,
                      help="断点续扫检查点文件路径（默认自动：<output>/.discover_ckpt.json）")
    disc.add_argument("--discover-reset", action="store_true", help="忽略已有检查点，从头开始")
    disc.add_argument("--discover-seed", type=int, default=None, help="随机种子（可复现）")

    args = p.parse_args()
    if args.port_end < args.port_start:
        p.error("--port-end 不能小于 --port-start")
    if args.threads < 1:
        p.error("--threads 至少为 1")
    if args.discover_threads < 1:
        p.error("--discover-threads 至少为 1")
    return args


def print_event(evt):
    t = evt["type"]
    if t == "target_start":
        print(f"\n=== 目标 {evt['ip']} ===")
    elif t == "ping":
        if evt["alive"]:
            ms = evt["latency_ms"]
            print("  [ping] 通" + (f"（{ms:.1f} ms）" if ms is not None else ""))
        else:
            print("  [ping] 不通（云服务器可能禁 ICMP，继续端口扫描）")
    elif t == "progress":
        if evt["done"] % 25 == 0 or evt["done"] == evt["total"]:
            print(f"  进度 {evt['done']}/{evt['total']}")
    elif t == "port_found":
        r = evt
        if r.get("is_http"):
            print(f"  [+] {r['port']} 开放  {r['scheme']}://{r['ip']}:{r['port']}  "
                  f"状态 {r['status']}  title: {r['title'] or '(无)'}")
        else:
            print(f"  [+] {r['port']} 开放（非 HTTP：{r.get('error', '')}）")
    elif t == "phase":
        if evt["phase"] == "screenshots":
            print("  端口扫描完成，正在截取网站首页…")
    elif t == "screenshot_done":
        if evt["ok"]:
            print(f"  [截图] {evt['ip']}:{evt['port']} 完成 → {evt['path']}")
        else:
            print(f"  [截图] {evt['ip']}:{evt['port']} 失败：{evt.get('error', '')}")
    elif t == "target_done":
        c = "（已取消）" if evt["cancelled"] else ""
        print(f"  扫描完成{c}：保留靶场页面 {evt.get('qualified_count', 0)} 个 / 共 {evt['total']} 个端口")
    elif t == "error":
        print(f"  [错误] {evt['message']}")
    # ---- 子域发现事件 ----
    elif t == "discovery_start":
        print(f"\n=== 子域发现启动 ===")
        print(f"  模板：{evt.get('template', '') or evt.get('prefix','') + '?'*(evt.get('length',0)) + evt.get('suffix','')}"
              f"  模式：{evt.get('mode')}  探测端口：{evt.get('port')}  空间总数：{evt.get('total'):,}")
        if evt.get("resume_from"):
            print(f"  从检查点续扫，已跳过 {evt['resume_from']:,} 个候选")
    elif t == "discovery_progress":
        eta = evt.get('eta')
        eta_s = f"  预计剩余 {eta:.0f}s" if isinstance(eta, (int, float)) else ""
        print(f"  [发现] 已探测 {evt['checked']:,} / {evt['target']:,}  "
              f"命中 {evt['found']}  速率 {evt['rate']}/s  耗时 {evt['elapsed']}s{eta_s}")
    elif t == "domain_found":
        print(f"  [命中] {evt['domain']}  ({evt.get('ip')}:{evt.get('port')}  "
              f"状态 {evt.get('status')}  title: {evt.get('title') or '(无)'})")
    elif t == "discovery_done":
        note = f"  备注：{evt.get('note','')}" if evt.get("note") else ""
        print(f"=== 子域发现完成：探测 {evt['checked']:,}，命中 {evt['found']} 个活靶场，"
              f"耗时 {evt['duration']}s ==={note}")


def main():
    configure_console()
    args = parse_args()
    outdir = resolve_output_dir(args.output, "public")
    outdir.mkdir(parents=True, exist_ok=True)  # 确保断点续扫检查点可写入

    # 子域发现模式：模板优先，否则显式 prefix/suffix/len
    discover_mode = bool(args.discover or args.discover_prefix or args.discover_suffix)
    if discover_mode:
        resume_path = args.discover_resume
        if resume_path is None:
            resume_path = str(outdir / ".discover_ckpt.json")
        # 显式 0 视为「不限」；None 同样为不限（穷举整个空间）
        discover_limit = args.discover_limit or None
        if discover_limit is None:
            space = 36 ** args.discover_len  # 默认字符集 a-z0-9
            print(f"⚠ 未设置 --discover-limit，将对整个空间（约 {space:,} 个候选）做 HTTP 探测，"
                  f"在真实网络上通常需数十小时甚至更久，建议加上 --discover-limit 限定采样量。")
        print(f"子域发现启动：模板 {args.discover or (args.discover_prefix + '?'*args.discover_len + args.discover_suffix)}"
              f"，探测端口 {args.discover_port}，发现线程 {args.discover_threads}"
              + (f"，上限 {discover_limit:,}" if discover_limit else "，上限 不限")
              + f"，结果目录 {outdir}")
        results = scanner_core.run_discovery_scan(
            template=args.discover,
            prefix=args.discover_prefix,
            suffix=args.discover_suffix,
            length=args.discover_len,
            charset=args.discover_charset or None,
            mode=args.discover_mode,
            discover_port=args.discover_port,
            port_start=args.port_start,
            port_end=args.port_end,
            timeout=args.timeout,
            connect_timeout=args.discover_connect_timeout,
            read_timeout=args.discover_read_timeout,
            threads=args.threads,
            discover_threads=args.discover_threads,
            limit=discover_limit,
            found_limit=args.discover_found_limit,
            resume_path=resume_path,
            reset=args.discover_reset,
            seed=args.discover_seed,
            fast=args.discover_fast,
            output=str(outdir),
            on_event=print_event,
            screenshots=not args.no_screenshot,
        )
    else:
        # 原有 IP 扫描模式（行为不变）
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        print(f"靶场扫描启动：目标 {', '.join(targets)}，"
              f"端口 {args.port_start}-{args.port_end}，{args.threads} 线程，结果目录 {outdir}")
        results = scanner_core.run_scan(
            targets=targets,
            port_start=args.port_start,
            port_end=args.port_end,
            timeout=args.timeout,
            threads=args.threads,
            output=str(outdir),
            on_event=print_event,
            screenshots=not args.no_screenshot,
        )

    print("\n========== 扫描汇总 ==========")
    for t in results:
        ping_desc = "ping 通" if t["ping"]["alive"] else "ping 不通"
        open_ports = sorted(r["port"] for r in t["ports"].values() if r["state"] == "open")
        port_desc = ", ".join(map(str, open_ports)) if open_ports else "无开放端口"
        print(f"{t['ip']}：{ping_desc}；靶场页面端口（{t['open_count']} 个）：{port_desc}")


if __name__ == "__main__":
    main()
