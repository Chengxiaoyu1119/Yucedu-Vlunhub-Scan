#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公网子域发现引擎（靶场改为 lab-XXXXXX.rzsec.cn 形式后的搜索优化）

背景与约束（基于实战探测 rzsec.cn 平台后修正）：
  - 该平台为通配符 DNS：*.rzsec.cn 全解析到同一个 nginx 前端 IP（114.132.123.93）。
    **DNS 完全无法区分真假靶场**，所有子域解析结果一致。
  - 前端行为统一：HTTP 80 → 301 跳转到 HTTPS；HTTPS 443 对「未拉起的靶场」统一返回
    404 "404 page not found"；对「已拉起的真实靶场」才返回带真实标题的 2xx 页面。
    因此**仅靠 HTTP 状态码/标题非空会误判**——所有子域都 301 且有默认标题。
  - 活靶场判定（已修正）：必须**跟随 301 重定向到达最终 HTTPS 响应**，且最终响应为
    2xx（200–299）且标题为「真实靶场标题」（非服务器默认/错误页）才算存活。
  - 组合空间 36^6 ≈ 21.8 亿，顺序穷举不现实；且活靶场数量极稀疏、按需临时拉起会过期，
    纯随机采样命中率趋近 0。故本引擎定位为「验证已知/有限子域 + 有界随机采样 + 断点续扫」，
    而非「穷举发现全部」。真正的靶场清单应来自平台控制台（需登录）。
  - 随机顺序通过「模 N 乘法置换」实现：value = (s + k*a) mod N（a 与 N 互质），
    遍历 k=0..N-1 恰好覆盖全部组合一次，且可凭游标 k 断点续扫。

仅依赖标准库。
"""

import concurrent.futures
import http.client
import json
import random
import re
import socket
import ssl
import string
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_CHARSET = string.ascii_lowercase + string.digits  # a-z0-9
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) RangeScanner/1.0")
MAX_BODY = 512 * 1024  # 首页最多抓取 512KB
DISCOVER_BODY = 32 * 1024  # 发现阶段只需 <head> 里的标题，抓 32KB 足够

# 并发甜点区上限。实测（2026-08-30）目标平台吞吐随并发先升后降：
#   20 并发 ≈107/s（延迟 165ms）→ 50 并发 ≈117/s（268ms）→ 200 并发 ≈79/s（508ms）
# 即超过约 50~64 并发后，服务端限速使延迟上升、吞吐反降。
# 因此 fast 模式不再盲目拉高线程，而是统一收敛到该上限。
MAX_EFFECTIVE_THREADS = 64

# 服务器默认/错误页标题（无真实靶场内容）。命中这些一律不算「活靶场」，
# 否则通配符前端（如 nginx 对一切子域统一回 301/404）会被误判为存活。
GENERIC_TITLES = {
    "", "301 moved permanently", "302 found", "302 moved temporarily",
    "303 see other", "307 temporary redirect", "308 permanent redirect",
    "400 bad request", "401 unauthorized", "403 forbidden", "404 not found",
    "404 page not found", "500 internal server error", "502 bad gateway",
    "503 service unavailable", "504 gateway timeout", "index of",
    "welcome to nginx", "nginx", "it works", "default page", "error",
    "网站建设中", "站点已关闭", "页面不存在", "访问被拒绝",
}


def _is_generic_title(title: str) -> bool:
    """标题是否为服务器默认/错误页（无真实靶场意义）。"""
    return (title or "").strip().lower() in GENERIC_TITLES


def _parse_location(loc: str, base_host: str, base_port: int):
    """解析重定向 Location，返回 (host, scheme, port, path)。相对路径沿用基准。"""
    if not loc:
        return None, None, None, None
    if loc.startswith("/"):  # 相对路径
        return base_host, "http", base_port, loc
    p = urlparse(loc)
    if not p.scheme:
        return base_host, "http", base_port, loc
    scheme = p.scheme.lower()
    host = p.hostname or base_host
    port = p.port or (443 if scheme == "https" else 80)
    return host, scheme, port, p.path or "/"


# --------------------------------------------------------------------------- #
# 小工具：标题提取 / 解码（与 scanner_core 保持一致，避免跨模块耦合）
# --------------------------------------------------------------------------- #
def _decode_body(body: bytes, content_type: str) -> str:
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


def _extract_title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


# --------------------------------------------------------------------------- #
# 模板解析
# --------------------------------------------------------------------------- #
def parse_template(template: str):
    """把 lab-??????.rzsec.cn 这样的模板拆成 (prefix, suffix, length)。

    - 取最长连续 `?`/`*` 段作为随机位；
    - 无通配符时 length=0，视为单个固定域名（生成器只产出它本身）。
    """
    m = re.search(r"[?*]+", template)
    if not m:
        return ("", template, 0)
    start, end = m.start(), m.end()
    return (template[:start], template[end:], end - start)


# --------------------------------------------------------------------------- #
# 候选空间：模 N 乘法置换实现「随机无放回 + 可续扫」
# --------------------------------------------------------------------------- #
class CandidateSpace:
    """length 位、字符集 charset 的全部组合（共 base^length 个）。

    - sequential 模式：value = k，即按字典序（base 编码）遍历；
    - random 模式：value = (s + k*a) mod N，a 与 N 互质 ⇒ 是 [0,N) 上的一个置换，
      遍历 k=0..N-1 恰好覆盖每个组合一次，且可凭游标 k 断点续扫。
    """

    def __init__(self, prefix: str, suffix: str, length: int,
                 charset: str = DEFAULT_CHARSET, mode: str = "random", seed=None):
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        # 去重并保持顺序，保证 charset 内字符唯一
        seen = set()
        self.charset = "".join(c for c in charset if not (c in seen or seen.add(c)))
        if not self.charset:
            raise ValueError("字符集不能为空")
        self.base = len(self.charset)
        self.total = self.base ** length if length > 0 else 1
        self.mode = mode
        rng = random.Random(seed)
        if mode == "sequential" or self.length == 0:
            self.a = 1
            self.s = 0
        else:
            # N = base^length；base=36=2^2*3^2 ⇒ N 只含质因子 2、3。
            # 取与 N 互质的步长 a：奇数且不被 3 整除即可。
            while True:
                a = rng.randrange(1, max(2, self.total))
                if a % 2 == 1 and a % 3 != 0:
                    break
            self.a = a
            self.s = rng.randrange(0, self.total)

    def value_at(self, k: int) -> int:
        if self.length == 0:
            return 0
        return (self.s + k * self.a) % self.total

    def domain(self, v: int) -> str:
        if self.length == 0:
            return self.prefix + self.suffix
        s = [""] * self.length
        x = v
        for i in range(self.length - 1, -1, -1):
            s[i] = self.charset[x % self.base]
            x //= self.base
        return self.prefix + "".join(s) + self.suffix

    def candidate_at(self, k: int) -> str:
        return self.domain(self.value_at(k))


# --------------------------------------------------------------------------- #
# 长连接池：按线程复用 TCP/TLS 连接（通配符平台批量探测用）
# --------------------------------------------------------------------------- #
# 实测（2026-08-30，目标 114.132.123.93）：
#   - 单次 DNS 解析 ≈130ms，且 probe_domain 每候选会解析两次（初始域名 + 301 跳转域名）；
#   - TCP+TLS 握手 ≈415ms，复用连接后单请求仅 ≈136ms；
#   - 吞吐并非随并发线性增长：50 并发 ≈117/s 见顶，200 并发反降至 ≈79/s
#     （延迟从 165ms 升至 508ms），说明服务端存在限速/饱和。
# 因此优化重点是「省掉每候选的 DNS 与握手」，并**把并发控制在甜点区**，而非盲目加线程。
class ConnPool:
    """按线程复用 http.client 长连接，仅变换 Host 头发起请求。

    线程隔离：连接保存在 threading.local 中，不跨线程共享，无需加锁。
    失败处理：请求异常时丢弃该连接并自动重连一次，仍失败则向上抛出。
    """

    def __init__(self, connect_timeout: float = 3.0, read_timeout: float = 3.0,
                 user_agent: str = UA, max_body: int = DISCOVER_BODY):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.user_agent = user_agent
        self.max_body = max_body
        self._local = threading.local()
        self._lock = threading.Lock()
        self.connects = 0       # 累计建连次数（用于观察复用效果）

    def _conns(self):
        conns = getattr(self._local, "conns", None)
        if conns is None:
            conns = {}
            self._local.conns = conns
        return conns

    def _get(self, scheme, host, port):
        key = (scheme, host, port)
        conns = self._conns()
        conn = conns.get(key)
        if conn is not None:
            return conn
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port,
                                               timeout=self.connect_timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.connect_timeout)
        conn.connect()
        try:
            conn.sock.settimeout(self.read_timeout)
        except (AttributeError, OSError):
            pass
        conns[key] = conn
        with self._lock:
            self.connects += 1
        return conn

    def _drop(self, scheme, host, port):
        conn = self._conns().pop((scheme, host, port), None)
        if conn is not None:
            try:
                conn.close()
            except (OSError, http.client.HTTPException):
                pass

    def request(self, scheme, host, port, host_header, path="/"):
        """发起一次 GET，返回 (status, headers, body)；失败自动重连一次。"""
        last_err = None
        for attempt in (0, 1):
            try:
                conn = self._get(scheme, host, port)
                conn.request("GET", path, headers={
                    "Host": host_header, "User-Agent": self.user_agent,
                    "Accept": "text/html,*/*", "Connection": "keep-alive"})
                resp = conn.getresponse()
                body = resp.read(self.max_body)
                headers = {k.lower(): v for k, v in resp.getheaders()}
                return resp.status, headers, body
            except (http.client.HTTPException, OSError, ssl.SSLError) as e:
                last_err = e
                self._drop(scheme, host, port)
                if attempt:
                    raise
        raise last_err

    def close(self):
        conns = self._conns()
        for conn in list(conns.values()):
            try:
                conn.close()
            except (OSError, http.client.HTTPException):
                pass
        conns.clear()


# --------------------------------------------------------------------------- #
# 单候选探测：TCP 连接 + HTTP GET（带 Host 头）
# --------------------------------------------------------------------------- #
def probe_domain(domain: str, port: int, timeout: float = 2.0,
                 connect_timeout: float = None, read_timeout: float = None,
                 user_agent: str = UA, max_body: int = None,
                 backend_ips: list = None, pool: "ConnPool" = None) -> dict:
    """对候选子域做探测。返回含 live 标记的字典。

    连接目标：
      - 默认（backend_ips=None）走 DNS 解析：通配符下每个子域映射到各自后端 IP；
      - 若给定 backend_ips（通配符后端为共享 IP 时），跳过 DNS、直接连这些 IP 并仅变换
        Host 头（vhost 枚举经典做法），适用于「所有子域解析到同一组 IP」的平台
        （如 rzsec.cn：*.rzsec.cn 全解析到同一 nginx 前端）。

    重定向处理：平台前端常对 HTTP 统一 301→HTTPS、对未拉起的靶场统一 404。因此必须
    **跟随 301/302/307/308 重定向到达最终响应**再判定，否则会停留在 301（被误判为存活）。

    活靶场判定（关键，针对通配符误报）：
      - 最终响应为 2xx（200–299）**且**标题为「真实靶场标题」（非服务器默认/错误页）才算存活。
      - 301/302/404/5xx 或通用默认标题一律不算存活。
      这样对「前端对一切子域回 301」的通配符，不会把 21.8 亿子域全判成活靶场。

    timeout 拆分：connect_timeout 控制建连时限，read_timeout 控制读取时限；死组合在
    connect 阶段即快速失败，不再傻等满 timeout。
    """
    if connect_timeout is None:
        connect_timeout = timeout
    if read_timeout is None:
        read_timeout = timeout
    if max_body is None:
        max_body = MAX_BODY

    info = {"domain": domain, "ip": None, "ok": False, "live": False,
            "status": None, "title": "", "server": "", "reason": None, "error": ""}

    # 1) 解析目标 IP（或复用给定后端 IP 池）
    if backend_ips:
        target_ips = list(backend_ips)
    else:
        try:
            ip = socket.gethostbyname(domain)
            info["ip"] = ip
            target_ips = [ip]
        except (socket.gaierror, OSError, UnicodeError) as e:
            info["reason"] = "dns"
            info["error"] = str(e)
            return info

    # 2) 跟随重定向，直到拿到最终响应
    scheme = "https" if port == 443 else "http"
    host, cur_port, cur_ips, last_err = domain, port, target_ips, ""
    final = None
    # 记录最终可达响应的 scheme/host/port/body，供调用方（已知子域验证）拿首页 URL 与快照
    final_scheme = final_host = final_port = None
    final_body = b""
    for _hop in range(6):
        followed = False
        for ip in cur_ips:
            try:
                if pool is not None:
                    # 复用长连接：连后端 IP，仅变换 Host 头，省掉 DNS 与 TCP+TLS 握手
                    status, headers, body = pool.request(scheme, ip, cur_port, host)
                    ctype = headers.get("content-type", "") or ""
                    title = _extract_title(_decode_body(body, ctype))
                    server = headers.get("server", "") or ""
                    location = headers.get("location")
                else:
                    if scheme == "https":
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn = http.client.HTTPSConnection(ip, cur_port,
                                                          timeout=connect_timeout, context=ctx)
                    else:
                        conn = http.client.HTTPConnection(ip, cur_port, timeout=connect_timeout)
                    conn.connect()
                    conn.request("GET", "/", headers={
                        "Host": host, "User-Agent": user_agent,
                        "Accept": "text/html,*/*", "Connection": "close"})
                    resp = conn.getresponse()
                    body = resp.read(max_body)
                    status = resp.status
                    ctype = resp.getheader("Content-Type", "") or ""
                    title = _extract_title(_decode_body(body, ctype))
                    server = resp.getheader("Server", "") or ""
                    location = resp.getheader("Location")
                    conn.close()
                final = {"ip": ip, "status": status, "title": title, "server": server}
                final_scheme, final_host, final_port, final_body = scheme, host, cur_port, body
                # 重定向：解析 Location 并进入下一跳（保留 Host 语义；共享 IP 模式下同域继续用后端 IP）
                if status in (301, 302, 303, 307, 308):
                    nh, nsch, nport, _ = _parse_location(location, host, cur_port)
                    if nh and _hop < 5:
                        if backend_ips and nh == domain:
                            cur_ips = list(backend_ips)
                        else:
                            try:
                                cur_ips = [socket.gethostbyname(nh)]
                            except (socket.gaierror, OSError, UnicodeError):
                                cur_ips = [ip]
                        scheme, host, cur_port = nsch, nh, nport
                        followed = True
                        break  # 跳到下一 hop 继续
                break  # 非重定向，结束内层循环
            except (http.client.HTTPException, OSError, ssl.SSLError,
                    UnicodeError, ValueError) as e:
                last_err = str(e)
                continue
        if not followed:
            break  # 无重定向或已达跳数上限，结束

    if not final:
        info["reason"] = "tcp"
        info["error"] = last_err
        return info

    info["ok"] = True
    info["ip"] = final["ip"]
    info["status"] = final["status"]
    info["title"] = final["title"]
    info["server"] = final["server"]
    # 暴露最终可达响应的 scheme/host/port/body，便于「已知子域验证」直接拿首页 URL 截图与快照
    info["scheme"] = final_scheme
    info["host"] = final_host
    info["port"] = final_port
    info["body"] = final_body
    # 活靶场：最终响应 2xx 且标题为真实靶场标题（非服务器默认/错误页）
    if 200 <= final["status"] < 300 and not _is_generic_title(final["title"]):
        info["live"] = True
    return info


def detect_wildcard_ips(space, samples: int = 5):
    """采样若干候选，判断是否通配符平台（所有子域解析到同一 IP）。

    命中时返回 [ip]，调用方据此整轮复用该 IP，省掉每候选一次（遇 301 则两次）
    DNS 解析；非通配符或解析失败返回 None，回退到逐次 DNS。
    """
    if space.length == 0:
        return None
    ips = set()
    for i in range(max(1, samples)):
        try:
            ips.add(socket.gethostbyname(space.candidate_at(i)))
        except (socket.gaierror, OSError, UnicodeError):
            return None
    if len(ips) == 1:
        return [ips.pop()]
    return None


# --------------------------------------------------------------------------- #
# 发现主流程
# --------------------------------------------------------------------------- #
def run_discovery(template: str = None, prefix: str = "", suffix: str = "", length: int = 6,
                  charset: str = None, mode: str = "random", port: int = 80,
                  timeout: float = 1.0, connect_timeout: float = 0.6,
                  read_timeout: float = 1.0, threads: int = 300, limit: int = None,
                  found_limit: int = None, resume_path: str = None, reset: bool = False,
                  seed=None, fast: bool = False, on_event=None,
                  cancel: threading.Event = None) -> list:
    """执行子域发现，返回发现的活靶场域名列表。

    参数：
      template      形如 lab-??????.rzsec.cn 的模板（? 为随机位），优先级高于 prefix/suffix/length
      prefix/suffix/length  显式模板；length=0 表示单个固定域名
      charset       候选字符集（默认 a-z0-9）
      mode          random（随机无放回）/ sequential（字典序）
      port          探测端口（默认 80，域名靶场首页所在端口）
      limit         最多探测候选数（None=不限，直至空间耗尽或取消）
      found_limit   发现足够活靶场即停止（None=不限）
      resume_path   断点续扫检查点文件；reset=True 时忽略已有检查点
    事件：discovery_start / discovery_progress / domain_found / discovery_done
    """
    on_event = on_event or (lambda e: None)
    cancel = cancel if cancel is not None else threading.Event()
    # 调用方常以 None/空串表示「未指定」（GUI 未选、CLI 未传），这里统一回退到默认字符集，
    # 否则 CandidateSpace 会对 None 做迭代而抛 TypeError。
    charset = charset or DEFAULT_CHARSET
    # 快速模式：更激进的超时，死组合秒退。
    # 注意：不再借 fast 提升并发——实测超过甜点区后加线程只会让吞吐下降。
    if fast:
        connect_timeout = min(connect_timeout, 0.4)
        read_timeout = min(read_timeout, 0.8)
    threads = max(1, min(int(threads), MAX_EFFECTIVE_THREADS))
    if template:
        prefix, suffix, length = parse_template(template)
    space = CandidateSpace(prefix, suffix, length, charset, mode, seed)

    # 通配符平台优化：整轮只解析一次后端 IP，并复用长连接。
    # 这两项分别省掉每候选的 DNS（130ms×1~2）与 TCP+TLS 握手（415ms）。
    backend_ips = detect_wildcard_ips(space)
    pool = None
    if backend_ips:
        pool = ConnPool(connect_timeout=max(connect_timeout, 3.0),
                        read_timeout=max(read_timeout, 2.0),
                        user_agent=UA, max_body=DISCOVER_BODY)

    # 端口校准：平台普遍把 HTTP 80 统一 301 到 HTTPS 443，若仍逐个走 80，
    # 每个候选都要多花一次跳转往返（实测 62/s vs 直连 443 的 92/s）。
    # 这里用首个候选探一次，若最终落在 https/443，则整轮直接改用 443。
    calibrated_port = None
    if port == 80 and space.total > 0:
        cal = probe_domain(space.candidate_at(0), 80, timeout=timeout,
                           connect_timeout=connect_timeout, read_timeout=read_timeout,
                           max_body=DISCOVER_BODY, backend_ips=backend_ips, pool=pool)
        if cal.get("scheme") == "https" and cal.get("port") == 443:
            calibrated_port = 443
            port = 443

    # 断点续扫：仅当检查点的 total/a/s 与本次一致时才接续游标 k
    k = 0
    if resume_path and not reset and Path(resume_path).exists():
        try:
            ck = json.loads(Path(resume_path).read_text())
            if ck.get("total") == space.total and ck.get("a") == space.a and ck.get("s") == space.s:
                k = int(ck.get("k", 0))
        except (OSError, ValueError, TypeError):  # 文件不可读 / JSON 损坏 / 字段类型异常
            k = 0

    state = {"k": k, "checked": 0, "found": []}
    lock = threading.Lock()
    t0 = time.time()
    on_event({"type": "discovery_start", "template": template or f"{prefix}?{suffix}",
              "prefix": prefix, "suffix": suffix, "length": length,
              "total": space.total, "mode": mode, "port": port, "resume_from": k,
              "wildcard_ips": backend_ips, "threads": threads,
              "calibrated_port": calibrated_port})

    def next_candidate():
        with lock:
            if limit is not None and state["checked"] >= limit:
                return None
            if state["k"] >= space.total:
                return None
            d = space.candidate_at(state["k"])
            state["k"] += 1
            state["checked"] += 1
            return d

    def probe_task(domain):
        return probe_domain(domain, port, timeout=timeout,
                            connect_timeout=connect_timeout, read_timeout=read_timeout,
                            max_body=DISCOVER_BODY, backend_ips=backend_ips, pool=pool)

    stop = threading.Event()
    pending = set()
    last_progress = 0.0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        while not stop.is_set():
            while len(pending) < max(1, threads) * 2:
                cand = next_candidate()
                if cand is None:
                    break
                pending.add(ex.submit(probe_task, cand))
            if not pending:
                break
            done, pending = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for f in done:
                try:
                    r = f.result()
                except (OSError, ValueError, TypeError, RuntimeError,
                        ssl.SSLError, http.client.HTTPException):
                    r = None
                if not r or not r.get("live"):
                    continue
                with lock:
                    state["found"].append(r["domain"])
                    fcount = len(state["found"])
                on_event({"type": "domain_found", "domain": r["domain"], "ip": r["ip"],
                          "port": port, "status": r["status"], "title": r["title"],
                          "server": r["server"]})
                if found_limit and fcount >= found_limit:
                    stop.set()
            now = time.time()
            if now - last_progress > 0.5 or stop.is_set():
                last_progress = now
                rate = state["checked"] / max(0.001, now - t0)
                # 进度上限：设了 limit 以 limit 为终点，否则以整个空间为终点（用于 ETA 展示）
                target = limit if limit else space.total
                remaining = max(0, target - state["checked"])
                eta = round(remaining / rate, 1) if rate > 0 else None
                on_event({"type": "discovery_progress", "checked": state["checked"],
                          "found": len(state["found"]), "rate": round(rate, 1),
                          "elapsed": round(now - t0, 1), "total": space.total,
                          "target": target, "eta": eta})
            if cancel.is_set():
                stop.set()
        for f in pending:
            f.cancel()

    # 写检查点（即便被取消也保留游标，便于下次续扫）
    if resume_path:
        try:
            Path(resume_path).write_text(json.dumps(
                {"total": space.total, "a": space.a, "s": space.s,
                 "k": state["k"], "found": state["found"]}, ensure_ascii=False))
        except (OSError, TypeError, ValueError):
            pass

    # 连接池按线程存放，这里只能关闭主线程持有的连接；工作线程的连接随线程
    # 退出被回收（服务端 keepalive 超时也会自行断开），不影响正确性。
    if pool:
        pool.close()

    elapsed = round(time.time() - t0, 1)
    on_event({"type": "discovery_done", "checked": state["checked"],
              "found": len(state["found"]), "found_domains": list(state["found"]),
              "duration": elapsed, "resume_k": state["k"]})
    return state["found"]
