#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""靶场扫描工具 —— 浏览器预览服务（无头/无 macOS 窗口时的界面预览方案）

原理：
  - 后端：复用真实的 scanner_app.desktop.gui.Api（与 GUI 按钮触发的同一套逻辑），
    通过 /api/<method> 暴露给前端。
  - 前端：直接托管 scanner_app/desktop/web/ 下的 index.html + app.js（不改动原文件），
    仅在 /preview 路由注入一段垫片脚本，把 window.pywebview.api.* 调用转发到本地服务，
    并补发 pywebviewready 事件，使 app.js 的 init() 正常启动。
  - 浏览器侧方法（open_url/open_report/open_path/notify/play_sound）在垫片里本地处理，
    避免去服务端开原生窗口。

用法：
  python3 scripts/preview_server.py [port]        # 默认 8753
  浏览器打开 http://127.0.0.1:8753/preview
"""

import json
import sys
import threading
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_HERE = Path(__file__).resolve()
# 本文件位于 scripts/ 下，项目根是其上一级；若被移回根目录则退化为所在目录。
# 这样移动文件位置不会导致找不到 scanner_app。
ROOT = _HERE.parents[1] if (_HERE.parents[1] / "scanner_app").is_dir() else _HERE.parent
sys.path.insert(0, str(ROOT))

from scanner_app.desktop import gui  # noqa: E402
from scanner_app.core.platform_support import RESULTS_ROOT  # noqa: E402

WEB_DIR = ROOT / "scanner_app" / "desktop" / "web"
ARTIFACTS = ROOT / ".artifacts"

# 浏览器侧本地处理的 api 方法（不开原生窗口）
CLIENT_SIDE = {"open_url", "open_report", "open_path", "notify", "play_sound"}

SHIM = r"""
<script>
(function () {
  function toast(t, m) {
    var d = document.createElement('div');
    d.style.cssText = 'position:fixed;right:12px;bottom:12px;background:#222;color:#fff;'
                    + 'padding:8px 12px;border-radius:6px;z-index:9999;font:13px sans-serif;max-width:60%';
    d.textContent = (t || '') + ' ' + (m || '');
    document.body.appendChild(d);
    setTimeout(function () { d.remove(); }, 3200);
  }
  function client(method, args) {
    args = args || [];
    if (method === 'open_url') { if (args[0]) window.open(args[0], '_blank'); return; }
    if (method === 'notify') { toast(args[0], args[1]); return; }
    if (method === 'play_sound') { return; }
    if (method === 'open_report') { console.log('[preview] open_report', args[0]); toast('报告已生成', args[0]); return; }
    if (method === 'open_path') { console.log('[preview] open_path', args[0]); return; }
    return fetch('/api/' + method, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ args: args })
    }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .catch(function (e) { console.error('[api] ' + method + ' failed', e); return null; });
  }
  window.pywebview = { api: new Proxy({}, { get: function (_, name) { return function () { return client(name, [].slice.call(arguments)); }; } }) };
  window.addEventListener('load', function () { window.dispatchEvent(new Event('pywebviewready')); });
})();
</script>
"""


class Handler(SimpleHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        # 标量与 None 也要能序列化：is_watching() 直接返回 bool，
        # 早先只对 dict/list 做 dumps，bool 会一路走到 len(data) 抛 TypeError，
        # 表现为前端 fetch 拿到 ERR_EMPTY_RESPONSE。
        if isinstance(body, (dict, list, bool, int, float)) or body is None:
            body = json.dumps(body, ensure_ascii=False)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _serve_file(self, path: Path, ctype=None):
        if not path.is_file():
            self._send(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype or self.guess_type(str(path)))
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        with open(path, "rb") as f:
            self.wfile.write(f.read())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/preview"):
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            html = html.replace(
                '<script src="app.js"></script>',
                SHIM + '\n<script src="app.js"></script>',
                1,
            )
            self._send(200, html, "text/html; charset=utf-8")
            return
        if parsed.path.startswith("/results/"):
            rel = urllib.parse.unquote(parsed.path[len("/results/"):])
            for base in (ARTIFACTS, RESULTS_ROOT):
                try:
                    p = (Path(base) / rel).resolve()
                    p.relative_to(Path(base).resolve())
                except Exception:
                    continue
                self._serve_file(p)
                return
            self._send(403, {"error": "forbidden"})
            return
        # 静态资源（app.js / chart.umd.min.js / app_icon.png 等）
        rel = urllib.parse.unquote(parsed.path.lstrip("/"))
        p = (WEB_DIR / rel).resolve()
        try:
            p.relative_to(WEB_DIR.resolve())
        except Exception:
            self._send(403, {"error": "forbidden"})
            return
        self._serve_file(p)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._send(404, {"error": "not found"})
            return
        method = parsed.path[len("/api/"):]
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        args = payload.get("args", [])
        try:
            fn = getattr(api, method)
            result = fn(*args)
        except Exception as e:  # 方法不存在或参数错误都回显，前端忽略即可
            self._send(500, {"error": repr(e), "method": method})
            return
        self._send(200, result if result is not None else {})

    def log_message(self, *a):
        pass


api = gui.Api()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8753
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"preview server on http://127.0.0.1:{port}/preview")
    srv.serve_forever()
