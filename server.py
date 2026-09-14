#!/usr/bin/env python3
"""Tiny web app around rxcompare: refreshes the comparison in the background and serves it.

Routes:
  /                 HTML report (default window HOURS; ?hours=N for another range)
  /summary.json     compact JSON of the same result (?hours=N)
  /healthz          200 once the first analysis has succeeded

Config via environment (see .env.example): A_URL A_KEY A_NAME B_URL B_KEY B_NAME
HOURS REFRESH_SEC PORT VERIFY_TLS RANGES
"""
import html, json, os, sys, threading, time, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import rxcompare as rx

HOURS = float(os.environ.get("HOURS", "3"))
REFRESH = int(os.environ.get("REFRESH_SEC", "300"))
PORT = int(os.environ.get("PORT", "8080"))
RANGES = [float(x) for x in os.environ.get("RANGES", "1,3,6,12,24,48").split(",")]
MAX_HOURS = 168.0

A = rx.Node(os.environ.get("A_NAME", "A"), os.environ.get("A_URL", ""), os.environ.get("A_KEY", ""))
B = rx.Node(os.environ.get("B_NAME", "B"), os.environ.get("B_URL", ""), os.environ.get("B_KEY", ""))

_cache = {}          # hours -> {"ts", "html", "summary"}
_locks = {}          # hours -> Lock, so concurrent requests don't both hit the repeaters
_locks_guard = threading.Lock()
_last_error = None


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, file=sys.stderr, flush=True)


def nav_html(hours):
    links = "".join(f'<a href="/?hours={h:g}" class="{"on" if h == hours else ""}">{h:g} h</a>' for h in RANGES)
    return (f'<div class="nav">{links}<a href="/summary.json?hours={hours:g}">json</a>'
            f'<span style="align-self:center;color:var(--muted);font-size:12px;margin-left:6px">refreshes every {REFRESH // 60} min</span></div>')


def compute(hours):
    global _last_error
    with _locks_guard:
        lock = _locks.setdefault(hours, threading.Lock())
    with lock:
        ent = _cache.get(hours)
        if ent and time.time() - ent["ts"] < REFRESH:
            return ent
        t = time.time()
        try:
            R = rx.analyze(A, B, hours)
            ent = {"ts": time.time(), "html": rx.render_html(R, nav_html(hours), refresh=REFRESH), "summary": rx.summary(R)}
            _cache[hours] = ent
            _last_error = None
            log(f"analysed {hours:g}h: {len(R['pairs'])} matched, {R['A']['n']}/{R['B']['n']} packets, {time.time()-t:.1f}s")
            return ent
        except Exception as e:
            _last_error = f"{type(e).__name__}: {e}"
            log("analysis failed:", _last_error)
            traceback.print_exc()
            if ent:          # serve stale rather than nothing
                return ent
            raise


def refresher():
    while True:
        try:
            compute(HOURS)
        except Exception:
            pass
        time.sleep(REFRESH)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(self.address_string(), fmt % args)

    def send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def hours(self, q):
        try:
            return max(0.25, min(MAX_HOURS, float(q.get("hours", [HOURS])[0])))
        except ValueError:
            return HOURS

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/healthz":
            ent = _cache.get(HOURS)
            return self.send(200 if ent else 503, json.dumps({"ok": bool(ent), "last_error": _last_error,
                                                            "age_s": time.time() - ent["ts"] if ent else None}),
                             "application/json")
        if u.path in ("/", "/index.html", "/summary.json"):
            try:
                ent = compute(self.hours(q))
            except Exception as e:
                return self.send(502, f"<h1>analysis failed</h1><pre>{html.escape(str(e))}</pre>")
            if u.path == "/summary.json":
                return self.send(200, json.dumps(ent["summary"], indent=1), "application/json")
            return self.send(200, ent["html"])
        self.send(404, "not found", "text/plain")


def main():
    if not (A.url and A.key and B.url and B.key):
        sys.exit("A_URL, A_KEY, B_URL, B_KEY must be set (copy .env.example to .env)")
    threading.Thread(target=refresher, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log(f"serving on :{PORT}  A={A.name} {A.url}  B={B.name} {B.url}  window={HOURS:g}h refresh={REFRESH}s")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
