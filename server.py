#!/usr/bin/env python3
"""Tiny web app around rxcompare: refreshes the comparison in the background and serves it.

Routes:
  /                 HTML report (default receiver pair and window; ?a=&b=&hours=N for others)
  /summary.json     compact JSON of the same result (same query parameters)
  /receivers.json   the receivers on offer — one per radio of each system, plus each system as a whole
  /healthz          200 once the first analysis has succeeded

Receivers come from receivers.yml (RECEIVERS to point elsewhere); with no such file the A_*/B_* env
vars are used, which is the two-node setup this started as. Other config: HOURS REFRESH_SEC PORT
VERIFY_TLS RANGES, plus the map settings in rxcompare.py
"""
import html, json, os, sys, threading, time, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import rxcompare as rx

HOURS = float(os.environ.get("HOURS", "3"))
REFRESH = int(os.environ.get("REFRESH_SEC", "300"))
PORT = int(os.environ.get("PORT", "8080"))
RANGES = [float(x) for x in os.environ.get("RANGES", "1,3,6,12,24,48").split(",")]
MAX_HOURS = 168.0

SITES, DEFAULT = rx.load_sites()

_cache = {}          # (a, b, hours) -> {"ts", "html", "summary"}
_locks = {}          # same key -> Lock, so concurrent requests don't both hit the receivers
_locks_guard = threading.Lock()
_last_error = None


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, file=sys.stderr, flush=True)


def registry():
    """id -> Receiver. Discovery is cached in the Site objects, so this is cheap after the first call."""
    return rx.receivers_of(SITES)


def default_pair():
    reg = registry()
    ids = [i for i in (DEFAULT or ()) if i in reg] if DEFAULT else []
    return tuple(ids[:2]) if len(ids) >= 2 else tuple(list(reg)[:2])


def nav_html(a, b, hours):
    """Range links, plus a row per side to pick which receiver it is. Anything not being changed is
    carried through, so switching one side keeps the other and the window."""
    reg = registry()
    out = []
    if len(reg) > 2:
        for side, cur, other in (("A", a, b), ("B", b, a)):
            links = "".join(
                f'<a href="/?{urlencode({"a": rid if side == "A" else other, "b": other if side == "A" else rid, "hours": f"{hours:g}"})}"'
                f' class="{"on" if rid == cur else ""}">{html.escape(rv.name)}</a>'
                for rid, rv in reg.items() if rid != other)
            out.append(f'<div class="nav"><span style="align-self:center;color:var(--muted);font-size:12px;'
                       f'min-width:14px;font-weight:600">{side}</span>{links}</div>')
    ranges = "".join(f'<a href="/?{urlencode({"a": a, "b": b, "hours": f"{h:g}"})}" class="{"on" if h == hours else ""}">{h:g} h</a>'
                     for h in RANGES)
    out.append(f'<div class="nav">{ranges}<a href="/summary.json?{urlencode({"a": a, "b": b, "hours": f"{hours:g}"})}">json</a>'
               f'<span style="align-self:center;color:var(--muted);font-size:12px;margin-left:6px">'
               f'data refreshes every {REFRESH // 60} min — reload for the latest</span></div>')
    return "".join(out)


def compute(a, b, hours):
    global _last_error
    key = (a, b, hours)
    with _locks_guard:
        lock = _locks.setdefault(key, threading.Lock())
    with lock:
        ent = _cache.get(key)
        if ent and time.time() - ent["ts"] < REFRESH:
            return ent
        reg = registry()
        for i in (a, b):
            if i not in reg:
                raise KeyError(f"unknown receiver {i!r}; available: {', '.join(reg)}")
        t = time.time()
        try:
            R = rx.analyze(reg[a], reg[b], hours)
            ent = {"ts": time.time(), "html": rx.render_html(R, nav_html(a, b, hours)), "summary": rx.summary(R)}
            _cache[key] = ent
            _last_error = None
            log(f"analysed {a} vs {b} over {hours:g}h: {len(R['pairs'])} matched, "
                f"{R['A']['n']}/{R['B']['n']} packets, {time.time()-t:.1f}s")
            return ent
        except Exception as e:
            _last_error = f"{a} vs {b} {hours:g}h: {type(e).__name__}: {e}"
            log("analysis failed:", _last_error)
            traceback.print_exc()
            if ent:          # serve stale rather than nothing
                return ent
            raise


def refresher():
    while True:
        try:
            a, b = default_pair()
            if a and b:
                compute(a, b, HOURS)
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

    def pair(self, q):
        da, db = default_pair()
        a, b = q.get("a", [da])[0], q.get("b", [db])[0]
        return a, b

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/healthz":
            ent = _cache.get((*default_pair(), HOURS))
            return self.send(200 if ent else 503, json.dumps({"ok": bool(ent), "last_error": _last_error,
                                                            "age_s": time.time() - ent["ts"] if ent else None}),
                             "application/json")
        if u.path == "/receivers.json":
            reg = registry()
            return self.send(200, json.dumps({"default": list(default_pair()),
                                              "receivers": [{"id": i, "name": r.name, "site": r.site.id,
                                                             "radio": r.radio, "url": r.url} for i, r in reg.items()]},
                                             indent=1), "application/json")
        if u.path in ("/", "/index.html", "/summary.json"):
            a, b = self.pair(q)
            if not (a and b):
                return self.send(503, "<h1>no receivers configured</h1><p>Write a receivers.yml "
                                      "(see receivers.example.yml) or set A_URL/A_KEY/B_URL/B_KEY.</p>")
            if a == b:
                return self.send(400, f"<h1>pick two different receivers</h1><pre>{html.escape(a)}</pre>")
            try:
                ent = compute(a, b, self.hours(q))
            except Exception as e:
                return self.send(502, f"<h1>analysis failed</h1><pre>{html.escape(str(e))}</pre>")
            if u.path == "/summary.json":
                return self.send(200, json.dumps(ent["summary"], indent=1), "application/json")
            return self.send(200, ent["html"])
        self.send(404, "not found", "text/plain")


def main():
    if not SITES:
        sys.exit("no receivers configured: write a receivers.yml (see receivers.example.yml) "
                 "or set A_URL/A_KEY/B_URL/B_KEY")
    threading.Thread(target=refresher, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    a, b = default_pair()
    log(f"serving on :{PORT}  sites={', '.join(s.id for s in SITES)}  default={a} vs {b}  "
        f"window={HOURS:g}h refresh={REFRESH}s")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
