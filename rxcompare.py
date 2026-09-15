#!/usr/bin/env python3
"""Compare RX performance of two openHop repeaters listening on the same channel.

Joins packets seen on both nodes by (packet_hash, path_hash, timestamp within
a few seconds) and reports RSSI/SNR deltas, packets heard by only one node,
per-neighbour breakdown, noise floor and CRC errors.

Usage:
  ./rxcompare.py                       # last hour, text report
  ./rxcompare.py --hours 6 --html report.html
  ./rxcompare.py --watch 60 --html report.html   # regenerate every 60s
  ./rxcompare.py --csv pairs.csv       # dump matched pairs

Keys/URLs come from env: A_URL A_KEY A_NAME B_URL B_KEY B_NAME
(or the --a-url/--a-key/... flags).
"""
import argparse, csv, html, json, math, os, ssl, statistics as st, sys, time, urllib.request, urllib.parse
from collections import Counter, defaultdict

MATCH_WINDOW_S = 3.0   # both nodes hear the same transmission within this many seconds
DEEP_DB = -8   # "deep" packets: decoded this far below the noise, where receiver sensitivity is what decides
TYPE_NAMES = {0: "REQ", 1: "RESPONSE", 2: "TXT_MSG", 3: "ACK", 4: "ADVERT", 5: "GRP_TXT", 6: "GRP_DATA",
              7: "ANON_REQ", 8: "PATH", 9: "TRACE", 10: "MULTIPART", 11: "CONTROL"}
PAGE = 1000
NAN = float("nan")

def _ssl_ctx():
    ctx = ssl.create_default_context()
    if os.environ.get("VERIFY_TLS", "true").lower() in ("0", "false", "no"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


CTX = _ssl_ctx()


# --------------------------------------------------------------------------- API

class Node:
    def __init__(self, name, url, key):
        self.name, self.url, self.key = name, url.rstrip("/"), key

    def get(self, path, **params):
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(f"{self.url}/api/{path}?{q}", headers={"X-API-Key": self.key})
        with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
            return json.load(r)

    def packets(self, start, end):
        out, offset = [], 0
        while True:
            d = self.get("bulk_packets", start_timestamp=start, end_timestamp=end, limit=PAGE, offset=offset)
            batch = d.get("data", [])
            # packets queued for transmission (the node's own, or a companion app's adverts and
            # requests sent through it) land in the same table with rssi 0 / snr 0 and, in no-TX
            # mode, drop_reason "No TX mode"; they were never on the air, so they are not RX data
            out.extend(p for p in batch if not (p.get("rssi") == 0 and p.get("snr") == 0))
            if len(batch) < PAGE:
                return out
            offset += PAGE

    def noise(self, hours):
        h = self.get("noise_floor_history", hours=hours)["data"]["history"]
        return [(x["timestamp"], x["noise_floor_dbm"]) for x in h if x.get("noise_floor_dbm") is not None]

    def crc(self, hours):
        return self.get("crc_error_count", hours=hours)["data"]["crc_error_count"]

    def crc_history(self, hours):
        try:
            h = self.get("crc_error_history", hours=hours)["data"]["history"]
        except Exception:
            return []
        return [(x["timestamp"], x["count"]) for x in h if x.get("count") is not None]


# --------------------------------------------------------------------------- analysis

def key(p):
    return (p.get("packet_hash"), p.get("path_hash"))


def match(pa, pb):
    """Greedy nearest-timestamp join. Returns (pairs, only_a, only_b)."""
    idx = defaultdict(list)
    for p in pb:
        idx[key(p)].append(p)
    used, pairs, only_a = set(), [], []
    for p in sorted(pa, key=lambda p: p["timestamp"]):
        best, bdt = None, MATCH_WINDOW_S
        for q in idx.get(key(p), []):
            if q["id"] in used:
                continue
            dt = abs(q["timestamp"] - p["timestamp"])
            if dt < bdt:
                best, bdt = q, dt
        if best:
            used.add(best["id"])
            pairs.append((p, best))
        else:
            only_a.append(p)
    only_b = [q for q in pb if q["id"] not in used]
    return pairs, only_a, only_b


def hop_canon(hashes):
    """Map each hop hash to the longest observed hash it is a prefix of, when that is unambiguous."""
    hs = sorted({h for h in hashes if h}, key=len, reverse=True)
    out = {}
    for h in hs:
        longer = [x for x in hs if len(x) > len(h) and x.startswith(h)]
        roots = {out.get(x, x) for x in longer}
        out[h] = roots.pop() if len(roots) == 1 else h
    return out


def mean(xs):
    return st.fmean(xs) if xs else NAN


def med(xs):
    return st.median(xs) if xs else NAN


def analyze(A, B, hours):
    end = time.time()
    start = end - hours * 3600
    pa, pb = A.packets(start, end), B.packets(start, end)
    # ignore our own transmissions (should be none in no-tx mode, but be safe)
    pa = [p for p in pa if not p.get("transmitted")]
    pb = [p for p in pb if not p.get("transmitted")]
    # only compare the period where both nodes were actually listening
    if pa and pb:
        overlap = max(min(p["timestamp"] for p in pa), min(p["timestamp"] for p in pb))
        if overlap - start > 60:
            pa = [p for p in pa if p["timestamp"] >= overlap]
            pb = [p for p in pb if p["timestamp"] >= overlap]
            start = overlap
    pairs, only_a, only_b = match(pa, pb)
    h = max(1, int(math.ceil(hours)))
    na, nb = A.noise(h), B.noise(h)
    na = [x for x in na if x[0] >= start]; nb = [x for x in nb if x[0] >= start]
    ca, cb = A.crc_history(h), B.crc_history(h)
    # the history endpoint caps at 1000 samples; if the cap truncated the window, mark the count as a lower bound
    crc_trunc = {"A": len(ca) >= 1000 and ca and ca[0][0] > start, "B": len(cb) >= 1000 and cb and cb[0][0] > start}
    ca = [x for x in ca if x[0] >= start]; cb = [x for x in cb if x[0] >= start]

    ra = [p["rssi"] for p, _ in pairs]; rb = [q["rssi"] for _, q in pairs]
    sa = [p["snr"] for p, _ in pairs];  sb = [q["snr"] for _, q in pairs]
    drssi = [b - a for a, b in zip(ra, rb)]
    dsnr = [b - a for a, b in zip(sa, sb)]
    # the two radios report SNR with a fixed-ish offset on the same packet; for every threshold-based
    # stat (below −8 dB, weakest decoded, sensitivity curves) split that offset between them so a
    # "−8 dB packet" means the same signal on both sides
    md = mean(dsnr) if dsnr else 0.0
    shift = {"a": md / 2, "b": -md / 2}

    # per upstream neighbour (last hop). Path hashes are 1-3 bytes of the same node id, so
    # "DB", "DB95" and "DB9570" are one neighbour: fold each hash into the longest one it prefixes.
    canon = hop_canon({p.get("upstream_hash") for p in pa} | {q.get("upstream_hash") for q in pb})
    hop_of = lambda p: canon.get(p.get("upstream_hash"), p.get("upstream_hash")) or "direct"
    nb_stats = defaultdict(lambda: {"both": 0, "a": 0, "b": 0, "ra": [], "rb": [], "sa": [], "sb": []})
    for p, q in pairs:
        s = nb_stats[hop_of(p)]
        s["both"] += 1; s["ra"].append(p["rssi"]); s["rb"].append(q["rssi"]); s["sa"].append(p["snr"]); s["sb"].append(q["snr"])
    for p in only_a:
        nb_stats[hop_of(p)]["a"] += 1
    for q in only_b:
        nb_stats[hop_of(q)]["b"] += 1
    neighbours = []
    for hop, s in sorted(nb_stats.items(), key=lambda kv: -(kv[1]["both"] + kv[1]["a"] + kv[1]["b"])):
        neighbours.append({"hop": hop, "both": s["both"], "a": s["a"], "b": s["b"],
                           "rssi_a": mean(s["ra"]), "rssi_b": mean(s["rb"]),
                           "snr_a": mean(s["sa"]), "snr_b": mean(s["sb"]),
                           "drssi": mean(s["rb"]) - mean(s["ra"]) if s["both"] else NAN,
                           "dsnr": mean(s["sb"]) - mean(s["sa"]) if s["both"] else NAN})

    # time buckets
    span = end - start
    bucket = 300 if span <= 2 * 3600 else 900 if span <= 12 * 3600 else 3600
    t0 = start - start % bucket
    nbk = int((end - t0) // bucket) + 1
    buckets = [{"t": t0 + i * bucket, "a": 0, "b": 0, "both": 0, "deep_a": 0, "deep_b": 0, "dsnr": [], "drssi": []} for i in range(nbk)]

    def bi(ts):
        return min(nbk - 1, max(0, int((ts - t0) // bucket)))
    for p, q in pairs:
        b = buckets[bi(p["timestamp"])]
        b["both"] += 1; b["a"] += 1; b["b"] += 1
        b["deep_a"] += p["snr"] + shift["a"] < DEEP_DB; b["deep_b"] += q["snr"] + shift["b"] < DEEP_DB
        b["dsnr"].append(q["snr"] - p["snr"]); b["drssi"].append(q["rssi"] - p["rssi"])
    for p in only_a:
        b = buckets[bi(p["timestamp"])]; b["a"] += 1; b["deep_a"] += p["snr"] + shift["a"] < DEEP_DB
    for q in only_b:
        b = buckets[bi(q["timestamp"])]; b["b"] += 1; b["deep_b"] += q["snr"] + shift["b"] < DEEP_DB
    for b in buckets:
        b["dsnr"] = mean(b["dsnr"]); b["drssi"] = mean(b["drssi"])
    # the last bucket is only partly elapsed: scale its counts to a full-bucket rate so the line doesn't dip
    last = buckets[-1]
    last["frac"] = max(0.0, min(1.0, (end - last["t"]) / bucket))
    if last["frac"] < 0.15 and len(buckets) > 1:
        buckets.pop()
    elif last["frac"] < 1.0:
        for k in ("a", "b", "both", "deep_a", "deep_b"):
            last[k] = round(last[k] / last["frac"], 1)

    # packet type mix over everything either node heard
    types = Counter(p["type"] for p in pa) | Counter(q["type"] for q in only_b)

    # neighbours one node hears and the other barely does (≥20 packets, one side under 50%, the other
    # over 85%) are a property of the two positions, not the receivers. The headline keeps them (that
    # is what each node actually decoded); the sensitivity analyses below leave them out.
    def heard(n):
        u = n["both"] + n["a"] + n["b"]
        return (n["both"] + n["a"]) / u, (n["both"] + n["b"]) / u
    one_sided = [n["hop"] for n in neighbours if n["both"] + n["a"] + n["b"] >= 20 and min(heard(n)) < 0.5 and max(heard(n)) > 0.85]
    os_hops = set(one_sided)
    sh_pairs = [(p, q) for p, q in pairs if hop_of(p) not in os_hops]
    sh_only_a = [p for p in only_a if hop_of(p) not in os_hops]
    sh_only_b = [q for q in only_b if hop_of(q) not in os_hops]

    # sensitivity curves: given one node decoded a transmission at SNR s, did the other?
    # binned by the reference node's own reading, so each curve is on that node's scale
    LVL = 2
    lvl = lambda v: max(-14, min(12, math.floor(v / LVL) * LVL))
    curve = {"a_given_b": defaultdict(lambda: [0, 0]), "b_given_a": defaultdict(lambda: [0, 0])}  # bin -> [decoded, seen]
    for p, q in sh_pairs:
        curve["b_given_a"][lvl(p["snr"] + shift["a"])][0] += 1; curve["b_given_a"][lvl(p["snr"] + shift["a"])][1] += 1
        curve["a_given_b"][lvl(q["snr"] + shift["b"])][0] += 1; curve["a_given_b"][lvl(q["snr"] + shift["b"])][1] += 1
    for p in sh_only_a:
        curve["b_given_a"][lvl(p["snr"] + shift["a"])][1] += 1
    for q in sh_only_b:
        curve["a_given_b"][lvl(q["snr"] + shift["b"])][1] += 1
    curves = {k: [{"snr": x, "decoded": v[0], "seen": v[1]} for x, v in sorted(c.items())] for k, c in curve.items()}

    # SNR delta by signal level, keyed on the packet's mean reading so neither node's noise biases the bin
    by_level = defaultdict(list)
    for p, q in sh_pairs:
        by_level[lvl((p["snr"] + q["snr"]) / 2)].append(q["snr"] - p["snr"])
    dsnr_by_level = [{"snr": x, "n": len(v), "mean": mean(v), "ci": 1.96 * st.pstdev(v) / math.sqrt(len(v)) if len(v) > 1 else NAN}
                     for x, v in sorted(by_level.items())]

    # decode rate per payload type (long packets collide more; short ones mostly test sensitivity)
    tstat = defaultdict(lambda: {"both": 0, "a": 0, "b": 0, "len": []})
    for p, q in sh_pairs:
        tstat[p["type"]]["both"] += 1; tstat[p["type"]]["len"].append(p["length"])
    for p in sh_only_a:
        tstat[p["type"]]["a"] += 1; tstat[p["type"]]["len"].append(p["length"])
    for q in sh_only_b:
        tstat[q["type"]]["b"] += 1; tstat[q["type"]]["len"].append(q["length"])
    by_type = [{"type": t, "name": TYPE_NAMES.get(t, f"type {t}"), "both": v["both"], "a": v["a"], "b": v["b"],
                "n": v["both"] + v["a"] + v["b"], "len": mean(v["len"])}
               for t, v in sorted(tstat.items(), key=lambda kv: -(kv[1]["both"] + kv[1]["a"] + kv[1]["b"]))]

    # match quality: clock offset between the nodes' timestamps and wild per-packet disagreements
    dts = sorted(q["timestamp"] - p["timestamp"] for p, q in pairs)
    clock = {"median": med(dts), "p5": dts[len(dts) // 20] if dts else NAN, "p95": dts[-max(1, len(dts) // 20)] if dts else NAN,
             "max_abs": max(abs(d) for d in dts) if dts else NAN, "wild": sum(1 for d in dsnr if abs(d) > 10)}

    return {
        "generated": time.time(), "start": start, "end": end, "bucket": bucket,
        "A": {"name": A.name, "url": A.url, "n": len(pa), "only": only_a, "rssi": ra, "snr": sa,
              "noise": na, "crc": sum(c for _, c in ca), "crc_lower_bound": bool(crc_trunc["A"]), "crc_hist": ca},
        "B": {"name": B.name, "url": B.url, "n": len(pb), "only": only_b, "rssi": rb, "snr": sb,
              "noise": nb, "crc": sum(c for _, c in cb), "crc_lower_bound": bool(crc_trunc["B"]), "crc_hist": cb},
        "pairs": pairs, "drssi": drssi, "dsnr": dsnr, "neighbours": neighbours, "buckets": buckets,
        "types": types, "curves": curves, "dsnr_by_level": dsnr_by_level, "by_type": by_type, "clock": clock,
        "one_sided": one_sided,
        "shared": {"pairs": len(sh_pairs), "only_a": len(sh_only_a), "only_b": len(sh_only_b),
                   "deep_a": sum(1 for p, _ in sh_pairs if p["snr"] + shift["a"] < DEEP_DB) + sum(1 for p in sh_only_a if p["snr"] + shift["a"] < DEEP_DB),
                   "deep_b": sum(1 for _, q in sh_pairs if q["snr"] + shift["b"] < DEEP_DB) + sum(1 for q in sh_only_b if q["snr"] + shift["b"] < DEEP_DB)},
        "snr_shift": shift,
    }


# --------------------------------------------------------------------------- text report

def fmt(x, w=6, d=1):
    return f"{x:{w}.{d}f}" if x == x else " " * (w - 1) + "-"


def print_report(R):
    A, B, pairs = R["A"], R["B"], R["pairs"]
    drssi, dsnr = R["drssi"], R["dsnr"]
    W = max(len(A["name"]), len(B["name"]), 8)
    print(f"\n{time.strftime('%Y-%m-%d %H:%M:%S')}  window: {time.strftime('%H:%M:%S', time.localtime(R['start']))} - now "
          f"({(R['end']-R['start'])/3600:.2f}h)   A={A['name']} ({A['url']})   B={B['name']} ({B['url']})")
    print("=" * 96)
    union = len(pairs) + len(A["only"]) + len(B["only"])
    print(f"{'':{W}}  {'packets':>8} {'decoded':>8} {'matched':>8} {'only':>6} {'RSSI avg':>9} {'RSSI med':>9} "
          f"{'SNR avg':>8} {'SNR med':>8} {'SNR min':>8} {f'<{DEEP_DB}dB':>7} {'noise avg':>10} {'noise min':>10} {'CRC err':>8}")
    for n in (A, B):
        nz = [v for _, v in n["noise"]]; fs = floor_stats(n, R["snr_shift"]["a" if n is A else "b"])
        print(f"{n['name']:{W}}  {n['n']:8d} {100*n['n']/union if union else NAN:7.1f}% {len(pairs):8d} {len(n['only']):6d} {fmt(mean(n['rssi']),9)} {fmt(med(n['rssi']),9)} "
              f"{fmt(mean(n['snr']),8,2)} {fmt(med(n['snr']),8,2)} {fmt(fs['snr_min'],8,1)} {fs['deep']:7d} {fmt(mean(nz),10)} {fmt(min(nz) if nz else NAN,10)} {n['crc']:8d}")
    print("-" * 96)
    if pairs:
        better_b = sum(1 for d in drssi if d > 0); better_a = sum(1 for d in drssi if d < 0)
        print(f"Delta (B - A) over {len(pairs)} matched packets:")
        print(f"  RSSI: mean {mean(drssi):+.2f} dB  median {med(drssi):+.1f}  "
              f"stdev {st.pstdev(drssi):.2f}  min {min(drssi):+d}  max {max(drssi):+d}")
        print(f"  SNR : mean {mean(dsnr):+.2f} dB  median {med(dsnr):+.2f}  "
              f"stdev {st.pstdev(dsnr):.2f}  min {min(dsnr):+.2f}  max {max(dsnr):+.2f}")
        print(f"  RSSI better on A: {better_a} ({100*better_a/len(pairs):.0f}%)   "
              f"on B: {better_b} ({100*better_b/len(pairs):.0f}%)   tie: {len(pairs)-better_a-better_b}")
        hist = Counter(max(-10, min(10, d)) for d in drssi)
        print("  RSSI delta histogram (dB, B-A):")
        for d in sorted(hist):
            lbl = f"{'<=' if d == -10 else '>=' if d == 10 else ''}{d:+d}"
            print(f"    {lbl:>5} {'#' * hist[d]} {hist[d]}")
    print("-" * 96)
    for n in (A, B):
        only = n["only"]
        if only:
            print(f"Heard only by {n['name']}: {len(only)}  "
                  f"(RSSI avg {mean([p['rssi'] for p in only]):.1f}, SNR avg {mean([p['snr'] for p in only]):.2f}, "
                  f"types {dict(sorted(Counter(p['type'] for p in only).items()))})")
    print("-" * 96)
    print("Per upstream neighbour (last hop):  n=both / A-only / B-only, RSSI/SNR averages on matched, delta = B-A")
    print(f"  {'hop':>6} {'both':>5} {'A-only':>6} {'B-only':>6}  {'RSSI A':>7} {'RSSI B':>7} {'dRSSI':>6}  {'SNR A':>6} {'SNR B':>6} {'dSNR':>6}")
    for s in R["neighbours"][:25]:
        print(f"  {s['hop']:>6} {s['both']:5d} {s['a']:6d} {s['b']:6d}  {fmt(s['rssi_a'],7)} {fmt(s['rssi_b'],7)} {fmt(s['drssi'],6)}  "
              f"{fmt(s['snr_a'],6,2)} {fmt(s['snr_b'],6,2)} {fmt(s['dsnr'],6,2)}")


def write_csv(R, path):
    A, B = R["A"]["name"], R["B"]["name"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts", "packet_hash", "path_hash", "upstream", "type", "length",
                    f"rssi_{A}", f"rssi_{B}", f"snr_{A}", f"snr_{B}", "drssi", "dsnr"])
        for p, q in R["pairs"]:
            w.writerow([f"{p['timestamp']:.3f}", p["packet_hash"], p["path_hash"], p.get("upstream_hash"),
                        p["type"], p["length"], p["rssi"], q["rssi"], p["snr"], q["snr"],
                        q["rssi"] - p["rssi"], round(q["snr"] - p["snr"], 2)])
    print(f"wrote {len(R['pairs'])} matched pairs to {path}")


# --------------------------------------------------------------------------- HTML report
# Self-contained: inline SVG, no external assets, so it opens as a local file.

CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--plane:#efefeb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--a:#2a78d6;--b:#eb6834;--good:#006300;--bad:#d03b3b}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--plane:#232322;--ink:#fff;--ink2:#c3c2b7;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--a:#3987e5;--b:#d95926;--good:#0ca30c;--bad:#e66767}}
:root[data-theme=dark]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--plane:#232322;--ink:#fff;--ink2:#c3c2b7;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--a:#3987e5;--b:#d95926;--good:#0ca30c;--bad:#e66767}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px 16px 48px}
main{max-width:1200px;margin:0 auto}
section{padding:26px 0 6px;border-top:1px solid var(--grid);margin-top:18px;scroll-margin-top:60px}section.first{border-top:0;margin-top:0;padding-top:4px}
section>h2{font-size:18px;margin:0 0 4px;font-weight:600;letter-spacing:-.01em}section>p.meta{margin:0 0 16px}
.topbar{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:6px 16px;align-items:center;justify-content:space-between;background:var(--page);padding:10px 0;border-bottom:1px solid var(--grid);margin:0 0 20px}
.jump{display:flex;flex-wrap:wrap;gap:2px}.jump a{color:var(--ink2);text-decoration:none;padding:5px 10px;border-radius:6px;font-size:13px}.jump a:hover{background:var(--grid);color:var(--ink)}
.panel{background:var(--plane);border-radius:14px;padding:18px 18px 12px;margin-top:4px}.panel .ctl{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin:0 0 14px}.panel .ctl label{color:var(--ink2);font-size:13px}
.panel .card{border-color:transparent}.panel .tile{border-color:transparent}
h1.who{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px 22px;margin:0 0 14px;font-size:30px;font-weight:600;letter-spacing:-.01em}
.who .node{display:inline-flex;align-items:baseline;gap:10px;padding-bottom:6px;border-bottom:4px solid}.who .node.a{border-color:var(--a)}.who .node.b{border-color:var(--b)}
.who .chip{font-size:15px;font-weight:700;line-height:1;color:#fff;padding:5px 7px 4px;border-radius:5px;align-self:center}.who .node.a .chip{background:var(--a)}.who .node.b .chip{background:var(--b)}
.who .vs{font-size:16px;font-weight:400;color:var(--muted)}
.ch{display:inline-block;font-size:11px;font-weight:700;line-height:1;color:#fff;padding:3px 5px 2px;border-radius:4px;vertical-align:.15em;margin-right:5px}.ch.a{background:var(--a)}.ch.b{background:var(--b)}
.tile .v .ch{font-size:13px;padding:4px 6px 3px;vertical-align:.25em;margin:0 6px 0 0}.tile .v .ch.b{margin-left:14px}
.meta{color:var(--ink2);max-width:72ch;margin:0 0 14px;line-height:1.5}.meta.warn{color:var(--b)}
.sub{color:var(--ink2);margin:0 0 20px;overflow-wrap:anywhere}.sub code{font-size:12px}
.nav{display:flex;flex-wrap:wrap;gap:6px;margin:0}.nav a{color:var(--ink2);text-decoration:none;border:1px solid var(--border);border-radius:6px;padding:3px 10px;font-size:13px}.nav a.on{color:var(--ink);border-color:var(--ink2);font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--ink2);font-size:13px;margin:0 0 12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:-1px}
.sw{display:inline-block;width:.6em;height:.6em;border-radius:50%;margin-right:.3em;vertical-align:baseline}.sw.a{background:var(--a)}.sw.b{background:var(--b)}


.tile{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.tile .l{color:var(--ink2);font-size:12px}.tile .v{font-size:26px;font-weight:600;line-height:1.2;margin:4px 0 2px}
.tile .v.hero{font-size:38px}.halves{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr));gap:18px;margin-top:6px}.half .h{font-size:12.5px;font-weight:600;color:var(--ink);margin-bottom:2px}.half .v{font-size:30px}.half .verdict{font-size:14px;margin-top:8px;color:var(--ink)}.half .verdict .k{color:var(--ink2);font-size:12px;font-weight:400}.half .note{font-size:11.5px;color:var(--ink2);margin-top:2px}.tile .sub{font-size:20px;font-weight:600;line-height:1.2;margin:10px 0 2px;color:var(--ink)}.tile .sub .ch{font-size:12px;padding:3px 5px 2px;vertical-align:.3em;margin:0 5px 0 0}.tile .sub .ch.b{margin-left:10px}.tile .sub .k{font-size:12px;font-weight:400;color:var(--ink2);margin-left:6px}.tile .d>div{margin-top:4px}.tile .v.hero .ch{font-size:15px;padding:5px 7px 4px;vertical-align:.35em}.tile .d b{color:var(--ink);font-weight:600}.tile .d{font-size:12px;color:var(--ink2)}.tile .d.good{color:var(--good)}.tile .d.bad{color:var(--bad)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:12px;align-items:start}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(440px,100%),1fr));gap:12px;align-items:start}
.top{display:grid;grid-template-columns:1fr;gap:12px;align-items:stretch}@media(min-width:860px){.top{grid-template-columns:2fr 1fr 1fr}}
.sbar{margin:8px 0 4px}.sbar .bar{display:flex;gap:2px;height:14px;border-radius:7px;overflow:hidden}.sbar .bar i{display:block;height:100%}.sbar .a{background:var(--a)}.sbar .b{background:var(--b)}.sbar .n{background:var(--axis)}
.sbar .seg{display:flex;gap:2px;font-size:10.5px;letter-spacing:-.01em;color:var(--ink2);margin-top:3px;white-space:nowrap}.sbar .seg span{text-align:center;overflow:hidden}.sbar .seg span.l{text-align:left;overflow:visible}.sbar .seg span.r{text-align:right;overflow:visible;direction:rtl}

.nodes{font-variant-numeric:tabular-nums}.nodes th{text-align:right}.nodes th:first-child{text-align:left}.nodes td.k{color:var(--ink2)}.nodes td.win-a{color:var(--a);font-weight:600}.nodes td.win-b{color:var(--b);font-weight:600}.nodes small{color:var(--muted);font-size:11px;margin-left:2px}
.nodes td,.nodes th{width:1%}.nodes td:last-child{width:auto;text-align:left;font-size:12px;padding-left:18px}.nodes td:nth-child(2),.nodes td:nth-child(3){padding-left:28px}
@media(max-width:700px){.nodes td:last-child,.nodes th:last-child{display:none}.nodes{table-layout:fixed}.nodes td,.nodes th{width:auto}.nodes th:first-child{width:42%}.nodes td{white-space:normal}.nodes td:nth-child(2),.nodes td:nth-child(3){padding-left:10px}}
.nodes .sw{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:-1px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:0}
.card h3{font-size:13px;font-weight:600;margin:0 0 2px}.card p{margin:0 0 8px;color:var(--ink2);font-size:12px}.reading{margin-top:12px}.reading ul{margin:6px 0 0;padding-left:18px;color:var(--ink2);font-size:13px;line-height:1.5}.reading li{margin:3px 0}.reading b{color:var(--ink)}.card .legend{margin:0 0 8px;font-size:12px}
svg{display:block;width:100%;height:auto;overflow:visible}
.ax text{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}.ax line{stroke:var(--grid)}.ax .base{stroke:var(--axis)}
.lbl{fill:var(--ink2);font-size:11px}
.hit{fill:transparent;pointer-events:all}.mark:hover,.hit:hover+.mark{opacity:.75}
table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
th,td{padding:5px 8px;text-align:right;border-bottom:1px solid var(--grid);white-space:nowrap}th{color:var(--ink2);font-weight:500}
th:first-child,td:first-child{text-align:left}.wrap{overflow-x:auto}
.bar{display:inline-block;height:10px;vertical-align:middle;border-radius:0 4px 4px 0}.bar.l{border-radius:4px 0 0 4px}
.select{font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--axis);border-radius:6px;padding:6px 10px;max-width:100%}
tr.pick{cursor:pointer}tr.pick:hover td{background:var(--grid)}.hit.pick{cursor:pointer}
details{margin-top:14px}summary{cursor:pointer;color:var(--ink2);font-weight:600;font-size:14px}details[open]>summary{margin-bottom:8px}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:6px 8px;border-radius:6px;opacity:0;transition:opacity .08s;white-space:pre;z-index:9}
"""

JS = """
const tip=document.getElementById('tip');
document.addEventListener('mousemove',e=>{const t=e.target.closest('[data-tip]');if(!t){tip.style.opacity=0;return}
tip.textContent=t.dataset.tip;tip.style.opacity=1;tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY+14)+'px';});

// ---- neighbour explorer: per-packet view of one upstream hop, rendered client-side from embedded data
(function(){
const EX=window.EXPLORE; if(!EX) return;
const sel=document.getElementById('ex-hop'), out=document.getElementById('ex-out');
const NA=EX.na, NB=EX.nb, W=520;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtT=t=>{const d=new Date(t*1000);return d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0')};
const fmtTs=t=>{const d=new Date(t*1000);return fmtT(t)+':'+d.getSeconds().toString().padStart(2,'0')};
const mean=a=>a.length?a.reduce((x,y)=>x+y,0)/a.length:NaN;
const f1=v=>isNaN(v)?'–':v.toFixed(1), f2=v=>isNaN(v)?'–':(v>0?'+':'')+v.toFixed(2);
function ticks(lo,hi,n){if(hi<=lo)hi=lo+1;const raw=(hi-lo)/n,mag=Math.pow(10,Math.floor(Math.log10(raw)));const step=[1,2,2.5,5,10].map(s=>s*mag).find(s=>s>=raw);const t=[];for(let v=Math.floor(lo/step)*step;v<=hi+1e-9;v+=step)t.push(+v.toFixed(6));return t}
function frame(h,ml,mb,xlo,xhi,ylo,yhi){const mt=12,mr=12,pw=W-ml-mr,ph=h-mt-mb;return{h,ml,mb,mt,x:v=>ml+(v-xlo)/((xhi-xlo)||1)*pw,y:v=>mt+ph-(v-ylo)/((yhi-ylo)||1)*ph,xlo,xhi,ylo,yhi,right:W-mr,bottom:h-mb}}
function axes(F,xt,yt,xf,yf,zero){let g='<g class="ax">';for(const t of yt)if(t>=F.ylo&&t<=F.yhi){const y=F.y(t);g+=`<line x1="${F.ml}" x2="${F.right}" y1="${y}" y2="${y}"/><text x="${F.ml-6}" y="${y+4}" text-anchor="end">${yf(t)}</text>`}
for(const t of xt)if(t>=F.xlo&&t<=F.xhi)g+=`<text x="${F.x(t)}" y="${F.bottom+16}" text-anchor="middle">${xf(t)}</text>`;
const by=(zero&&F.ylo<=0&&0<=F.yhi)?F.y(0):F.bottom;return g+`<line class="base" x1="${F.ml}" x2="${F.right}" y1="${by}" y2="${by}"/></g>`}
function timeTicks(a,b){const span=b-a,step=[900,1800,3600,7200,14400,21600,43200,86400].find(s=>span/s<=7);const t=[];for(let v=Math.ceil(a/step)*step;v<=b;v+=step)t.push(v);return t}
function bucketIdx(t){return Math.min(EX.nb_buckets-1,Math.max(0,Math.floor((t-EX.t0)/EX.bucket)))}
function snrChart(rows){
  if(!rows.length)return'<p>no packets</p>';
  const vals=rows.flatMap(r=>[r[2],r[3]]).filter(v=>v!=null);
  let lo=Math.min(...vals),hi=Math.max(...vals);const pad=(hi-lo)*.1||1;lo-=pad;hi+=pad;
  const F=frame(300,44,28,EX.start,EX.end,lo,hi);
  let g=axes(F,timeTicks(EX.start,EX.end),ticks(lo,hi,5),fmtT,v=>(v>0?'+':'')+v,false);
  // bucketed mean SNR per node, drawn under the dots so the trend reads even when the dots are dense
  for(const [k,col] of [[2,'var(--a)'],[3,'var(--b)']]){const acc=[];for(const r of rows)if(r[k]!=null){const i=bucketIdx(r[0]);(acc[i]=acc[i]||[]).push(r[k])}
    let d='',pen=false;for(let i=0;i<EX.nb_buckets;i++){if(!acc[i]||acc[i].length<2){pen=false;continue}d+=(pen?'L':'M')+F.x(EX.t0+(i+.5)*EX.bucket)+','+F.y(mean(acc[i]));pen=true}
    g+=`<path fill="none" stroke="${col}" stroke-width="2.5" stroke-opacity=".55" stroke-linejoin="round" stroke-linecap="round" d="${d}"/>`}
  for(const r of rows){const x=F.x(r[0]);const both=r[2]!=null&&r[3]!=null;
    const tipS=`${fmtTs(r[0])}\n${NA}: ${r[2]==null?'missed':r[2].toFixed(2)+' dB'+(r[4]!=null?' ('+r[4]+' dBm)':'')}\n${NB}: ${r[3]==null?'missed':r[3].toFixed(2)+' dB'+(r[5]!=null?' ('+r[5]+' dBm)':'')}`+(both?`\nΔ ${f2(r[3]-r[2])} dB`:'');
    if(both)g+=`<line x1="${x}" x2="${x}" y1="${F.y(r[2])}" y2="${F.y(r[3])}" stroke="var(--axis)" stroke-width="1.5"/>`;
    for(const [v,col] of [[r[2],'var(--a)'],[r[3],'var(--b)']]){if(v==null)continue;const y=F.y(v);
      g+=both?`<circle cx="${x}" cy="${y}" r="4" fill="${col}" stroke="var(--surface)" stroke-width="1.5" pointer-events="none"/>`
             :`<circle cx="${x}" cy="${y}" r="4.5" fill="var(--surface)" stroke="${col}" stroke-width="2" pointer-events="none"/>`}
    const ys=[r[2],r[3]].filter(v=>v!=null).map(F.y);
    g+=`<rect class="hit" x="${x-4}" y="${Math.min(...ys)-6}" width="8" height="${Math.max(...ys)-Math.min(...ys)+12}" data-tip="${esc(tipS)}"/>`}
  return`<svg viewBox="0 0 ${W} ${F.h}" xmlns="http://www.w3.org/2000/svg">${g}</svg>`}
function countChart(rows){
  const n=EX.nb_buckets,ca=new Array(n).fill(0),cb=new Array(n).fill(0);
  for(const r of rows){const i=bucketIdx(r[0]);if(r[2]!=null)ca[i]++;if(r[3]!=null)cb[i]++}
  if(EX.frac<1){ca[n-1]=Math.round(ca[n-1]/EX.frac);cb[n-1]=Math.round(cb[n-1]/EX.frac)}
  const ts=ca.map((_,i)=>EX.t0+i*EX.bucket),mx=Math.max(1,...ca,...cb);
  const F=frame(300,44,28,ts[0],ts[n-1]||ts[0]+1,0,mx*1.1);
  let g=axes(F,timeTicks(ts[0],ts[n-1]),ticks(0,mx,5),fmtT,v=>v,true);
  for(const [c,col] of [[ca,'var(--a)'],[cb,'var(--b)']]){g+=`<path fill="none" stroke="${col}" stroke-width="2" stroke-linejoin="round" d="${c.map((v,i)=>(i?'L':'M')+F.x(ts[i])+','+F.y(v)).join('')}"/>`}
  const half=n>1?(F.x(ts[1])-F.x(ts[0]))/2:20;
  ts.forEach((t,i)=>{const part=(i==n-1&&EX.frac<1)?`\n(${Math.round(EX.frac*100)}% elapsed, scaled to a full bucket)`:'';g+=`<rect class="hit" x="${F.x(t)-half}" y="${F.mt}" width="${2*half}" height="${F.bottom-F.mt}" data-tip="${fmtT(t)}\n${esc(NA)}: ${ca[i]}\n${esc(NB)}: ${cb[i]}${part}"/>`;
    for(const [c,col] of [[ca,'var(--a)'],[cb,'var(--b)']])g+=`<circle cx="${F.x(t)}" cy="${F.y(c[i])}" r="3" fill="${col}" stroke="var(--surface)" stroke-width="2" pointer-events="none"/>`});
  return`<svg viewBox="0 0 ${W} ${F.h}" xmlns="http://www.w3.org/2000/svg">${g}</svg>`}
function render(h){
  const rows=EX.pk.filter(r=>r[1]===h).sort((a,b)=>a[0]-b[0]);
  const both=rows.filter(r=>r[2]!=null&&r[3]!=null),oa=rows.filter(r=>r[3]==null),ob=rows.filter(r=>r[2]==null);
  const sa=mean(both.map(r=>r[2])),sb=mean(both.map(r=>r[3]));
  const stat=(l,v)=>`<div class="tile"><div class="l">${l}</div><div class="v" style="font-size:20px">${v}</div></div>`;
  out.innerHTML=`<div class="tiles" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(140px,100%),1fr));gap:12px;margin-bottom:12px">
    ${stat('Decoded by both',both.length)}${stat('Only <span class="ch a">A</span>',oa.length)}${stat('Only <span class="ch b">B</span>',ob.length)}
    ${stat('Mean SNR, matched',`<span class="ch a">A</span>${f1(sa)}<span class="ch b" style="margin-left:10px">B</span>${f1(sb)}`)}
    ${stat('Δ SNR, B − A',f2(sb-sa)+' dB')}</div>
  <div class="grid2">
   <div class="card"><h3>Every packet from ${esc(EX.hops[h])}</h3><p>Filled dots joined by a stem: decoded by both. Hollow ring: decoded by one node only. Lines are the mean SNR per ${EX.bucket/60} min on each node. Hover for values.</p>${EX.leg}${snrChart(rows)}</div>
   <div class="card"><h3>Decoded per ${EX.bucket/60} min</h3><p>How many of this neighbour's packets each node decoded.${EX.frac<1?' Last bucket is scaled to a full-bucket rate.':''}</p>${EX.leg}${countChart(rows)}</div></div>`;
  history.replaceState(null,'','#hop='+encodeURIComponent(EX.hops[h]))}
sel.addEventListener('change',()=>render(+sel.value));
document.querySelectorAll('[data-hop]').forEach(el=>el.addEventListener('click',()=>{const i=EX.hops.indexOf(el.dataset.hop);if(i<0)return;sel.value=i;render(i);document.getElementById('explore').scrollIntoView({behavior:'smooth',block:'start'})}));
const m=location.hash.match(/^#hop=(.+)$/);const init=m?EX.hops.indexOf(decodeURIComponent(m[1])):-1;
if(init>=0)sel.value=init;render(+sel.value);
})();
"""


def esc(s):
    return html.escape(str(s), quote=True)


def signed(v, fmt="g"):
    """Signed number with a typographic minus, so −1 reads as clearly as +1 on an axis."""
    t = f"{v:+{fmt}}"
    return t[1:] if not t.strip("+-0.") else t.replace("-", "−")


def nice_ticks(lo, hi, n=5):
    if hi <= lo:
        hi = lo + 1
    raw = (hi - lo) / n
    mag = 10 ** math.floor(math.log10(raw))
    step = next(s * mag for s in (1, 2, 2.5, 5, 10) if s * mag >= raw)
    t0 = math.floor(lo / step) * step
    ticks = []
    while t0 <= hi + 1e-9:
        ticks.append(round(t0, 10))
        t0 += step
    return ticks


def tlabel(ts):
    return time.strftime("%H:%M", time.localtime(ts))


class Svg:
    """Minimal plot frame: left/bottom axes, hairline grid, scales."""

    def __init__(self, w=520, h=240, ml=44, mr=12, mt=12, mb=28):
        self.w, self.h, self.ml, self.mr, self.mt, self.mb = w, h, ml, mr, mt, mb
        self.parts = []

    def scales(self, xlo, xhi, ylo, yhi):
        self.xlo, self.xhi, self.ylo, self.yhi = xlo, xhi, ylo, yhi
        pw, ph = self.w - self.ml - self.mr, self.h - self.mt - self.mb
        self.x = lambda v: self.ml + (v - xlo) / (xhi - xlo or 1) * pw
        self.y = lambda v: self.mt + ph - (v - ylo) / (yhi - ylo or 1) * ph

    def axes(self, xticks, yticks, xfmt=lambda t: f"{t:g}", yfmt=lambda t: f"{t:g}", y0=True):
        g = ['<g class="ax">']
        for t in yticks:
            if self.ylo <= t <= self.yhi:
                y = self.y(t)
                g.append(f'<line x1="{self.ml}" x2="{self.w-self.mr}" y1="{y:.1f}" y2="{y:.1f}"/>'
                         f'<text x="{self.ml-6}" y="{y+4:.1f}" text-anchor="end">{esc(yfmt(t))}</text>')
        for t in xticks:
            if self.xlo <= t <= self.xhi:
                x = self.x(t)
                g.append(f'<text x="{x:.1f}" y="{self.h-self.mb+16}" text-anchor="middle">{esc(xfmt(t))}</text>')
        by = self.y(0) if y0 and self.ylo <= 0 <= self.yhi else self.h - self.mb
        g.append(f'<line class="base" x1="{self.ml}" x2="{self.w-self.mr}" y1="{by:.1f}" y2="{by:.1f}"/></g>')
        self.parts.append("".join(g))

    def add(self, s):
        self.parts.append(s)

    def render(self):
        return f'<svg viewBox="0 0 {self.w} {self.h}" xmlns="http://www.w3.org/2000/svg">{"".join(self.parts)}</svg>'


def chart_hist(values, lo, hi, step, title, unit="dB", color="var(--ink2)", clamp=True, h=240, marker=None, sides=None):
    """Single-series histogram. Each bin is centred on a multiple of `step` (so the 0 bin is
    symmetric around zero) and the ends are clamped to [lo,hi]. `marker=(value, label)` draws a
    vertical reference line. `sides=(left, right)` colours negative bins A and positive bins B and
    labels which node each side favours."""
    if not values:
        return "<p>no data</p>"
    bins = defaultdict(int)
    for v in values:
        b = round(v / step) * step
        if clamp:
            b = max(lo, min(hi, b))
        bins[round(b, 6)] += 1
    xs = sorted(bins)
    s = Svg(h=h, mb=42 if sides else 28)
    s.scales(lo - step, hi + step, 0, max(bins.values()) * 1.08)
    s.axes([x for x in xs if int(round(x / step)) % (2 if step < 1 else 1) == 0], nice_ticks(0, max(bins.values())), xfmt=signed)
    bw = max(2, min(24, (s.x(step) - s.x(0)) - 2))
    total = len(values)
    for x in xs:
        n = bins[x]
        cx = s.x(x); top = s.y(n); base = s.y(0)
        r = min(4, bw / 2, (base - top))
        edge = "≤" if clamp and x == lo else "≥" if clamp and x == hi else ""
        rng = f" ({signed(x - step / 2)}…{signed(x + step / 2)})" if not edge else ""
        col = color if not sides or x == 0 else "var(--a)" if x < 0 else "var(--b)"
        s.add(f'<rect class="hit" x="{cx-bw/2-1:.1f}" y="{s.mt}" width="{bw+2:.1f}" height="{s.h-s.mt-s.mb}" '
              f'data-tip="Δ {edge}{signed(x)} {unit}{rng}: {n} packets ({100*n/total:.0f}%)"/>')
        s.add(f'<path class="mark" fill="{col}" d="M{cx-bw/2:.1f},{base:.1f}V{top+r:.1f}q0,-{r} {r},-{r}h{bw-2*r:.1f}q{r},0 {r},{r}V{base:.1f}Z"/>')
    if sides:
        left, right = sides
        y = s.h - 6
        s.add(f'<text class="lbl" x="{s.ml}" y="{y}" fill="var(--a)">← {esc(left)} cleaner</text>'
              f'<text class="lbl" x="{s.w-s.mr}" y="{y}" text-anchor="end" fill="var(--b)">{esc(right)} cleaner →</text>')
    if marker:
        mv, ml = marker
        mx = s.x(mv)
        s.add(f'<line x1="{mx:.1f}" x2="{mx:.1f}" y1="{s.mt}" y2="{s.h-s.mb}" stroke="var(--ink)" stroke-width="1.5"/>'
              f'<text class="lbl" x="{mx+6:.1f}" y="{s.mt+12}" fill="var(--ink)">{esc(ml)}</text>')
    return s.render()


def chart_excl_neighbours(neigh, na, nb, flag=frozenset()):
    """Diverging counts per upstream hop: packets only A decoded (left) vs only B (right)."""
    rows = sorted([n for n in neigh if n["a"] + n["b"] >= 3], key=lambda n: -(n["a"] + n["b"]))[:16]
    if not rows:
        return "<p>no exclusive packets yet</p>"
    mx = max(max(n["a"], n["b"]) for n in rows) or 1
    rh = 20
    s = Svg(w=520, h=rh * len(rows) + 40, ml=96, mr=16, mt=8, mb=26)
    s.scales(-mx * 1.15, mx * 1.15, 0, len(rows))
    s.axes(nice_ticks(-mx, mx, 6), [], xfmt=lambda t: f"{abs(t):g}", y0=False)
    s.add(f'<line x1="{s.x(0):.1f}" x2="{s.x(0):.1f}" y1="{s.mt}" y2="{s.h-s.mb}" stroke="var(--axis)"/>')
    for i, n in enumerate(rows):
        y = s.mt + i * rh + 4
        for v, col, sign in ((n["a"], "var(--a)", -1), (n["b"], "var(--b)", 1)):
            if not v:
                continue
            x0, x1 = sorted((s.x(0), s.x(sign * v)))
            w = max(1, x1 - x0); r = min(4, w)
            d = (f"M{x0:.1f},{y}h{w-r:.1f}q{r},0 {r},{r}v{rh-8-2*r}q0,{r} -{r},{r}h-{w-r:.1f}Z" if sign > 0 else
                 f"M{x1:.1f},{y}h-{w-r:.1f}q-{r},0 -{r},{r}v{rh-8-2*r}q0,{r} {r},{r}h{w-r:.1f}Z")
            s.add(f'<path class="mark" fill="{col}" d="{d}"/>')
        s.add(f'<rect class="hit pick" data-hop="{esc(n["hop"])}" x="{s.ml}" y="{y-2}" width="{s.w-s.ml-s.mr}" height="{rh}" data-tip="hop {esc(n["hop"])}{" ◐ one-sided: heard from one position only" if n["hop"] in flag else ""}: '
              f'only {esc(na)} {n["a"]}, only {esc(nb)} {n["b"]}, both {n["both"]}"/>')
        s.add(f'<text x="{s.ml-8}" y="{y+rh-9}" text-anchor="end" fill="var(--ink2)" font-size="11">{"<tspan fill=\"var(--muted)\">◐ </tspan>" if n["hop"] in flag else ""}{esc(n["hop"])}</text>')
        s.add(f'<text x="{s.ml-8-58}" y="{y+rh-9}" text-anchor="end" fill="var(--muted)" font-size="10">n={n["both"]}</text>')
    return s.render()


def chart_decode_curve(curves, na, nb, step=2, min_n=5):
    """Sensitivity curves: P(A decoded | B heard it at SNR s) in A's colour, and vice versa.
    Each curve sits on the reference node's own SNR scale."""
    series = [("a_given_b", "var(--a)", na, nb), ("b_given_a", "var(--b)", nb, na)]
    pts = {k: [c for c in curves[k] if c["seen"] >= min_n] for k, *_ in series}
    if not any(pts.values()):
        return "<p>not enough packets yet</p>"
    s = Svg(w=520, h=270, ml=44, mb=40)
    s.scales(-14 - step / 2, 12 + step * 1.5, 0, 1.06)
    s.axes(list(range(-14, 13, 4)), [0, .25, .5, .75, 1], xfmt=lambda t: ("≤" if t == -14 else "") + signed(t), yfmt=lambda t: f"{100*t:.0f}%")
    s.add(f'<text class="lbl" x="{(s.ml+s.w-s.mr)/2:.0f}" y="{s.h-4}" text-anchor="middle">SNR as read by the node that heard it, dB</text>')
    # sample size per bin as a faint bar behind the curves, so a point on 8 packets doesn't read like one on 800
    mxn = max(c["seen"] for k in pts for c in pts[k]) or 1
    bw = (s.x(step) - s.x(0)) - 3
    for k, col, who, ref in series:
        for i, c in enumerate(pts[k]):
            x = s.x(c["snr"] + step / 2) - bw / 2 + (bw / 2 if k == "b_given_a" else 0)
            top = s.y(0.35 * c["seen"] / mxn)
            s.add(f'<rect x="{x:.1f}" y="{top:.1f}" width="{bw/2:.1f}" height="{s.y(0)-top:.1f}" fill="{col}" fill-opacity=".14" pointer-events="none"/>')
    for k, col, who, ref in series:
        d, pen = [], False
        for c in pts[k]:
            x, y = s.x(c["snr"] + step / 2), s.y(c["decoded"] / c["seen"])
            d.append(f'{"L" if pen else "M"}{x:.1f},{y:.1f}'); pen = True
        s.add(f'<path fill="none" stroke="{col}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" d="{"".join(d)}"/>')
    # one hit column per bin with both nodes' figures
    bins = sorted({c["snr"] for k in pts for c in pts[k]})
    half = (s.x(step) - s.x(0)) / 2
    for x in bins:
        tip = [f"{signed(x)}…{signed(x + step)} dB"]
        for k, col, who, ref in series:
            c = next((c for c in pts[k] if c["snr"] == x), None)
            if c:
                pr = c["decoded"] / c["seen"]; ci = 1.96 * math.sqrt(pr * (1 - pr) / c["seen"])
                tip.append(f"{ref} heard {c['seen']} at that level · {who} also decoded {c['decoded']} ({100*pr:.0f}% ±{100*ci:.0f})")
        cx = s.x(x + step / 2)
        s.add(f'<rect class="hit" x="{cx-half:.1f}" y="{s.mt}" width="{2*half:.1f}" height="{s.h-s.mt-s.mb}" data-tip="{esc(chr(10).join(tip))}"/>')
        for k, col, who, ref in series:
            c = next((c for c in pts[k] if c["snr"] == x), None)
            if c:
                pr = c["decoded"] / c["seen"]; ci = 1.96 * math.sqrt(pr * (1 - pr) / c["seen"])
                y1, y2 = s.y(max(0, pr - ci)), s.y(min(1, pr + ci))
                s.add(f'<path d="M{cx:.1f},{y1:.1f}V{y2:.1f}M{cx-3:.1f},{y1:.1f}h6M{cx-3:.1f},{y2:.1f}h6" stroke="{col}" stroke-width="1.5" fill="none" pointer-events="none"/>')
                s.add(f'<circle class="mark" cx="{cx:.1f}" cy="{s.y(pr):.1f}" r="{3 + min(2, math.log10(c["seen"])):.1f}" fill="{col}" '
                      f'stroke="var(--surface)" stroke-width="2" pointer-events="none"/>')
    return s.render()


def chart_delta_by_level(rows, na, nb, step=2, min_n=5):
    """Mean Δ SNR (B−A) with 95% CI whiskers, per 2 dB of signal level. Flat = a calibration offset;
    a slope or a kink near the floor = the radios really differ there."""
    rows = [r for r in rows if r["n"] >= min_n]
    if not rows:
        return "<p>not enough matched packets yet</p>"
    ext = max(abs(r["mean"]) + (r["ci"] if r["ci"] == r["ci"] else 0) for r in rows)
    lim = max(2.0, math.ceil(ext * 2) / 2)
    s = Svg(w=520, h=270, ml=44, mb=40)
    s.scales(-14 - step / 2, 12 + step * 1.5, -lim, lim)
    s.axes(list(range(-14, 13, 4)), nice_ticks(-lim, lim, 5), xfmt=lambda t: ("≤" if t == -14 else "") + signed(t), yfmt=lambda t: f"{signed(t)}", y0=True)
    s.add(f'<text class="lbl" x="{(s.ml+s.w-s.mr)/2:.0f}" y="{s.h-4}" text-anchor="middle">mean of the two SNR readings, dB</text>')
    s.add(f'<text class="lbl" x="{s.ml+4}" y="{s.mt+11}" fill="var(--b)">{esc(nb)} cleaner ↑</text>'
          f'<text class="lbl" x="{s.ml+4}" y="{s.h-s.mb-5}" fill="var(--a)">{esc(na)} cleaner ↓</text>')
    d = "".join(f'{"L" if i else "M"}{s.x(r["snr"] + step / 2):.1f},{s.y(r["mean"]):.1f}' for i, r in enumerate(rows))
    s.add(f'<path fill="none" stroke="var(--axis)" stroke-width="1.5" d="{d}"/>')
    half = (s.x(step) - s.x(0)) / 2
    for r in rows:
        cx = s.x(r["snr"] + step / 2); cy = s.y(r["mean"])
        col = "var(--b)" if r["mean"] > 0 else "var(--a)"
        ci = f" ± {r['ci']:.2f}" if r["ci"] == r["ci"] else ""
        s.add(f'<rect class="hit" x="{cx-half:.1f}" y="{s.mt}" width="{2*half:.1f}" height="{s.h-s.mt-s.mb}" '
              f'data-tip="{signed(r["snr"])}…{signed(r["snr"] + step)} dB: {r["n"]} packets\nΔ SNR {signed(r["mean"], ".2f")}{ci} dB"/>')
        if r["ci"] == r["ci"]:
            y1, y2 = s.y(r["mean"] - r["ci"]), s.y(r["mean"] + r["ci"])
            s.add(f'<path d="M{cx:.1f},{y1:.1f}V{y2:.1f}M{cx-3:.1f},{y1:.1f}h6M{cx-3:.1f},{y2:.1f}h6" stroke="{col}" stroke-width="1.5" fill="none" pointer-events="none"/>')
        s.add(f'<circle class="mark" cx="{cx:.1f}" cy="{cy:.1f}" r="4" fill="{col}" stroke="var(--surface)" stroke-width="2" pointer-events="none"/>')
    return s.render()


def chart_type_rates(by_type, na, nb, min_n=10):
    """Decode rate per payload type, one row per type, A above B. Long packets are exposed to
    collisions for longer, so a gap that opens only on long types is timing, not sensitivity."""
    rows = [t for t in by_type if t["n"] >= min_n][:8]
    if not rows:
        return "<p>not enough packets yet</p>"
    rh = 26
    s = Svg(w=520, h=rh * len(rows) + 40, ml=150, mr=96, mt=8, mb=26)
    s.scales(0, 1.0, 0, len(rows))
    s.axes([0, .25, .5, .75, 1], [], xfmt=lambda t: f"{100*t:.0f}%", y0=False)
    for i, t in enumerate(rows):
        y = s.mt + i * rh + 3
        ra, rb = (t["both"] + t["a"]) / t["n"], (t["both"] + t["b"]) / t["n"]
        for j, (v, col) in enumerate(((ra, "var(--a)"), (rb, "var(--b)"))):
            w = max(1, s.x(v) - s.x(0)); r = min(3, w)
            s.add(f'<path class="mark" fill="{col}" d="M{s.x(0):.1f},{y + j*10}h{w-r:.1f}q{r},0 {r},{r}v{8-2*r}q0,{r} -{r},{r}h-{w-r:.1f}Z"/>')
        s.add(f'<rect class="hit" x="{s.ml}" y="{y-3}" width="{s.w-s.ml-s.mr}" height="{rh}" data-tip="{esc(t["name"])} · {t["n"]} transmissions, avg {t["len"]:.0f} B\n'
              f'{esc(na)} decoded {t["both"]+t["a"]} ({100*ra:.0f}%)\n{esc(nb)} decoded {t["both"]+t["b"]} ({100*rb:.0f}%)"/>')
        s.add(f'<text x="{s.ml-8}" y="{y+13}" text-anchor="end" fill="var(--ink2)" font-size="11">{esc(t["name"])}</text>')
        s.add(f'<text x="{s.ml-8-66}" y="{y+13}" text-anchor="end" fill="var(--muted)" font-size="10">n={t["n"]} · {t["len"]:.0f} B</text>')
        gap = rb - ra
        s.add(f'<text x="{s.w-s.mr+8}" y="{y+13}" fill="var(--ink2)" font-size="11" font-variant-numeric="tabular-nums">'
              f'<tspan fill="var(--a)">{100*ra:.0f}</tspan><tspan fill="var(--muted)"> / </tspan><tspan fill="var(--b)">{100*rb:.0f}</tspan>'
              f'<tspan fill="var(--muted)" font-size="10" dx="6">{signed(100*gap, ".0f")}</tspan></text>')
    return s.render()


def chart_dumbbell(neigh, na, nb, flag=frozenset()):
    """Per neighbour: mean SNR on A and on B as two dots joined by a line, strongest at the top."""
    rows = sorted([n for n in neigh if n["both"] >= 3], key=lambda n: -(n["snr_a"] + n["snr_b"]))[:20]
    if not rows:
        return "<p>not enough matched packets per neighbour yet</p>"
    vals = [v for n in rows for v in (n["snr_a"], n["snr_b"])]
    lo, hi = min(vals) - 1.5, max(vals) + 1.5
    rh = 20
    s = Svg(w=520, h=rh * len(rows) + 40, ml=96, mr=16, mt=8, mb=26)
    s.scales(lo, hi, 0, len(rows))
    s.axes(nice_ticks(lo, hi, 6), [], xfmt=signed, y0=False)
    if lo < 0 < hi:
        s.add(f'<line x1="{s.x(0):.1f}" x2="{s.x(0):.1f}" y1="{s.mt}" y2="{s.h-s.mb}" stroke="var(--axis)"/>')
    for i, n in enumerate(rows):
        cy = s.mt + i * rh + rh / 2
        xa, xb = s.x(n["snr_a"]), s.x(n["snr_b"])
        s.add(f'<rect class="hit pick" data-hop="{esc(n["hop"])}" x="{s.ml}" y="{cy-rh/2:.1f}" width="{s.w-s.ml-s.mr}" height="{rh}" data-tip="hop {esc(n["hop"])}, {n["both"]} matched\n'
              f'SNR {esc(na)} {n["snr_a"]:+.2f}  {esc(nb)} {n["snr_b"]:+.2f}  Δ {n["dsnr"]:+.2f} dB"/>')
        s.add(f'<line x1="{xa:.1f}" x2="{xb:.1f}" y1="{cy:.1f}" y2="{cy:.1f}" stroke="var(--axis)" stroke-width="2"/>')
        for x, col in ((xa, "var(--a)"), (xb, "var(--b)")):
            s.add(f'<circle class="mark" cx="{x:.1f}" cy="{cy:.1f}" r="5" fill="{col}" stroke="var(--surface)" stroke-width="2" pointer-events="none"/>')
        s.add(f'<text x="{s.ml-8}" y="{cy+4:.1f}" text-anchor="end" fill="var(--ink2)" font-size="11">{"<tspan fill=\"var(--muted)\">◐ </tspan>" if n["hop"] in flag else ""}{esc(n["hop"])}</text>')
        s.add(f'<text x="{s.ml-8-58}" y="{cy+4:.1f}" text-anchor="end" fill="var(--muted)" font-size="10">n={n["both"]}</text>')
    return s.render()


def chart_hist2(va, vb, lo, hi, step, na, nb, unit="dB"):
    """Two-series grouped histogram (A-only vs B-only SNR)."""
    if not va and not vb:
        return "<p>no data</p>"
    def binned(vs):
        c = defaultdict(int)
        for v in vs:
            c[max(lo, min(hi, math.floor(v / step) * step))] += 1
        return c
    ba, bb = binned(va), binned(vb)
    xs = sorted(set(ba) | set(bb))
    mx = max(list(ba.values()) + list(bb.values()) + [1])
    s = Svg()
    s.scales(lo - step / 2, hi + step * 1.5, 0, mx * 1.08)
    s.axes([x for x in xs if int(x / step) % 2 == 0], nice_ticks(0, mx), xfmt=signed)
    slot = s.x(step) - s.x(0)
    bw = max(2, min(12, (slot - 4) / 2))
    for x in xs:
        for i, (c, col, name) in enumerate(((ba, "var(--a)", na), (bb, "var(--b)", nb))):
            n = c.get(x, 0)
            if not n:
                continue
            cx = s.x(x + step / 2) + (i - 0.5) * (bw + 2)
            top, base = s.y(n), s.y(0); r = min(4, bw / 2, base - top)
            s.add(f'<rect class="hit" x="{cx-bw/2-1:.1f}" y="{s.mt}" width="{bw+2:.1f}" height="{s.h-s.mt-s.mb}" '
                  f'data-tip="only {name}\\nSNR {signed(x)}…{signed(x+step)} {unit}: {n}"/>')
            s.add(f'<path class="mark" fill="{col}" d="M{cx-bw/2:.1f},{base:.1f}V{top+r:.1f}q0,-{r} {r},-{r}h{bw-2*r:.1f}q{r},0 {r},{r}V{base:.1f}Z"/>')
    return s.render()


def chart_scatter(xa, xb, na, nb, unit, pairs_meta):
    """A vs B for matched packets, with the y=x identity line. Dots as A=x, B=y."""
    if not xa:
        return "<p>no data</p>"
    lo, hi = min(min(xa), min(xb)), max(max(xa), max(xb))
    pad = (hi - lo) * 0.05 or 1
    lo, hi = lo - pad, hi + pad
    s = Svg(w=520, h=360, ml=48, mb=34)
    s.scales(lo, hi, lo, hi)
    tk = nice_ticks(lo, hi, 6)
    s.axes(tk, tk, xfmt=lambda t: f"{t:g}", yfmt=lambda t: f"{t:g}", y0=False)
    s.add(f'<line x1="{s.x(lo):.1f}" y1="{s.y(lo):.1f}" x2="{s.x(hi):.1f}" y2="{s.y(hi):.1f}" stroke="var(--axis)" stroke-width="1"/>')
    s.add(f'<text class="lbl" x="{(s.ml+s.w-s.mr)/2:.0f}" y="{s.h-4}" text-anchor="middle">{esc(na)} {unit}</text>')
    s.add(f'<text class="lbl" transform="translate(12,{(s.mt+s.h-s.mb)/2:.0f}) rotate(-90)" text-anchor="middle">{esc(nb)} {unit}</text>')
    # overplot: identical coords stack, so count them and size the dot slightly by count
    cnt = Counter(zip(xa, xb))
    meta = {}
    for (a, b), m in zip(zip(xa, xb), pairs_meta):
        meta.setdefault((a, b), m)
    for (a, b), n in cnt.items():
        r = 3.5 + min(3, math.log2(n))
        m = meta[(a, b)]
        s.add(f'<circle class="mark" cx="{s.x(a):.1f}" cy="{s.y(b):.1f}" r="{r:.1f}" fill="var(--a)" fill-opacity=".55" '
              f'stroke="var(--surface)" stroke-width="2" data-tip="{esc(na)} {a:g} / {esc(nb)} {b:g} {unit}  (Δ {b-a:+g})\\n'
              f'{n} packet{"s" if n>1 else ""}{"" if n>1 else "  hop "+esc(m)}"/>')
    return s.render()


def chart_lines(series, ts, yfmt=lambda v: f"{v:g}", zero=False, ylo=None, yhi=None):
    """series: list of (name, color, [values or nan]). One shared x (timestamps)."""
    vals = [v for _, _, vs in series for v in vs if v == v]
    if not vals:
        return "<p>no data</p>"
    lo = min(vals) if ylo is None else ylo
    hi = max(vals) if yhi is None else yhi
    if zero:
        lo, hi = min(lo, 0), max(hi, 0)
    pad = (hi - lo) * 0.1 or 1
    lo, hi = lo - pad, hi + pad
    s = Svg(w=520, h=220, ml=44)
    s.scales(ts[0], ts[-1] if ts[-1] > ts[0] else ts[0] + 1, lo, hi)
    span = ts[-1] - ts[0]
    step = next(st_ for st_ in (900, 1800, 3600, 7200, 4 * 3600, 6 * 3600, 12 * 3600, 86400) if span / st_ <= 7)
    xt = [t for t in range(int(ts[0] - ts[0] % step + step), int(ts[-1]) + 1, step)]
    s.axes(xt, nice_ticks(lo, hi, 5), xfmt=tlabel, yfmt=yfmt, y0=zero)
    for name, col, vs in series:
        d, pen = [], False
        for t, v in zip(ts, vs):
            if v != v:
                pen = False; continue
            d.append(f'{"L" if pen else "M"}{s.x(t):.1f},{s.y(v):.1f}'); pen = True
        s.add(f'<path fill="none" stroke="{col}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" d="{"".join(d)}"/>')
    # hover columns
    if len(ts) > 1:
        half = (s.x(ts[1]) - s.x(ts[0])) / 2
        for i, t in enumerate(ts):
            tipl = [tlabel(t)] + [f"{n}: {yfmt(vs[i])}" for n, _, vs in series if vs[i] == vs[i]]
            s.add(f'<rect class="hit" x="{s.x(t)-half:.1f}" y="{s.mt}" width="{2*half:.1f}" height="{s.h-s.mt-s.mb}" data-tip="{esc(chr(10).join(tipl))}"/>')
            for n, col, vs in series:
                if vs[i] == vs[i]:
                    s.add(f'<circle class="mark" cx="{s.x(t):.1f}" cy="{s.y(vs[i]):.1f}" r="3" fill="{col}" stroke="var(--surface)" stroke-width="2" pointer-events="none"/>')
    return s.render()


def chart_neighbours(neigh, na, nb, flag=frozenset()):
    """Horizontal diverging bars: ΔSNR (B−A) per upstream hop; colour = whichever node is better."""
    rows = [n for n in neigh if n["both"] >= 3][:20]
    if not rows:
        return "<p>not enough matched packets per neighbour yet</p>"
    mx = max(abs(n["dsnr"]) for n in rows) or 1
    rh = 20
    s = Svg(w=520, h=rh * len(rows) + 40, ml=96, mr=16, mt=8, mb=26)
    s.scales(-mx * 1.15, mx * 1.15, 0, len(rows))
    s.axes(nice_ticks(-mx, mx, 6), [], xfmt=signed, y0=False)
    s.add(f'<line x1="{s.x(0):.1f}" x2="{s.x(0):.1f}" y1="{s.mt}" y2="{s.h-s.mb}" stroke="var(--axis)"/>')
    for i, n in enumerate(rows):
        y = s.mt + i * rh + 4
        x0, x1 = sorted((s.x(0), s.x(n["dsnr"])))
        col = "var(--b)" if n["dsnr"] > 0 else "var(--a)"
        w = max(1, x1 - x0); r = min(4, w)
        d = (f"M{x0:.1f},{y}h{w-r:.1f}q{r},0 {r},{r}v{rh-8-2*r}q0,{r} -{r},{r}h-{w-r:.1f}Z" if n["dsnr"] > 0 else
             f"M{x1:.1f},{y}h-{w-r:.1f}q-{r},0 -{r},{r}v{rh-8-2*r}q0,{r} {r},{r}h{w-r:.1f}Z")
        s.add(f'<rect class="hit pick" data-hop="{esc(n["hop"])}" x="{s.ml}" y="{y-2}" width="{s.w-s.ml-s.mr}" height="{rh}" data-tip="hop {esc(n["hop"])}: {n["both"]} matched, '
              f'{n["a"]} only {esc(na)}, {n["b"]} only {esc(nb)}\\nSNR {esc(na)} {n["snr_a"]:.1f}  {esc(nb)} {n["snr_b"]:.1f}  Δ {n["dsnr"]:+.2f} dB\\n'
              f'RSSI {esc(na)} {n["rssi_a"]:.0f}  {esc(nb)} {n["rssi_b"]:.0f}  Δ {n["drssi"]:+.1f} dB"/>')
        s.add(f'<path class="mark" fill="{col}" d="{d}"/>')
        s.add(f'<text class="ax" x="{s.ml-8}" y="{y+rh-9}" text-anchor="end" fill="var(--ink2)" font-size="11">{"<tspan fill=\"var(--muted)\">◐ </tspan>" if n["hop"] in flag else ""}{esc(n["hop"])}</text>')
        s.add(f'<text x="{s.ml-8-58}" y="{y+rh-9}" text-anchor="end" fill="var(--muted)" font-size="10">n={n["both"]}</text>')
    return s.render()


def segbar(segments, tip=""):
    """Segmented 100% bar with a label row. segments: [(share 0-1, cls 'a'|'n'|'b', label)];
    outer labels overflow outward, the middle label is dropped when its segment is too narrow."""
    bar = "".join(f'<i class="{c}" style="width:{100*w:.2f}%"></i>' for w, c, _ in segments)
    labs = []
    for i, (w, c, lbl) in enumerate(segments):
        al = "l" if i == 0 else "r" if i == len(segments) - 1 else ""
        show = lbl if (al or w >= 0.11) else ""
        labs.append(f'<span class="{al}" style="width:{100*w:.2f}%">{show}</span>')
    return f'<div class="sbar" data-tip="{esc(tip)}"><div class="bar">{bar}</div><div class="seg">{"".join(labs)}</div></div>'


def tile(label, value, delta="", cls="", hero=False):
    return (f'<div class="tile{" hero" if hero else ""}"><div class="l">{esc(label)}</div><div class="v{" hero" if hero else ""}">{value}</div>'
            f'<div class="d {cls}">{delta}</div></div>')


def render_html(R, nav="", refresh=0):
    """Return the full report page. `nav` is optional HTML placed under the title (range links);
    `refresh` > 0 makes the page reload itself every that many seconds."""
    A, B, pairs = R["A"], R["B"], R["pairs"]
    na, nb = A["name"], B["name"]
    canon = hop_canon({p.get("upstream_hash") for p, _ in pairs} | {p.get("upstream_hash") for p in A["only"]} | {q.get("upstream_hash") for q in B["only"]})
    hopname = lambda p: canon.get(p.get("upstream_hash"), p.get("upstream_hash")) or "direct"
    drssi, dsnr = R["drssi"], R["dsnr"]
    npair = len(pairs)
    nz_a = [v for _, v in A["noise"]]; nz_b = [v for _, v in B["noise"]]
    better_b = sum(1 for d in dsnr if d > 0); better_a = sum(1 for d in dsnr if d < 0)
    span_h = (R["end"] - R["start"]) / 3600
    win = f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(R['start']))} → {time.strftime('%H:%M', time.localtime(R['end']))} ({span_h:.1f} h)"
    leg = f'<div class="legend"><span><span class="ch a">A</span>{esc(na)}</span><span><span class="ch b">B</span>{esc(nb)}</span></div>'

    # ---- headline row + per-node table
    fa, fb = floor_stats(A, R["snr_shift"]["a"]), floor_stats(B, R["snr_shift"]["b"])
    union = npair + len(A["only"]) + len(B["only"])
    rate_a = A["n"] / union if union else NAN; rate_b = B["n"] / union if union else NAN
    md = mean(dsnr)
    ci = 1.96 * st.pstdev(dsnr) / math.sqrt(npair) if npair > 1 else NAN
    lead = nb if md > 0 else na
    ties = npair - better_a - better_b
    oa, ob = len(A["only"]), len(B["only"])
    # the gap is paired (every transmission is a yes/no on each node), so its CI comes from the per-transmission difference
    gap = (ob - oa) / union if union else NAN
    gap_ci = 1.96 * math.sqrt(max(0.0, (oa + ob) / union - gap * gap) / union) if union else NAN
    rate_bar = segbar([(oa / union, "a", f"A only {100*oa/union:.0f}%"), (npair / union, "n", f"both {100*npair/union:.0f}%"), (ob / union, "b", f"B only {100*ob/union:.0f}%")],
                      tip=f"only {na}: {oa:,} ({100*oa/union:.1f}%)\nboth: {npair:,} ({100*npair/union:.1f}%)\nonly {nb}: {ob:,} ({100*ob/union:.1f}%)") if union else ""
    snr_bar = segbar([(better_a / npair, "a", f"A {100*better_a/npair:.0f}%"), (ties / npair, "n", f"tie {100*ties/npair:.0f}%"), (better_b / npair, "b", f"B {100*better_b/npair:.0f}%")],
                     tip=f"{na} better: {better_a:,}\ntie: {ties:,}\n{nb} better: {better_b:,}") if npair else ""
    # neighbours one node hears and the other barely does: position, not receiver, and they move every
    # sensitivity number. Report the decode rate without them alongside the full one.
    def heard(n):
        u = n["both"] + n["a"] + n["b"]
        return (n["both"] + n["a"]) / u, (n["both"] + n["b"]) / u
    os_hops = set(R["one_sided"])
    one_sided = [n for n in R["neighbours"] if n["hop"] in os_hops]
    sh = R["shared"]
    ex_union = sh["pairs"] + sh["only_a"] + sh["only_b"]
    ex_rate_a = (sh["pairs"] + sh["only_a"]) / ex_union if ex_union else NAN; ex_rate_b = (sh["pairs"] + sh["only_b"]) / ex_union if ex_union else NAN
    ex_gap = ex_rate_b - ex_rate_a
    ex_deep_a, ex_deep_b = sh["deep_a"], sh["deep_b"]
    os_note = (f"Without {', '.join(esc(n['hop']) for n in one_sided)}: "
               f"<span class=\"ch a\">A</span>{100*ex_rate_a:.1f}% <span class=\"ch b\">B</span>{100*ex_rate_b:.1f}%." if one_sided else "")

    # ---- the reading: a few sentences derived from the numbers, so the tiles don't contradict each other unexplained
    reading = []
    if union:
        lead_r, lag_r = (nb, na) if gap > 0 else (na, nb)
        if one_sided and (ex_gap > 0) != (gap > 0) and abs(ex_gap) > gap_ci:
            tail = f", but <b>the lead reverses</b> without the one-sided neighbours: {esc(na)} {100*ex_rate_a:.1f}% vs {esc(nb)} {100*ex_rate_b:.1f}%."
        elif one_sided and abs(ex_gap) <= gap_ci:
            tail = f", but without the one-sided neighbours the two are level ({esc(na)} {100*ex_rate_a:.1f}% vs {esc(nb)} {100*ex_rate_b:.1f}%)."
        elif one_sided:
            tail = f"; {100*ex_rate_a:.1f}% vs {100*ex_rate_b:.1f}% without the one-sided neighbours."
        else:
            tail = "."
        if abs(gap) > gap_ci:
            reading.append(f"<b>{esc(lead_r)} decoded {100*abs(gap):.1f} pts more</b> of the {union:,} transmissions on the air (±{100*gap_ci:.1f}){tail}")
        else:
            reading.append(f"<b>Both decoded the same share</b> of the {union:,} transmissions, within noise (gap {signed(100*gap, '.1f')} ±{100*gap_ci:.1f} pts).")
    if npair:
        reader = nb if md > 0 else na
        lv = [r["mean"] for r in R["dsnr_by_level"] if r["n"] >= 30]
        spread = max(lv) - min(lv) if len(lv) > 1 else NAN
        if spread == spread and spread < 1.0:
            reading.append(f"On the same packet <b>{esc(reader)} reads {abs(md):.2f} dB higher SNR</b>, and the offset is the same at every signal level (spread {spread:.1f} dB) — "
                           f"a reporting difference between the radios more than a receive difference.")
        elif spread == spread:
            reading.append(f"On the same packet <b>{esc(reader)} reads {abs(md):.2f} dB higher SNR</b>, but the offset changes with level (spread {spread:.1f} dB), so part of it is real.")
        else:
            reading.append(f"On the same packet <b>{esc(reader)} reads {abs(md):.2f} dB higher SNR</b>.")
    if fa["deep"] + fb["deep"] >= 20:
        hi, lo = (fb, fa) if fb["deep"] > fa["deep"] else (fa, fb)
        hn, ln = (nb, na) if fb["deep"] > fa["deep"] else (na, nb)
        ex_hi, ex_lo = (ex_deep_b, ex_deep_a) if hn == nb else (ex_deep_a, ex_deep_b)
        gap_full, gap_sh = hi["deep"] - lo["deep"], ex_hi - ex_lo
        share = 1 - gap_sh / gap_full if gap_full > 0 else 0
        ex_tail = (f" Without the one-sided neighbours it is {ex_hi:,} against {ex_lo:,}"
                   + (f" — {100*share:.0f}% of that gap was those neighbours." if share > 0.2 else ".")) if one_sided else ""
        if hi["deep"] >= 1.25 * max(1, lo["deep"]):
            reading.append(f"<b>{esc(hn)} decodes more of the deep packets</b>: {hi['deep']:,} below {signed(DEEP_DB)} dB against {lo['deep']:,} on a common SNR scale; "
                           f"5th-percentile floor {signed(hi['snr_p5'], '.1f')} vs {signed(lo['snr_p5'], '.1f')} dB.{ex_tail}")
        else:
            reading.append(f"Both reach about the same floor: {fa['deep']:,} / {fb['deep']:,} packets below {signed(DEEP_DB)} dB, 5th-percentile floor {signed(fa['snr_p5'], '.1f')} / {signed(fb['snr_p5'], '.1f')} dB.")
    if one_sided:
        who = lambda n: na if heard(n)[0] > heard(n)[1] else nb
        reading.append(f"<b>{len(one_sided)} neighbour{'s are' if len(one_sided) > 1 else ' is'} heard almost only by one node</b>: "
                       + ", ".join(f"{esc(n['hop'])} by {esc(who(n))} ({100*max(heard(n)):.0f}% vs {100*min(heard(n)):.0f}%)" for n in one_sided)
                       + ". A receiver difference would show on every neighbour; a neighbour only one node hears comes from where that node sits "
                         "(multipath nulls, obstruction, antenna orientation). Swap the boards between positions to confirm.")
    reading_card = f'<div class="card reading"><h3>Reading</h3><ul>{"".join(f"<li>{r}</li>" for r in reading)}</ul></div>' if reading else ""

    # hero: two panels side by side, same size — everything at these positions, and shared neighbours only
    def panel(title, ra_, rb_, bar, verdict, note):
        return (f'<div class="half"><div class="h">{title}</div>'
                f'<div class="v"><span class="ch a">A</span>{100*ra_:.1f}%<span class="ch b">B</span>{100*rb_:.1f}%</div>{bar}'
                f'<div class="verdict">{verdict}</div><div class="note">{note}</div></div>')
    def verdict(g, ci_, n_lead):
        return f"<b>{esc(n_lead)} +{100*abs(g):.1f} pts</b> <span class=\"k\">±{100*ci_:.1f}</span>" if abs(g) > ci_ else f"<b>Level</b> <span class=\"k\">gap {signed(100*g, '.1f')} ±{100*ci_:.1f}</span>"
    panels = ""
    if union:
        panels += panel("All neighbours, at these positions", rate_a, rate_b, rate_bar, verdict(gap, gap_ci, nb if gap > 0 else na),
                        f"{union:,} transmissions")
    if one_sided and ex_union:
        ex_bar = segbar([(sh["only_a"] / ex_union, "a", f"A only {100*sh['only_a']/ex_union:.0f}%"), (sh["pairs"] / ex_union, "n", f"both {100*sh['pairs']/ex_union:.0f}%"),
                         (sh["only_b"] / ex_union, "b", f"B only {100*sh['only_b']/ex_union:.0f}%")],
                        tip=f"shared neighbours only ({ex_union:,} transmissions)\nonly {na}: {sh['only_a']:,}\nboth: {sh['pairs']:,}\nonly {nb}: {sh['only_b']:,}")
        panels += panel("Shared neighbours only", ex_rate_a, ex_rate_b, ex_bar, verdict(ex_gap, gap_ci, nb if ex_gap > 0 else na),
                        f"{ex_union:,} transmissions · without ◐ {', '.join(esc(h) for h in R['one_sided'])}")
    tiles = [
        f'<div class="tile hero"><div class="l">Share of transmissions decoded</div><div class="halves">{panels}</div></div>' if union else tile("Share of transmissions decoded", "–"),
        tile("SNR on the same packet, B − A", f"{signed(md, '.2f')} dB" if npair else "–",
             f"<b>{esc(lead)} reads higher</b> on {100*max(better_a, better_b)/npair:.0f}% of {npair:,} shared packets (CI ±{ci:.2f}). "
             f"Largely a reporting offset between the radios — diagnostic, not the outcome." if npair else ""),
        tile(f"Decoded below {signed(DEEP_DB)} dB SNR",
             f"<span class=\"ch a\">A</span>{fa['deep']:,}<span class=\"ch b\">B</span>{fb['deep']:,}",
             (f"<b>{fa['deep_pct']:.0f}% / {fb['deep_pct']:.0f}%</b> of each node's packets"
              + (f" · shared neighbours only <b>{ex_deep_a:,} / {ex_deep_b:,}</b>" if one_sided else "")
              + f" · floor (5th pct) <b>{signed(fa['snr_p5'], '.1f')} / {signed(fb['snr_p5'], '.1f')} dB</b>. Common SNR scale.")),
    ]
    def wins(x, y, higher_better=True):
        return ("a" if (x > y) == higher_better else "b") if x == x and y == y and x != y else ""
    def row(k, va, vb, tip="", win=""):
        ca = ' class="win-a"' if win == "a" else ""; cb = ' class="win-b"' if win == "b" else ""
        return f'<tr><td class="k">{k}</td><td{ca}>{va}</td><td{cb}>{vb}</td><td class="k">{tip}</td></tr>'
    node_rows = "".join([
        row("Decoded, of every transmission on the air", f"{100*rate_a:.1f}%", f"{100*rate_b:.1f}%", f"{union:,} distinct transmissions; higher is better", wins(rate_a, rate_b)),
        row("… shared neighbours only", f"{100*ex_rate_a:.1f}%", f"{100*ex_rate_b:.1f}%", f"{ex_union:,} transmissions, without {', '.join(esc(h) for h in R['one_sided'])}", wins(ex_rate_a, ex_rate_b)) if one_sided else "",
        row("Packets decoded", f"{A['n']:,}", f"{B['n']:,}", "", wins(A["n"], B["n"])),
        row("Heard only by this node", f"{len(A['only']):,}", f"{len(B['only']):,}", "packets the other node missed"),
        row("Average SNR of those", fmt(mean([p['snr'] for p in A['only']]),0,1)+" dB", fmt(mean([p['snr'] for p in B['only']]),0,1)+" dB", "low means the other node ran out of sensitivity; high means collisions or timing"),
        row(f"Decoded below {signed(DEEP_DB)} dB SNR", f"{fa['deep']:,} <small>({fa['deep_pct']:.0f}%)</small>", f"{fb['deep']:,} <small>({fb['deep_pct']:.0f}%)</small>",
            "deep in the noise, where sensitivity rather than luck decides; common SNR scale; higher is better", wins(fa["deep"], fb["deep"])),
        row("Sensitivity floor (5th percentile SNR)", f"{fmt(fa['snr_p5'],0,1)} dB <small>(weakest {fmt(fa['snr_min'],0,1)})</small>", f"{fmt(fb['snr_p5'],0,1)} dB <small>(weakest {fmt(fb['snr_min'],0,1)})</small>",
            "the level below which only 1 in 20 decodes happens; common SNR scale; lower is better",
            wins(fa["snr_p5"], fb["snr_p5"], False) if abs(fa["snr_p5"] - fb["snr_p5"]) >= 0.25 else ""),
        row("Mean SNR, matched packets", f"{mean(A['snr']):.2f} dB", f"{mean(B['snr']):.2f} dB", "partly a reading offset between the radios"),
        row("Mean RSSI, matched packets", f"{mean(A['rssi']):.1f} dBm", f"{mean(B['rssi']):.1f} dBm", "calibration differs per radio, see the RSSI scatter"),
        row("Noise floor avg / min", f"{mean(nz_a):.1f} / {fmt(min(nz_a) if nz_a else NAN,0,1)} dBm", f"{mean(nz_b):.1f} / {fmt(min(nz_b) if nz_b else NAN,0,1)} dBm",
            "node's own measurement; lower is quieter, but partly calibration", wins(mean(nz_a), mean(nz_b), False)),
        row("CRC errors", f"{'≥' if A['crc_lower_bound'] else ''}{A['crc']:,}", f"{'≥' if B['crc_lower_bound'] else ''}{B['crc']:,}",
            "preambles detected but not decoded: packets at the edge, or false detections in noise"),
    ])
    node_table = (f'<div class="card wrap"><table class="nodes"><thead><tr><th></th>'
                  f'<th><span class="ch a">A</span>{esc(na)}</th>'
                  f'<th><span class="ch b">B</span>{esc(nb)}</th><th></th></tr></thead><tbody>{node_rows}</tbody></table></div>')

    # ---- time series
    bk = R["buckets"]
    ts = [b["t"] for b in bk]
    partial = f"Last bucket is {100*bk[-1].get('frac', 1):.0f}% elapsed and scaled to a full-bucket rate." if bk and bk[-1].get("frac", 1) < 1 else ""
    cnt_chart = chart_lines([(na, "var(--a)", [b["a"] for b in bk]), (nb, "var(--b)", [b["b"] for b in bk])], ts,
                            yfmt=lambda v: f"{v:g}", zero=True)
    def brate(b, k):
        u = b["a"] + b["b"] - b["both"]
        return b[k] / u if u else NAN
    rate_chart = chart_lines([(na, "var(--a)", [brate(b, "a") for b in bk]), (nb, "var(--b)", [brate(b, "b") for b in bk])], ts,
                             yfmt=lambda v: f"{100*v:.0f}%")
    deep_chart = chart_lines([(na, "var(--a)", [b["deep_a"] for b in bk]), (nb, "var(--b)", [b["deep_b"] for b in bk])], ts,
                             yfmt=lambda v: f"{v:g}", zero=True)
    dsnr_chart = chart_lines([("Δ SNR (B−A)", "var(--ink2)", [b["dsnr"] for b in bk])], ts,
                             yfmt=lambda v: f"{v:+.2f}", zero=True)

    def bucketed(pts, agg):
        # fold (timestamp, value) samples into the packet buckets
        acc = defaultdict(list)
        for t, v in pts:
            i = min(len(bk) - 1, max(0, int((t - ts[0]) // R["bucket"])))
            acc[i].append(v)
        return [agg(acc[i]) if i in acc else NAN for i in range(len(bk))]
    nz_series = lambda pts: bucketed(pts, mean)
    def crc_series(pts):
        v = bucketed(pts, sum)
        if bk and bk[-1].get("frac", 1) < 1 and v[-1] == v[-1]:
            v[-1] = round(v[-1] / bk[-1]["frac"], 1)
        return v
    crc_chart = chart_lines([(na, "var(--a)", crc_series(A["crc_hist"])), (nb, "var(--b)", crc_series(B["crc_hist"]))], ts,
                            yfmt=lambda v: f"{v:g}", zero=True)
    noise_chart = chart_lines([(na, "var(--a)", nz_series(A["noise"])), (nb, "var(--b)", nz_series(B["noise"]))], ts,
                              yfmt=lambda v: f"{v:.1f}")

    # ---- neighbours heard by only one node
    ex_a = [n for n in R["neighbours"] if n["both"] == 0 and n["a"] >= 3 and n["b"] == 0]
    ex_b = [n for n in R["neighbours"] if n["both"] == 0 and n["b"] >= 3 and n["a"] == 0]
    excl_note = ""
    for n_, lst in ((na, ex_a), (nb, ex_b)):
        if lst:
            excl_note += (f'<p style="margin-top:10px"><b>Never decoded by the other node:</b> only {esc(n_)} hears '
                          + ", ".join(f"{esc(x['hop'])} ({x['a'] + x['b']})" for x in lst) + "</p>")
    # ---- explorer data: one row per transmission [ts, hop index, snrA, snrB, rssiA, rssiB]
    hops = [n["hop"] for n in R["neighbours"]]
    hidx = {h: i for i, h in enumerate(hops)}
    pk = [[round(p["timestamp"], 1), hidx[hopname(p)], p["snr"], q["snr"], p["rssi"], q["rssi"]] for p, q in pairs]
    pk += [[round(p["timestamp"], 1), hidx[hopname(p)], p["snr"], None, p["rssi"], None] for p in A["only"]]
    pk += [[round(q["timestamp"], 1), hidx[hopname(q)], None, q["snr"], None, q["rssi"]] for q in B["only"]]
    explore = json.dumps({"hops": hops, "pk": pk, "start": R["start"], "end": R["end"], "t0": R["buckets"][0]["t"] if R["buckets"] else R["start"],
                          "nb_buckets": len(bk), "frac": bk[-1].get("frac", 1) if bk else 1,
                          "bucket": R["bucket"], "na": na, "nb": nb, "leg": leg}, separators=(",", ":")).replace("</", "<\\/")
    hop_opts = "".join(f'<option value="{i}">{esc(n["hop"])} ({n["both"] + n["a"] + n["b"]} packets)</option>' for i, n in enumerate(R["neighbours"]))

    # ---- neighbour table
    nrows = []
    mxd = max([abs(n["dsnr"]) for n in R["neighbours"] if n["dsnr"] == n["dsnr"]] or [1])
    for n in R["neighbours"][:40]:
        if n["dsnr"] == n["dsnr"]:
            w = 60 * abs(n["dsnr"]) / mxd
            bar = (f'<span class="bar" style="width:{w:.0f}px;background:var(--b)"></span>' if n["dsnr"] > 0
                   else f'<span class="bar l" style="width:{w:.0f}px;background:var(--a)"></span>')
            dcell = f'{n["dsnr"]:+.2f} {bar}'
        else:
            dcell = "–"
        u = n["both"] + n["a"] + n["b"]
        ha, hb = (n["both"] + n["a"]) / u, (n["both"] + n["b"]) / u
        hcell = lambda v, w, col: f'<td style="color:var(--{col})">{100*v:.0f}%</td>' if v - w >= 0.005 else f"<td>{100*v:.0f}%</td>"
        nrows.append(f"<tr data-hop=\"{esc(n['hop'])}\" class=\"pick\"><td>{esc(n['hop'])}{' <span title=\"one-sided: heard from one position only\" style=\"color:var(--muted)\">◐</span>' if n['hop'] in os_hops else ''}</td><td>{n['both']}</td><td>{n['a']}</td><td>{n['b']}</td>{hcell(ha, hb, 'a')}{hcell(hb, ha, 'b')}"
                     f"<td>{fmt(n['rssi_a'],0,1)}</td><td>{fmt(n['rssi_b'],0,1)}</td><td>{fmt(n['drssi'],0,1)}</td>"
                     f"<td>{fmt(n['snr_a'],0,2)}</td><td>{fmt(n['snr_b'],0,2)}</td><td>{dcell}</td></tr>")

    # ---- bucket table (table view for the time charts)
    brows = "".join(f"<tr><td>{tlabel(b['t'])}</td><td>{b['a']}</td><td>{b['b']}</td><td>{b['both']}</td>"
                    f"<td>{fmt(100*brate(b,'a'),0,0)}%</td><td>{fmt(100*brate(b,'b'),0,0)}%</td>"
                    f"<td>{fmt(b['drssi'],0,2)}</td><td>{fmt(b['dsnr'],0,2)}</td></tr>" for b in bk)

    # ---- matched pairs table (collapsed)
    prow = "".join(f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(p['timestamp']))}</td><td>{esc(hopname(p))}</td>"
                   f"<td>{p['type']}</td><td>{p['length']}</td><td>{p['rssi']}</td><td>{q['rssi']}</td><td>{q['rssi']-p['rssi']:+d}</td>"
                   f"<td>{p['snr']:.2f}</td><td>{q['snr']:.2f}</td><td>{q['snr']-p['snr']:+.2f}</td></tr>"
                   for p, q in sorted(pairs, key=lambda pq: -pq[0]["timestamp"]))

    # ---- match quality
    ck = R["clock"]
    if npair:
        tight = abs(ck["p95"]) < 0.5 * MATCH_WINDOW_S and abs(ck["p5"]) < 0.5 * MATCH_WINDOW_S
        clock_note = (f'<p class="meta{"" if tight else " warn"}">Clocks: {esc(nb)} stamps the same packet {signed(ck["median"], ".2f")} s relative to {esc(na)} '
                      f'(5th–95th pct {signed(ck["p5"], ".2f")}…{signed(ck["p95"], ".2f")} s, max |Δt| {ck["max_abs"]:.2f} s against a {MATCH_WINDOW_S:g} s window'
                      + ("" if tight else " — close to the window; drift would turn matches into exclusives") + f'). '
                      f'{ck["wild"]} pair{"s" if ck["wild"] != 1 else ""} ({100*ck["wild"]/npair:.1f}%) differ by more than 10 dB, usually a collision at one node.</p>')
    else:
        clock_note = ""

    only_a_snr = [p["snr"] for p in A["only"]]; only_b_snr = [p["snr"] for p in B["only"]]
    meta = [hopname(p) for p, _ in pairs]

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RX compare: {esc(na)} vs {esc(nb)}</title>{f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ''}<style>{CSS}</style></head><body><main>
<h1 class="who"><span class="node a"><span class="chip">A</span>{esc(na)}</span><span class="vs">vs</span><span class="node b"><span class="chip">B</span>{esc(nb)}</span></h1>
<p class="meta">Receive comparison for {time.strftime('%H:%M', time.localtime(R['start']))}–{time.strftime('%H:%M', time.localtime(R['end']))} on {time.strftime('%Y-%m-%d', time.localtime(R['start']))} ({span_h:.1f} h), generated {time.strftime('%H:%M:%S')}.
A transmission counts as matched when both nodes log the same packet hash and path within {MATCH_WINDOW_S:g} s.
Neither node transmits, so the share of the traffic each one decoded is a clean receive comparison; SNR on shared packets explains it. Deltas are B&nbsp;−&nbsp;A, so positive means {esc(nb)} did better.</p>
<nav class="topbar"><div class="jump"><a href="#overview">Overview</a><a href="#missed">Missed</a><a href="#sensitivity">Sensitivity</a><a href="#matched">Matched</a><a href="#neighbours">Neighbours</a><a href="#explore">Explore</a><a href="#time">Over time</a><a href="#data">Data</a></div>{nav}</nav>

<section id="overview" class="first">
<div class="top">{"".join(tiles)}</div>
{reading_card}
<h2 style="margin-top:22px">Per node</h2>
{node_table}
</section>

<section id="missed">
<h2>Packets only one node decoded</h2>
<p class="meta">{len(A['only']):,} transmissions only {esc(na)} decoded, {len(B['only']):,} only {esc(nb)}.</p>
<div class="grid2">
<div class="card"><h3>How weak were they</h3><p>SNR of packets the other node missed. Misses on the left are the other node running out of sensitivity; misses on the right are collisions or timing.</p>{leg}{chart_hist2(only_a_snr, only_b_snr, -14, 12, 2, na, nb)}</div>
<div class="card"><h3>Which neighbours were missed</h3><p>Per upstream hop: packets only {esc(na)} decoded (left) and only {esc(nb)} decoded (right). n is how many both decoded. ◐ marks a one-sided neighbour, heard from one position only. Click a row to explore it.</p>{leg}{chart_excl_neighbours(R['neighbours'], na, nb, os_hops)}{excl_note}</div>
</div>
</section>

<section id="sensitivity">
<h2>Sensitivity or collisions?</h2>
<p class="meta">Where each node stops decoding, whether the SNR offset between them is the same at every level, and whether misses depend on how long a packet is on the air. These are questions about the radios, so this section uses only the neighbours both positions hear{f" ({', '.join(esc(h) for h in R['one_sided'])} left out)" if one_sided else ""}.</p>
<div class="grid2">
<div class="card"><h3>Chance the other node decoded it too</h3><p>For every transmission one node decoded at a given SNR, the share the other node also decoded. The higher curve is the more sensitive receiver. Whiskers are 95% CI; the faint bars are how many packets each point rests on. Readings are on a common scale (the {signed(md, ".2f")} dB offset between the radios split between them).</p>{leg}{chart_decode_curve(R['curves'], na, nb)}</div>
<div class="card"><h3>Δ SNR by signal level, B − A</h3><p>Flat means a fixed reporting offset between the radios. A slope or a bend near the floor means they genuinely differ where it matters. Whiskers are 95% CI.</p>{chart_delta_by_level(R['dsnr_by_level'], na, nb)}</div>
<div class="card"><h3>Decode rate by packet type</h3><p>Long packets sit on the air longer and collide more. A gap that opens only on long types is timing, not sensitivity.</p>{leg}{chart_type_rates(R['by_type'], na, nb)}</div>
</div>
</section>

<section id="matched">
<h2>The same transmission, heard by both</h2>
<p class="meta">{npair:,} transmissions decoded by both nodes. This is the like-for-like comparison.</p>
{clock_note}
<div class="grid2">
<div class="card"><h3>SNR: {esc(na)} vs {esc(nb)}</h3><p>Each dot is one transmission. Above the diagonal means {esc(nb)} decoded it cleaner. Dot size grows with overplotting.</p>{chart_scatter(A['snr'], B['snr'], na, nb, 'dB', meta)}</div>
<div class="card"><h3>Δ SNR per packet, B − A</h3><p>Left of zero: {esc(na)} decoded the packet cleaner; right of zero: {esc(nb)} did. Bars are coloured by the winning node.</p>{chart_hist(dsnr, -8, 8, 1, '', h=360, marker=(md, f'mean {signed(md, ".2f")}'), sides=(na, nb))}</div>
</div>
</section>

<section id="neighbours">
<h2>By upstream neighbour</h2>
<p class="meta">Last hop before this node. Path hashes of different lengths that refer to the same node (<code>DB</code>, <code>DB95</code>, <code>DB9570</code>) are merged under the longest form. ◐ marks a one-sided neighbour: heard from one position only, so it says where the boards sit, not which radio is better.</p>
<div class="grid2">
<div class="card"><h3>Δ SNR per neighbour, B − A</h3><p>Averaged over matched packets, last hop with at least 3 matches. Bar colour is the node that hears that neighbour better. Click a row to explore it.</p>{chart_neighbours(R['neighbours'], na, nb, os_hops)}</div>
<div class="card"><h3>Mean SNR per neighbour, on each node</h3><p>Strongest neighbours at the top. Neighbours near the decode threshold (below about −5 dB) are where a sensitivity difference shows; strong ones tell you little.</p>{leg}{chart_dumbbell(R['neighbours'], na, nb, os_hops)}</div>
</div>
</section>

<section id="explore">
<h2>Explore a neighbour</h2>
<p class="meta">Everything in this panel is one neighbour's packets in the current window. Pick one here, or click a row in any neighbour chart or table.</p>
<div class="panel">
<div class="ctl"><label for="ex-hop">Neighbour</label><select id="ex-hop" class="select">{hop_opts}</select></div>
<div id="ex-out"></div>
</div>
</section>

<section id="time">
<h2>Over time</h2>
<p class="meta">Both nodes, all neighbours, in {R['bucket']//60}-minute buckets.</p>
<div class="grid2">
<div class="card"><h3>Packets decoded per {R['bucket']//60} min</h3><p>Matched and exclusive packets together. {partial}</p>{leg}{cnt_chart}</div>
<div class="card"><h3>Decode rate per {R['bucket']//60} min</h3><p>Each node's share of the transmissions at least one of them decoded in that bucket. Shows whether the gap is steady or comes with traffic bursts or noise.</p>{leg}{rate_chart}</div>
<div class="card"><h3>Mean Δ SNR per {R['bucket']//60} min, B − A</h3><p>Should be flat. A drift points at a temperature, hardware or interference change on one side.</p>{dsnr_chart}</div>
<div class="card"><h3>Noise floor, dBm</h3><p>Each node's own measurement. The offset between them is partly RSSI calibration.</p>{leg}{noise_chart}</div>
<div class="card"><h3>Packets decoded below {signed(DEEP_DB)} dB per {R['bucket']//60} min</h3><p>The floor stat over time, on the common SNR scale. If one node's line sinks while the other's holds, its front end got noisier. {partial}</p>{leg}{deep_chart}</div>
<div class="card"><h3>CRC errors per {R['bucket']//60} min</h3><p>Preambles detected but not decoded: packets at the edge, or false detections in noise. Read with the chart on the left — more CRC errors <em>and</em> fewer deep decodes points at a noisier front end. {partial}</p>{leg}{crc_chart}</div>
</div>
</section>

<section id="data">
<h2>Data</h2>
<p class="meta">The numbers behind the charts, and the RSSI check.</p>
<details><summary>RSSI calibration check: why the report compares SNR, not RSSI</summary>
<div class="grid2" style="margin-top:10px">
<div class="card"><h3>RSSI: {esc(na)} vs {esc(nb)}</h3><p>A bend away from the diagonal means the two radios report RSSI on different calibration curves.</p>{chart_scatter(A['rssi'], B['rssi'], na, nb, 'dBm', meta)}</div>
<div class="card"><h3>Δ RSSI per packet, B − A</h3><p>A bimodal shape here is a calibration artefact, not antenna gain. Mean {mean(drssi):+.2f} dB.</p>{chart_hist(drssi, -10, 10, 1, '', h=360)}</div>
</div></details>
<details open><summary>Per-neighbour table ({len(R['neighbours'])} rows)</summary>
<div class="card wrap"><table><thead><tr><th>last hop</th><th>both</th><th>only {esc(na)}</th><th>only {esc(nb)}</th><th>heard by {esc(na)}</th><th>heard by {esc(nb)}</th>
<th>RSSI {esc(na)}</th><th>RSSI {esc(nb)}</th><th>Δ RSSI</th><th>SNR {esc(na)}</th><th>SNR {esc(nb)}</th><th>Δ SNR (B−A)</th></tr></thead>
<tbody>{"".join(nrows)}</tbody></table></div></details>
<details><summary>Per-bucket table ({len(bk)} rows)</summary><div class="card wrap"><table><thead><tr><th>bucket</th><th>{esc(na)}</th><th>{esc(nb)}</th><th>both</th><th>rate {esc(na)}</th><th>rate {esc(nb)}</th><th>Δ RSSI</th><th>Δ SNR</th></tr></thead><tbody>{brows}</tbody></table></div></details>
<details><summary>All matched packets ({npair} rows)</summary><div class="card wrap"><table><thead><tr><th>time</th><th>hop</th><th>type</th><th>len</th>
<th>RSSI {esc(na)}</th><th>RSSI {esc(nb)}</th><th>Δ</th><th>SNR {esc(na)}</th><th>SNR {esc(nb)}</th><th>Δ</th></tr></thead><tbody>{prow}</tbody></table></div></details>
</section>
</main><div id="tip"></div><script>window.EXPLORE={explore};</script><script>{JS}</script></body></html>"""
    return doc


def write_html(R, path):
    with open(path, "w") as f:
        f.write(render_html(R))
    print(f"wrote {path}")


def floor_stats(n, shift=0.0):
    """Sensitivity floor of one node over every packet it decoded (matched and exclusive):
    weakest SNR, 5th percentile, and how many were below DEEP_DB. `shift` puts the node's
    readings on the common scale (half the reading offset between the two radios)."""
    vs = sorted(v + shift for v in n["snr"] + [p["snr"] for p in n["only"]])
    if not vs:
        return {"snr_min": NAN, "snr_p5": NAN, "deep": 0, "deep_pct": NAN}
    return {"snr_min": vs[0], "snr_p5": vs[len(vs) // 20], "deep": sum(1 for v in vs if v < DEEP_DB),
            "deep_pct": 100 * sum(1 for v in vs if v < DEEP_DB) / len(vs)}


def summary(R):
    """Compact JSON-able summary of a result (for the web app / scripting)."""
    A, B = R["A"], R["B"]
    def side(n):
        u = len(R["pairs"]) + len(A["only"]) + len(B["only"])
        sh_ = R["snr_shift"]["a" if n is A else "b"]
        return {"name": n["name"], "packets": n["n"], "only": len(n["only"]), "decode_rate": n["n"] / u if u else NAN,
                "only_snr_avg": mean([p["snr"] for p in n["only"]]),
                "snr_avg": mean(n["snr"]), "rssi_avg": mean(n["rssi"]),
                "noise_avg": mean([v for _, v in n["noise"]]), "crc_errors": n["crc"],
                **floor_stats(n, sh_)}
    union = len(R["pairs"]) + len(A["only"]) + len(B["only"])
    d = {"generated": R["generated"], "start": R["start"], "end": R["end"], "matched": len(R["pairs"]), "union": union,
         "one_sided_neighbours": R["one_sided"], "shared_neighbours": R["shared"],
         "clock": R["clock"], "decode_curves": R["curves"], "dsnr_by_level": R["dsnr_by_level"], "by_type": R["by_type"],
         "A": side(A), "B": side(B),
         "delta_b_minus_a": {"snr_mean": mean(R["dsnr"]), "snr_median": med(R["dsnr"]),
                             "rssi_mean": mean(R["drssi"]), "rssi_median": med(R["drssi"]),
                             "b_better_snr": sum(1 for d in R["dsnr"] if d > 0),
                             "a_better_snr": sum(1 for d in R["dsnr"] if d < 0)},
         "neighbours": R["neighbours"]}
    return json.loads(json.dumps(d, default=lambda x: None), parse_constant=lambda _: None)


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=float, default=1.0)
    ap.add_argument("--watch", type=int, metavar="SEC", help="repeat every SEC seconds")
    ap.add_argument("--csv", metavar="FILE", help="write matched pairs")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report")
    ap.add_argument("--quiet", action="store_true", help="skip the text report")
    for s in "ab":
        ap.add_argument(f"--{s}-url", default=os.environ.get(f"{s.upper()}_URL"))
        ap.add_argument(f"--{s}-key", default=os.environ.get(f"{s.upper()}_KEY"))
        ap.add_argument(f"--{s}-name", default=os.environ.get(f"{s.upper()}_NAME", s.upper()))
    args = ap.parse_args()
    if not all((args.a_url, args.a_key, args.b_url, args.b_key)):
        sys.exit("need A_URL/A_KEY/B_URL/B_KEY (env or flags)")
    A = Node(args.a_name, args.a_url, args.a_key)
    B = Node(args.b_name, args.b_url, args.b_key)
    while True:
        try:
            R = analyze(A, B, args.hours)
            if not args.quiet:
                print_report(R)
            if args.csv:
                write_csv(R, args.csv)
            if args.html:
                write_html(R, args.html)
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            if not args.watch:
                raise
        if not args.watch:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
