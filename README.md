# openhop-rxcompare

[![docker](https://github.com/metrafonic/openhop-rxcompare/actions/workflows/docker.yml/badge.svg)](https://github.com/metrafonic/openhop-rxcompare/actions/workflows/docker.yml)

Compare the receive performance of two openHop LoRa repeaters
listening on the same channel — e.g. two different boards or antennas installed side by
side, both in no-TX mode.

It pulls packet history from each node's openHop API, joins the packets that both nodes
heard (same `packet_hash` + `path_hash` within 3 s), and reports:

- **decode rate** (the headline — neither node transmits, so this is a clean receive comparison):
  of every transmission at least one node heard, the share each node decoded,
  with a paired confidence interval and the same rate without *one-sided neighbours* (hops one
  node hears and the other barely does — position, not receiver)
- a **Reading** card that turns the headline numbers into a few sentences: who decodes more,
  whether the SNR offset is flat across levels (reporting) or not (real), who reaches deeper,
  and which neighbours are one-sided
- **SNR on shared packets** (with a confidence interval), per upstream neighbour and over time —
  the diagnostic behind the decode rate, not the outcome (RSSI is calibrated differently per
  radio and is shown but flagged as such)
- packets **only one node** decoded: how weak they were (sensitivity vs. collisions) and
  which neighbours each node misses
- **sensitivity or collisions**: the chance the other node also decoded a packet, by SNR
  (each node's real floor), the SNR offset by signal level (calibration vs. genuine), and
  decode rate by packet type (long packets collide more)
- **decode rate over time** and a match-quality check (clock offset between the nodes,
  pairs that disagree wildly)
- **per neighbour**: SNR on each node side by side, so threshold-level neighbours stand out
- **where the neighbours are**: every neighbour whose advert carried a position, placed around the
  two radios — a bearing-and-distance radar (inline SVG, log distance), a terrain map (Leaflet,
  loaded on request), SNR against distance with a fit per node, and a reading that says whether the
  difference has a *direction* (the masts) or not (the receivers). Radios more than 1 km apart get
  their own lines and the reading switches to "the split is geography"
- noise floor and CRC errors per node, over the same window
- an interactive **neighbour explorer**: pick a hop and see every one of its packets over the
  window on both nodes, plus its decode counts per bucket
- a self-contained HTML report with hover tooltips, light/dark, phone layout and table views

Upstream hop hashes of different lengths (`DB`, `DB95`, `DB9570` are the same node in openHop
paths) are merged so each neighbour appears once.

![report](docs/report.png)

## Run with Docker

A multi-arch image (amd64, arm64) is published to
`ghcr.io/metrafonic/openhop-rxcompare` on every push to `main`.

```sh
cp .env.example .env      # fill in the two node URLs and API keys
docker compose up -d
open http://localhost:8090
```

To build the image yourself instead of pulling it:

```sh
docker build -t ghcr.io/metrafonic/openhop-rxcompare:latest .
docker compose up -d
```

Routes:

| path | what |
|---|---|
| `/` | report for the default window (`HOURS`); `/?hours=24` for another range |
| `/summary.json` | the same numbers as JSON (`?hours=` works here too) |
| `/healthz` | 200 once the first analysis succeeded |

The default window is refreshed every `REFRESH_SEC` in the background; other ranges are
computed on demand and cached for the same period.

## Run without Docker

Needs only Python 3.10+, no third-party packages.

```sh
set -a; . ./.env; set +a
python3 server.py                                 # web app on $PORT (default 8080)
python3 rxcompare.py --hours 6                    # text report
python3 rxcompare.py --hours 6 --html report.html --csv pairs.csv
python3 rxcompare.py --watch 300 --html report.html   # regenerate every 5 min
```

## Configuration

All settings are environment variables — see [`.env.example`](.env.example).

| var | meaning |
|---|---|
| `A_URL`, `A_KEY`, `A_NAME` | node A base URL, API key (`X-API-Key`), display name |
| `B_URL`, `B_KEY`, `B_NAME` | node B |
| `HOURS` | default comparison window (default 3) |
| `REFRESH_SEC` | background refresh / cache lifetime (default 300) |
| `RANGES` | ranges offered in the nav, hours (default `1,3,6,12,24,48`) |
| `LISTEN_PORT` | host port for compose (default 8090) |
| `VERIFY_TLS` | set `false` for self-signed certs |
| `TZ` | timezone for time axes |
| `A_LAT`, `A_LON`, `B_LAT`, `B_LON` | override a radio's position (default: openHop's `/api/gps`, manual config or fix) |
| `ADVERT_LOOKBACK_H` | how far back to read adverts for neighbour positions (default 336 — nodes advertise once a day or less) |
| `ADVERT_CACHE` | JSON file where adverts accumulate across runs, so a position once seen sticks (the Docker image sets `/data/adverts.json` on a volume) |
| `MAP_TILES`, `MAP_ATTRIB` | Leaflet tile template and attribution (default OpenTopoMap) |
| `MAP_AUTO` | `1` loads the map without the click; otherwise the click is remembered per browser |
| `MAP_GRAY` | tiles are desaturated so only the data carries colour; `0` keeps the tiles' own colours |

API keys are created in the openHop web UI under *Sessions → API tokens*.

## How the comparison works

Both nodes log every packet they decode with RSSI and SNR. A transmission is identified by
`(packet_hash, path_hash)` — the same payload relayed by two different neighbours is two
different transmissions — and matched across nodes when the timestamps are within 3 s.
The comparison window is clamped to the period where both nodes have data, so a restart on
one side doesn't count as missed packets.

Neighbour positions come from the neighbours' own adverts: a MeshCore advert carries the node's
public key, name and (when set) lat/lon, and a hop hash in a path is the first 1–3 bytes of that
key. A hop is placed when the positioned adverts whose key starts with it agree; a 1-byte hash that
several keys start with is left off as ambiguous. Adverts are read from both nodes' packet history
over the last `ADVERT_LOOKBACK_H` and merged into `ADVERT_CACHE`.

Compare **SNR**, not RSSI: different LoRa front ends report RSSI on different calibration
curves (the RSSI scatter in the report typically shows a bend rather than a straight
offset), while SNR is measured against each radio's own demodulator and reflects what
actually got decoded.

## License

MIT
