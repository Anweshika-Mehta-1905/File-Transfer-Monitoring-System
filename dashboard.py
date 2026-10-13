#!/usr/bin/env python3
"""
dashboard.py - Live web dashboard for the DLP monitor (read-only, stdlib only).

Run it NEXT TO dlp_monitor.py, from the same folder, so it reads the same
audit_events.jsonl. It never writes to disk and never touches monitored files.

    python dashboard.py -c config.json                    # http://127.0.0.1:8080
    python dashboard.py -c config.json --token S3CRET     # require ?token=S3CRET

Security: binds to 127.0.0.1 by default. Audit data contains file paths and
hashes, so do NOT expose it publicly without HTTPS + authentication.
"""
import argparse
import hmac
import json
import os
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DLP Monitor Dashboard</title>
<style>
  :root { --bg:#0f1419; --card:#1a212b; --text:#e6e9ee; --muted:#8b95a5; --line:#2a3340; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:14px/1.45 system-ui,sans-serif; }
  header { padding:16px 20px; border-bottom:1px solid var(--line); display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
  h1 { font-size:18px; margin:0; flex:1; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; padding:16px 20px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px; }
  .card b { display:block; font-size:26px; }
  .CRITICAL { color:#ff5c5c; } .HIGH { color:#ff9f43; } .WARNING { color:#f5d547; } .INFO { color:#5cc8ff; }
  select, button { background:var(--card); color:var(--text); border:1px solid var(--line); border-radius:6px; padding:6px 10px; }
  .wrap { padding:0 20px 24px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; min-width:900px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:600; position:sticky; top:0; background:var(--bg); }
  td.path { font-family:ui-monospace,monospace; font-size:12px; word-break:break-all; }
  tr.alert { background:rgba(255,92,92,.07); }
  .sev { font-weight:700; } .muted { color:var(--muted); font-size:12px; }
</style></head><body>
<header>
  <h1>DLP Monitor - Live Audit Feed</h1>
  <label class="muted">Severity
    <select id="filter"><option value="">All</option><option>CRITICAL</option><option>HIGH</option>
    <option>WARNING</option><option>INFO</option></select></label>
  <span class="muted" id="status">connecting...</span>
</header>
<div class="cards" id="cards"></div>
<div class="wrap"><table><thead><tr>
  <th>Time (UTC)</th><th>Severity</th><th>Event</th><th>Source</th><th>Destination</th><th>Details</th>
</tr></thead><tbody id="rows"></tbody></table></div>
<script>
const token = new URLSearchParams(location.search).get('token') || '';
const $ = id => document.getElementById(id);

function cell(tr, text, cls) {                 // textContent only: filenames are untrusted input
  const td = document.createElement('td');
  td.textContent = text || '';
  if (cls) td.className = cls;
  tr.appendChild(td);
  return td;
}

function render(data) {
  const cards = $('cards'); cards.textContent = '';
  for (const s of ['CRITICAL','HIGH','WARNING','INFO']) {
    const d = document.createElement('div'); d.className = 'card';
    const b = document.createElement('b'); b.className = s; b.textContent = data.counts[s] || 0;
    d.appendChild(b); d.appendChild(document.createTextNode(s));
    cards.appendChild(d);
  }
  const want = $('filter').value;
  const rows = $('rows'); rows.textContent = '';
  for (const e of data.events) {
    if (want && e.severity !== want) continue;
    const tr = document.createElement('tr');
    if (e.severity === 'CRITICAL' || e.severity === 'HIGH') tr.className = 'alert';
    cell(tr, (e.timestamp || '').replace('T',' ').slice(0,19), 'muted');
    cell(tr, e.severity, 'sev ' + e.severity);
    cell(tr, e.event_type);
    cell(tr, e.src, 'path');
    cell(tr, e.dst, 'path');
    const skip = ['timestamp','severity','event_type','src','dst'];
    const det = Object.entries(e).filter(([k,v]) => !skip.includes(k) && v)
      .map(([k,v]) => k + ': ' + (k.startsWith('sha256') ? String(v).slice(0,16)+'...' : v)).join('\\n');
    const td = cell(tr, det, 'muted'); td.style.whiteSpace = 'pre-wrap';
    rows.appendChild(tr);
  }
  $('status').textContent = 'updated ' + new Date().toLocaleTimeString() + ' - ' + data.total + ' events';
}

async function refresh() {
  try {
    const r = await fetch('/api/events?limit=300&token=' + encodeURIComponent(token));
    if (r.status === 401) { $('status').textContent = 'unauthorized: add ?token=... to the URL'; return; }
    render(await r.json());
  } catch (e) { $('status').textContent = 'dashboard server unreachable'; }
}
$('filter').addEventListener('change', refresh);
refresh(); setInterval(refresh, 2000);
</script></body></html>
"""


def read_events(path, limit):
    """Return (counts, newest-first events, total) from the JSONL audit stream."""
    events = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # partial line mid-write
    counts = Counter(e.get("severity") for e in events)
    return dict(counts), events[-limit:][::-1], len(events)


class Handler(BaseHTTPRequestHandler):
    jsonl_path = "audit_events.jsonl"
    token = None

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        if self.token:
            supplied = qs.get("token", [""])[0] or self.headers.get("X-Token", "")
            if not hmac.compare_digest(supplied, self.token):
                return self._send(401, "unauthorized", "text/plain")
        if url.path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif url.path == "/api/events":
            try:
                limit = max(1, min(int(qs.get("limit", ["200"])[0]), 2000))
            except ValueError:
                limit = 200
            counts, events, total = read_events(self.jsonl_path, limit)
            self._send(200, json.dumps({"counts": counts, "events": events, "total": total}),
                       "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def log_message(self, *args):  # keep the console quiet
        pass


def main():
    ap = argparse.ArgumentParser(description="Web dashboard for the DLP monitor")
    ap.add_argument("-c", "--config", default="config.json")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--token", default=os.environ.get("DLP_DASH_TOKEN"),
                    help="require this token (or set DLP_DASH_TOKEN)")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        Handler.jsonl_path = json.load(fh).get("event_log_jsonl", "audit_events.jsonl")
    Handler.token = args.token

    if args.host not in ("127.0.0.1", "localhost") and not args.token:
        ap.error("refusing to listen on a non-local address without --token")

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    suffix = f"/?token={args.token}" if args.token else ""
    print(f"Dashboard: http://{args.host}:{args.port}{suffix}   (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
