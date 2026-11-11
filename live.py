#!/usr/bin/env python3
"""Real-time Mini SIEM: tails an sshd auth log, re-evaluates rules as lines arrive,
logs new alerts once, and serves a live dashboard (auto-refresh every 2s).

  python live.py --log /var/log/auth.log                 # localhost:8080
  python live.py --log /var/log/auth.log --bind 0.0.0.0  # LAN access
"""
import argparse, json, os, threading, time
from collections import deque
from dataclasses import asdict
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mini_siem import CSS, detect, parse_line, stats

PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mini SOC Alert Dashboard</title><style>/*CSS*/</style>
<header><h1>Mini SOC Alert Dashboard</h1><small id="live">● connecting…</small></header>
<main><div class="cards">
<div class="card"><span>Events (window)</span><b id="total">0</b></div>
<div class="card f"><span>Failed Logins</span><b id="failed">0</b></div>
<div class="card s"><span>Successful Logins</span><b id="successful">0</b></div>
<div class="card a"><span>Active Alerts</span><b id="alerts">0</b></div></div>
<div class="panel"><h2>Detection alerts</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Entity</th>
<th>Events</th><th>First seen</th><th>MITRE</th><th>Detail</th></tr></thead><tbody id="rows"></tbody></table></div></div>
<footer>ATT&amp;CK mappings are indicative. Alerts need analyst investigation.</footer></main>
<script>
const $=id=>document.getElementById(id);
async function tick(){
  try{
    const s=await (await fetch('/api/state',{cache:'no-store'})).json();
    for(const k of ['total','failed','successful','alerts']) $(k).textContent=s.stats[k];
    const tb=$('rows'); tb.replaceChildren();
    if(!s.alerts.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.textContent='No active alerts';tr.appendChild(td);tb.appendChild(tr);}
    for(const a of s.alerts){
      const tr=document.createElement('tr');
      for(const k of ['severity','rule','entity','events','first_seen','mitre','detail']){
        const td=document.createElement('td');
        if(k==='severity'){const b=document.createElement('span');b.className='badge '+a.severity.toLowerCase();b.textContent=a.severity;td.appendChild(b);}
        else td.textContent=a[k];  // textContent: log data is attacker-controlled
        tr.appendChild(td);}
      tb.appendChild(tr);}
    $('live').textContent='● live · updated '+(s.updated||'waiting for events'); $('live').className='on';
  }catch(e){$('live').textContent='● disconnected'; $('live').className='off';}
}
tick(); setInterval(tick,2000);
</script>"""
PAGE = PAGE.replace("/*CSS*/", CSS)


class State:
    def __init__(self, retention_min, alert_log):
        self.lock = threading.Lock()
        self.events, self.alerts, self.seen = deque(), [], set()
        self.retention = timedelta(minutes=retention_min)
        self.alert_log, self.updated, self.dirty = alert_log, None, False

    def add(self, ev):
        with self.lock:
            self.events.append(ev)
            self.dirty = True

    def refresh(self, quiet=False):
        with self.lock:
            if not self.dirty:
                return
            self.dirty = False
            if not self.events:
                return
            cutoff = max(e.ts for e in self.events) - self.retention
            self.events = deque(e for e in self.events if e.ts >= cutoff)
            self.alerts = detect(list(self.events))
            self.updated = datetime.now().isoformat(timespec="seconds")
            new = []
            for a in self.alerts:
                key = (a.rule, a.entity, a.first_seen)
                if key not in self.seen:
                    self.seen.add(key)
                    new.append(a)
        if quiet:  # history from backfill: show on dashboard, don't re-alert
            return
        for a in new:
            line = f"{datetime.now().isoformat(timespec='seconds')} ALERT {a.severity} {a.rule} {a.entity} {a.mitre} - {a.detail}"
            print(line, flush=True)
            if self.alert_log:
                with open(self.alert_log, "a") as f:
                    f.write(line + "\n")

    def snapshot(self):
        with self.lock:
            return {"stats": stats(list(self.events), self.alerts),
                    "alerts": [asdict(a) for a in self.alerts], "updated": self.updated}


def tail(path, state, year, stop):
    f = open(path, errors="replace")
    ino = os.fstat(f.fileno()).st_ino
    ingest = lambda line: (lambda e: e and state.add(e))(parse_line(line, year))
    while (line := f.readline()):          # backfill existing history
        ingest(line)
    state.refresh(quiet=True)
    last = time.time()
    while not stop.is_set():
        pos = f.tell()
        line = f.readline()
        if line and line.endswith("\n"):
            ingest(line)
            if time.time() - last > 1:
                state.refresh(); last = time.time()
            continue
        if line:                            # partial line still being written
            f.seek(pos)
        state.refresh(); last = time.time()
        time.sleep(0.5)
        try:                                # handle logrotate / truncation
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():
                f.close(); f = open(path, errors="replace"); ino = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            pass


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/state":
                body, ctype = json.dumps(state.snapshot()).encode(), "application/json"
            elif self.path in ("/", "/index.html"):
                body, ctype = PAGE.encode(), "text/html; charset=utf-8"
            else:
                self.send_error(404); return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True, help="sshd auth log to follow")
    ap.add_argument("--year", type=int, help="year for syslog timestamps (default: infer)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="127.0.0.1", help="use 0.0.0.0 for LAN access")
    ap.add_argument("--retention", type=int, default=60, help="minutes of events to keep")
    ap.add_argument("--alert-log", default="alerts.log", help="append new alerts here ('' to disable)")
    a = ap.parse_args()
    state, stop = State(a.retention, a.alert_log or None), threading.Event()
    threading.Thread(target=tail, args=(a.log, state, a.year, stop), daemon=True).start()
    print(f"Following {a.log} | dashboard http://{a.bind}:{a.port}/", flush=True)
    try:
        ThreadingHTTPServer((a.bind, a.port), make_handler(state)).serve_forever()
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
