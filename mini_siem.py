#!/usr/bin/env python3
"""Mini SIEM: rule-based auth log analyzer with ATT&CK tagging, HTML dashboard, JSON report.

Usage:
  python mini_siem.py                          # synthetic demo data
  python mini_siem.py --log /var/log/auth.log  # real sshd logs (syslog format)
"""
import argparse, html, json, re
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path

WINDOW = timedelta(minutes=10)
FAIL_THRESHOLD = 4      # failures in WINDOW to alert
SPRAY_USERS = 3         # distinct usernames from one IP in WINDOW
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass(frozen=True)
class Event:
    ts: datetime
    user: str
    ip: str
    outcome: str  # "fail" | "success"


@dataclass
class Alert:
    severity: str
    rule: str
    entity: str
    events: int
    first_seen: str
    mitre: str
    detail: str


def first_window(evs, ok):
    """Return the first sliding WINDOW of events (sorted) satisfying ok(window), else None."""
    evs = sorted(evs, key=lambda e: e.ts)
    for i, start in enumerate(evs):
        w = [e for e in evs[i:] if e.ts - start.ts <= WINDOW]
        if ok(w):
            return w
    return None


def detect(events):
    alerts, spray_ips = [], set()
    fails = [e for e in events if e.outcome == "fail"]
    by_ip, by_user = defaultdict(list), defaultdict(list)
    for e in fails:
        by_ip[e.ip].append(e)
        by_user[e.user].append(e)

    def add(sev, rule, entity, w, mitre, detail):
        alerts.append(Alert(sev, rule, entity, len(w), min(e.ts for e in w).isoformat(), mitre, detail))

    # Password spray: one IP, many distinct users
    for ip, evs in by_ip.items():
        w = first_window(evs, lambda w: len(w) >= SPRAY_USERS and len({e.user for e in w}) >= SPRAY_USERS)
        if w:
            spray_ips.add(ip)
            add("HIGH", "POSSIBLE_PASSWORD_SPRAY", ip, w, "T1110.003",
                f"{len({e.user for e in w})} distinct users targeted")

    # Repeated failures by IP (suppressed if the IP is already a spray alert -> correlation)
    for ip, evs in by_ip.items():
        if ip in spray_ips:
            continue
        w = first_window(evs, lambda w: len(w) >= FAIL_THRESHOLD)
        if w:
            add("HIGH", "REPEATED_FAILURES_BY_IP", ip, w, "T1110", f"{len(w)} failures in {WINDOW}")

    # Repeated failures by user
    for user, evs in by_user.items():
        w = first_window(evs, lambda w: len(w) >= FAIL_THRESHOLD)
        if w:
            add("MEDIUM", "REPEATED_FAILURES_BY_USER", user, w, "T1110", f"{len(w)} failures in {WINDOW}")

    # Success after failures from the same IP
    seen = set()
    for s in sorted((e for e in events if e.outcome == "success"), key=lambda e: e.ts):
        prior = [f for f in by_ip.get(s.ip, []) if timedelta(0) <= s.ts - f.ts <= WINDOW]
        if len(prior) >= FAIL_THRESHOLD - 1 and s.ip not in seen:
            seen.add(s.ip)
            add("HIGH", "SUCCESS_AFTER_FAILURES", s.ip, prior + [s], "T1110 / T1078",
                f"login as '{s.user}' after {len(prior)} failures")

    return sorted(alerts, key=lambda a: (SEV_ORDER[a.severity], a.first_seen))


def synthetic_events():
    t = lambda m, s=0: datetime(2026, 11, 1, 9, m, s)
    ev = []
    # Brute force then success: 198.51.100.77 -> Tunde
    ev += [Event(t(1 + i), "Tunde", "198.51.100.77", "fail") for i in range(4)]
    ev.append(Event(t(6), "Tunde", "198.51.100.77", "success"))
    # Spray: 203.0.113.99 across many users
    ev += [Event(t(20 + i), u, "203.0.113.99", "fail") for i, u in enumerate(["alice", "Tunde", "carol", "dave"])]
    # Benign noise
    ev += [Event(t(30), "alice", "192.0.2.50", "success"),
           Event(t(35), "carol", "192.0.2.51", "success"),
           Event(t(40), "dave", "192.0.2.52", "fail"),
           Event(t(41), "dave", "192.0.2.52", "success"),
           Event(t(45), "alice", "192.0.2.50", "success"),
           Event(t(46), "carol", "192.0.2.51", "fail"),
           Event(t(47), "carol", "192.0.2.51", "success"),
           Event(t(50), "dave", "192.0.2.52", "success"),
           Event(t(55), "Tunde", "192.0.2.53", "success")]
    return ev


_TAIL = r"sshd(?:-session)?\[\d+\]: (Failed|Accepted) \w+ for (?:invalid user )?(\S+) from (\S+)"
LINE = re.compile(r"^(\w{3})\s+(\d+) (\d\d:\d\d:\d\d) \S+ " + _TAIL)   # traditional syslog
LINE_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\S+) \S+ " + _TAIL)           # ISO timestamps (rsyslog/journal)


def parse_line(line, year=None, now=None):
    """Parse one sshd log line into an Event, or None. Handles sshd and sshd-session (OpenSSH 9.8+)."""
    m = LINE.match(line)
    if m:
        mon, day, hms, res, user, ip = m.groups()
        now = now or datetime.now()
        try:
            ts = datetime.strptime(f"{year or now.year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        if not year and ts > now + timedelta(days=1):  # Dec log read in Jan
            ts = ts.replace(year=ts.year - 1)
        return Event(ts, user, ip, "fail" if res == "Failed" else "success")
    m = LINE_ISO.match(line)
    if m:
        iso, res, user, ip = m.groups()
        try:
            ts = datetime.fromisoformat(iso).replace(tzinfo=None)
        except ValueError:
            return None
        return Event(ts, user, ip, "fail" if res == "Failed" else "success")
    return None


def parse_auth_log(path, year=None):
    lines = Path(path).read_text(errors="replace").splitlines()
    return [e for e in (parse_line(l, year) for l in lines) if e]


def stats(events, alerts):
    failed = sum(e.outcome == "fail" for e in events)
    success = sum(e.outcome == "success" for e in events)
    return {"total": len(events), "failed": failed, "successful": success, "alerts": len(alerts)}


CSS = """
:root{--bg:#eef2f7;--panel:#fff;--text:#1f2937;--muted:#6b7280;--border:#e5e7eb;--accent:#4f46e5;--high:#dc2626;--medium:#d97706;--low:#2563eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}
header{background:linear-gradient(90deg,#312e81,var(--accent));color:#fff;padding:20px 28px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
header h1{margin:0;font-size:22px;letter-spacing:.3px}
header small{color:#c7d2fe}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--border);border-top:4px solid var(--accent);border-radius:10px;padding:14px 16px}
.card.f{border-top-color:var(--high)}.card.s{border-top-color:#16a34a}.card.a{border-top-color:var(--medium)}
.card span{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.card b{font-size:28px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-top:20px;padding:16px}
.panel h2{margin:0 0 8px;font-size:16px}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--border);white-space:nowrap}
th{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}
.badge.high{background:var(--high)}.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}
#live.on{color:#86efac}#live.off{color:#fca5a5}
footer{color:var(--muted);font-size:12px;margin-top:16px}
"""


def render_html(s, alerts):
    items = [("", "Total Events", s["total"]), ("f", "Failed Logins", s["failed"]),
             ("s", "Successful Logins", s["successful"]), ("a", "Alerts Generated", s["alerts"])]
    cards = "".join(f'<div class="card {c}"><span>{k}</span><b>{v}</b></div>' for c, k, v in items)
    rows = "".join(
        f'<tr><td><span class="badge {a.severity.lower()}">{a.severity}</span></td><td>{a.rule}</td>'
        f'<td>{html.escape(a.entity)}</td><td>{a.events}</td><td>{a.first_seen}</td><td>{a.mitre}</td>'
        f'<td>{html.escape(a.detail)}</td></tr>' for a in alerts
    ) or '<tr><td colspan="7">No alerts</td></tr>'
    return f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mini SOC Alert Dashboard</title><style>{CSS}</style>
<header><h1>Mini SOC Alert Dashboard</h1><small>Offline report</small></header>
<main><div class="cards">{cards}</div>
<div class="panel"><h2>Detection alerts</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Entity</th><th>Events</th><th>First seen</th><th>MITRE</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div></div>
<footer>ATT&amp;CK mappings are indicative. Alerts need analyst investigation, not proof of malice.</footer></main>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="sshd auth.log to analyze (default: synthetic data)")
    ap.add_argument("--year", type=int, help="year for syslog timestamps")
    ap.add_argument("--out", default=".", help="output directory")
    a = ap.parse_args()
    events = parse_auth_log(a.log, a.year) if a.log else synthetic_events()
    alerts = detect(events)
    s = stats(events, alerts)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "dashboard.html").write_text(render_html(s, alerts))
    (out / "incidents.json").write_text(json.dumps({"stats": s, "alerts": [asdict(x) for x in alerts]}, indent=2))
    print(f"{s['total']} events, {s['alerts']} alerts -> {out}/dashboard.html, incidents.json")


if __name__ == "__main__":
    main()
