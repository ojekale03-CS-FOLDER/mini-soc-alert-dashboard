# Mini SOC Alert Dashboard

A small, dependency-free Python SIEM for SSH authentication logs. It detects brute-force and password-spray activity, tags alerts with MITRE ATT&CK techniques, and shows them on a live web dashboard. Built as a hands-on blue-team learning project.

## Features

- Rule-based detections over a sliding 10-minute window
- Correlation: a password-spray alert suppresses the duplicate per-IP alert
- MITRE ATT&CK mapping and severity levels
- Real-time mode: tails a log file and updates the dashboard every 2 seconds
- Static mode: generates an HTML report and a JSON incident file from synthetic data
- Handles `sshd` and `sshd-session` log lines, and log rotation
- No third-party dependencies (Python 3.8+)

## Detection rules

| Rule | Trigger | Severity | ATT&CK |
|---|---|---|---|
| REPEATED_FAILURES_BY_IP | 4+ failed logins from one IP | HIGH | T1110 |
| REPEATED_FAILURES_BY_USER | 4+ failed logins on one account | MEDIUM | T1110 |
| POSSIBLE_PASSWORD_SPRAY | 3+ distinct usernames from one IP | HIGH | T1110.003 |
| SUCCESS_AFTER_FAILURES | Successful login after 3+ failures from the same IP | HIGH | T1110 / T1078 |

Thresholds are constants at the top of `mini_siem.py`.

## Quick start

Demo with built-in synthetic data:

    python3 mini_siem.py --out demo

Then open `demo/dashboard.html` in a browser.

Live mode against a real SSH log:

    sudo python3 live.py --log /var/log/auth.log

Then open http://127.0.0.1:8080/. New alerts are also appended to `alerts.log`. On systems without `/var/log/auth.log`, install rsyslog or export the journal to a file.

## Security notes

- Usernames in logs are attacker-controlled. The dashboard renders all log data as plain text and sets a strict Content-Security-Policy.
- The dashboard has no authentication and binds to localhost by default. Do not expose it to untrusted networks.
- ATT&CK mappings are indicative. Alerts need analyst investigation.

## Disclaimer

Educational project. Only monitor systems you own or are authorized to monitor.
