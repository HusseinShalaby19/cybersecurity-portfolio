#!/usr/bin/env python3
"""
Detection rules over Windows Security events exported to CSV.

Expected columns: TimeCreated, EventID, TargetUserName, SubjectUserName,
IpAddress, LogonType, GroupName. (Export from Event Viewer / Get-WinEvent /
a SIEM search and rename fields as needed.)

Usage:
    python detect.py data/synthetic-security-log.csv --markdown reports/investigation-output.md
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

BRUTE_FORCE_THRESHOLD = 10          # failures for one account
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
SPRAY_DISTINCT_USERS = 10           # distinct accounts from one source
SPRAY_WINDOW = timedelta(minutes=15)
SUCCESS_AFTER_FAIL_MIN = 5
SUCCESS_AFTER_FAIL_WINDOW = timedelta(minutes=30)
PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "schema admins", "administrators",
                     "account operators", "backup operators", "server operators"}
GROUP_ADD_EVENTS = {4728, 4732, 4756}

LOGON_TYPES = {"2": "interactive", "3": "network", "10": "RDP"}


@dataclass
class Alert:
    time: datetime
    rule: str
    severity: str
    attack: str
    summary: str


def load(path: Path) -> list[dict]:
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["_t"] = datetime.fromisoformat(r["TimeCreated"])
        r["_id"] = int(r["EventID"])
    return sorted(rows, key=lambda r: r["_t"])


def sliding_groups(events, key, window, min_count, distinct=None):
    """Yield (key, first, last, events) for the first window per key that meets the threshold."""
    buckets = defaultdict(list)
    for e in events:
        buckets[key(e)].append(e)
    for k, evs in buckets.items():
        lo = 0
        for hi in range(len(evs)):
            while evs[hi]["_t"] - evs[lo]["_t"] > window:
                lo += 1
            win = evs[lo:hi + 1]
            n = len({distinct(e) for e in win}) if distinct else len(win)
            if n >= min_count:
                # extend to the end of the burst for reporting
                end = hi
                while end + 1 < len(evs) and evs[end + 1]["_t"] - evs[end]["_t"] <= window:
                    end += 1
                yield k, evs[lo:end + 1]
                break


def detect(rows: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    fails = [r for r in rows if r["_id"] == 4625]

    for user, burst in sliding_groups(fails, lambda e: e["TargetUserName"], BRUTE_FORCE_WINDOW, BRUTE_FORCE_THRESHOLD):
        srcs = sorted({e["IpAddress"] for e in burst})
        lt = LOGON_TYPES.get(burst[0]["LogonType"], burst[0]["LogonType"])
        alerts.append(Alert(burst[0]["_t"], "DET-01 Brute force", "high", "T1110.001",
                            f"{len(burst)} failed {lt} logons for '{user}' from {', '.join(srcs)} "
                            f"between {burst[0]['_t']:%H:%M:%S} and {burst[-1]['_t']:%H:%M:%S}"))

    sprays = list(sliding_groups(fails, lambda e: e["IpAddress"], SPRAY_WINDOW, SPRAY_DISTINCT_USERS,
                                 distinct=lambda e: e["TargetUserName"]))
    for src, burst in sprays:
        users = {e["TargetUserName"] for e in burst}
        alerts.append(Alert(burst[0]["_t"], "DET-02 Password spray", "high", "T1110.003",
                            f"{len(users)} distinct accounts failed from {src} in "
                            f"{(burst[-1]['_t'] - burst[0]['_t']).seconds // 60} min"))

    # success after many failures from the same source
    fails_by_src = defaultdict(list)
    for e in fails:
        fails_by_src[e["IpAddress"]].append(e)
    for r in rows:
        if r["_id"] != 4624 or not r["IpAddress"]:
            continue
        prior = [f for f in fails_by_src.get(r["IpAddress"], [])
                 if timedelta(0) <= r["_t"] - f["_t"] <= SUCCESS_AFTER_FAIL_WINDOW]
        if len(prior) >= SUCCESS_AFTER_FAIL_MIN:
            alerts.append(Alert(r["_t"], "DET-03 Success after failures", "critical", "T1078",
                                f"'{r['TargetUserName']}' logged on from {r['IpAddress']} after "
                                f"{len(prior)} failures from that source in the previous 30 min"))

    for r in rows:
        if r["_id"] == 4740:
            alerts.append(Alert(r["_t"], "DET-04 Account lockout", "medium", "T1110",
                                f"'{r['TargetUserName']}' locked out"))
        elif r["_id"] == 4720:
            alerts.append(Alert(r["_t"], "DET-05 Account created", "medium", "T1136.002",
                                f"'{r['TargetUserName']}' created by '{r['SubjectUserName']}'"))
        elif r["_id"] in GROUP_ADD_EVENTS and r["GroupName"].lower() in PRIVILEGED_GROUPS:
            alerts.append(Alert(r["_t"], "DET-06 Privileged group change", "critical", "T1098",
                                f"'{r['TargetUserName']}' added to '{r['GroupName']}' by '{r['SubjectUserName']}'"))
        elif r["_id"] == 1102:
            alerts.append(Alert(r["_t"], "DET-07 Security log cleared", "critical", "T1070.001",
                                f"Audit log cleared by '{r['SubjectUserName']}'"))
    return sorted(alerts, key=lambda a: a.time)


def to_markdown(alerts: list[Alert], rows: list[dict], source: str) -> str:
    lines = [f"# Detection output — `{source}`", "",
             f"Events analysed: **{len(rows)}** · Alerts: **{len(alerts)}**", "",
             "| Time | Rule | Severity | ATT&CK | Summary |", "|---|---|---|---|---|"]
    lines += [f"| {a.time:%Y-%m-%d %H:%M:%S} | {a.rule} | {a.severity} | {a.attack} | {a.summary} |" for a in alerts]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--markdown", type=Path)
    args = ap.parse_args(argv)
    rows = load(args.csv)
    alerts = detect(rows)
    for a in alerts:
        print(f"{a.time:%H:%M:%S}  [{a.severity.upper():8}] {a.rule:32} {a.summary}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(alerts, rows, args.csv.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
