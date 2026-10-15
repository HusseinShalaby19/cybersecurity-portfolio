#!/usr/bin/env python3
"""
Generate a synthetic Windows Security event log (CSV) for detection practice.

Everything here is fictional: account names are generic (user01..user40),
hosts are lab names, and addresses come from private (RFC 1918) and
documentation (RFC 5737) ranges. Output is deterministic (fixed seed) so the
investigation write-up can be reproduced exactly.

Scenario injected on top of normal background activity:
  1. Brute force against the built-in admin account over RDP from an
     internet address -> account lockout.
  2. Password spray from an internal workstation across many accounts.
  3. One sprayed account logs in successfully from the same workstation.
  4. That account creates a new user and adds it to Domain Admins.
  5. The Security log is cleared.
"""
from __future__ import annotations

import csv
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

SEED = 1337
START = datetime(2026, 3, 9, 7, 0, 0)
DC = "LAB-DC01"
FIELDS = ["TimeCreated", "EventID", "Computer", "TargetUserName", "SubjectUserName",
          "IpAddress", "LogonType", "Status", "GroupName"]

USERS = [f"user{i:02d}" for i in range(1, 41)]
WORKSTATIONS = {u: f"10.20.10.{100 + i}" for i, u in enumerate(USERS)}


def ev(t, eid, target="", subject="", ip="", ltype="", status="", group=""):
    return {"TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%S"), "EventID": eid, "Computer": DC,
            "TargetUserName": target, "SubjectUserName": subject, "IpAddress": ip,
            "LogonType": ltype, "Status": status, "GroupName": group}


def background(rng: random.Random) -> list[dict]:
    rows = []
    for u in USERS:
        t = START + timedelta(minutes=rng.randint(0, 120))
        # occasional mistyped password before a good logon
        if rng.random() < 0.15:
            rows.append(ev(t - timedelta(seconds=20), 4625, u, ip=WORKSTATIONS[u], ltype=2, status="0xC000006A"))
        rows.append(ev(t, 4624, u, ip=WORKSTATIONS[u], ltype=2))
        for _ in range(rng.randint(3, 8)):
            t += timedelta(minutes=rng.randint(10, 60))
            rows.append(ev(t, 4624, u, ip=WORKSTATIONS[u], ltype=3))
    return rows


def scenario() -> list[dict]:
    rows = []
    # 1. RDP brute force against built-in admin from an internet (documentation) address
    t = START + timedelta(hours=1, minutes=12)
    for i in range(42):
        rows.append(ev(t + timedelta(seconds=7 * i), 4625, "Administrator", ip="203.0.113.77",
                       ltype=10, status="0xC000006A"))
    rows.append(ev(t + timedelta(seconds=7 * 42), 4740, "Administrator", subject=DC + "$"))

    # 2. Password spray from an internal workstation (one attempt per account)
    spray_src = "10.20.10.187"
    t = START + timedelta(hours=2, minutes=40)
    targets = USERS[:28]
    for i, u in enumerate(targets):
        rows.append(ev(t + timedelta(seconds=19 * i), 4625, u, ip=spray_src, ltype=3, status="0xC000006A"))

    # 3. Spray succeeds for one account
    victim = "user17"
    t_ok = t + timedelta(seconds=19 * len(targets) + 40)
    rows.append(ev(t_ok, 4624, victim, ip=spray_src, ltype=3))

    # 4. Persistence + privilege escalation
    rows.append(ev(t_ok + timedelta(minutes=6), 4720, "helpdesk_tmp", subject=victim))
    rows.append(ev(t_ok + timedelta(minutes=7), 4728, "helpdesk_tmp", subject=victim, group="Domain Admins"))

    # 5. Defense evasion
    rows.append(ev(t_ok + timedelta(minutes=15), 1102, subject=victim))
    return rows


def main(out: Path) -> None:
    rng = random.Random(SEED)
    rows = sorted(background(rng) + scenario(), key=lambda r: r["TimeCreated"])
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} events to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic-security-log.csv"))
