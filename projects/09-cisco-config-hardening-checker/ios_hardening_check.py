#!/usr/bin/env python3
"""
Cisco IOS / IOS-XE configuration hardening checker.

Reads a `show running-config` text file and compares it against a baseline
derived from common hardening guidance (CIS Cisco IOS benchmark themes and
Cisco's IOS hardening guide). Read-only: it never connects to a device.

Usage:
    python ios_hardening_check.py samples/fictional-access-switch-before.cfg
    python ios_hardening_check.py running.cfg --markdown report.md --fail-under 80
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    cid: str
    category: str
    title: str
    severity: str
    passed: bool
    evidence: str
    fix: str


WEIGHT = {"high": 3, "medium": 2, "low": 1}


def blocks(cfg: str, header_re: str) -> list[tuple[str, list[str]]]:
    """Return [(header, [child lines])] for top-level sections matching header_re."""
    out, cur = [], None
    for line in cfg.splitlines():
        if line and not line.startswith(" "):
            cur = None
            if re.match(header_re, line):
                cur = (line.strip(), [])
                out.append(cur)
        elif cur is not None and line.strip():
            cur[1].append(line.strip())
    return out


def has(cfg: str, pattern: str) -> bool:
    return re.search(pattern, cfg, re.MULTILINE) is not None


def check(cfg: str) -> list[Result]:
    r: list[Result] = []

    def add(cid, cat, title, sev, ok, evidence, fix):
        r.append(Result(cid, cat, title, sev, ok, evidence, fix))

    # --- Access / authentication -------------------------------------------------
    add("AAA-01", "Authentication", "AAA new-model enabled", "medium",
        has(cfg, r"^aaa new-model"), "aaa new-model", "aaa new-model + TACACS+/RADIUS with local fallback")
    enable_pw = has(cfg, r"^enable password ")
    add("AUTH-01", "Authentication", "No 'enable password' (use enable secret)", "high",
        not enable_pw, "enable password present" if enable_pw else "not present",
        "no enable password; enable algorithm-type scrypt secret <secret>")
    weak_secret = has(cfg, r"^enable secret (5|0) ")
    add("AUTH-02", "Authentication", "Enable secret uses strong hash (type 8/9)", "medium",
        has(cfg, r"^enable secret (8|9) ") and not weak_secret,
        "type 5/0 secret" if weak_secret else "", "enable algorithm-type scrypt secret <secret>")
    weak_users = re.findall(r"^username (\S+) .*password (?:0|7) ", cfg, re.MULTILINE)
    add("AUTH-03", "Authentication", "Local users use 'secret', not reversible 'password'", "high",
        not weak_users, f"{len(weak_users)} local user(s) with type 0/7 password",
        "username <name> privilege 15 algorithm-type scrypt secret <secret>")
    add("AUTH-04", "Authentication", "service password-encryption enabled", "low",
        has(cfg, r"^service password-encryption"), "",
        "service password-encryption (obfuscation only — still use secrets)")
    add("AUTH-05", "Authentication", "Login brute-force protection (login block-for)", "medium",
        has(cfg, r"^login block-for "), "", "login block-for 120 attempts 5 within 60")

    # --- Management plane ---------------------------------------------------------
    vtys = blocks(cfg, r"^line vty ")
    telnet = any(any(re.match(r"transport input (telnet|all)", l) or
                     (re.match(r"transport input", l) and "telnet" in l) for l in kids) for _, kids in vtys)
    ssh_only = vtys and all(any(l == "transport input ssh" for l in kids) for _, kids in vtys)
    add("MGMT-01", "Management plane", "VTY lines accept SSH only (no Telnet)", "high",
        bool(ssh_only) and not telnet, "telnet allowed on VTY" if telnet else "",
        "line vty 0 15 / transport input ssh")
    add("MGMT-02", "Management plane", "SSH version 2 enforced", "high",
        has(cfg, r"^ip ssh version 2"), "", "ip ssh version 2 (with RSA key >= 2048 bits)")
    acl = vtys and all(any(l.startswith("access-class ") for l in kids) for _, kids in vtys)
    add("MGMT-03", "Management plane", "VTY access restricted with access-class", "high",
        bool(acl), "", "access-class MGMT-ONLY in (permit management subnet only)")
    no_timeout = any("exec-timeout 0 0" in kids or "exec-timeout 0" in kids
                     for _, kids in vtys + blocks(cfg, r"^line con "))
    add("MGMT-04", "Management plane", "Idle session timeout set", "medium",
        not no_timeout, "exec-timeout 0 0 found" if no_timeout else "", "exec-timeout 10 0")
    http = has(cfg, r"^ip http server")
    add("MGMT-05", "Management plane", "Clear-text HTTP server disabled", "high",
        not http, "ip http server enabled" if http else "", "no ip http server")

    # --- SNMP -------------------------------------------------------------------
    comms = re.findall(r"^snmp-server community (\S+)(.*)$", cfg, re.MULTILINE)
    default_comm = [c for c, _ in comms if c.lower() in {"public", "private", "cisco"}]
    rw = [c for c, rest in comms if " RW" in rest.upper()]
    add("SNMP-01", "SNMP", "No default SNMP community strings", "high",
        not default_comm, f"default communities: {len(default_comm)}", "remove; use SNMPv3")
    add("SNMP-02", "SNMP", "No read-write SNMP community", "high",
        not rw, f"RW communities: {len(rw)}", "no snmp-server community <x> RW")
    add("SNMP-03", "SNMP", "SNMPv3 (authPriv) used instead of v1/v2c", "medium",
        not comms and has(cfg, r"^snmp-server group \S+ v3 priv"), "",
        "snmp-server group NMS v3 priv / snmp-server user ... auth sha ... priv aes 256")

    # --- Logging & time ----------------------------------------------------------
    add("LOG-01", "Logging", "Remote syslog configured", "medium",
        has(cfg, r"^logging (host )?\d+\.\d+\.\d+\.\d+"), "", "logging host <collector>")
    add("LOG-02", "Logging", "Timestamps on log messages", "low",
        has(cfg, r"^service timestamps log datetime"), "", "service timestamps log datetime msec localtime show-timezone")
    add("LOG-03", "Logging", "NTP configured", "medium",
        has(cfg, r"^ntp server "), "", "ntp server <ntp1> / ntp server <ntp2>")
    add("LOG-04", "Logging", "Login success/failure logging", "low",
        has(cfg, r"^login on-failure log") and has(cfg, r"^login on-success log"), "",
        "login on-failure log / login on-success log")

    # --- Services & control plane ------------------------------------------------
    add("SVC-01", "Services", "IP source routing disabled", "medium",
        has(cfg, r"^no ip source-route"), "", "no ip source-route")
    add("SVC-02", "Services", "CDP disabled globally or on edge ports", "low",
        has(cfg, r"^no cdp run"), "", "no cdp run (or 'no cdp enable' on user/edge ports)")
    add("SVC-03", "Services", "TCP keepalives for sessions", "low",
        has(cfg, r"^service tcp-keepalives-in") and has(cfg, r"^service tcp-keepalives-out"), "",
        "service tcp-keepalives-in / service tcp-keepalives-out")
    add("BAN-01", "Services", "Legal login banner present", "low",
        has(cfg, r"^banner (login|motd) "), "", "banner login ^Authorised access only^")

    # --- Layer 2 (switches) ------------------------------------------------------
    access_ports = [(h, k) for h, k in blocks(cfg, r"^interface (Gi|Fa|Te|Ethernet)")
                    if "switchport mode access" in k]
    if access_ports:
        no_bpdu = [h for h, k in access_ports
                   if "shutdown" not in k and "spanning-tree bpduguard enable" not in k]
        add("L2-01", "Layer 2", "BPDU Guard on access ports", "medium", not no_bpdu,
            f"{len(no_bpdu)} access port(s) without BPDU Guard", "spanning-tree bpduguard enable (or portfast bpduguard default)")
        vlan1 = [h for h, k in access_ports if "shutdown" not in k and not any(l.startswith("switchport access vlan") for l in k)]
        add("L2-02", "Layer 2", "Access ports not left in VLAN 1", "medium", not vlan1,
            f"{len(vlan1)} active access port(s) in VLAN 1", "switchport access vlan <user-vlan>; park unused ports in a dead VLAN")
        unused = [h for h, k in access_ports if "shutdown" not in k and not any(l.startswith("description") for l in k)]
        add("L2-03", "Layer 2", "Unused / undocumented ports shut down", "low", not unused,
            f"{len(unused)} active port(s) with no description", "shutdown unused ports; describe active ones")
        add("L2-04", "Layer 2", "DHCP snooping enabled", "medium", has(cfg, r"^ip dhcp snooping$"),
            "", "ip dhcp snooping / ip dhcp snooping vlan <user-vlans> / trust uplinks only")
    return r


def score(results: list[Result]) -> int:
    total = sum(WEIGHT[x.severity] for x in results)
    got = sum(WEIGHT[x.severity] for x in results if x.passed)
    return round(100 * got / total) if total else 100


def to_markdown(results: list[Result], name: str) -> str:
    s = score(results)
    fails = [x for x in results if not x.passed]
    lines = [f"# IOS hardening check — `{name}`", "",
             f"**Score: {s}/100** · {len(results) - len(fails)} passed · {len(fails)} failed", "",
             "| ID | Category | Check | Severity | Result | Evidence | Remediation |", "|---|---|---|---|---|---|---|"]
    for x in results:
        lines.append(f"| {x.cid} | {x.category} | {x.title} | {x.severity} | {'PASS' if x.passed else '**FAIL**'} | "
                     f"{x.evidence if not x.passed else ''} | {'' if x.passed else '`' + x.fix + '`'} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", type=Path)
    ap.add_argument("--markdown", type=Path)
    ap.add_argument("--fail-under", type=int, help="exit 1 if score below this value")
    a = ap.parse_args(argv)
    res = check(a.config.read_text(encoding="utf-8", errors="replace"))
    for x in res:
        print(f"{'PASS' if x.passed else 'FAIL'}  {x.cid:7} [{x.severity:6}] {x.title}")
    s = score(res)
    print(f"\nScore: {s}/100")
    if a.markdown:
        a.markdown.parent.mkdir(parents=True, exist_ok=True)
        a.markdown.write_text(to_markdown(res, a.config.name))
    return 1 if a.fail_under is not None and s < a.fail_under else 0


if __name__ == "__main__":
    sys.exit(main())
