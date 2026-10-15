# Cisco IOS Configuration Hardening Checker

**Type:** Personal lab / tool &nbsp;·&nbsp; **Language:** Python 3 (standard library only) &nbsp;·&nbsp; **Status:** Working, tested against fictional before/after configs

## Purpose

Switches and routers are often deployed quickly and never revisited: Telnet left on, `public` SNMP community, no remote logging, user ports left in VLAN 1. This tool reads a `show running-config` file and scores it against a hardening baseline, listing the exact command to fix each failed check. It is useful before handover, during periodic reviews, or as a gate in a config-backup pipeline.

## Baseline (26 checks)

| Category | Checks |
|---|---|
| Authentication | AAA new-model · no `enable password` · type 8/9 enable secret · local users with `secret` not `password` · password encryption · `login block-for` |
| Management plane | SSH-only VTY · SSH v2 · VTY `access-class` · idle timeout · HTTP server disabled |
| SNMP | No default communities · no RW communities · SNMPv3 authPriv |
| Logging & time | Remote syslog · timestamps · NTP · login success/failure logging |
| Services | No IP source routing · CDP disabled · TCP keepalives · login banner |
| Layer 2 (switches) | BPDU Guard on access ports · no active ports in VLAN 1 · unused ports shut down · DHCP snooping |

Checks are weighted by severity (high = 3, medium = 2, low = 1) to give a score out of 100. Based on themes from the CIS Cisco IOS benchmark and Cisco's IOS hardening guide; this is not an official CIS implementation.

## Usage

```bash
python ios_hardening_check.py samples/fictional-access-switch-before.cfg
python ios_hardening_check.py running.cfg --markdown reports/report.md
python ios_hardening_check.py running.cfg --fail-under 80     # non-zero exit for pipelines
python -m pytest -q
```

## Before / after

Both configs are fictional and were written for this lab; secrets are placeholders.

| Config | Score | Passed | Failed | Report |
|---|---|---|---|---|
| Access switch — before | **0 / 100** | 0 | 26 | [`reports/before-report.md`](reports/before-report.md) |
| Access switch — after hardening | **100 / 100** | 26 | 0 | [`reports/after-report.md`](reports/after-report.md) |

Main changes between the two: Telnet removed and VTY limited to a management ACL, TACACS+ with a local break-glass account, SNMPv2 communities replaced by SNMPv3 authPriv, HTTP server disabled, remote syslog + NTP, management moved off VLAN 1, unused ports shut and parked in an unused VLAN, BPDU Guard and DHCP snooping on user ports.

## Limitations

- Pattern-based: it reads text, it does not model IOS behaviour (e.g. it does not resolve which ACL entries actually match).
- Focused on access switches and branch routers; does not cover routing-protocol authentication, CoPP or IOS-XR/NX-OS syntax.
- A hardened config still needs secure secrets, patching and change control.

## Skills demonstrated

Network device hardening · Cisco IOS · management-plane security · SNMPv3 · Layer 2 security · Python · automated compliance checking
