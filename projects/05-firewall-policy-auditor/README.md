# Firewall Policy Auditor (FortiOS-style)

**Type:** Personal lab / tool &nbsp;·&nbsp; **Language:** Python 3 (standard library only) &nbsp;·&nbsp; **Status:** Working, tested against fictional sample configs

## Why I built it

Firewall rulebases grow over time: temporary vendor rules stay forever, "any/any" rules get added during go-live, and admin access ends up reachable from the internet. Reviewing a large rulebase by eye is slow and easy to get wrong, so I wrote a small read-only auditor that reads a FortiGate configuration backup and produces a prioritized findings report.

## What it checks

| ID | Check | Default severity |
|---|---|---|
| FW-001 | Any-to-any accept rule (source, destination and service all unrestricted) | High / Critical from WAN |
| FW-002 | Accept rule with service `ALL` | Medium |
| FW-003 | RDP / SSH / SMB / Telnet / VNC reachable from the internet with source `all` | Critical |
| FW-004 | Clear-text or high-risk services (Telnet, FTP, TFTP, SNMP, SMB, RDP…) | Medium / High |
| FW-005 | Logging disabled on an accept rule | Medium |
| FW-006 | Internet-bound accept rule with no security profiles (web filter, IPS, AV) | Medium |
| FW-007 | Rule with no name or comment (no owner / purpose) | Low |
| FW-008 | Rule labelled "temp" but on a permanent `always` schedule | Medium |
| FW-009 | Shadowed rule — fully covered by an earlier rule, so it never matches | Medium |
| FW-010 | Disabled rule left in the rulebase | Low |
| MGMT-001 | HTTP or Telnet admin access on a WAN interface | Critical |
| MGMT-002 | HTTPS/SSH admin access on a WAN interface | High |
| MGMT-003 | Administrator account without trusted hosts | High |
| MGMT-004 | Administrator account without MFA | Medium |
| MGMT-005 | Admin idle timeout longer than 15 minutes | Low |
| MGMT-006 | Admin GUI not redirected from HTTP to HTTPS | Low |

Administrator account names are never written to the report — they are replaced with a short hash.

## Usage

```bash
python fw_audit.py samples/fictional-branch-fw.conf
python fw_audit.py samples/fictional-branch-fw.conf --markdown reports/report.md --json reports/findings.json
python fw_audit.py config.conf --fail-on high    # exits 1 if anything High or above (useful in CI / change review)
python -m pytest -q                              # run the unit tests
```

## Results on the sample configs

Both sample configs are **fictional** and were written for this lab. Addresses use private (RFC 1918) and documentation (RFC 5737) ranges.

- `samples/fictional-branch-fw.conf` — deliberately weak branch firewall → **17 findings** (2 critical, 5 high, 6 medium, 4 low). Full output: [`reports/fictional-branch-fw-report.md`](reports/fictional-branch-fw-report.md)
- `samples/fictional-hardened-fw.conf` — the same site after remediation → **0 critical / high**, 1 medium (RDP for vendors over MFA VPN with a one-time schedule — documented as an accepted risk).

## Remediation mapping

| Finding in the weak config | Fix applied in the hardened config |
|---|---|
| Inbound RDP from the internet "temporarily" for a vendor | Vendor access only through SSL-VPN with MFA, limited to one server, with an expiring schedule |
| Staff any/any to internet, no profiles | Only HTTPS/DNS from the staff subnet, web filter + IPS + AV, full logging |
| Staff-to-guest any/any rule | Removed — guest network isolated |
| HTTP/SSH/HTTPS admin on WAN | Admin only on a dedicated management interface |
| Admin without trusted hosts / MFA | Trusted hosts set to the management subnet, FortiToken enforced |

## Limitations

- Address objects are compared by name, not resolved to IP ranges, so shadowing detection is conservative (it only reports clear-cut cases).
- Does not evaluate VIPs, central NAT, local-in policies or VDOMs.
- It is a review aid, not a replacement for a change-review process.

## Skills demonstrated

Firewall policy review · least-privilege rule design · management-plane hardening · Python parsing and reporting · unit testing
