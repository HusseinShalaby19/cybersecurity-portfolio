# Cybersecurity & Network Security Portfolio

Systems and network engineer working on enterprise and hospitality infrastructure — firewalls, switching, wireless, Windows Server / Active Directory, virtualization, backup and low-voltage systems — and building toward a focus on network security, infrastructure hardening and security operations.

This repository has two parts:

- **Professional case studies** — sanitized write-ups of the kind of infrastructure work I do. They describe experience; they are not lab builds.
- **Hands-on labs and tools** — things I built and tested myself, using only fictional or synthetic data.

## Hands-on labs and tools

| # | Project | What it shows | Stack |
|---|---|---|---|
| 05 | [Firewall policy auditor](projects/05-firewall-policy-auditor/) | Reads a FortiOS-style config and flags any/any rules, internet-exposed RDP, admin access on WAN, shadowed rules, missing logging | Python, pytest |
| 06 | [Windows authentication log investigation](projects/06-windows-auth-log-investigation/) | Detects brute force → password spray → compromised account → new Domain Admin → log cleared; full incident timeline and containment plan | Python, Sigma, MITRE ATT&CK |
| 07 | [Active Directory security audit](projects/07-ad-security-audit-powershell/) | Read-only checks for stale accounts, Kerberoastable / AS-REP roastable accounts, admin group sprawl, delegation and password policy | PowerShell, mocked-AD tests |
| 08 | [Hotel network segmentation reference design](projects/08-hospitality-network-segmentation/) | Zones for PCI, guest, IoT/GRMS, CCTV, IPTV, vendors; inter-zone policy matrix; PCI DSS scoping; test plan | Architecture, Mermaid |
| 09 | [Cisco IOS hardening checker](projects/09-cisco-config-hardening-checker/) | Scores a running-config against 26 hardening checks; before/after: 0 → 100 | Python, pytest |

## Professional case studies (sanitized)

| # | Case study | Focus |
|---|---|---|
| 01 | [Enterprise data center & office infrastructure](projects/01-enterprise-infrastructure-security/) | Security across network, firewall, servers, storage, wireless and CCTV |
| 02 | [Firewall high availability & identity-based access](projects/02-firewall-ha-access-control/) | HA pair, AD-integrated, role-based internet access, functional testing |
| 03 | [Active Directory migration & GPO hardening](projects/03-active-directory-hardening/) | Migration with minimal disruption, removable media and settings restrictions |
| 04 | [Network infrastructure handover](projects/04-enterprise-network-handover/) | Security-focused handover checklist and acceptance testing |

## Run everything

```bash
pip install -r requirements.txt
python -m pytest -q                                  # Python tests for projects 05, 06, 09
pwsh -File projects/07-ad-security-audit-powershell/tests/Test-WithMockAD.ps1
python tools/sanitize_check.py .                     # confirm nothing sensitive is in the repo
```

GitHub Actions runs the same checks on every push.

## Confidentiality

- No client or employer names, real hostnames, domains, IP addresses, usernames, credentials, configuration exports or proprietary diagrams.
- All lab data is fictional or synthetic. Addresses use private (RFC 1918), CGNAT (RFC 6598) and documentation (RFC 5737) ranges.
- [`tools/sanitize_check.py`](tools/sanitize_check.py) scans every file for public IPs, e-mail addresses, secrets and a private deny-list of real names before anything is published.

## Skills

`Firewall policy & HA` `Network segmentation` `Cisco / FortiGate / Aruba` `Active Directory & GPO` `Windows event log analysis` `Detection engineering (Sigma)` `MITRE ATT&CK` `PCI DSS scoping` `Python` `PowerShell` `Infrastructure handover & documentation`

## Certifications

Cisco CCNA · HPE ATP – Hybrid Cloud · Google Cybersecurity Professional Certificate
