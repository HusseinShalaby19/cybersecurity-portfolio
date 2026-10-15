# IOS hardening check — `fictional-access-switch-after.cfg`

**Score: 100/100** · 26 passed · 0 failed

| ID | Category | Check | Severity | Result | Evidence | Remediation |
|---|---|---|---|---|---|---|
| AAA-01 | Authentication | AAA new-model enabled | medium | PASS |  |  |
| AUTH-01 | Authentication | No 'enable password' (use enable secret) | high | PASS |  |  |
| AUTH-02 | Authentication | Enable secret uses strong hash (type 8/9) | medium | PASS |  |  |
| AUTH-03 | Authentication | Local users use 'secret', not reversible 'password' | high | PASS |  |  |
| AUTH-04 | Authentication | service password-encryption enabled | low | PASS |  |  |
| AUTH-05 | Authentication | Login brute-force protection (login block-for) | medium | PASS |  |  |
| MGMT-01 | Management plane | VTY lines accept SSH only (no Telnet) | high | PASS |  |  |
| MGMT-02 | Management plane | SSH version 2 enforced | high | PASS |  |  |
| MGMT-03 | Management plane | VTY access restricted with access-class | high | PASS |  |  |
| MGMT-04 | Management plane | Idle session timeout set | medium | PASS |  |  |
| MGMT-05 | Management plane | Clear-text HTTP server disabled | high | PASS |  |  |
| SNMP-01 | SNMP | No default SNMP community strings | high | PASS |  |  |
| SNMP-02 | SNMP | No read-write SNMP community | high | PASS |  |  |
| SNMP-03 | SNMP | SNMPv3 (authPriv) used instead of v1/v2c | medium | PASS |  |  |
| LOG-01 | Logging | Remote syslog configured | medium | PASS |  |  |
| LOG-02 | Logging | Timestamps on log messages | low | PASS |  |  |
| LOG-03 | Logging | NTP configured | medium | PASS |  |  |
| LOG-04 | Logging | Login success/failure logging | low | PASS |  |  |
| SVC-01 | Services | IP source routing disabled | medium | PASS |  |  |
| SVC-02 | Services | CDP disabled globally or on edge ports | low | PASS |  |  |
| SVC-03 | Services | TCP keepalives for sessions | low | PASS |  |  |
| BAN-01 | Services | Legal login banner present | low | PASS |  |  |
| L2-01 | Layer 2 | BPDU Guard on access ports | medium | PASS |  |  |
| L2-02 | Layer 2 | Access ports not left in VLAN 1 | medium | PASS |  |  |
| L2-03 | Layer 2 | Unused / undocumented ports shut down | low | PASS |  |  |
| L2-04 | Layer 2 | DHCP snooping enabled | medium | PASS |  |  |
