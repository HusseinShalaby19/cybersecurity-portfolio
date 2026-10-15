# IOS hardening check — `fictional-access-switch-before.cfg`

**Score: 0/100** · 0 passed · 26 failed

| ID | Category | Check | Severity | Result | Evidence | Remediation |
|---|---|---|---|---|---|---|
| AAA-01 | Authentication | AAA new-model enabled | medium | **FAIL** | aaa new-model | `aaa new-model + TACACS+/RADIUS with local fallback` |
| AUTH-01 | Authentication | No 'enable password' (use enable secret) | high | **FAIL** | enable password present | `no enable password; enable algorithm-type scrypt secret <secret>` |
| AUTH-02 | Authentication | Enable secret uses strong hash (type 8/9) | medium | **FAIL** |  | `enable algorithm-type scrypt secret <secret>` |
| AUTH-03 | Authentication | Local users use 'secret', not reversible 'password' | high | **FAIL** | 1 local user(s) with type 0/7 password | `username <name> privilege 15 algorithm-type scrypt secret <secret>` |
| AUTH-04 | Authentication | service password-encryption enabled | low | **FAIL** |  | `service password-encryption (obfuscation only — still use secrets)` |
| AUTH-05 | Authentication | Login brute-force protection (login block-for) | medium | **FAIL** |  | `login block-for 120 attempts 5 within 60` |
| MGMT-01 | Management plane | VTY lines accept SSH only (no Telnet) | high | **FAIL** | telnet allowed on VTY | `line vty 0 15 / transport input ssh` |
| MGMT-02 | Management plane | SSH version 2 enforced | high | **FAIL** |  | `ip ssh version 2 (with RSA key >= 2048 bits)` |
| MGMT-03 | Management plane | VTY access restricted with access-class | high | **FAIL** |  | `access-class MGMT-ONLY in (permit management subnet only)` |
| MGMT-04 | Management plane | Idle session timeout set | medium | **FAIL** | exec-timeout 0 0 found | `exec-timeout 10 0` |
| MGMT-05 | Management plane | Clear-text HTTP server disabled | high | **FAIL** | ip http server enabled | `no ip http server` |
| SNMP-01 | SNMP | No default SNMP community strings | high | **FAIL** | default communities: 1 | `remove; use SNMPv3` |
| SNMP-02 | SNMP | No read-write SNMP community | high | **FAIL** | RW communities: 1 | `no snmp-server community <x> RW` |
| SNMP-03 | SNMP | SNMPv3 (authPriv) used instead of v1/v2c | medium | **FAIL** |  | `snmp-server group NMS v3 priv / snmp-server user ... auth sha ... priv aes 256` |
| LOG-01 | Logging | Remote syslog configured | medium | **FAIL** |  | `logging host <collector>` |
| LOG-02 | Logging | Timestamps on log messages | low | **FAIL** |  | `service timestamps log datetime msec localtime show-timezone` |
| LOG-03 | Logging | NTP configured | medium | **FAIL** |  | `ntp server <ntp1> / ntp server <ntp2>` |
| LOG-04 | Logging | Login success/failure logging | low | **FAIL** |  | `login on-failure log / login on-success log` |
| SVC-01 | Services | IP source routing disabled | medium | **FAIL** |  | `no ip source-route` |
| SVC-02 | Services | CDP disabled globally or on edge ports | low | **FAIL** |  | `no cdp run (or 'no cdp enable' on user/edge ports)` |
| SVC-03 | Services | TCP keepalives for sessions | low | **FAIL** |  | `service tcp-keepalives-in / service tcp-keepalives-out` |
| BAN-01 | Services | Legal login banner present | low | **FAIL** |  | `banner login ^Authorised access only^` |
| L2-01 | Layer 2 | BPDU Guard on access ports | medium | **FAIL** | 3 access port(s) without BPDU Guard | `spanning-tree bpduguard enable (or portfast bpduguard default)` |
| L2-02 | Layer 2 | Access ports not left in VLAN 1 | medium | **FAIL** | 2 active access port(s) in VLAN 1 | `switchport access vlan <user-vlan>; park unused ports in a dead VLAN` |
| L2-03 | Layer 2 | Unused / undocumented ports shut down | low | **FAIL** | 2 active port(s) with no description | `shutdown unused ports; describe active ones` |
| L2-04 | Layer 2 | DHCP snooping enabled | medium | **FAIL** |  | `ip dhcp snooping / ip dhcp snooping vlan <user-vlans> / trust uplinks only` |
