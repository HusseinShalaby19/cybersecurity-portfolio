# Firewall policy audit — `fictional-branch-fw.conf`

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 5 |
| Medium | 6 |
| Low | 4 |

| ID | Severity | Object | Finding | Recommendation |
|---|---|---|---|---|
| FW-003 | critical | policy 2 (Inbound-RDP-temp-vendor) | **Remote access service exposed to the internet.** Inbound from WAN with source 'all' permits: RDP. | Remove direct exposure; publish remote access through MFA-protected VPN/ZTNA and restrict sources. |
| MGMT-001 | critical | interface port1 | **Clear-text admin protocol on WAN interface.** allowaccess includes http. | Remove HTTP/Telnet from all interfaces; manage only from a dedicated management network. |
| FW-001 | high | policy 1 (Staff-to-Internet) | **Any-to-any accept rule.** Source, destination and service are all unrestricted. | Replace with explicit source/destination objects and only the services required. |
| FW-001 | high | policy 4 | **Any-to-any accept rule.** Source, destination and service are all unrestricted. | Replace with explicit source/destination objects and only the services required. |
| FW-004 | high | policy 2 (Inbound-RDP-temp-vendor) | **Clear-text or high-risk service permitted.** Allows: RDP. | Use encrypted alternatives (SSH, SFTP, HTTPS, SNMPv3) or tightly scope the rule. |
| FW-004 | high | policy 5 (Staff-FTP-to-Internet) | **Clear-text or high-risk service permitted.** Allows: FTP. | Use encrypted alternatives (SSH, SFTP, HTTPS, SNMPv3) or tightly scope the rule. |
| MGMT-003 | high | admin account #f6fe86 | **Administrator without trusted hosts.** Admin account can log in from any source address. | Set trusthost entries limited to the management network. |
| FW-005 | medium | policy 2 (Inbound-RDP-temp-vendor) | **Logging disabled on accept rule.** logtraffic is set to disable. | Enable logging (all or utm) so allowed traffic can be investigated. |
| FW-006 | medium | policy 1 (Staff-to-Internet) | **Internet-bound rule without security profiles.** No AV / web filter / IPS profiles applied to outbound traffic. | Apply web filtering, application control, IPS and AV profiles as per policy. |
| FW-006 | medium | policy 5 (Staff-FTP-to-Internet) | **Internet-bound rule without security profiles.** No AV / web filter / IPS profiles applied to outbound traffic. | Apply web filtering, application control, IPS and AV profiles as per policy. |
| FW-008 | medium | policy 2 (Inbound-RDP-temp-vendor) | **Temporary rule with permanent schedule.** Rule is labelled temporary but runs on schedule 'always'. | Attach a one-time schedule with an expiry date or remove the rule. |
| FW-009 | medium | policy 5 (Staff-FTP-to-Internet) | **Shadowed rule (never matches).** Fully covered by earlier policy 1 (Staff-to-Internet); action here is 'accept', earlier action is 'accept'. | Reorder or remove the rule; confirm intended behaviour with the rule owner. |
| MGMT-004 | medium | admin account #f6fe86 | **Administrator without MFA.** two-factor is not enabled. | Enable FortiToken / email / RADIUS-backed MFA for all administrators. |
| FW-007 | low | policy 4 | **Rule has no name or comment.** Purpose and owner cannot be determined from the rulebase. | Record purpose, owner, ticket reference and review date in the comment. |
| FW-010 | low | policy 6 (Old-migration-rule) | **Disabled policy left in rulebase.** Policy is disabled but still present. | Remove unused policies after confirming with the owner; keep the rulebase reviewable. |
| MGMT-005 | low | system global | **Long admin idle timeout.** admintimeout is 60 minutes. | Set admintimeout to 15 minutes or less. |
| MGMT-006 | low | system global | **HTTP admin not redirected to HTTPS.** admin-https-redirect is disabled. | Enable HTTPS redirect for the admin GUI. |
