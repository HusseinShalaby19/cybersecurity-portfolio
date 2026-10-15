# Windows Authentication Log Investigation

**Type:** Personal lab &nbsp;·&nbsp; **Data:** 100% synthetic &nbsp;·&nbsp; **Tools:** Python 3, Sigma &nbsp;·&nbsp; **Status:** Working, reproducible

## Objective

Practise the investigation workflow a SOC analyst or infrastructure engineer follows after suspicious authentication activity on a domain controller: detect, build a timeline, scope the impact, and recommend containment. The lab also produces portable detection logic (Sigma) that can be loaded into a SIEM.

## Lab data

[`generate_synthetic_logs.py`](generate_synthetic_logs.py) creates a deterministic Windows Security log (348 events, fixed seed) with normal user activity plus an injected attack chain. All accounts (`user01`…`user40`), hosts and addresses are fictional; addresses use private and documentation ranges.

| Event ID | Meaning |
|---|---|
| 4624 / 4625 | Successful / failed logon |
| 4740 | Account locked out |
| 4720 | User account created |
| 4728 / 4732 / 4756 | Member added to a security group |
| 1102 | Security audit log cleared |

## Detection rules

| Rule | Logic | ATT&CK |
|---|---|---|
| DET-01 Brute force | ≥ 10 failures for one account in 5 min | T1110.001 |
| DET-02 Password spray | ≥ 10 distinct accounts failing from one source in 15 min | T1110.003 |
| DET-03 Success after failures | Successful logon from a source with ≥ 5 failures in the prior 30 min | T1078 |
| DET-04 Account lockout | Event 4740 | T1110 |
| DET-05 Account created | Event 4720 | T1136.002 |
| DET-06 Privileged group change | 4728/4732/4756 to Domain Admins, Administrators, etc. | T1098 |
| DET-07 Log cleared | Event 1102 | T1070.001 |

Implemented in [`detect.py`](detect.py) and as Sigma rules in [`sigma/`](sigma/) (the brute-force and spray rules use Sigma correlation rules).

```bash
python generate_synthetic_logs.py              # writes data/synthetic-security-log.csv
python detect.py data/synthetic-security-log.csv --markdown reports/detection-output.md
python -m pytest -q
```

Tests confirm that every stage of the injected scenario is detected **and** that the background activity on its own (including normal mistyped passwords) produces **zero** alerts.

## Investigation write-up

### Timeline (from [`reports/detection-output.md`](reports/detection-output.md))

| Time | Event | Assessment |
|---|---|---|
| 08:12 – 08:16 | 42 failed RDP logons for `Administrator` from an internet address (203.0.113.77) | Automated RDP brute force — RDP is reachable from the internet |
| 08:16 | `Administrator` locked out | Lockout policy worked; attack unsuccessful |
| 09:40 – 09:48 | 28 different accounts fail once each from internal host 10.20.10.187 | Password spray from inside the network. The host is not one of the known user workstations |
| 09:49 | `user17` logs on successfully from 10.20.10.187 | **Credential compromised** |
| 09:55 | `user17` creates account `helpdesk_tmp` | Persistence |
| 09:56 | `helpdesk_tmp` added to **Domain Admins** | Privilege escalation — full domain compromise must be assumed |
| 10:04 | Security log cleared by `user17` | Defense evasion — local DC logs from before this point are lost; rely on forwarded/SIEM copies |

### Two separate problems

1. **External exposure** — RDP reachable from the internet. The lockout stopped this attempt, but it will repeat.
2. **Internal compromise** — an unknown internal device ran a spray, found a weak password, and an account with rights to create users and modify Domain Admins was taken over.

### Containment and recovery recommendations

1. Disable `helpdesk_tmp` and `user17`; reset `user17`'s password; isolate host 10.20.10.187 at the switch/firewall.
2. Remove `helpdesk_tmp` from Domain Admins and review every privileged group for other changes since 09:40.
3. Because a Domain Admin was created, reset the `krbtgt` password twice (with replication in between) and rotate other privileged and service-account credentials.
4. Pull the forwarded logs (SIEM / Windows Event Forwarding) for the period the local log was cleared.
5. Block inbound RDP at the perimeter; provide remote access only through an MFA-protected VPN.
6. Find out why a standard-named account could create users and edit Domain Admins (delegation review — see the [AD audit script](../07-ad-security-audit-powershell/)).

### Preventive controls

- Password policy / banned-password list long enough to defeat spraying; MFA for remote and privileged access.
- Tiered admin model: day-to-day accounts never hold directory-admin rights.
- Forward Security logs off the DC in real time so clearing the local log does not destroy evidence.
- Alert on 4720 + privileged group changes outside approved change windows.

## Limitations

- Synthetic data is cleaner than production logs; real environments need tuning for service accounts, NAT and VPN concentrators (noted in each Sigma rule's false positives).
- In real 4728/4732 events the group name is in `TargetUserName` and the added member in `MemberName`; the CSV here uses a simplified `GroupName` column. The Sigma rules use the real field names.

## Skills demonstrated

Windows event log analysis · detection engineering · Sigma · MITRE ATT&CK mapping · incident timeline and scoping · containment planning · Python
