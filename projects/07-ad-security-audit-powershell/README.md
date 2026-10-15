# Active Directory Security Audit (PowerShell)

**Type:** Personal lab / tool &nbsp;·&nbsp; **Language:** PowerShell 5.1+ / 7 &nbsp;·&nbsp; **Status:** Tested offline against a mocked AD module; live validation to be done in a disposable lab domain

## Why

Most AD compromises do not need a zero-day — they use stale accounts, service accounts with weak passwords and SPNs, accounts without Kerberos pre-auth, and over-populated admin groups. This script is a **read-only** health check that surfaces those issues quickly, so they can be fixed through normal change control. It complements the GPO hardening work in [case study 03](../03-active-directory-hardening/).

## Checks

| ID | Check | Why it matters | Severity |
|---|---|---|---|
| AD-01 | Enabled users inactive > N days (default 90) | Forgotten accounts are easy targets | Medium |
| AD-02 | PasswordNeverExpires | Old passwords accumulate exposure | Medium |
| AD-03 | PasswordNotRequired | Account may have a blank password | High |
| AD-04 | Privileged group members (recursive) | Admin sprawl; Operators groups should be empty | Review |
| AD-05 | User accounts with an SPN | Kerberoasting (T1558.003) | High |
| AD-06 | Kerberos pre-auth disabled | AS-REP roasting (T1558.004) | High |
| AD-07 | Reversible password encryption | Passwords recoverable in clear text | High |
| AD-08 | Non-DC computers with unconstrained delegation | Ticket theft / privilege escalation | High |
| AD-09 | krbtgt password older than 180 days | Golden-ticket persistence window | Medium |
| AD-10 | Weak default password / lockout policy | Brute force and spraying | Medium |
| AD-11 | Enabled computers inactive > N days | Unmanaged, unpatched objects | Low |
| AD-12 | Built-in Administrator used recently | Shared, non-attributable admin use | Medium |

## Usage

```powershell
# On a domain-joined admin workstation with RSAT installed
.\Invoke-ADSecurityAudit.ps1 -OutputPath .\ad-audit -InactiveDays 90
```

Output: `summary.csv`, `report.html`, and one CSV per check with results.
**Account and computer names are masked by default** (replaced with a short hash); use `-ShowNames` only for internal remediation work. Never publish reports from a real environment.

## Testing

`tests/Test-WithMockAD.ps1` loads a stub `ActiveDirectory` module that returns a small **fictional** directory seeded with one example of each weakness, runs the audit, and asserts:

- every seeded weakness is counted correctly (11 checks), and false positives are excluded (domain controller excluded from AD-08, `krbtgt` excluded from AD-05);
- no account names appear anywhere in the output when `-ShowNames` is not used.

```powershell
pwsh -File tests/Test-WithMockAD.ps1
```

Result: all checks pass. Next step: run against a disposable Windows Server lab domain with deliberately misconfigured accounts and record the results here.

## Remediation notes

| Finding | Typical fix |
|---|---|
| Service account with SPN + never-expiring password | Move to a group Managed Service Account (gMSA); otherwise 25+ character password and AES-only encryption |
| Pre-auth disabled / reversible encryption / password not required | Clear the flag, reset the password, confirm the application still works |
| Users in Backup / Account / Server Operators | Remove; delegate the specific permission needed instead |
| Old krbtgt password | Reset twice with replication between resets (use Microsoft's reset script) |
| Lockout threshold 0, short minimum length | Lockout 5–10 attempts; 14+ character minimum or passphrases; fine-grained policy for admins |

## Skills demonstrated

Active Directory security · Kerberos attack surface · least privilege · PowerShell scripting · offline testing with mocks · safe handling of identity data
