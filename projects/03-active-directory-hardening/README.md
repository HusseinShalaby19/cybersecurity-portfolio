# Active Directory Migration & Group Policy Hardening

**Type:** Professional case study (sanitized) &nbsp;·&nbsp; **Environment:** Windows Server / Active Directory
**Confidentiality:** No domain names, usernames, OU names from the real environment or exported policies are included. The OU structure and GPO list below are generic examples.

## Context

Users and organizational structure had to move to a new Active Directory environment with as little disruption to staff as possible, and workstation policy needed tightening: removable storage, access to system settings, and a consistent desktop.

## My role

- Supported migration of directory users and organizational structure to the new Active Directory environment, focusing on minimizing service disruption.
- Implemented and validated Group Policy settings including removable-media restrictions, Control Panel restrictions and standard desktop configuration.

## Example OU and group model (fictional)

```
corp.example
├── Admin
│   ├── Tier0-Accounts        (directory admins - separate from daily accounts)
│   └── Tier1-Accounts        (server admins)
├── Users
│   ├── Front-Office
│   ├── Finance
│   └── Back-Office
├── Computers
│   ├── Workstations
│   ├── Kiosks
│   └── Servers
├── Service-Accounts
└── Disabled                  (leavers - disabled, then deleted after retention)
```

Policies link to OUs; permissions are granted to **groups**, never to individual users.

## Migration approach (generic method)

| Phase | Activities |
|---|---|
| Discover | Export current users, groups, OUs, and dependencies (mapped drives, printers, application logons) |
| Clean | Remove stale and duplicate accounts before migrating instead of carrying them over |
| Pilot | Migrate a small group, confirm logon, file access, printers and email |
| Migrate | Move remaining users in batches with a rollback point for each batch |
| Validate | Confirm group membership, access to shares, and that GPOs apply (`gpresult /r`, RSOP) |
| Decommission | Retire old objects after an agreed parallel-run period |

## GPO baseline (examples)

Removable-media, Control Panel and standard-desktop settings reflect the project scope; screen lock and audit policy are recommended additions for a similar environment.

| Setting | Purpose | Notes |
|---|---|---|
| Deny read/write on removable storage | Reduce data leakage and malware via USB | Exception group for approved users |
| Prohibit access to Control Panel and PC settings | Stop users changing network/security settings | Not applied to IT |
| Restrict command prompt / registry editor (where required) | Limit casual tampering | Not a security boundary on its own |
| Standard desktop / wallpaper / lock screen | Consistency, legal notice | |
| Screen lock after inactivity | Unattended front-desk PCs | |
| Audit policy (logon, account management, policy change) | Evidence for investigations | Feeds [log investigation lab](../06-windows-auth-log-investigation/) |

## Validation checklist (template)

- [ ] Policy applies to the intended OU only (`gpresult /r` on a test machine per OU)
- [ ] Exception groups work as intended
- [ ] USB storage blocked for standard users, allowed for the exception group
- [ ] No unexpected impact on line-of-business applications during pilot
- [ ] Rollback documented (unlink GPO / remove from security filtering)

## Takeaways

- Pilot first: a GPO linked at the wrong level can lock out a whole department.
- Restrictions like "no Control Panel" improve consistency but are not security boundaries; real protection comes from least privilege (no local admin), patching and monitoring.
- Migration is the best moment to clean up — carrying stale accounts into a new domain carries the risk too.

## Related lab

- [Active Directory security audit script](../07-ad-security-audit-powershell/) — read-only checks for stale accounts, Kerberoastable service accounts, privileged-group sprawl and weak policy.
