#!/usr/bin/env python3
"""
FortiOS-style firewall policy auditor.

Parses a FortiGate configuration backup (plain-text FortiOS syntax) and flags
common policy and management-plane weaknesses. Read-only: the tool never
connects to a device, it only reads a config file you supply.

Usage:
    python fw_audit.py samples/fictional-branch-fw.conf
    python fw_audit.py config.conf --json findings.json --markdown report.md
    python fw_audit.py config.conf --fail-on high      # non-zero exit for CI

Only run it against configurations you are authorised to review, and never
commit real configuration backups to a public repository.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Services that carry credentials or data in clear text, or are common
# ransomware / lateral-movement entry points when exposed.
INSECURE_SERVICES = {"TELNET", "FTP", "TFTP", "HTTP", "SNMP", "SMB", "SAMBA", "RDP", "VNC", "NetBIOS"}
REMOTE_ADMIN_SERVICES = {"RDP", "SSH", "TELNET", "VNC", "SMB", "SAMBA", "WINRM"}
WEAK_ADMIN_ACCESS = {"http", "telnet"}
ANY = {"all", "any"}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    obj: str
    detail: str
    recommendation: str


@dataclass
class Policy:
    policy_id: str
    attrs: dict = field(default_factory=dict)

    def get(self, key: str, default=None):
        return self.attrs.get(key, default)

    def values(self, key: str) -> list[str]:
        v = self.attrs.get(key, [])
        return v if isinstance(v, list) else [v]

    @property
    def label(self) -> str:
        name = self.get("name")
        name = name[0] if isinstance(name, list) and name else name
        return f"policy {self.policy_id}" + (f" ({name})" if name else "")

    @property
    def enabled(self) -> bool:
        return (self.get("status") or ["enable"])[0] != "disable"

    @property
    def action(self) -> str:
        return (self.get("action") or ["deny"])[0]


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_config(text: str) -> dict[str, dict[str, dict]]:
    """Return {section: {edit_key: {attr: [values]}}} for every `config` block.

    Nested `config` blocks inside an `edit` are skipped (their contents are not
    needed for the checks below).
    """
    sections: dict[str, dict[str, dict]] = {}
    stack: list[str] = []          # config section names
    current_edit: str | None = None
    nested_depth = 0               # depth of configs nested inside an edit

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        if not tokens:
            continue
        kw = tokens[0]

        if kw == "config":
            if current_edit is not None:
                nested_depth += 1
                continue
            stack.append(" ".join(tokens[1:]))
            sections.setdefault(stack[-1], {})
        elif kw == "end":
            if nested_depth:
                nested_depth -= 1
                continue
            if stack:
                stack.pop()
            current_edit = None
        elif kw == "edit" and not nested_depth and stack:
            current_edit = tokens[1] if len(tokens) > 1 else ""
            sections[stack[-1]].setdefault(current_edit, {})
        elif kw == "next" and not nested_depth:
            current_edit = None
        elif kw == "set" and not nested_depth and stack and len(tokens) >= 2:
            target = sections[stack[-1]]
            key = current_edit if current_edit is not None else "__global__"
            target.setdefault(key, {})[tokens[1]] = tokens[2:]
    return sections


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _is_any(values: list[str]) -> bool:
    return any(v.lower() in ANY for v in values)


def _services(p: Policy) -> set[str]:
    return {s.upper() for s in p.values("service")}


def check_policies(policies: list[Policy], wan_intfs: set[str]) -> list[Finding]:
    out: list[Finding] = []
    for p in policies:
        if not p.enabled:
            out.append(Finding("FW-010", "low", "Disabled policy left in rulebase", p.label,
                               "Policy is disabled but still present.",
                               "Remove unused policies after confirming with the owner; keep the rulebase reviewable."))
            continue
        if p.action != "accept":
            continue

        src_any, dst_any = _is_any(p.values("srcaddr")), _is_any(p.values("dstaddr"))
        svc = _services(p)
        svc_any = "ALL" in svc
        from_wan = bool(set(p.values("srcintf")) & wan_intfs)
        to_wan = bool(set(p.values("dstintf")) & wan_intfs)

        if src_any and dst_any and svc_any:
            out.append(Finding("FW-001", "critical" if from_wan else "high",
                               "Any-to-any accept rule", p.label,
                               "Source, destination and service are all unrestricted.",
                               "Replace with explicit source/destination objects and only the services required."))
        elif svc_any:
            out.append(Finding("FW-002", "medium", "Accept rule allows ALL services", p.label,
                               "Service is set to ALL.",
                               "Restrict to the specific services the business flow needs."))

        if from_wan and src_any:
            exposed = (svc & REMOTE_ADMIN_SERVICES) or ({"ALL"} if svc_any else set())
            if exposed:
                out.append(Finding("FW-003", "critical", "Remote access service exposed to the internet", p.label,
                                   f"Inbound from WAN with source 'all' permits: {', '.join(sorted(exposed))}.",
                                   "Remove direct exposure; publish remote access through MFA-protected VPN/ZTNA and restrict sources."))

        insecure = svc & INSECURE_SERVICES
        if to_wan and not from_wan:
            insecure -= {"HTTP"}   # outbound web browsing over HTTP is normal; inspected by web filter
        if insecure:
            out.append(Finding("FW-004", "high" if (from_wan or to_wan) else "medium",
                               "Clear-text or high-risk service permitted", p.label,
                               f"Allows: {', '.join(sorted(insecure))}.",
                               "Use encrypted alternatives (SSH, SFTP, HTTPS, SNMPv3) or tightly scope the rule."))

        if (p.get("logtraffic") or ["utm"])[0] == "disable":
            out.append(Finding("FW-005", "medium", "Logging disabled on accept rule", p.label,
                               "logtraffic is set to disable.",
                               "Enable logging (all or utm) so allowed traffic can be investigated."))

        if to_wan and (p.get("utm-status") or ["disable"])[0] != "enable":
            out.append(Finding("FW-006", "medium", "Internet-bound rule without security profiles", p.label,
                               "No AV / web filter / IPS profiles applied to outbound traffic.",
                               "Apply web filtering, application control, IPS and AV profiles as per policy."))

        if not p.get("comments") and not p.get("name"):
            out.append(Finding("FW-007", "low", "Rule has no name or comment", p.label,
                               "Purpose and owner cannot be determined from the rulebase.",
                               "Record purpose, owner, ticket reference and review date in the comment."))

        if (p.get("schedule") or ["always"])[0] == "always" and "temp" in " ".join(
                (p.get("name") or []) + (p.get("comments") or [])).lower():
            out.append(Finding("FW-008", "medium", "Temporary rule with permanent schedule", p.label,
                               "Rule is labelled temporary but runs on schedule 'always'.",
                               "Attach a one-time schedule with an expiry date or remove the rule."))

    out.extend(check_shadowing(policies))
    return out


def _covers(a: list[str], b: list[str]) -> bool:
    """True if value list `a` covers everything in `b`."""
    return _is_any(a) or set(b) <= set(a)


def check_shadowing(policies: list[Policy]) -> list[Finding]:
    """Flag rules that can never match because an earlier enabled rule covers them.

    FortiOS evaluates policies top-down in the order they appear in the config.
    This is a conservative object-name comparison, not a full address-range
    resolution, so it reports only clear-cut cases.
    """
    out = []
    active = [p for p in policies if p.enabled]
    for i, later in enumerate(active):
        for earlier in active[:i]:
            if all(_covers(earlier.values(k), later.values(k))
                   for k in ("srcintf", "dstintf", "srcaddr", "dstaddr")) and \
                    ("ALL" in _services(earlier) or _services(later) <= _services(earlier)):
                out.append(Finding("FW-009", "medium", "Shadowed rule (never matches)", later.label,
                                   f"Fully covered by earlier {earlier.label}; action here is '{later.action}', "
                                   f"earlier action is '{earlier.action}'.",
                                   "Reorder or remove the rule; confirm intended behaviour with the rule owner."))
                break
    return out


def check_interfaces(interfaces: dict[str, dict]) -> tuple[list[Finding], set[str]]:
    out, wan = [], set()
    for name, attrs in interfaces.items():
        role = (attrs.get("role") or [""])[0]
        if role == "wan":
            wan.add(name)
    for name in wan:
        access = {a.lower() for a in interfaces[name].get("allowaccess", [])}
        weak = access & WEAK_ADMIN_ACCESS
        admin = access & {"https", "ssh", "http", "telnet"}
        if weak:
            out.append(Finding("MGMT-001", "critical", "Clear-text admin protocol on WAN interface", f"interface {name}",
                               f"allowaccess includes {', '.join(sorted(weak))}.",
                               "Remove HTTP/Telnet from all interfaces; manage only from a dedicated management network."))
        elif admin:
            out.append(Finding("MGMT-002", "high", "Administrative access enabled on WAN interface", f"interface {name}",
                               f"allowaccess includes {', '.join(sorted(admin))}.",
                               "Disable admin access on WAN or restrict with trusted hosts and local-in policies."))
    return out, wan


def check_admins(admins: dict[str, dict]) -> list[Finding]:
    out = []
    for name, attrs in admins.items():
        if not any(k.startswith("trusthost") for k in attrs):
            out.append(Finding("MGMT-003", "high", "Administrator without trusted hosts", f"admin account #{_mask(name)}",
                               "Admin account can log in from any source address.",
                               "Set trusthost entries limited to the management network."))
        if not attrs.get("two-factor") or attrs["two-factor"][0] == "disable":
            out.append(Finding("MGMT-004", "medium", "Administrator without MFA", f"admin account #{_mask(name)}",
                               "two-factor is not enabled.",
                               "Enable FortiToken / email / RADIUS-backed MFA for all administrators."))
    return out


def check_global(glob: dict) -> list[Finding]:
    out = []
    g = glob.get("__global__", {})
    timeout = int((g.get("admintimeout") or ["5"])[0])
    if timeout > 15:
        out.append(Finding("MGMT-005", "low", "Long admin idle timeout", "system global",
                           f"admintimeout is {timeout} minutes.", "Set admintimeout to 15 minutes or less."))
    if (g.get("admin-https-redirect") or ["enable"])[0] == "disable":
        out.append(Finding("MGMT-006", "low", "HTTP admin not redirected to HTTPS", "system global",
                           "admin-https-redirect is disabled.", "Enable HTTPS redirect for the admin GUI."))
    return out


def _mask(name: str) -> str:
    """Never echo account names into reports; output a stable short hash instead."""
    import hashlib
    return hashlib.sha256(name.encode()).hexdigest()[:6]


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def audit(text: str) -> list[Finding]:
    cfg = parse_config(text)
    findings, wan = check_interfaces(cfg.get("system interface", {}))
    policies = [Policy(pid, attrs) for pid, attrs in cfg.get("firewall policy", {}).items()]
    findings += check_policies(policies, wan)
    findings += check_admins(cfg.get("system admin", {}))
    findings += check_global(cfg.get("system global", {}))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.obj))
    return findings


def to_markdown(findings: list[Finding], source: str) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines = [f"# Firewall policy audit — `{source}`", "",
             "| Severity | Count |", "|---|---|"]
    lines += [f"| {s.capitalize()} | {c} |" for s, c in counts.items() if c]
    lines += ["", "| ID | Severity | Object | Finding | Recommendation |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.rule_id} | {f.severity} | {f.obj} | **{f.title}.** {f.detail} | {f.recommendation} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config", type=Path)
    ap.add_argument("--json", type=Path, help="write findings as JSON")
    ap.add_argument("--markdown", type=Path, help="write a Markdown report")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any finding at or above this severity")
    args = ap.parse_args(argv)

    findings = audit(args.config.read_text(encoding="utf-8", errors="replace"))
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.rule_id} {f.obj}: {f.title}")
    print(f"\n{len(findings)} finding(s).")

    if args.json:
        args.json.write_text(json.dumps([asdict(f) for f in findings], indent=2))
    if args.markdown:
        args.markdown.write_text(to_markdown(findings, args.config.name))
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
