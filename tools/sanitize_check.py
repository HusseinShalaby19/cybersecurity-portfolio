#!/usr/bin/env python3
"""
Pre-publish sanitization scanner.

Fails (exit 1) if the repository contains anything that should not be public:
  - IPv4 addresses outside private (RFC 1918), CGNAT (RFC 6598) and
    documentation (RFC 5737) ranges
  - e-mail addresses
  - private keys, cloud/API tokens, or password assignments that are not
    clearly placeholders
  - any term in a local, git-ignored deny-list (client names, real hostnames,
    domains, people) - put one term per line in .sanitize-denylist.txt

Usage:  python tools/sanitize_check.py [path]
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ALLOWED_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",      # RFC 1918
    "100.64.0.0/10",                                       # RFC 6598 (CGNAT)
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # RFC 5737 documentation
    "127.0.0.0/8", "0.0.0.0/8", "255.0.0.0/8",             # loopback, wildcards, masks
)]
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}
SKIP_FILES = {".sanitize-denylist.txt"}
TEXT_EXT = {".md", ".py", ".ps1", ".psm1", ".yml", ".yaml", ".conf", ".cfg", ".csv", ".json", ".txt", ".html", ""}

IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RES = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?([^\s'\"<>]{6,})"), "credential assignment"),
]
PLACEHOLDER = re.compile(r"(?i)placeholder|example|redacted|changeme|<|\$|\*\*\*")
ALLOWED_EMAILS = {"noreply@anthropic.com"}


def scan(root: Path) -> list[str]:
    deny_file = root / ".sanitize-denylist.txt"
    deny = [t.strip() for t in deny_file.read_text().splitlines()
            if t.strip() and not t.startswith("#")] if deny_file.exists() else []
    problems = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name in SKIP_FILES or any(d in p.parts for d in SKIP_DIRS):
            continue
        if p.suffix.lower() not in TEXT_EXT:
            continue
        rel = p.relative_to(root)
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in IP_RE.finditer(line):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                if not any(ip in net for net in ALLOWED_NETS):
                    problems.append(f"{rel}:{n}: public IP address {ip}")
            for m in EMAIL_RE.finditer(line):
                if m.group(0).lower() not in ALLOWED_EMAILS:
                    problems.append(f"{rel}:{n}: e-mail address")
            for rx, label in SECRET_RES:
                m = rx.search(line)
                if m and not (label == "credential assignment" and PLACEHOLDER.search(m.group(0))):
                    problems.append(f"{rel}:{n}: possible {label}")
            low = line.lower()
            for term in deny:
                if term.lower() in low:
                    problems.append(f"{rel}:{n}: deny-listed term (#{deny.index(term) + 1})")
    return problems


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    problems = scan(root)
    for line in problems:
        print(line)
    print(f"\n{'FAIL' if problems else 'PASS'}: {len(problems)} issue(s) found.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
