#!/usr/bin/env python3
"""
cmloot_analyze.py - Targeted credential extractor for SCCM Content Library loot.

Only surfaces actionable findings: credentials, keys, tokens, service accounts,
and infrastructure references that directly lead to further access.

Usage:
    python3 cmloot_analyze.py CMLootOut/
    python3 cmloot_analyze.py CMLootOut/ --severity critical high
    python3 cmloot_analyze.py CMLootOut/ --json --out findings.json
"""

import os
import re
import sys
import json
import argparse
from collections import defaultdict

RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]

RULES = {
    "CRITICAL": [
        ("Cleartext password (key=value)",
         r'(?i)(?:password|passwd|pwd|wachtwoord)\s*[=:]\s*["\']?([^\s"\';<>]{4,})'),
        ("Cleartext password (XML attribute)",
         r'(?i)(?:password|passwd|pwd|wachtwoord)\s*=\s*["\']([^"\']+?)["\']'),
        ("PSCredential / SecureString usage",
         r'(?i)(?:ConvertTo-SecureString|New-Object\s+System\.Management\.Automation\.PSCredential|Get-Credential|PSCredential|Read-Host\s+-AsSecureString)'),
        ("Connection string with embedded credentials",
         r'(?i)(?:Server|Data Source|Address|Addr)\s*=\s*[^;"]+?(?:;|)(?:Password|Pwd|User\s+ID|Uid|Integrated\s+Security\s*=\s*(?:True|SSPI))[^"\']*'),
        ("net use with explicit credentials",
         r'(?i)net\s+use\s+\S+.*(?:/user[:\s]|/password[:\s]|/p[:\s])\s*(\S+)'),
        ("Private key material",
         r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|<RSAKeyValue'),
        ("Certificate blob (X509)",
         r'<X509Certificate[^>]*>[A-Za-z0-9+/=]{80,}'),
        ("Encryption/AES key (hex)",
         r'(?i)(?:aes|encryption)\s*(?:key|iv)\s*[=:]\s*["\']?([0-9A-Fa-f]{16,})'),
        ("API key / token / secret",
         r'(?i)(?:api[_-]?key|apikey|bearer|secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']?(\S{8,})'),
    ],
    "HIGH": [
        ("LDAP bind path",
         r'(?:LDAP|GC)://[^\s<>"\']{10,}'),
        ("SQL/DB connection string",
         r'(?i)(?:connectionstring|connstring|connection_string)\s*[=:]\s*["\']?(\S{10,}?)["\']?;?\s*$'),
        ("MDT domain join credential",
         r'(?i)(?:DomainAdmin|DomainAdminPassword|DomainAdminDomain|MachinePassword)\s*[=:]\s*["\']?([^\s"\'<>]{3,})'),
        ("MDT local admin credential",
         r'(?i)(?:AdministratorPassword|LocalAdminPassword|AdminPassword)\s*[=:]\s*["\']?([^\s"\'<>]{3,})'),
        ("MDT join domain/target",
         r'(?i)(?:JoinDomain|MachineObjectOU|UserDomain|UserID)\s*[=:]\s*["\']?([^\s"\'<>]{3,})'),
        ("Network Access Account (NAA)",
         r'(?i)(?:NetworkAccessAccount|NAAAccount|Client\s*Push\s*Account)\s*[=:]\s*["\']?(\S+)'),
        ("Credential in XML/INI attribute",
         r'(?i)(?:password|credential|secret|apikey|token)\s*=\s*["\']([^"\']{3,}?)["\']'),
        ("Symantec/AV management server",
         r'(?i)(?:sylink|epo\.config)\s*[=:]\s*["\']?(https?://[^\s"\'<>]+)'),
        ("SCCM site code",
         r'(?i)SiteCode\s*[=:]\s*["\']?([A-Z0-9]{3})["\']?'),
        ("RunAs with service account",
         r'(?i)(?:RunAs|ServiceAccount|LogOnAs)\s*[=:]\s*["\']?([^\s"\'<>]+)',
         r'(?i)RunAs\s+\S+\s+/\S*user:\s*(\S+)'),
    ],
    "MEDIUM": [
        ("Internal domain (FQDN)",
         r'(?i)([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:local|corp|internal|lab|test|intra|pri|domain)\b)'),
        ("Service account (dollar sign)",
         r'([a-zA-Z][a-zA-Z0-9_-]{1,30}\$)'),
        ("ADMIN$ / C$ share reference",
         r'(?:\\\\[^\s<>"\'\\]+\\(?:ADMIN\$|C\$|IPC\$))'),
        ("Cert thumbprint",
         r'(?i)(?:certthumbprint|certificatehash|thumbprint)\s*[=:]\s*["\']?([A-Fa-f0-9]{40,})'),
    ],
}

NOISE_VALUES = {
    "", "true", "false", "none", "null", "0", "1", "yes", "no",
    "password", "passwd", "pwd", "secret", "token", "key", "credential",
    "********", "******", "*****", "****", "**********",
    "changeme", "changeme!", "password1", "password123", "test", "default",
    "~", "-", "--", "na", "n/a", "notset", "not set", "not_set",
    "enabled", "disabled", "inherit", "parent",
}

NOISE_PATTERNS = [
    r'(?i)^https?://(www\.)?microsoft\.com',
    r'(?i)^https?://(www\.)?w3\.org',
    r'(?i)^https?://schemas\.microsoft\.com',
    r'(?i)^https?://go\.microsoft\.com',
    r'(?i)^urn:schemas-microsoft-com',
    r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$',
    r'(?i)^\{[0-9A-Fa-f]{8}-',
    r'(?i)^https?://schemas\.xmlsoap\.org',
]

compiled_noise = [re.compile(p) for p in NOISE_PATTERNS]

SKIP_EXTENSIONS = {".exe", ".dll", ".sys", ".msi", ".msu", ".mui", ".cat", ".ppd", ".cab"}

SCAN_EXTENSIONS = {
    ".xml", ".ini", ".config", ".ps1", ".ps1xml", ".vbs", ".bat", ".cmd",
    ".psm1", ".psd1", ".json", ".yaml", ".yml", ".inf", ".provxml", ".mof",
}


def is_scannable(filepath):
    _, ext = os.path.splitext(filepath)
    if ext.lower() in SKIP_EXTENSIONS:
        return False
    if ext.lower() in SCAN_EXTENSIONS:
        return True
    try:
        with open(filepath, 'rb') as f:
            head = f.read(2048)
        return b'\x00' not in head
    except Exception:
        return False


def is_noise(value):
    if not value:
        return True
    v = value.strip().strip('"\'').strip()
    if v.lower() in NOISE_VALUES:
        return True
    if len(v) < 3:
        return True
    for p in compiled_noise:
        if p.match(v):
            return True
    return False


def scan_file(filepath, compiled_rules):
    hits = []
    try:
        with open(filepath, 'r', errors='replace', encoding='utf-8-sig') as f:
            lines = f.readlines()
    except Exception:
        return hits

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or len(stripped) < 5:
            continue

        for severity in SEVERITY_ORDER:
            for label, pattern in compiled_rules[severity]:
                m = pattern.search(stripped)
                if not m:
                    continue

                groups = [g for g in m.groups() if g] if m.groups() else []
                value = groups[0] if groups else m.group(0)
                value = value.strip().strip('"\'').strip()

                if is_noise(value):
                    continue

                line_preview = stripped[:250]
                hits.append({
                    "line_no": i,
                    "severity": severity,
                    "label": label,
                    "value": value[:200],
                    "full_line": line_preview,
                })
                break

    return hits


def format_size(size):
    if size < 1024:
        return f"{size}B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f}KB"
    else:
        return f"{size/(1024*1024):.1f}MB"


def main():
    parser = argparse.ArgumentParser(
        description="Extract credentials from CMLoot downloads",
        epilog="Examples:\n"
               "  python3 cmloot_analyze.py CMLootOut/\n"
               "  python3 cmloot_analyze.py CMLootOut/ --severity critical high\n"
               "  python3 cmloot_analyze.py CMLootOut/ --json --out findings.json",
    )
    parser.add_argument('lootdir', help='CMLoot output directory')
    parser.add_argument('--severity', nargs='*', default=None,
                        help='Filter: CRITICAL HIGH MEDIUM (default: all)')
    parser.add_argument('--ext', nargs='*', default=None,
                        help='Only scan these extensions (e.g. XML PS1 VBS)')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--out', default=None, help='Write report to file')
    parser.add_argument('--no-color', action='store_true', help='No colors')
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()
    filter_sev = set(s.upper() for s in args.severity) if args.severity else set(SEVERITY_ORDER)
    filter_ext = set(e.lower().lstrip('.') for e in args.ext) if args.ext else None
    lootdir = args.lootdir.rstrip(os.sep)

    if not os.path.isdir(lootdir):
        print(f"Error: {lootdir} is not a directory")
        sys.exit(1)

    compiled_rules = {}
    for severity, rules in RULES.items():
        compiled_rules[severity] = []
        for entry in rules:
            label = entry[0]
            patterns = entry[1:]
            for pat in patterns:
                compiled_rules[severity].append((label, re.compile(pat)))

    all_files = sorted([f for f in os.listdir(lootdir)
                        if os.path.isfile(os.path.join(lootdir, f)) and not f.startswith('_')])
    scannable = []
    for fname in all_files:
        fpath = os.path.join(lootdir, fname)
        _, ext = os.path.splitext(fname)
        if filter_ext and ext.lower().lstrip('.') not in filter_ext:
            continue
        if is_scannable(fpath):
            scannable.append(fname)

    if not scannable:
        print("No scannable files found.")
        sys.exit(0)

    print(f"Scanning {len(scannable)} files in {lootdir}/ ...\n")

    results = []
    sev_counts = defaultdict(int)

    for fname in scannable:
        fpath = os.path.join(lootdir, fname)
        hits = scan_file(fpath, compiled_rules)

        filtered = [h for h in hits if h["severity"] in filter_sev]
        if not filtered:
            continue

        seen_values = defaultdict(set)
        deduped = []
        for h in filtered:
            dedup_key = (h["label"], h["value"].lower())
            if dedup_key in seen_values[h["label"]]:
                continue
            seen_values[h["label"]].add(dedup_key)
            deduped.append(h)
            sev_counts[h["severity"]] += 1

        if deduped:
            results.append({
                "file": fname,
                "size": os.path.getsize(fpath),
                "hits": deduped,
            })

    results.sort(key=lambda x: (
        min(SEVERITY_ORDER.index(h["severity"]) for h in x["hits"]),
        -len(x["hits"]),
    ))

    total_hits = sum(len(r["hits"]) for r in results)

    if args.json:
        json_out = []
        for r in results:
            for h in r["hits"]:
                json_out.append({
                    "severity": h["severity"],
                    "label": h["label"],
                    "file": r["file"],
                    "line": h["line_no"],
                    "value": h["value"],
                    "context": h["full_line"],
                })
        print(json.dumps(json_out, indent=2))
        if args.out:
            with open(args.out, 'w') as f:
                json.dump(json_out, f, indent=2)
            print(f"\nWritten to {args.out}", file=sys.stderr)
        sys.exit(0)

    sev_color = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": CYAN}

    for r in results:
        fname = r["file"]
        fsize = format_size(r["size"])
        top_sev = min((SEVERITY_ORDER.index(h["severity"]) for h in r["hits"]))
        top_label = SEVERITY_ORDER[top_sev]
        marker = " <<<" if top_label in ("CRITICAL", "HIGH") else ""

        if use_color:
            print(f"{BOLD}{fname}{RESET}  ({fsize}){marker}")
        else:
            print(f"--- {fname}  ({fsize}){marker} ---")

        for h in r["hits"]:
            sev = h["severity"]
            label = h["label"]
            value = h["value"]
            line_no = h["line_no"]

            if use_color:
                c = sev_color.get(sev, "")
                print(f"  L{line_no:>4d} [{c}{sev}{RESET}] {label}")
                print(f"         {DIM}{value}{RESET}")
            else:
                print(f"  L{line_no:>4d} [{sev}] {label}")
                print(f"         {value}")

        print()

    print("=" * 60)
    print(f"  {total_hits} unique hits in {len(results)}/{len(scannable)} files")
    for sev in SEVERITY_ORDER:
        if sev in filter_sev:
            cnt = sev_counts.get(sev, 0)
            if use_color:
                print(f"  {sev_color.get(sev, '')}{sev}{RESET}: {cnt}")
            else:
                print(f"  {sev}: {cnt}")
    print("=" * 60)

    if sev_counts.get("CRITICAL", 0) > 0:
        print("  >>> CRITICAL: plaintext credentials found <<<")
    elif sev_counts.get("HIGH", 0) > 0:
        print("  >>> HIGH: likely credential or infrastructure references <<<")

    if args.out:
        with open(args.out, 'w') as rf:
            rf.write(f"CMLoot Analysis — {len(scannable)} files, {total_hits} unique hits\n\n")
            for r in results:
                rf.write(f"--- {r['file']}  ({format_size(r['size'])}) ---\n")
                for h in r["hits"]:
                    rf.write(f"  L{h['line_no']:4d} [{h['severity']}] {h['label']}\n")
                    rf.write(f"         {h['value']}\n")
                rf.write("\n")
        print(f"\nReport written to {args.out}")


if __name__ == "__main__":
    main()
