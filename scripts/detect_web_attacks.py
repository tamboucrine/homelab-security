#!/usr/bin/env python3
import re
from collections import defaultdict

LOG_FILE = "/var/log/nginx/access.log"

PATTERNS = {
    "SQL Injection": re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(union.*select)|(select.*from)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./)|(\.\.%2f)|(etc/passwd)|(boot\.ini)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>)|(%3Cscript%3E)|(javascript:)", re.IGNORECASE),
}

def parse_log():
    findings = defaultdict(list)
    with open(LOG_FILE, "r") as f:
        for line in f:
            match = re.match(r'(\S+) - - \[.*?\] "(.*?)"', line)
            if not match:
                continue
            ip, request = match.groups()
            for attack_type, pattern in PATTERNS.items():
                if pattern.search(request):
                    findings[ip].append((attack_type, request))
    return findings

def main():
    findings = parse_log()
    if not findings:
        print("Tidak ada pola serangan web yang terdeteksi.")
        return

    for ip, hits in findings.items():
        print(f"\nIP: {ip}")
        print(f"  Jumlah percobaan mencurigakan: {len(hits)}")
        types = set(h[0] for h in hits)
        print(f"  Jenis serangan terdeteksi : {', '.join(types)}")
        print(f"  Status                    : MENCURIGAKAN")
        for attack_type, request in hits[:3]:
            print(f"    [{attack_type}] {request}")

if __name__ == "__main__":
    main()
