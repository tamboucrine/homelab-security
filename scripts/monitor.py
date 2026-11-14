#!/usr/bin/env python3
import re
import os
from datetime import datetime
from collections import defaultdict

AUTH_LOG = "/var/log/auth.log"
WEB_LOG = "/var/log/nginx/access.log"
ALERT_LOG = os.path.expanduser("~/soc-tools/alerts.log")

SSH_THRESHOLD = 5
WEB_THRESHOLD = 10

WEB_ATTACK_PATTERNS = {
    "SQL Injection": re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(union.*select)|(select.*from)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./)|(\.\.%2f)|(etc/passwd)|(boot\.ini)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>)|(%3Cscript%3E)|(javascript:)", re.IGNORECASE),
}

def check_ssh():
    pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    attempts = defaultdict(list)
    with open(AUTH_LOG, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                user, ip = match.groups()
                attempts[ip].append(user)

    alerts = []
    for ip, users in attempts.items():
        if len(users) >= SSH_THRESHOLD:
            alerts.append(f"[SSH BRUTE FORCE] {ip} - {len(users)} percobaan gagal, user: {', '.join(set(users))}")
    return alerts

def check_web():
    pattern = re.compile(r'(\S+) - - \[.*?\] ".*?" 404')
    not_found = defaultdict(int)
    with open(WEB_LOG, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                not_found[match.group(1)] += 1

    alerts = []
    for ip, count in not_found.items():
        if count >= WEB_THRESHOLD:
            alerts.append(f"[WEB SCANNING] {ip} - {count} request 404")
    return alerts

def check_web_attacks():
    findings = defaultdict(list)
    with open(WEB_LOG, "r") as f:
        for line in f:
            match = re.match(r'(\S+) - - \[.*?\] "(.*?)"', line)
            if not match:
                continue
            ip, request = match.groups()
            for attack_type, pattern in WEB_ATTACK_PATTERNS.items():
                if pattern.search(request):
                    findings[ip].append(attack_type)

    alerts = []
    for ip, types in findings.items():
        unique_types = set(types)
        alerts.append(f"[WEB ATTACK PATTERN] {ip} - {len(types)} percobaan, jenis: {', '.join(unique_types)}")
    return alerts

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_alerts = check_ssh() + check_web() + check_web_attacks()

    with open(ALERT_LOG, "a") as f:
        if all_alerts:
            for alert in all_alerts:
                line = f"{timestamp} {alert}"
                print(line)
                f.write(line + "\n")
        else:
            print(f"{timestamp} Tidak ada anomali terdeteksi.")

if __name__ == "__main__":
    main()
