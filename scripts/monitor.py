#!/usr/bin/env python3
import re
import os
import json
from datetime import datetime
from collections import defaultdict

AUTH_LOG = "/var/log/auth.log"
WEB_LOG = "/var/log/nginx/access.log"
ALERT_LOG = os.path.expanduser("~/soc-tools/alerts.log")
STATE_FILE = os.path.expanduser("~/soc-tools/state.json")

SSH_THRESHOLD = 5
WEB_THRESHOLD = 10

WEB_ATTACK_PATTERNS = {
    "SQL Injection": re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(union.*select)|(select.*from)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./)|(\.\.%2f)|(etc/passwd)|(boot\.ini)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>)|(%3Cscript%3E)|(javascript:)", re.IGNORECASE),
}

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"ssh": {}, "web_scan": {}, "web_attack": {}}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def check_ssh(state):
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
        count = len(users)
        if count >= SSH_THRESHOLD:
            last_count = state["ssh"].get(ip, 0)
            if count > last_count:
                new_attempts = count - last_count
                alerts.append(f"[SSH BRUTE FORCE] {ip} - {count} percobaan gagal total ({new_attempts} baru), user: {', '.join(set(users))}")
                state["ssh"][ip] = count
    return alerts

def check_web(state):
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
            last_count = state["web_scan"].get(ip, 0)
            if count > last_count:
                new_requests = count - last_count
                alerts.append(f"[WEB SCANNING] {ip} - {count} request 404 total ({new_requests} baru)")
                state["web_scan"][ip] = count
    return alerts

def check_web_attacks(state):
    findings = defaultdict(set)
    with open(WEB_LOG, "r") as f:
        for line in f:
            match = re.match(r'(\S+) - - \[.*?\] "(.*?)"', line)
            if not match:
                continue
            ip, request = match.groups()
            for attack_type, pattern in WEB_ATTACK_PATTERNS.items():
                if pattern.search(request):
                    findings[ip].add(attack_type)

    alerts = []
    for ip, types in findings.items():
        known_types = set(state["web_attack"].get(ip, []))
        new_types = types - known_types
        if new_types:
            alerts.append(f"[WEB ATTACK PATTERN] {ip} - jenis baru terdeteksi: {', '.join(new_types)}")
            state["web_attack"][ip] = list(types | known_types)
    return alerts

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state = load_state()

    all_alerts = check_ssh(state) + check_web(state) + check_web_attacks(state)

    with open(ALERT_LOG, "a") as f:
        if all_alerts:
            for alert in all_alerts:
                line = f"{timestamp} {alert}"
                print(line)
                f.write(line + "\n")
        else:
            print(f"{timestamp} Tidak ada anomali baru terdeteksi.")

    save_state(state)

if __name__ == "__main__":
    main()
