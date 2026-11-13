#!/usr/bin/env python3
import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5  # jumlah gagal login dianggap mencurigakan

def parse_failed_logins(log_file):
    pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    failed_attempts = defaultdict(list)

    with open(log_file, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                user, ip = match.groups()
                failed_attempts[ip].append(user)

    return failed_attempts

def main():
    attempts = parse_failed_logins(LOG_FILE)

    print("=== SSH Brute Force Detection Report ===\n")

    if not attempts:
        print("Tidak ada percobaan login gagal yang terdeteksi.")
        return

    for ip, users in attempts.items():
        total = len(users)
        status = "MENCURIGAKAN" if total >= THRESHOLD else "normal"
        print(f"IP: {ip}")
        print(f"  Jumlah percobaan gagal: {total}")
        print(f"  Username yang dicoba : {', '.join(set(users))}")
        print(f"  Status               : {status}")
        print("-" * 40)

if __name__ == "__main__":
    main()
