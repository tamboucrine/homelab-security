#!/usr/bin/env python3
import re
from collections import defaultdict

LOG_FILE = "/var/log/nginx/access.log"
THRESHOLD = 10  # jumlah request 404 dianggap scanning

def parse_404(log_file):
    pattern = re.compile(r'(\S+) - - \[.*?\] ".*?" 404')
    not_found = defaultdict(int)

    with open(log_file, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                not_found[ip] += 1

    return not_found

def main():
    results = parse_404(LOG_FILE)

    print("=== Web Scanning Detection Report ===\n")

    if not results:
        print("Tidak ada request 404 yang terdeteksi.")
        return

    for ip, count in results.items():
        status = "MENCURIGAKAN (kemungkinan scanning)" if count >= THRESHOLD else "normal"
        print(f"IP: {ip}")
        print(f"  Jumlah request 404: {count}")
        print(f"  Status            : {status}")
        print("-" * 40)

if __name__ == "__main__":
    main()
