import os
import re
import argparse
import requests
from tabulate import tabulate
import json

BASE_DIR = os.path.dirname(__file__)
TEST_DIR = os.path.join(BASE_DIR, "test_files")
STATUS_FILE = os.path.join(BASE_DIR, "alert_status.json")

def load_statuses():
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_statuses():
    with open(STATUS_FILE, "w") as f:
        json.dump(ALERT_STATUSES, f)

# Alert state: open, false_positive, active, revoked
ALERTS = []
ALERT_STATUSES = {}

# Patterns
password_pattern = re.compile(r"(?:password|pwd)\s*[:=]\s*['\"]?(.+?)['\"]?$", re.IGNORECASE)
url_pattern = re.compile(r"url\s*=\s*(http[s]?://[^\s]+)", re.IGNORECASE)
username_pattern = re.compile(r"username\s*=\s*([^\s]+)", re.IGNORECASE)
dummy_patterns = [r"password\d*", r"1234", r"abcd", r"pass", r"admin", r"test"]

def fetch_alerts():
    alerts = []
    aid = 1
    for fname in sorted(os.listdir(TEST_DIR)):
        fpath = os.path.join(TEST_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        with open(fpath, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if password_pattern.search(line):
                    alerts.append({"alert_id": aid, "path": fname, "line": lineno})
                    if str(aid) not in ALERT_STATUSES:
                        ALERT_STATUSES[str(aid)] = "open"
                    aid += 1
    return alerts

def get_alert(aid):
    return next((a for a in ALERTS if a["alert_id"] == aid), None)

def extract_line(path, line_no):
    full = os.path.join(TEST_DIR, path)
    with open(full, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
        return lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

def is_commented(line):
    return line.strip().startswith("#")

def extract_password(line):
    m = password_pattern.search(line)
    return m.group(1) if m else ""

def detect_dummy_password(pwd):
    return any(re.search(p, pwd, re.IGNORECASE) for p in dummy_patterns)

def extract_metadata(path):
    full = os.path.join(TEST_DIR, path)
    url = username = None
    with open(full, "r", encoding="utf-8") as f:
        for line in f:
            if not url:
                u_match = url_pattern.search(line)
                if u_match:
                    url = u_match.group(1)
            if not username:
                n_match = username_pattern.search(line)
                if n_match:
                    username = n_match.group(1)
            if url and username:
                break
    return url, username

def classify(aid, silent=False):
    alert = get_alert(aid)
    if not alert:
        print(f"Alert #{aid} not found.")
        return

    line = extract_line(alert["path"], alert["line"])
    pwd = extract_password(line)
    reasons = []

    if is_commented(line):
        reasons.append("Line is commented out.")
    if detect_dummy_password(pwd):
        reasons.append("Matches dummy password pattern.")

    if reasons:
        if not silent:
            print(f"Alert #{aid} is a FALSE POSITIVE")
            for r in reasons:
                print(f"- {r}")
        return "false_positive"
    else:
        if not silent:
            print(f"Alert #{aid} is a POTENTIAL VALID EXPOSURE")
        return "valid_exposure"


def close_fp(aid):
    if ALERT_STATUSES.get(str(aid)) != "open":
        print(f"Alert #{aid} is not open. Current status: {ALERT_STATUSES.get(str(aid))}")
        return
    result = classify(aid, silent=True)
    if result == "false_positive":
        ALERT_STATUSES[str(aid)] = "FALSE_POSITIVE"
        print(f"Alert #{aid} closed as false positive.")
    else:
        print("Not a false positive. Cannot close as such.")

def check_active(aid):
    alert = get_alert(aid)
    if not alert:
        print(f"Alert #{aid} not found.")
        return

    if ALERT_STATUSES.get(str(aid)) != "open":
        print(f"Alert #{aid} is not open. Current status: {ALERT_STATUSES.get(str(aid))}")
        return

    line = extract_line(alert["path"], alert["line"])
    pwd = extract_password(line)
    url, username = extract_metadata(alert["path"])

    if not url or not username:
        print(f"Could not extract URL or username from {alert['path']}.")
        return

    payload = {"username": username, "password": pwd}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            ALERT_STATUSES[str(aid)] = "active"
            print(f"Password is in use — needs remediation.")
        else:
            print(f"Password no longer in use — the alert can be revoked.")

    except Exception as e:
        print(f"Error testing credentials: {e}")

def revoke(aid):
    status = ALERT_STATUSES.get(str(aid))
    if status == "revoked":
        print(f"Alert #{aid} is already revoked.")
    elif status == "active":
        print(f"Cannot revoke alert #{aid} — password still in use.")
    else:
        ALERT_STATUSES[str(aid)] = "REVOKED"
        print(f"Alert #{aid} revoked.")

def list_alerts():
    rows = []
    for alert in ALERTS:
        aid = alert["alert_id"]
        status = ALERT_STATUSES.get(str(aid), "open")
        rows.append((aid, alert["path"], alert["line"], status))
    print(tabulate(rows, headers=["ID", "File", "Line", "Status"], tablefmt="github"))

def show_status(aid):
    status = ALERT_STATUSES.get(str(aid))
    if status:
        print(f"Alert #{aid} status: {status}")
    else:
        print(f"Alert #{aid} not found.")

def reset_statuses():
    for alert in ALERTS:
        ALERT_STATUSES[str(alert["alert_id"])] = "open"
    save_statuses()
    print("All alert statuses have been reset to 'open'.")

if __name__ == "__main__":
    ALERT_STATUSES.update(load_statuses())
    ALERTS = fetch_alerts()

    parser = argparse.ArgumentParser(description="Secret Remediation CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("reset")
    
    sub.add_parser("list")
    classify_p = sub.add_parser("classify"); classify_p.add_argument("id", type=int)
    close_fp_p = sub.add_parser("close-fp"); close_fp_p.add_argument("id", type=int)
    check_p = sub.add_parser("check-active"); check_p.add_argument("id", type=int)
    revoke_p = sub.add_parser("revoke"); revoke_p.add_argument("id", type=int)
    status_p = sub.add_parser("status"); status_p.add_argument("id", type=int)

    args = parser.parse_args()

    if args.cmd == "list":
        list_alerts()
    elif args.cmd == "classify":
        classify(args.id)
    elif args.cmd == "close-fp":
        close_fp(args.id)
        save_statuses()
    elif args.cmd == "check-active":
        check_active(args.id)
        save_statuses()
    elif args.cmd == "revoke":
        revoke(args.id)
        save_statuses()
    elif args.cmd == "status":
        show_status(args.id)
    elif args.cmd == "reset":
        reset_statuses()
