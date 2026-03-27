import time
import re
from datetime import datetime
from collections import defaultdict

# =========================
# COLORS 🎨
# =========================

RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# =========================
# CONFIG
# =========================

AUDIT_LOG = "/var/log/audit/audit.log"
AUTH_LOG = "/var/log/auth.log"

CRITICAL_FILES = ["/etc/shadow", "/etc/sudoers"]

# =========================
# SOURCE IP (AUTH LOG)
# =========================

def get_source_ip():
    try:
        with open(AUTH_LOG, "r") as f:
            lines = f.readlines()

        for line in reversed(lines):
            if "Accepted" in line:
                match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    return match.group(1)

        return "LOCAL"
    except:
        return "UNKNOWN"

# =========================
# SESSION TYPE
# =========================

def get_session_type():
    return "REMOTE (SSH)" if get_source_ip() != "LOCAL" else "LOCAL"

# =========================
# DETECTION ENGINE 🔥
# =========================

def detect_event(line):
    alerts = []

    # 🔥 FILE ACCESS
    if "type=PATH" in line:
        match = re.search(r'name="([^"]+)"', line)
        if match:
            file = match.group(1)

            if file in CRITICAL_FILES:
                alerts.append({
                    "type": "CRITICAL_FILE_ACCESS",
                    "file": file,
                    "mitre": "T1003",
                    "severity": "HIGH"
                })

    # 🔥 PERMISSION CHANGE (chmod)
    if "chmod" in line or "fchmod" in line:
        match = re.search(r'name="([^"]+)"', line)
        if match:
            file = match.group(1)

            if file in CRITICAL_FILES:
                alerts.append({
                    "type": "FILE_PERMISSION_MODIFIED",
                    "file": file,
                    "mitre": "T1222",
                    "severity": "CRITICAL"
                })

    return alerts

# =========================
# BEHAVIOR TRACKING
# =========================

class BehaviorTracker:
    def __init__(self):
        self.activity = defaultdict(int)

    def score(self, key):
        self.activity[key] += 1
        return self.activity[key]

# =========================
# DISPLAY 🎨
# =========================

def print_alert(alert, score):
    ip = get_source_ip()
    session = get_session_type()

    color = RED if alert["severity"] in ["HIGH", "CRITICAL"] else YELLOW

    print(f"\n{color}🚨 SECURITY ALERT 🚨{RESET}")
    print(f"{CYAN}Type:{RESET} {alert['type']}")
    print(f"{CYAN}File:{RESET} {alert['file']}")
    print(f"{CYAN}MITRE:{RESET} {alert['mitre']}")
    print(f"{CYAN}Severity:{RESET} {color}{alert['severity']}{RESET}")
    print(f"{CYAN}Behavior Score:{RESET} {score}")

    print(f"{YELLOW}--- Investigation Data ---{RESET}")
    print(f"{CYAN}Source IP:{RESET} {ip}")
    print(f"{CYAN}Session Type:{RESET} {session}")
    print(f"{CYAN}Time:{RESET} {datetime.now().isoformat()}")

    print(f"{color}{'-'*50}{RESET}")

# =========================
# MAIN LOOP
# =========================

def main():
    print(f"{GREEN}🟢 Watchdog Started (FIM + Detection Mode){RESET}")

    tracker = BehaviorTracker()

    try:
        with open(AUDIT_LOG, "r") as f:
            f.seek(0, 2)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.1)
                    continue

                alerts = detect_event(line)

                for alert in alerts:
                    score = tracker.score(alert["file"])
                    print_alert(alert, score)

    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    main()