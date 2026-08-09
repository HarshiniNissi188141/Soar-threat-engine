import json
import os
import time
from dotenv import load_dotenv
import requests

# Secrets load cheydaniki
load_dotenv()

LOG_FILE = "./logs/cowrie.json"
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Local Denylist File (Firewall simulation kosam block aynavi indulo save chestam)
DENYLIST_FILE = "./denylist.txt"


def query_abuseipdb(ip_address):
    """1. Threat Intelligence Lookup (AbuseIPDB API Query)"""
    # Localhost/Docker IP s unte known hacker IP simualte chestam
    if (
        ip_address in ["127.0.0.1", "0.0.0.0"]
        or ip_address.startswith("192.168.")
        or ip_address.startswith("172.")
    ):
        ip_to_check = "118.25.6.39"
    else:
        ip_to_check = ip_address

    if not ABUSEIPDB_KEY or ABUSEIPDB_KEY == "YOUR_ACTUAL_API_KEY_HERE":
        # Key add cheyakapothe simulation data test kosam
        return {
            "score": 95,
            "reports": 320,
            "country": "CN",
            "checked_ip": ip_to_check,
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    params = {"ipAddress": ip_to_check, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "checked_ip": ip_to_check,
            }
        else:
            return {
                "score": 95,
                "reports": 320,
                "country": "CN",
                "checked_ip": ip_to_check,
            }
    except Exception:
        return {
            "score": 95,
            "reports": 320,
            "country": "CN",
            "checked_ip": ip_to_check,
        }


def evaluate_risk(score):
    """2. Detection & Decision Logic (Risk Severity)"""
    if score >= 80:
        return "CRITICAL", "BLOCK_IMMEDIATELY"
    elif score >= 50:
        return "HIGH", "ALERT_AND_MONITOR"
    elif score >= 20:
        return "MEDIUM", "LOG_EVENT"
    else:
        return "LOW", "NO_ACTION"


def take_mitigation_action(ip_address, risk_level, action):
    """3. Automated Mitigation (Local Firewall Denylist Setup)"""
    if action == "BLOCK_IMMEDIATELY":
        print(f"[ACTION TAKEN] 🚫 Blocked IP {ip_address}! Adding to Denylist.")

        # Denylist txt file lo write chestunnam
        with open(DENYLIST_FILE, "a") as f:
            f.write(
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} - BLOCKED IP: {ip_address} | Risk: {risk_level}\n"
            )


def parse_event(raw_line):
    try:
        return json.loads(raw_line.strip())
    except Exception:
        return None


def process_telemetry(event):
    if not event:
        return

    event_id = event.get("eventid", "unknown")
    src_ip = event.get("src_ip", "0.0.0.0")

    if event_id in ["cowrie.login.failed", "cowrie.login.success"]:
        username = event.get("username", "<none>")
        password = event.get("password", "<none>")

        print("\n" + "=" * 60)
        print(f"[🚨 ATTACK DETECTED] SSH Auth Attempt from IP: {src_ip}")
        print(f" Attempted Credentials: Username='{username}' | Password='{password}'")

        # Step 1: Threat Intel Enrichment
        print("[*] Querying Threat Intelligence (AbuseIPDB)...")
        intel = query_abuseipdb(src_ip)
        checked_ip = intel.get("checked_ip", src_ip)
        score = intel.get("score", 0)

        print(f"[THREAT INTEL] Target IP: {checked_ip} | Abuse Score: {score}%")

        # Step 2: Risk Evaluation Decision
        risk_level, recommended_action = evaluate_risk(score)
        print(
            f"[DECISION ENGINE] Risk Severity: {risk_level} | Action: {recommended_action}"
        )

        # Step 3: Automated Mitigation Response
        take_mitigation_action(checked_ip, risk_level, recommended_action)
        print("=" * 60)


def monitor_logs():
    print("=" * 60)
    print("      🛡️  AUTOMATED THREAT DETECTION & SOAR ENGINE  🛡️")
    print("=" * 60)
    print(f"[*] Engine Status: ACTIVE")
    print(f"[*] Monitoring Honeypot Logs: {LOG_FILE}\n")

    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file {LOG_FILE} not found! Make sure Honeypot is running.")
        return

    with open(LOG_FILE, "r") as f:
        # File lo unna previous records fast check
        for line in f:
            event_data = parse_event(line)
            process_telemetry(event_data)

        # Real-time ongoing attacks monitoring
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            event_data = parse_event(line)
            process_telemetry(event_data)


if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("\n[*] Stopping SOAR Engine... Shutdown complete.")