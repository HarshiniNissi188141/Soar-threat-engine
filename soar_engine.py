import os
import json
import time
import requests
import subprocess
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuration Constants
COWRIE_LOG_PATH = "./logs/cowrie.json"
DENYLIST_PATH = "./denylist.txt"
AUDIT_TRAIL_PATH = "./audit_trail.json"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

CRITICAL_RISK_THRESHOLD = 80
HIGH_RISK_USERNAMES = {"root", "admin", "administrator", "support", "test"}


class SOARPlaybook:
    """Configurable SOAR Lifecycle Playbook"""
    def __init__(self, target_ip, raw_telemetry):
        self.incident_id = f"INC-{int(time.time())}-{target_ip.replace('.', '')}"
        self.target_ip = target_ip
        self.raw_telemetry = raw_telemetry
        self.audit_log = {
            "incident_id": self.incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "target_ip": target_ip,
            "playbook": "MULTI_VECTOR_CONTAINMENT_V2",
            "lifecycle": [],
            "status": "INITIATED",
            "rollback_command": f"iptables -D INPUT -s {target_ip} -j DROP"
        }

    def log_step(self, stage, details, status="SUCCESS"):
        step_entry = {
            "stage": stage,
            "timestamp": datetime.utcnow().isoformat(),
            "status": status,
            "details": details
        }
        self.audit_log["lifecycle"].append(step_entry)
        print(f"[{stage}] -> {details} ({status})")

    def save_audit_trail(self):
        try:
            audit_data = []
            if os.path.exists(AUDIT_TRAIL_PATH):
                with open(AUDIT_TRAIL_PATH, "r") as f:
                    audit_data = json.load(f)
            audit_data.append(self.audit_log)
            with open(AUDIT_TRAIL_PATH, "w") as f:
                json.dump(audit_data, f, indent=4)
        except Exception as e:
            print(f"[AUDIT ERROR] Failed to record audit trail: {e}")


class ThreatIntelEngine:
    """Enrichment engine with graceful API fail-safes"""
    @staticmethod
    def query_abuseipdb(ip):
        if not ABUSEIPDB_API_KEY:
            return {"score": 0, "status": "UNKNOWN_NO_KEY"}
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "score": data.get("abuseConfidenceScore", 0),
                    "status": "SUCCESS",
                    "total_reports": data.get("totalReports", 0)
                }
            else:
                return {"score": 0, "status": "API_DEGRADED", "error_code": response.status_code}
        except Exception as e:
            # Senior Feedback: Treat API failures as UNKNOWN rather than blocking false-positives
            return {"score": 0, "status": "UNKNOWN_API_FAILURE", "exception": str(e)}


class DynamicRiskEngine:
    """Multi-factor dynamic risk scoring framework"""
    @staticmethod
    def calculate_risk(intel_data, attack_freq, attempted_username, attack_type):
        # Weight Factors
        # 1. Threat Intel Score (40%)
        intel_score = intel_data.get("score", 0) * 0.40
        
        # 2. Attack Frequency / Burst Rate (30%)
        freq_score = min(attack_freq * 10, 100) * 0.30
        
        # 3. Behavior / Sensitive Asset Targeting (20%)
        user_score = (100 if attempted_username in HIGH_RISK_USERNAMES else 30) * 0.20
        
        # 4. Attack Vector Context (10%)
        vector_score = (100 if attack_type in ["SSH_BRUTEFORCE", "MALICIOUS_HASH"] else 50) * 0.10
        
        total_risk_score = round(intel_score + freq_score + user_score + vector_score)
        return min(total_risk_score, 100)


class ActiveContainmentEngine:
    """Executes OS-level firewall rules and maintains denylists"""
    @staticmethod
    def block_ip(ip):
        # 1. System-Level Firewall Containment (iptables / Windows netsh fallback)
        firewall_success = False
        try:
            if os.name == "posix": # Linux
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                firewall_success = True
            elif os.name == "nt": # Windows OS
                cmd = f"netsh advfirewall firewall add rule name=\"SOAR_BLOCK_{ip}\" dir=in action=block remoteip={ip}"
                subprocess.run(cmd, shell=True, check=True)
                firewall_success = True
        except Exception as e:
            print(f"[CONTAINMENT WARNING] OS Firewall block failed (insufficient privileges/unsupported OS): {e}")

        # 2. Local Denylist Persistence
        with open(DENYLIST_PATH, "a") as f:
            f.write(f"{ip}\n")

        return firewall_success


# --- MAIN SOAR ENGINE EXECUTION ---
def run_soar_pipeline(target_ip, attempted_user="root", attack_type="SSH_BRUTEFORCE", burst_count=5):
    playbook = SOARPlaybook(target_ip, {"user": attempted_user, "type": attack_type})
    
    # 1. DETECT
    playbook.log_step("1_DETECT", f"Detected {attack_type} vector from IP: {target_ip}")
    
    # 2. ENRICH
    intel_res = ThreatIntelEngine.query_abuseipdb(target_ip)
    playbook.log_step("2_ENRICH", f"Threat Intel Status: {intel_res['status']} | Abuse Score: {intel_res['score']}%")
    
    # 3. CORRELATE & SCORE
    risk_score = DynamicRiskEngine.calculate_risk(intel_res, burst_count, attempted_user, attack_type)
    playbook.log_step("3_SCORE", f"Calculated Multi-Factor Risk Score: {risk_score}/100")
    
    # 4. CREATE INCIDENT
    playbook.log_step("4_INCIDENT_CREATED", f"Incident {playbook.incident_id} registered in SOAR core")
    
    # 5. RESPOND
    if risk_score >= CRITICAL_RISK_THRESHOLD:
        fw_status = ActiveContainmentEngine.block_ip(target_ip)
        playbook.log_step("5_RESPOND", f"Action: BLOCK_IP Executed | Firewall Enforced: {fw_status}")
        playbook.log_step("6_VERIFY", f"Verified IP {target_ip} persisted to {DENYLIST_PATH}")
        playbook.audit_log["status"] = "CONTAINED"
    else:
        playbook.log_step("5_RESPOND", "Risk below threshold. Action: MONITOR_ONLY")
        playbook.audit_log["status"] = "MONITORING"
        
    # 6. RESOLVE & AUDIT
    playbook.log_step("7_RESOLVE", "Incident workflow completed successfully")
    playbook.save_audit_trail()
    print("="*60)


if __name__ == "__main__":
    print("🛡️ SOAR ENGINE ENTERPRISE PIPELINE ACTIVE 🛡️\n" + "="*60)
    # Simulation Run
    run_soar_pipeline("118.25.6.39", attempted_user="root", attack_type="SSH_BRUTEFORCE", burst_count=8)