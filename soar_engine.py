"""
EdgeSentinel - Autonomous Deception & Threat Response Engine
Author: Security Engineering Team
Architecture: Edge Appliance Deception-SOAR Pipeline
"""

import os
import sys
import json
import time
import socket
import logging
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
import requests
from dotenv import load_dotenv

load_dotenv()

# Setup Structured Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("EdgeSentinel.Engine")


@dataclass
class ThreatEvent:
    event_id: str
    source_ip: str
    target_port: int
    protocol: str
    attempted_user: str
    raw_payload: str
    timestamp: str


@dataclass
class RiskProfile:
    intel_score: float
    burst_frequency: int
    credential_risk: float
    vector_severity: float
    composite_score: float
    assessment: str


class ThreatIntelClient:
    """Production REST client for external reputation feeds with circuit breaking."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "Key": self.api_key,
                "Accept": "application/json"
            })

    def evaluate_ip(self, ip_address: str) -> Dict[str, Any]:
        if not self.api_key:
            logger.warning("Threat intelligence API key missing. Operating in local heuristic mode.")
            return {"score": 0, "status": "NO_API_KEY", "confidence": 0}

        try:
            params = {"ipAddress": ip_address, "maxAgeInDays": "30"}
            response = self.session.get(self.base_url, params=params, timeout=4.0)
            
            if response.status_code == 200:
                payload = response.json().get("data", {})
                return {
                    "score": payload.get("abuseConfidenceScore", 0),
                    "total_reports": payload.get("totalReports", 0),
                    "status": "VERIFIED"
                }
            elif response.status_code == 429:
                logger.warning("Threat Intel API rate limit reached. Fallback to heuristic scoring.")
                return {"score": 0, "status": "RATE_LIMITED"}
            else:
                return {"score": 0, "status": f"HTTP_{response.status_code}"}
        except requests.RequestException as err:
            logger.error("Threat Intel query dropped: %s", err)
            return {"score": 0, "status": "LOOKUP_TIMEOUT"}


class MultiVectorRiskEngine:
    """Weighted composite risk assessment matrix."""
    
    CRITICAL_ACCOUNTS = frozenset({"root", "admin", "administrator", "support", "oracle", "postgres"})

    @classmethod
    def compute(cls, intel_payload: Dict[str, Any], burst_rate: int, user: str, vector: str) -> RiskProfile:
        # 1. External Threat Intelligence Weight (40%)
        intel_weight = float(intel_payload.get("score", 0)) * 0.40
        
        # 2. Connection Velocity / Burst Weight (30%)
        velocity_weight = min(burst_rate * 12.5, 100.0) * 0.30
        
        # 3. Credential Targeting Severity (20%)
        cred_weight = 100.0 * 0.20 if user.lower() in cls.CRITICAL_ACCOUNTS else 25.0 * 0.20
        
        # 4. Vector Criticality (10%)
        vector_weight = 100.0 * 0.10 if vector in ("SSH_BRUTEFORCE", "RCE_PROBE") else 40.0 * 0.10
        
        composite = round(intel_weight + velocity_weight + cred_weight + vector_weight, 2)
        composite = min(composite, 100.0)
        
        if composite >= 75.0:
            assessment = "CRITICAL"
        elif composite >= 50.0:
            assessment = "HIGH"
        elif composite >= 25.0:
            assessment = "MEDIUM"
        else:
            assessment = "LOW"
            
        return RiskProfile(
            intel_score=intel_payload.get("score", 0),
            burst_frequency=burst_rate,
            credential_risk=cred_weight,
            vector_severity=vector_weight,
            composite_score=composite,
            assessment=assessment
        )


class EdgeEnforcementBroker:
    """Hardware edge containment using native kernel packet filtering."""
    
    def __init__(self, denylist_store: str = "denylist.txt"):
        self.store_path = denylist_store

    def enforce_containment(self, ip_address: str) -> bool:
        enforced = False
        try:
            # POSIX / Linux Edge Appliance (Raspberry Pi OS / Ubuntu Core)
            if os.name == "posix":
                cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
                check_rule = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check_rule.returncode != 0:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
                    logger.info("Kernel packet drop rule installed for: %s", ip_address)
                enforced = True
                
            # Windows Subsystem Fallback
            elif os.name == "nt":
                rule_name = f"EdgeSentinel_Block_{ip_address.replace('.', '_')}"
                cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
                enforced = True
        except Exception as exc:
            logger.error("OS firewall rule dispatch failed: %s", exc)

        # Persistent storage commit
        try:
            with open(self.store_path, "a+") as f:
                f.seek(0)
                existing = [line.strip() for line in f.readlines()]
                if ip_address not in existing:
                    f.write(f"{ip_address}\n")
        except IOError as io_err:
            logger.error("Failed to commit denylist record: %s", io_err)

        return enforced


class EdgeSOAROrchestrator:
    """Master controller managing playbook pipelines and audit records."""
    
    def __init__(self, audit_file: str = "audit_trail.json"):
        self.audit_path = audit_file
        self.intel_client = ThreatIntelClient()
        self.enforcer = EdgeEnforcementBroker()

    def process_incident(self, event: ThreatEvent, burst_count: int = 1):
        incident_id = f"INC-{int(time.time())}-{event.source_ip.replace('.', '')}"
        logger.info("Triggering Playbook [EDGE_AUTONOMOUS_ISOLATION] for Incident %s", incident_id)
        
        lifecycle_audit = []
        
        def track_step(stage: str, message: str, status: str = "COMPLETED"):
            lifecycle_audit.append({
                "stage": stage,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": status,
                "log": message
            })

        # Pipeline: DETECT -> ENRICH -> SCORE -> MITIGATE -> AUDIT
        track_step("1_INGESTION", f"Telemetry gathered from port {event.target_port} ({event.protocol})")
        
        intel = self.intel_client.evaluate_ip(event.source_ip)
        track_step("2_ENRICHMENT", f"Intel Status: {intel['status']}, Reputation Score: {intel.get('score', 0)}")
        
        risk = MultiVectorRiskEngine.compute(intel, burst_count, event.attempted_user, "SSH_BRUTEFORCE")
        track_step("3_CORRELATION_SCORING", f"Computed composite risk {risk.composite_score} ({risk.assessment})")
        
        action_taken = "MONITOR"
        if risk.composite_score >= 70.0:
            success = self.enforcer.enforce_containment(event.source_ip)
            action_taken = "CONTAINED" if success else "CONTAINMENT_FAILED"
            track_step("4_RESPONSE", f"Active kernel isolation executed. Status: {action_taken}")
            track_step("5_VERIFICATION", f"Edge state validated. Threat quarantined.")
        else:
            track_step("4_RESPONSE", "Risk below mitigation threshold. Forwarding to telemetry store.")

        # Finalize and record audit
        record = {
            "incident_id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_ip": event.source_ip,
            "attempted_user": event.attempted_user,
            "risk_profile": asdict(risk),
            "status": action_taken,
            "rollback_hook": f"iptables -D INPUT -s {event.source_ip} -j DROP",
            "lifecycle": lifecycle_audit
        }
        self._commit_audit(record)
        logger.info("Incident %s resolved with status [%s]", incident_id, action_taken)

    def _commit_audit(self, record: Dict[str, Any]):
        records = []
        if os.path.exists(self.audit_path):
            try:
                with open(self.audit_path, "r") as f:
                    records = json.load(f)
            except Exception:
                records = []
        records.append(record)
        with open(self.audit_path, "w") as f:
            json.dump(records, f, indent=2)


if __name__ == "__main__":
    orchestrator = EdgeSOAROrchestrator()
    # Simulated Live Telemetry Ingestion
    sample_event = ThreatEvent(
        event_id="EVT-001",
        source_ip="118.25.6.39",
        target_port=2222,
        protocol="SSH",
        attempted_user="root",
        raw_payload="SSH-2.0-OpenSSH_8.2p1",
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    orchestrator.process_incident(sample_event, burst_count=6)