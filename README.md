# 🛡️ Automated SOAR Engine & Threat Intelligence Dashboard

An enterprise-grade Security Operations, Automation, and Response (**SOAR**) framework designed to capture live attack vectors via Honeypot telemetry, enrich threat data via external Threat Intelligence APIs, evaluate risk dynamically, and execute automated containment actions.

---

## 🏛️ System Architecture Workflow

```text
       [ External Attacker / Brute-Force Simulation ]
                            │
                            ▼
      [ Docker Cowrie Honeypot Sensor (Port 2222) ]
                            │
                            ▼
             [ JSON Telemetry Log Stream ]
                            │
                            ▼
        [ SOAR Threat Detection & Ingestion Engine ]
                            │
                            ▼
          [ AbuseIPDB Threat Intel API Query ]
                            │
                            ▼
       [ Dynamic Risk Decision Engine (Risk >= 80%) ]
                            │
                            ▼
       [ Automated Mitigation: Block IP to Denylist ]
                            │
                            ▼
      [ Real-Time Streamlit SOC Operations Dashboard ]