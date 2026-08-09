# 🛡️ Automated SOAR Engine & Threat Intelligence Dashboard

An enterprise-grade Security Operations, Automation, and Response (**SOAR**) framework designed to capture live attack vectors via Honeypot telemetry, enrich threat data via external Threat Intelligence APIs, evaluate risk dynamically, and execute automated containment actions.

---

## 🔗 Quick Links & Source Code

* **🖥️ Engine Script:** [`soar_engine.py`](./soar_engine.py)
* **📊 Visual Dashboard:** [`dashboard.py`](./dashboard.py)
* **⚙️ Security Rules (.gitignore):** [`.gitignore`](./.gitignore)

---

## 🖼️ Live Visual Demo

> **SOC Dashboard Visual Telemetry:**
> 
<img width="1908" height="907" alt="Screenshot 2026-08-09 161313" src="https://github.com/user-attachments/assets/a4241b7d-2990-4bc5-8397-4ac7dff820bd" />
*<img width="1902" height="901" alt="Screenshot 2026-08-09 161320" src="https://github.com/user-attachments/assets/adf1b3b3-50d4-48b3-818e-d25bff41ffbf" />


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
