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
> *(Drag & drop your dashboard screenshot image here directly in GitHub editor)*

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
