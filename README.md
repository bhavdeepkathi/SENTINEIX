# SentinelX – AI‑Powered Incident Response & Digital Forensics Platform

SentinelX is a full‑stack, open‑source platform that helps security analysts **detect, investigate, and respond** to cyber incidents.  
It combines **rule‑based detection**, **machine‑learning models**, **MITRE ATT&CK mapping**, an **LLM‑assisted investigation assistant**, and **automated PDF report generation** – all wrapped in a modern React + FastAPI stack.

---

## 🚀 Features

| Area | Capability |
|------|------------|
| **Log Ingestion** | Upload JSON, CSV, Linux `auth.log`, Windows Security EVTX (text export), or generic “key=value” logs. Automatic normalisation to a canonical `LogEvent` schema. |
| **Rule‑based Detection** | 6 built‑in rules (failed‑login bursts, impossible travel, privilege escalation, suspicious PowerShell, large data transfer, malware IOC keywords). |
| **ML‑based Detection** | IsolationForest (anomaly) + RandomForest / XGBoost (classification). Models are trained offline and baked into the Docker image (`ml/models/`). |
| **Alert Correlation** | Time‑window + entity (user / IP / host) grouping → creates **Incident** objects with risk score (0‑100) and severity tier. |
| **MITRE ATT&CK Mapping** | Automatic mapping of observed behaviours to technique IDs (e.g., T1059.001, T1078, T1068, T1041). |
| **AI Investigation Assistant** | LLM (OpenAI‑compatible) builds an *attack story*: summary, attack sequence, root cause, affected assets, MITRE techniques, confidence, and prioritized recommendations. Falls back to a deterministic mock when no LLM key is provided. |
| **Evidence Management** | Upload arbitrary files (PCAP, memory dumps, screenshots…); SHA‑256 hash stored for integrity verification. |
| **Automated PDF Report** | One‑click professional PDF (timeline, alerts, evidence, AI narrative, MITRE map, recommendations). |
| **Role‑Based Access Control** | `admin`, `analyst`, `investigator` – JWT‑based auth with HttpOnly‑compatible Bearer tokens. |
| **Modern UI** | React 18 + Vite + Tailwind CSS + Lucide icons; responsive, dark‑mode ready, accessible. |
| **Containerised** | `docker compose up -d` spins up Postgres 16, FastAPI (uvicorn), React (nginx) in seconds. |

---

## 🏗 Architecture Overview

```
+----------------+          +----------------+          +-----------------+
|   React UI     |  HTTPS   |   FastAPI      |  async   |   PostgreSQL 16 |
|  (React 18 +   |<-------->|  (uvicorn,     |<-------->|   (SQLAlchemy)  |
|   Vite, Tailwind)          |   FastAPI)    |  asyncpg |                 |
+----------------+          +----------------+          +-----------------+
                                   |
                     +---------------------------+
                     |   ML artefacts (joblib)   |
                     |  • IsolationForest        |
                     |  • RandomForest / XGBoost |
                     +---------------------------+
                     |
                     |   LLM (OpenAI‑compatible)
                     +---------------------------+
```

All services run inside Docker containers orchestrated by **docker‑compose**.

---

## 📦 Quick Start (Docker Compose)

```bash
# 1️⃣ Clone the repository
git clone https://github.com/your‑org/sentinelx.git
cd sentinelx

# 2️⃣ (Optional) Add a real OpenAI key for real LLM investigations
#    Edit docker-compose.yml → backend.environment.OPENAI_API_KEY

# 3️⃣ Spin up the stack
docker compose up -d --build

# 4️⃣ Open the UI
open http://localhost:5173
```

The first run will:
1. Build the backend image (Python 3.11, installs Python deps, copies ML models).
2. Build the frontend image (Node 20 → Vite build → Nginx).
3. Start Postgres 16, FastAPI (port 8000), React + Nginx (port 5173).

**Default credentials** (seeded at first DB init)  

| Role | E‑mail | Password |
|------|--------|----------|
| analyst | `bhavdeepbhukan129@gmail.com` | *any* (set on first register) |

Register with that e‑mail on first visit; the JWT is stored in `localStorage` and automatically attached to every API call.

---

## 🛠 Development Setup (without Docker)

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd ../frontend
npm ci
npm run dev   # Vite dev server on http://localhost:5173 (proxies /api → localhost:8000)
```

Environment variables (create `.env` files or export):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://sentinelx:sentinelx@localhost:5432/sentinelx` | Asyncpg DSN |
| `SECRET_KEY` | `change_me_in_prod` | JWT signing key |
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT TTL |
| `OPENAI_API_KEY` | *empty* | Real LLM key (optional) |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | Override for compatible endpoints |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |

---

## 📂 Project Layout

```
sentinelx/
├─ backend/
│   ├─ app/
│   │   ├─ api/               # FastAPI routers (auth, logs, alerts, incidents, investigations, evidence, ml, reports)
│   │   ├─ core/              # config, security, database, dependencies
│   │   ├─ models/            # SQLAlchemy models
│   │   ├─ schemas/           # Pydantic request/response models
│   │   ├─ services/          # detection, correlation, ai_investigation, ml_detection, forensic, report_generator, llm_client
│   │   └─ main.py            # FastAPI app factory
│   ├─ ml/
│   │   ├─ datasets/          # synthetic training data
│   │   ├─ train.py / evaluate.py
│   │   └─ models/            # joblib artefacts (isolation_forest.joblib, random_forest.joblib, scaler.joblib, …)
│   ├─ Dockerfile
│   └─ requirements.txt
├─ frontend/
│   ├─ src/
│   │   ├─ pages/            # Dashboard, Incidents, IncidentDetail, Login, Register
│   │   ├─ components/       # reusable UI (StatCard, Modal, Table, etc.)
│   │   ├─ services/         # api.ts (axios instance)
│   │   ├─ context/          # AuthContext (JWT handling)
│   │   ├─ layouts/          # Layout with top nav
│   │   └── App.tsx
│   ├─ Dockerfile
│   ├─ nginx.conf
│   └─ package.json
├─ ml/                         # duplicate of backend/ml for convenience
├─ sample_data/                # ready‑to‑upload demo logs (json, csv, auth.log, …)
├─ docker-compose.yml
└── README.md
```

---

## 📖 Usage Walk‑through

1. **Log in / Register** – use the seeded analyst e‑mail `bhavdeepbhukan129@gmail.com`.
2. **Upload Logs** – *Incidents → Upload Logs* → pick `sample_data/sample_logs.json` (or any `.json/.csv/.log/.txt`).  
   The file is normalised to `LogEvent` rows.
3. **Run Detection** – “Run Detection” (60 min default) → creates **Alerts** via rule engine + ML models.
10. **Correlate Alerts** – groups related alerts into **Incidents** (risk score, severity, MITRE tags).
3. **Open Incident** → view **Timeline, Alerts, Evidence, AI Investigation, MITRE ATT&CK, Recommendations, Report**.
4. **AI Investigation** → *Start AI Investigation* → mock (or real LLM) narrative, MITRE mapping, confidence, recommendations.
5. **Report** → *Download Report* → professional PDF with timeline, evidence hashes, MITRE map, AI narrative, recommendations.

---

## 🧪 Testing

```bash
# Backend unit / integration tests
cd backend
pytest -v

# Frontend unit tests
cd ../frontend
npm test
```

All tests run in CI (GitHub Actions) on every push.

---

## 🤝 Contributing

1. Fork → create a feature branch (`git checkout -b feat/awesome`).
2. Follow the existing code style (`black`, `isort`, `eslint`, `prettier`).
3. Write tests for new behaviour.
4. Open a PR with a clear description.

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

* **FastAPI**, **SQLAlchemy**, **Pydantic**, **Uvicorn** – modern Python web stack.  
* **React**, **Vite**, **Tailwind CSS**, **Lucide Icons** – modern front‑end.  
* **scikit‑learn**, **XGBoost**, **joblib** – ML modelling.  
* **OpenAI / compatible LLM APIs** – AI investigation narrative.  
* **ReportLab** – PDF generation.  
* **Docker / Docker Compose** – reproducible deployment.

---

*Happy hunting!* 🎯  
*– The SentinelX Team*