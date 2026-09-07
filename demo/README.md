# Zero-Trust API Gateway • Full-Stack Demo Testbed

This directory contains the end-to-end full-stack demonstration testbed for the **Zero-Trust API Gateway**. It proves that the gateway enforces **graph-aware, trust-scored ReBAC authorization** with **closed-loop policy feedback** and **real-time SHAP explainability** by routing real traffic from a React frontend through the Python gateway to backend microservices of varying sensitivity.

---

## 🏗️ Architecture Overview

```
                          ┌───────────────────────────┐
                          │   Demo Frontend (React)   │
                          │   http://localhost:5173   │
                          └─────────────┬─────────────┘
                                        │ HTTP requests with JWT & Telemetry
                                        ▼
                          ┌───────────────────────────┐
                          │  Zero-Trust API Gateway   │
                          │   http://localhost:8000   │
                          └──────┬─────────────┬──────┘
             ReBAC Check / Graph │             │ Isolation Forest Anomaly
             Narrowing Invalidation            │ Scoring & SHAP Explainer
                                 ▼             ▼
                          ┌───────────┐   ┌───────────┐
                          │  SpiceDB  │   │   Redis   │
                          │  :50051   │   │   :6379   │
                          └───────────┘   └───────────┘
                                        │ (When Allowed)
         ┌──────────────────────────────┼──────────────────────────────┐
         ▼                              ▼                              ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│   Docs Service   │           │   Team Service   │           │ Payroll Service  │
│  (Low Sensitivity│           │(Medium Sensitivity│          │(High Sensitivity │
│   Port :3001)    │           │   Port :3002)    │           │   Port :3003)    │
└──────────────────┘           └──────────────────┘           └──────────────────┘
```

---

## 👥 Personas & Authorization Matrix

| Persona | Subject String | Role / Department | Allowed Resources | Expected Trust Baseline |
| :--- | :--- | :--- | :--- | :--- |
| **Alice Cooper** | `user:alice` | Staff Eng (Lead) | `doc1` (view/edit), `team:eng` | $1.00$ (ALLOW) |
| **Bob Martin** | `user:bob` | Software Engineer | `doc1` (view), `team:eng` | $1.00$ (ALLOW) |
| **Charlie Davis** | `user:charlie` | Security Admin | `doc1` (view), `financials` (view) | $1.00$ (ALLOW) |
| **Mallory Vance** | `user:mallory` | Rogue Contractor | None | Graph Deny ($403$) |

---

## 🚀 Quick Start Guide

### Step 1: Start Infrastructure & Mock Services
In the project root, launch SpiceDB, Redis, and the 3 mock microservices:
```bash
docker compose up -d spicedb redis docs-service team-service payroll-service
```

### Step 2: Initialize SpiceDB Schema and Relationships
Load the ReBAC schema and default relationship tuples into SpiceDB:
```bash
uv run python scripts/setup_spicedb.py
```

### Step 3: Train / Verify Anomaly Baseline Model
Generate the baseline Isolation Forest anomaly model and pre-computed TreeExplainer background dataset:
```bash
uv run python scripts/train_baseline_model.py
```

### Step 4: Start the Zero-Trust Gateway
Run the FastAPI gateway interceptor service:
```bash
uv run uvicorn app.gateway.main:app --port 8000 --reload
```

### Step 5: Start the Demo Frontend
In a separate terminal, run the Vite development server:
```bash
cd demo/frontend
pnpm install
pnpm dev
```
Open **http://localhost:5173** in your web browser.

---

## 🧪 Interactive Walkthrough Scenarios

### 1. Normal Authorization Flow (Green Band • ALLOW)
1. Select **Alice Cooper** in the persona switcher.
2. Click **Invoke via Gateway** under **Documentation Service** (`/api/v1/document/doc1`).
3. **Result:** `HTTP 200 OK`, `Action: ALLOW`, `Trust Score: 1.00`.

### 2. Unauthorized Graph Access (ReBAC Graph Violation)
1. Select **Alice Cooper**.
2. Click **Invoke via Gateway** under **Payroll & Compensation** (`/api/v1/document/financials`).
3. **Result:** `HTTP 403 Forbidden`. The ReBAC graph blocks the request because Alice lacks the `team:security#admin` relation.

### 3. Rapid Request Burst Anomaly (Degradation to STEP_UP)
1. Select **Alice Cooper** (fresh session).
2. Click **Trigger Rapid Request Burst (20 reqs)** in the Anomaly Injection Lab.
3. Observe the live audit feed: As the 1-minute request rate surges past the model's normal envelope, the trust score drops from $1.00 \to 0.70$.
4. Next invocation results in `HTTP 401 Unauthorized` with `Action: STEP_UP` and challenge `MFA_REQUIRED`.

### 4. Impossible Travel Anomaly (Closed-Loop NARROW Feedback)
1. Select **Bob Martin**.
2. Click **Simulate Impossible Travel (SF → Tokyo)**.
3. The gateway detects a velocity of $\approx 8,200\text{ km/h}$, causing severe trust decay into the `NARROW` band ($< 0.60$).
4. The Closed-Loop Feedback loop automatically writes a temporary restriction tuple into SpiceDB.
5. In the SHAP Attributions pane, observe `geo_velocity_kmh` highlighted as the primary anomalous driver.

### 5. Rogue Device Fingerprint Injection
1. Select **Charlie Davis**.
2. Click **Inject Rogue Device Fingerprint**.
3. Telemetry header `X-Device-Id` changes to `unknown_rogue_device_attacker`.
4. Trust engine penalizes device fingerprint mismatch, degrading trust and surfacing SHAP attribution indicators.
