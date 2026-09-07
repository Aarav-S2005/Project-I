# Zero-Trust API Gateway with Graph-Aware Trust & Closed-Loop Policy Feedback

A high-performance **Zero-Trust API Gateway** combining continuous session trust evaluation, fine-grained **ReBAC (Relationship-Based Access Control)** authorization, **graph-structural anomaly detection**, **closed-loop policy narrowing**, and **real-time SHAP explainability**.

---

## 1. System Architecture

The architecture is structured as a decoupled, defense-in-depth pipeline where incoming HTTP traffic is inspected, contextualized, authorized, scored for behavioral and structural anomalies, and governed through closed-loop policy feedback before reaching upstream services.

### Core Architectural Layers

1. **Ingress & Authentication Layer (`app/gateway/`)**
   - Implements a FastAPI application acting as the single point of entry for protected microservices.
   - Authenticates incoming JWT Bearer tokens and extracts rich client telemetry, including IP address, geographic coordinates (latitude/longitude), hardware device identifiers, User-Agent strings, requested resource types, and permissions.
   - Hosts the `ZeroTrustInterceptor`, which orchestrates the evaluation lifecycle on every HTTP request.

2. **Policy & Relationship Graph Layer (`app/policy/`)**
   - Integrates with **SpiceDB** over high-speed gRPC using Google Zanzibar-style Relationship-Based Access Control (ReBAC).
   - Models organizational hierarchies, team memberships, role relations, resource ownership, and dynamic restriction sets defined in `schema.zed`.
   - Performs permission checks (`CheckPermission`) and relationship tree expansions (`ExpandPermissionTree`) to trace authorization paths from subjects to target resources.

3. **Dual-Stream Feature Extraction Engine (`app/features/`)**
   - Extracts an 8-dimensional numerical feature vector per request across two parallel streams:
     - **Behavioral Stream (`app/features/behavioral.py`)**: Queries Redis sorted sets to compute rolling 1-minute and 5-minute request rates using sliding windows, calculates great-circle geo-velocity (km/h) between consecutive request coordinates, detects device fingerprint mismatches against stored session baselines, and quantifies time-of-day deviations from standard business hours.
     - **Graph-Structural Stream (`app/features/graph.py`)**: Analyzes the SpiceDB ReBAC relationship path, extracting graph hop counts, novelty scores for previously unseen authorization trajectories, and flags for direct privilege shortcuts that bypass intermediate group hierarchies.

4. **Trust & Anomaly Scoring Engine (`app/trust_engine/`)**
   - Evaluates the 8-dimensional feature vector against a trained scikit-learn **Isolation Forest** model to produce a normalized anomaly severity score between 0.0 (benign) and 1.0 (severe anomaly).
   - Manages a continuous, stateful session trust score ($0.00 \le T \le 1.00$) in Redis.
   - Implements asymmetric exponential decay on anomalous signals and gradual linear recovery on sustained normal traffic.

5. **Decision & Closed-Loop Feedback Engine (`app/decision/`)**
   - Maps the continuous session trust score into four discrete operational bands (`ALLOW`, `STEP_UP`, `NARROW`, `DENY`).
   - **Closed-Loop Feedback**: When a session's trust score degrades into the `NARROW` band, the engine automatically writes a temporary `restricted` relationship tuple into SpiceDB. This immediately mutates the active ReBAC graph and revokes non-essential permissions in real time without requiring manual administrative intervention.

6. **Explainability & Immutable Audit Engine (`app/audit/`)**
   - Computes real-time feature attributions using **SHAP (SHapley Additive exPlanations)** with a `TreeExplainer` model.
   - Decomposes the anomaly decision into mathematical contribution percentages, indicating exactly which features (e.g., impossible travel speed, request rate spike, or rogue hardware fingerprint) drove trust degradation.
   - Persists immutable, structured audit records in Redis and exposes a queryable REST API (`/audit/records`).

7. **Demo & Microservices Testbed (`demo/`)**
   - Contains three Express.js backend services of varying sensitivity: `docs-service` (low sensitivity, port 3001), `team-service` (medium sensitivity, port 3002), and `payroll-service` (high sensitivity, port 3003).
   - Includes a React + TypeScript single-page application dashboard providing interactive persona switching, real-time trust meters, an anomaly injection laboratory, and live SHAP audit visualization.

---

## 2. Decision Bands & Policy Matrix

| Trust Band | Action | HTTP Response | System Action & Closed-Loop Feedback |
| :--- | :--- | :--- | :--- |
| **$0.80 \le T \le 1.00$** | `ALLOW` | `200 OK` | Access granted; request forwarded to upstream backend service. Normal session recovery applied. |
| **$0.60 \le T < 0.80$** | `STEP_UP` | `401 Unauthorized` | Step-up multi-factor authentication challenge returned via `WWW-Authenticate: Step-Up`. |
| **$0.35 \le T < 0.60$** | `NARROW` | `403 Forbidden` | **Closed-Loop Policy Narrowing**: Writes an automated restriction tuple into SpiceDB, revoking elevated permissions. |
| **$0.00 \le T < 0.35$** | `DENY` | `403 Forbidden` | ReBAC policy violation or severe anomaly collapse: request blocked immediately. |

---

## 3. How It Works (End-to-End Request Lifecycle)

Every incoming API request passes through the following sequential stages:

1. **Context Ingestion & JWT Validation**:
   The client issues an HTTP request with an `Authorization: Bearer <JWT>` header and client metadata headers (`X-Device-Id`, `X-Client-Latitude`, `X-Client-Longitude`). The gateway decodes the JWT, extracts session identifiers, and constructs an immutable `RequestContext`.

2. **ReBAC Graph Check**:
   The gateway queries SpiceDB over gRPC to determine whether the subject possesses the required relationship (e.g., `viewer`, `editor`, `admin`) on the target resource. If the ReBAC graph check fails or a restriction tuple exists, access is denied immediately.

3. **Dual-Stream Feature Extraction**:
   If ReBAC validation passes, the gateway queries Redis and the SpiceDB graph expansion to build the 8-dimensional feature vector:
   - `request_rate_1m`: Requests in the preceding 60 seconds (Redis sliding window).
   - `request_rate_5m`: Requests in the preceding 300 seconds (Redis sliding window).
   - `geo_velocity_kmh`: Great-circle velocity relative to the previous request's coordinates and timestamp.
   - `device_fingerprint_mismatch`: Binary flag (1.0 if device ID diverges from session baseline, 0.0 otherwise).
   - `time_of_day_deviation`: Deviation of request timestamp from business working hours (0.0 to 1.0).
   - `hop_count`: Number of relationship edges traversed from subject to resource in SpiceDB.
   - `path_novelty_score`: Frequency penalty for uncommon graph traversal trajectories.
   - `privilege_shortcut_flag`: Binary indicator (1.0 if direct assignment bypasses team membership paths).

4. **Machine Learning Anomaly Inference & Trust Decay**:
   The feature vector is evaluated by the Isolation Forest model. The raw anomaly score updates the session's continuous trust score:
   - If anomalous ($\text{score} > 0.55$), trust decays exponentially based on anomaly severity.
   - If normal ($\text{score} \le 0.55$), trust recovers linearly up to the 1.0 maximum.

5. **Decision Evaluation & Closed-Loop Write-Back**:
   The resulting trust score is mapped against the decision thresholds. If the score falls into the `NARROW` band, the Decision Engine automatically executes a SpiceDB write to insert a `restricted` relationship tuple for that subject and resource.

6. **SHAP Feature Attribution & Audit Logging**:
   The SHAP `TreeExplainer` computes exact contribution scores for each feature. An immutable `AuditRecord` containing the decision result, trust scores, raw features, and top anomaly drivers is persisted to Redis and broadcast to the audit feed.

7. **Response Dispatch**:
   If the decision is `ALLOW`, the gateway proxies the request to the upstream microservice. Otherwise, it returns the appropriate HTTP status code, headers (`X-Trust-Score`, `X-Decision-Action`, `X-Audit-Record-Id`), and enforcement payload.

---

## 4. How to Run the Demo

### Prerequisites
- Python 3.12+
- `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh` or `winget install astral-sh.uv`)
- Node.js 20+ and `pnpm` (`npm install -g pnpm`)
- Docker & Docker Compose

---

### Step-by-Step Setup

#### Step 1: Clone Repository and Install Python Dependencies
```bash
git clone <repository-url>
cd <repository-directory>
uv sync
```

#### Step 2: Start Infrastructure & Mock Microservices in Docker
Launch SpiceDB, Redis, and the three backend demo services (`docs-service`, `team-service`, `payroll-service`):
```bash
docker compose up -d
```

#### Step 3: Initialize SpiceDB Schema & Default Graph Relationships
Apply the Zed schema and write baseline tuples (Alice in Eng, Bob in Eng, Charlie in Security Admin):
```bash
uv run python scripts/setup_spicedb.py
```

#### Step 4: Train the Baseline Anomaly Detection Model
Generate the synthetic baseline training dataset and serialize the Isolation Forest model along with pre-computed background datasets:
```bash
uv run python scripts/train_baseline_model.py
```

#### Step 5: Start the Zero-Trust API Gateway
Run the gateway service on port 8000:
```bash
uv run uvicorn app.gateway.main:app --port 8000 --reload
```

#### Step 6: Start the Demo Frontend
In a separate terminal, launch the interactive React dashboard:
```bash
cd demo/frontend
pnpm install
pnpm dev
```
Open **`http://localhost:5173`** in your browser.

---

### Automated Traffic Simulation (300+ Requests CLI Benchmark)

To simulate a complete high-volume stream of clean and anomalous traffic with real-time SHAP analysis:
```bash
uv run python scripts/simulate_traffic.py --count 300
```

---

### Interactive Walkthrough Scenarios (In the Web Dashboard)

1. **Authorized Normal Request (`ALLOW`)**:
   - Select **Alice Cooper** in the persona switcher.
   - Click **Invoke via Gateway** on the **Documentation Service** (`/api/v1/document/doc1`).
   - Observe `HTTP 200 OK`, `Action: ALLOW`, `Trust Score: 1.00`.

2. **ReBAC Graph Authorization Violation (`DENY`)**:
   - Select **Alice Cooper**.
   - Click **Invoke via Gateway** on **Payroll & Compensation** (`/api/v1/document/financials`).
   - Observe `HTTP 403 Forbidden` because Alice lacks membership in `team:security#admin`.

3. **Volumetric Rate Spike Anomaly (`STEP_UP`)**:
   - Select **Alice Cooper**.
   - Click **Trigger Rapid Request Burst (20 reqs)** in the Anomaly Injection Lab.
   - Observe the trust score degrade into the `STEP_UP` band ($0.60 - 0.79$) and subsequent requests prompt for MFA (`HTTP 401`).

4. **Impossible Travel Anomaly & Closed-Loop Policy Feedback (`NARROW`)**:
   - Select **Bob Martin**.
   - Click **Simulate Impossible Travel (SF → Tokyo)**.
   - The gateway calculates a velocity of $> 8,000\text{ km/h}$, degrading trust into the `NARROW` band ($0.35 - 0.59$).
   - The gateway automatically writes a restriction tuple into SpiceDB and displays `geo_velocity_kmh` as the primary SHAP threat driver.

---

## 5. System Limitations & Technical Trade-offs

While this architecture provides continuous trust-based authorization, several technical trade-offs and operational constraints apply:

1. **In-Line SHAP Computation Latency Overhead**
   - Computing exact SHAP values using `TreeExplainer` on every request introduces mathematical overhead (typically $10\text{ ms} - 50\text{ ms}$ per evaluation).
   - In ultra-high-throughput production environments (tens of thousands of requests per second), SHAP evaluations should be executed asynchronously via a background task queue (e.g., Celery or Kafka worker) or calculated on a sampled percentage of traffic rather than strictly in-band.

2. **Cold Start & Baseline Profiling Requirements**
   - The unsupervised Isolation Forest model requires a calibration period with representative normal traffic to establish accurate anomaly boundaries.
   - In new deployments or newly onboarded user cohorts, benign deviations (such as an employee traveling or changing hardware) may trigger false-positive trust decay until the baseline profile incorporates the new patterns.

3. **State Synchronization & Single Redis Dependency**
   - The feature extraction layer relies heavily on Redis for sliding-window request counting, device fingerprint baselines, and session trust state.
   - In multi-region deployments, cross-region replication latency in Redis can introduce race conditions in velocity calculations or rate tracking unless sticky session routing is enforced at the global load balancer.

4. **Stateless JWT vs. Stateful Continuous Revocation**
   - Standard JWT tokens are cryptographically signed and stateless. Although the gateway inspects and enforces authorization on every proxied request, any internal downstream microservice that accepts the JWT directly (bypassing the gateway) would not be aware of closed-loop SpiceDB restrictions unless it re-validates with the gateway or checks a centralized revocation list.

5. **Telemetry Header Integrity at Ingress**
   - Client telemetry features (`X-Device-Id`, `X-Client-Latitude`, `X-Client-Longitude`) rely on trusted edge infrastructure (e.g., Cloudflare, AWS CloudFront, or enterprise MDM agents).
   - If an attacker can spoof ingress headers directly without passing through an authenticated edge proxy, they could fabricate geographical coordinates or rotate device identifiers unless cryptographic device attestation (e.g., WebAuthn or client mTLS) is enforced.

6. **SpiceDB Storage Engine Persistence**
   - The default development and demo setup runs SpiceDB with an ephemeral memory datastore engine (`datastore-engine: memory`).
   - Restarting the SpiceDB container clears all schema definitions and relationship tuples, requiring re-running `scripts/setup_spicedb.py`. Production environments require persistent PostgreSQL or CockroachDB storage backends.
