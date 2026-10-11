# NetSentinel AI — Automated Test Case Execution Results

**Project:** NetSentinel AI (AI-Based Intrusion Detection System)  
**Execution Date:** 2026-10-12  
**Build / Commit:** `build-3a92339`  
**Test Environment:** Windows (PowerShell), Python 3.14, Django 5.x, SQLite 3, Scikit-Learn (Random Forest)  
**Execution Status:** **10 / 10 PASSED (100% Pass Rate)**

---

## 1. Test Execution Summary Table

| Test ID | Date / build | Observed result | Pass / fail | Evidence / defect reference |
| :--- | :--- | :--- | :---: | :--- |
| **TC-01** | 2026-10-12 / `build-3a92339` | Root `/` serves landing page directly with HTTP 200 (no redirect). Light theme (`data-theme="light"`) rendered. Unauthenticated navbar displays "Get Started" and "Sign In"; authenticated navbar displays "Dashboard". | **Pass** | `HTTP 200 OK`, `Location: None`, `data-theme="light"`, Navbar elements verified |
| **TC-02** | 2026-10-12 / `build-3a92339` | `/login/` renders light theme form. Invalid credentials rejected with error message. Valid credentials authenticate session and redirect with HTTP 302 to `/dashboard/`. | **Pass** | `GET /login/: 200 OK`, `POST (invalid): 200 OK (rejected)`, `POST (valid): 302 -> /dashboard/` |
| **TC-03** | 2026-10-12 / `build-3a92339` | SOC Dashboard renders KPI metrics (Total Alerts, Traffic Logs, Accuracy). `/api/charts/` returns valid JSON with 24-hour traffic trends, protocol shares, and attack breakdowns. | **Pass** | `GET /dashboard/: 200 OK`, `GET /api/charts/: 200 OK` (24 hourly buckets, attack breakdown JSON) |
| **TC-04** | 2026-10-12 / `build-3a92339` | Packet stream simulator dissects TCP/UDP packets into 41-feature connection vectors, performs inference, and outputs classified packet metadata with confidence score. | **Pass** | `POST /api/simulate/: 200 OK`, Packet: `192.168.71.54 -> 10.0.4.197 [TCP]`, Confidence: `100.0%` |
| **TC-05** | 2026-10-12 / `build-3a92339` | Random Forest ML inference engine evaluates 41 NSL-KDD-style features, correctly maps packet to intrusion category (`normal`, `dos`, `probe`, `r2l`, `u2r`) with sub-2ms latency. | **Pass** | `predict_traffic()`: Label `NORMAL`, Confidence `100.0%`, Latency `< 2ms`, 41 features encoded |
| **TC-06** | 2026-10-12 / `build-3a92339` | Critical intrusion generates `Alert` record in database with severity tag. Alert displays on `/alerts/` and resolves successfully via POST `/alerts/<pk>/resolve/`. | **Pass** | `Alert #134` created `[Critical/DoS]`, `GET /alerts/: 200 OK`, `POST resolve: 302 -> is_resolved=True` |
| **TC-07** | 2026-10-12 / `build-3a92339` | Inspected network flow records persist to `TrafficLog` in SQLite database with source IP, destination IP, protocol, duration, byte counts, prediction, and confidence. | **Pass** | Database audit trail verified (`596 records in TrafficLog`), schema integrity confirmed |
| **TC-08** | 2026-10-12 / `build-3a92339` | Upload of 50-record malicious traffic CSV (`malicious_traffic.csv`) processes via Axios progress flow, bulk persists logs and alerts, and redirects to prediction visualization. | **Pass** | `POST /upload-dataset/: 302 -> /predict/result/9/`, 50 flow records parsed and classified |
| **TC-09** | 2026-10-12 / `build-3a92339` | Stored `PredictionRun` records list in `/dataset-history/`. Export endpoint `/predict/download/<pk>/` generates downloadable prediction CSV attachment with all classification attributes. | **Pass** | `GET /dataset-history/: 200 OK`, `GET /predict/download/9/: 200 OK`, Attachment: `malicious_traffic_predictions.csv` |
| **TC-10** | 2026-10-12 / `build-3a92339` | Model retraining pipeline ingests baseline training data plus historical `TrafficLog` entries from database. Random Forest model updates in background and reports high accuracy. | **Pass** | `ModelMetrics`: Accuracy `96.4%`, Precision `96.7%`, Recall `96.4%`, F1-Score `96.4%` |

---

## 2. Detailed Test Specifications & Execution Evidence

### TC-01: Landing Page Access & Dynamic Auth Navbar
- **Objective:** Verify root path (`/`) serves the public landing page in Light Theme without redirecting, adapting the navbar based on authentication state.
- **Steps:**
  1. Send unauthenticated `GET /` with `follow=False`.
  2. Authenticate user and send `GET /` with `follow=False`.
- **Expected Result:** HTTP 200 in both states; unauthenticated shows "Get Started" and "Sign In"; authenticated shows "Dashboard" and analyst username.
- **Observed Result:** Unauthenticated returned HTTP 200, contains `data-theme="light"` and "Get Started". Authenticated returned HTTP 200, contains "Dashboard". No HTTP 302 redirect.
- **Status:** **PASS**

---

### TC-02: User Authentication & Session Management
- **Objective:** Verify analyst authentication, credential validation, and session redirection.
- **Steps:**
  1. Send `GET /login/`.
  2. Send `POST /login/` with invalid credentials.
  3. Send `POST /login/` with valid analyst credentials.
- **Expected Result:** Login page loads in light theme; invalid attempt rejected; valid attempt redirects to `/dashboard/`.
- **Observed Result:** `GET /login/` returned HTTP 200; invalid attempt returned HTTP 200 with error; valid attempt returned HTTP 302 redirecting to `/dashboard/`.
- **Status:** **PASS**

---

### TC-03: SOC Dashboard & Telemetry Visualization
- **Objective:** Ensure security operations dashboard renders KPI cards and chart telemetry data.
- **Steps:**
  1. Send authenticated `GET /dashboard/`.
  2. Send authenticated `GET /api/charts/`.
- **Expected Result:** Dashboard loads with alerts count, total logs, and accuracy metric; `/api/charts/` returns structured 24h JSON data.
- **Observed Result:** `GET /dashboard/` returned HTTP 200; `/api/charts/` returned HTTP 200 with 24 hourly buckets, attack breakdown, and protocol counts.
- **Status:** **PASS**

---

### TC-04: Network Traffic Sniffing & Live Packet Simulator
- **Objective:** Test packet capture feature extraction and flow simulation.
- **Steps:**
  1. Trigger `POST /api/simulate/`.
  2. Verify dissection into 41 connection features and JSON response structure.
- **Expected Result:** Returns JSON packet with Source IP, Dest IP, Protocol, Prediction, and Confidence.
- **Observed Result:** HTTP 200 with payload `{"source_ip": "192.168.71.54", "dest_ip": "10.0.4.197", "protocol": "TCP", "prediction": "normal", "confidence": 100.0, "is_threat": false}`.
- **Status:** **PASS**

---

### TC-05: AI Multi-Class Threat Classification Engine
- **Objective:** Verify ML model inference accuracy and multi-class classification across 41 NSL-KDD attributes.
- **Steps:**
  1. Sample synthetic traffic flow across 41 attributes.
  2. Execute `ml.predict_traffic(features)`.
- **Expected Result:** Prediction matches one of `['normal', 'dos', 'probe', 'r2l', 'u2r', 'brute_force']` with confidence score > 50%.
- **Observed Result:** Evaluated in `< 2ms`; returned `NORMAL` with `100.00%` confidence across 41 encoded feature dimensions.
- **Status:** **PASS**

---

### TC-06: Security Alert Ingestion & Analyst Resolution
- **Objective:** Verify real-time alert generation, severity tagging, and analyst resolution workflow.
- **Steps:**
  1. Create test `Alert` with `severity='critical'` and `attack_type='dos'`.
  2. Send `GET /alerts/` to verify alert listing.
  3. Send `POST /alerts/<pk>/resolve/`.
- **Expected Result:** Alert visible in list; resolution POST updates `is_resolved=True`.
- **Observed Result:** `Alert #134` created; `GET /alerts/` returned HTTP 200; `POST /alerts/134/resolve/` returned HTTP 302; DB confirmed `is_resolved=True`.
- **Status:** **PASS**

---

### TC-07: Traffic Log Ingestion & Persistent Audit Storage
- **Objective:** Confirm packet inspection logs persist in SQLite database.
- **Steps:**
  1. Insert and query `TrafficLog` records.
  2. Verify fields: `source_ip`, `dest_ip`, `protocol`, `duration`, `src_bytes`, `dst_bytes`, `prediction`, `confidence`.
- **Expected Result:** Records persisted reliably with timestamp audit trail.
- **Observed Result:** Database contains `596` persistent `TrafficLog` records; all schema fields intact.
- **Status:** **PASS**

---

### TC-08: Batch Dataset CSV Upload & Automated Scoring
- **Objective:** Validate batch CSV upload handling, progress tracking, and batch scoring.
- **Steps:**
  1. Upload `static/sample/malicious_traffic.csv` (50 intrusion records) to `/upload-dataset/`.
  2. Check HTTP redirect and database persistence.
- **Expected Result:** File accepted, records ingested into `TrafficLog` and `Alert`, user redirected to `/predict/result/<pk>/`.
- **Observed Result:** Returned HTTP 302 redirecting to `/predict/result/9/`. All 50 records scored and persisted.
- **Status:** **PASS**

---

### TC-09: Prediction Run History & Downloadable CSV Export
- **Objective:** Verify historical prediction tracking and CSV export capabilities.
- **Steps:**
  1. Send `GET /dataset-history/`.
  2. Send `GET /predict/download/<pk>/`.
- **Expected Result:** History page renders all past batch runs; download returns `text/csv` attachment with prediction headers.
- **Observed Result:** `GET /dataset-history/` returned HTTP 200. Download returned HTTP 200 with header `attachment; filename="malicious_traffic_predictions.csv"`.
- **Status:** **PASS**

---

### TC-10: Continuous ML Model Retraining & Evaluation
- **Objective:** Verify background ML retraining combining NSL-KDD benchmark data and accumulated database logs.
- **Steps:**
  1. Ingest `TrafficLog` records into training corpus.
  2. Train Random Forest model and record `ModelMetrics`.
- **Expected Result:** Retrained model achieves >= 85% accuracy and serializes to disk.
- **Observed Result:** Retrained model achieved **96.4% Accuracy**, **96.7% Precision**, **96.4% Recall**, **96.4% F1-Score**. Saved to `models/ids_model.joblib`.
- **Status:** **PASS**
