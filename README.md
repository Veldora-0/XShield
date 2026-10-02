# XShield
## Hybrid XSS Attack Detection & Risk Intelligence Platform

XShield is a hybrid web security platform that combines deterministic XSS detection, character-level machine learning, risk scoring, behavioral intelligence, and incident correlation to analyze untrusted web application input.

> **Scope & Positioning Notice:** XShield is designed for input-layer threat analysis and defense-in-depth security intelligence. It is not an end-to-end Web Application Firewall (WAF), does not claim 100% detection accuracy, is not represented as guaranteed XSS prevention, and does not replace context-aware output encoding, strict Content Security Policy (CSP), or secure software design.

---

## 1. Overview

Cross-Site Scripting (XSS) remains one of the most prevalent and evasive client-side vulnerabilities in web applications. While traditional signature-based detection mechanisms offer high interpretability and zero false positives for known exploit syntax, they struggle against novel variations and obfuscated payloads. Conversely, standalone machine-learning classifiers can generalize across token sequences but can introduce uncertainty, latency, or false positives on complex benign payloads.

XShield resolves these challenges through a **multi-tiered hybrid architecture**:
- **Deterministic Heuristic Engine (R001–R006):** Validates submitted input against established structural indicators (HTML tags, script constructs, event handlers, execution functions, dangerous URL schemes, and encoding tricks).
- **Statistical ML Engine:** Employs character-level TF-IDF feature extraction (3–5 n-grams, 88,828 features) and Logistic Regression trained on 24,327 verified unique samples.
- **Max-Signal Hybrid Fusion:** Combines rule and ML signals into an explainable 0–100 risk score that drives a four-stage triage policy (`allow`, `flag`, `block`, `block_and_alert`).
- **Contextual Intelligence:** Correlates real-time events across application scopes to surface frequency bursts, repeated suspicious behavior, pattern diversity, and correlated security incidents.

---

## 2. Key Features

- **Authenticated REST Ingestion API:** High-throughput `POST /api/v1/events` endpoint secured by cryptographically generated `X-API-Key` headers stored as one-way SHA-256 hashes.
- **Explainable Rule Engine:** Six independent, deterministic detection rules (R001–R006) providing transparent scoring and forensic reasoning.
- **High-Capacity ML Classifier:** Character-level TF-IDF vectorizer (88,828 features) coupled with an optimized Logistic Regression classifier operating at a calibrated decision threshold of `0.35`.
- **Max-Signal Fusion & Risk Engine:** Dynamically selects the strongest threat signal between heuristics and machine learning, mapping inputs to Low, Medium, High, or Critical risk tiers.
- **Behavioral Intelligence:** Tracks recent per-application telemetry to detect short-window bursts, endpoint repetition, and cross-rule pattern diversity.
- **Deterministic Incident Correlation:** Automatically clusters related events sharing request IDs, endpoints, or attack patterns within sliding time windows.
- **Dedicated SOC Security Console:** Unauthenticated local operations center featuring executive metrics, telemetry graphs, live event inspection, incident correlation views, and registered application tracking.
- **Interactive Payload Scanner & Public Portal:** Interactive exploration workbench allowing security analysts to inspect arbitrary payloads with real-time rule breakdown and ML probability confidence scores.
- **Independent Apex Enterprise Client Integration:** Demonstrates real-time external telemetry ingestion from a separate client web application via HTTP REST API.
- **Full Test Coverage:** 157 automated tests covering all detection algorithms, API ingestion boundaries, database operations, behavioral analytics, and security hardening.

---

## 3. Architecture

```text
Web Application / ApexTestWebsite (Client)
              |
          X-API-Key (SHA-256 Authenticated)
              |
              v
       XShield REST API (POST /api/v1/events)
              |
    Validation / Normalization (Bounded Payload Contract)
              |
              v
     Security Analysis Pipeline
          /             \
         /               \
     Rules                ML
   R001–R006       TF-IDF + LR
  (Structural)     (Statistical)
         \               /
          \             /
           v           v
        Max-Signal Fusion
              |
         Risk 0–100
              |
      Allow / Flag / Block
              |
      Behavioral Analysis (Burst, Repetition, Pattern Diversity)
              |
       Incident Correlation (Deterministic Clustering)
              |
       SQLite Database (Parameterized Persistence)
              |
       Security Console (Dashboard, Events, Incidents)
```

---

## 4. Detection Pipeline

Every input analyzed by XShield passes through a synchronized multi-stage pipeline:

1. **Input Normalization:** Bounded input slices (up to 10,000 characters) are whitespace-normalized, case-folded, and single-pass entity/URL decoded for analysis. Decoded content is treated strictly as data and is never rendered or executed.
2. **Deterministic Rule Execution:** Rules R001 through R006 evaluate the normalized and decoded views. Each matched rule contributes its configured integer weight to the total rule score (capped at 100).
3. **Statistical Inference:** The character-level TF-IDF vectorizer extracts 3–5 character n-grams, transforming the input into an 88,828-dimensional sparse representation evaluated by the Logistic Regression classifier.
4. **Signal Fusion:** The normalized rule score ($[0.0, 1.0]$) and ML probability ($[0.0, 1.0]$) are evaluated using **Max-Signal Fusion**:
   $$\text{hybrid\_signal} = \max(\text{normalized\_rule\_score}, \text{ml\_score})$$
5. **Policy Triage:** The hybrid signal is mapped to a 0–100 risk score and dispatched to the action engine (`allow`, `flag`, `block`, or `block_and_alert`).
6. **Telemetry Logging:** The execution context, rule hits, ML probabilities, decision metadata, and truncated inputs are atomically recorded in SQLite.

### Active Detection Rules (R001–R006)

| Rule ID | Rule Name | Weight | Primary Detection Purpose |
| :---: | :--- | :---: | :--- |
| **R001** | Unexpected HTML markup | 12 | Detects HTML tags and structural markup in non-HTML input fields. |
| **R002** | Script-related construct | 30 | Identifies `<script>` tags, closing tags, and execution functions (`eval(`, `setTimeout(`, `setInterval(`). |
| **R003** | Event-handler attribute | 25 | Matches inline browser event handler attributes (e.g., `onload=`, `onerror=`, `onclick=`). |
| **R004** | Suspicious URL scheme | 25 | Flags script-capable URI schemes including `javascript:`, `vbscript:`, and `data:`. |
| **R005** | Encoded suspicious representation | 15 | Detects encoded entities (`%3c`, `&#x...;`) that resolve into executable constructs upon decoding. |
| **R006** | Multiple suspicious indicators | 15 | Correlates co-occurring base indicators (triggers when 2 or more of R001–R005 match simultaneously). |

---

## 5. Machine Learning

XShield employs an optimized, explainable machine-learning baseline specifically tuned for character-level token analysis in short, structured web inputs:

- **Vectorization:** Character-level TF-IDF (`analyzer="char"`).
- **N-Gram Range:** 3 to 5 characters (`ngram_range=(3, 5)`), capturing syntax fragments, delimiters, and obfuscated sequences without relying on whitespace tokenization.
- **Vocabulary Size:** 88,828 active features (`min_df=2`, `sublinear_tf=True`).
- **Classifier:** Logistic Regression (`solver="liblinear"`, `class_weight="balanced"`, `max_iter=1000`, `random_state=42`).
- **Decision Threshold:** Calibrated operating threshold of **0.35** for high-sensitivity attack detection.
- **Training Corpus:** Trained on a verified canonical dataset of **24,327** unique samples (~24.3K):
  - **15,839** Benign samples (65.11%)
  - **8,488** XSS samples (34.89%)
  - **0** Duplicate texts
  - **0** Overlap with the frozen evaluation benchmark

---

## 6. Risk Engine

The risk engine converts the bounded hybrid signal into a standardized 0–100 risk score:
$$\text{risk\_score} = \text{hybrid\_signal} \times 100$$

### Risk Tiers and Action Policies

| Score Range | Risk Level | Action | System Response |
| :---: | :---: | :---: | :--- |
| **0 – 29** | **Low** | `allow` | Input is accepted and permitted through standard escaped rendering flows. |
| **30 – 59** | **Medium** | `flag` | Input is permitted but marked for operational review and defensive monitoring. |
| **60 – 79** | **High** | `block` | Input is rejected; the submitted text is discarded and blocked from reflection. |
| **80 – 100** | **Critical** | `block_and_alert` | Input is immediately rejected and flagged for prioritized security incident triage. |

---

## 7. Behavioral Intelligence

The behavioral intelligence engine evaluates recent event history on a per-application basis to detect multi-stage attack patterns that might evade single-request inspection:

- **Repeated Suspicious Activity:** Detects clients generating recurring Medium, High, or Critical risk events within a sliding time window.
- **Endpoint Repetition:** Identifies repeated probe patterns directed at identical normalized URL endpoints.
- **Burst / High-Frequency Activity:** Triggers heuristic alerts when event volume exceeds short-window burst thresholds (e.g., rapid automated fuzzing or scanner runs).
- **Attack-Pattern Diversity:** Measures the diversity of triggered detection rules across consecutive requests, surfacing broad multi-vector reconnaissance.
- **Bounded Scope:** All calculations operate strictly on bounded, application-scoped historical records without inferring human identity or executing external tracking.

---

## 8. Incident Correlation

XShield clusters related security events into discrete, actionable incidents using deterministic correlation logic:

- **Correlation Criteria:** Events are grouped based on shared `request_id`, normalized endpoint paths, or overlapping detection rule patterns within the application-scoped correlation window.
- **Automatic Incident Triggering:** Any event evaluated at **High** or **Critical** risk automatically generates or associates with an incident.
- **Deterministic Incident IDs:** Generated using cryptographic SHA-256 digests over normalized event attributes, ensuring consistent forensic tracking.
- **Contextual Telemetry:** Each incident synthesizes timelines, affected endpoints, matched rule catalogs, risk summaries, and behavioral indicators.

---

## 9. REST API

XShield provides an authenticated REST API for external applications and microservices:

### `POST /api/v1/events`

Ingests and analyzes security events submitted by registered applications.

#### Headers
```http
Content-Type: application/json
X-API-Key: xsh_your_api_key_here
```

#### Request Payload
```json
{
  "event_type": "request_observation",
  "endpoint": "/search",
  "http_method": "POST",
  "request_id": "req-98234-abc",
  "input_fields": {
    "query": "search term",
    "filter": "active"
  },
  "metadata": {
    "client_ip": {
      "value": "192.168.1.100",
      "trust": "observed"
    }
  },
  "retention_mode": "truncated"
}
```

#### Response (201 Created)
```json
{
  "accepted": true,
  "event_id": 142,
  "application": "apex-test",
  "status": "stored",
  "analysis": {
    "risk_score": 12.0,
    "risk_level": "Low",
    "action": "allow"
  }
}
```

#### Status Codes
- `201 Created`: Event successfully authenticated, analyzed, and persisted.
- `400 Bad Request`: Malformed JSON or invalid syntax.
- `401 Unauthorized`: Missing, malformed, or invalid `X-API-Key`.
- `403 Forbidden`: Revoked or expired API key or inactive application.
- `413 Request Entity Too Large`: Request body exceeds bounded limit (16 KiB).
- `415 Unsupported Media Type`: Non-JSON Content-Type header.
- `422 Unprocessable Entity`: Request contract violation or missing required fields.

---

## 10. Security Controls & Hardening

XShield enforces rigorous defensive programming practices across all tiers:

- **Payload Non-Execution:** **XShield analyzes submitted input strictly as data; it never executes, evaluates, or interprets submitted payloads.**
- **API Key Hashing:** API keys are generated using cryptographically secure random bytes with an `xsh_` prefix and stored exclusively as one-way SHA-256 digests. Plaintext keys are never stored, logged, or recoverable.
- **Constant-Time Comparison:** Security tokens and key hashes are verified using `hmac.compare_digest` to prevent timing side-channel attacks.
- **Application Isolation:** Every API key is strictly scoped to an application identifier. Events cannot cross application boundaries.
- **SQL Parameterization:** All SQLite interactions use parameterized queries (`?` placeholders). No string concatenation is used in SQL operations.
- **Output Autoescaping:** All HTML views utilize Jinja2 template autoescaping to prevent console reflection vulnerabilities.
- **Bounded Request Limits:** Server-side request limits enforce a 16 KiB maximum payload size to prevent denial-of-service via memory exhaustion.
- **Defensive HTTP Headers:** Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, and Content Security Policy (CSP).
- **Fail-Closed Protection:** In protected client integrations, communication failures or high-risk assessments fail safely by rejecting malicious inputs.

---

## 11. Security Console

The XShield Security Operations Console provides a centralized local interface for threat observation:

- **Executive Dashboard (`/dashboard`):** Real-time threat volume, risk distribution gauges, engine telemetry, and recent event feeds.
- **Events Ledger (`/dashboard/events`):** Full telemetry audit log with multi-criteria filtering by risk tier (`Low`, `Medium`, `High`, `Critical`), action type (`allow`, `flag`, `block`), and keyword search.
- **Incidents View (`/dashboard/incidents`):** Correlated security incidents with linked events, chronological timelines, and root-cause indicators.
- **Behavioral Intelligence (`/dashboard/behavior`):** Active behavioral context metrics showing short-window bursts, repetitive endpoints, and attack diversity scores.
- **Applications Registry (`/dashboard/applications`):** Status, key counts, and telemetry volume for registered client integrations.
- **Event Detail View (`/dashboard/event/<id>`):** Detailed forensic breakdown for individual events with escaped payload views, rule-by-rule inspection, and ML confidence.
- **Light/Dark Theme:** Full theme toggle with persistent preference storage across sessions.

> **Demonstration Mode Note:** The local security console is unauthenticated to allow straightforward evaluation during project demonstrations. Production deployments require enterprise single sign-on (SSO) and role-based access control (RBAC).

---

## 12. ApexTestWebsite Integration

`ApexTestWebsite` is an independent external demonstration web application that integrates with XShield strictly through HTTP REST API calls:

- **Decoupled Architecture:** ApexTestWebsite runs as an independent service (port `3000`) and does not import XShield internal Python modules.
- **API Authentication:** Authenticates outbound event submissions using an application-scoped `X-API-Key`.
- **Live Interception:** Forwards form inputs to `POST /api/v1/events` on XShield and enforces real-time blocking when high-risk scores are returned.

---

## 13. Controlled XSS Playground

ApexTestWebsite includes a controlled side-by-side demonstration sandbox to showcase attack detection and prevention:

- **Protected Mode:** Inputs are intercepted by XShield. Malicious payloads are detected, assigned High/Critical risk, blocked, and recorded in the Security Console.
- **Vulnerable-Render Mode:** Demonstrates the raw consequences of unencoded input reflection in an isolated, safe test sandbox using harmless local test vectors (e.g., benign text probes).
- **Educational Value:** Clearly illustrates why input detection and contextual output encoding are complementary layers of defense.

---

## 14. Benchmark Results

The XShield detection pipeline was evaluated against a **frozen benchmark of 3,967 samples** (`data/processed/xss_test.csv`).

> **Methodology Note:** The frozen benchmark was kept strictly isolated from model training and threshold selection. No vectorizer or classifier was fitted on this benchmark set.

### Final Evaluation Metrics (Frozen Held-Out Benchmark)

| Detection Engine | Accuracy | Precision (XSS) | Recall (XSS) | F1-Score (XSS) |
| :--- | :---: | :---: | :---: | :---: |
| **Rule-Based Engine (R001–R006)** | 99.80% | 100.00% | 92.45% | 96.08% |
| **Final ML Model (TF-IDF + LR)** | **99.92%** | **100.00%** | **97.17%** | **98.56%** |
| **Hybrid Detector (Fusion)** | 99.72% | 100.00% | 89.62% | 94.53% |

### Confusion Matrix Breakdown

| Detection Engine | True Negatives (TN) | False Positives (FP) | False Negatives (FN) | True Positives (TP) | Total Samples |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Rule-Based Engine** | 3,861 | 0 | 8 | 98 | 3,967 |
| **Final ML Model** | **3,861** | **0** | **3** | **103** | **3,967** |
| **Hybrid Detector** | 3,861 | 0 | 11 | 95 | 3,967 |

- **Zero False Positives:** Across 3,861 benign benchmark samples, the final ML model achieved a **0.00% false-positive rate** ($\text{FP} = 0$).
- **High Recall:** The model successfully identified 103 out of 106 XSS attacks ($\text{Recall} = 97.17\%$).

---

## 15. Project Structure

```text
XShield/
├── app/                              # Core application package
│   ├── __init__.py                   # Application factory (Flask)
│   ├── __main__.py                   # CLI entry point for python -m app
│   ├── api.py                        # REST API routes (POST /api/v1/events)
│   ├── config.py                     # Configuration constants & limits
│   ├── routes.py                     # Public routes & Security Console views
│   ├── validation.py                 # Input validation and size checks
│   ├── database/                     # SQLite persistence layer
│   │   ├── __init__.py
│   │   └── db.py                     # Schema migrations & queries
│   ├── detector/                     # Rule-based heuristic engines
│   │   ├── __init__.py
│   │   ├── hybrid_detector.py        # Max-Signal fusion orchestration
│   │   ├── rule_engine.py            # Rule execution runner
│   │   └── rules.py                  # R001-R006 rule definitions
│   ├── ml/                           # Machine learning components
│   │   ├── __init__.py
│   │   └── predictor.py              # TF-IDF vectorization & inference
│   ├── response/                     # Action policy dispatch
│   │   ├── __init__.py
│   │   └── action_engine.py          # Allow / Flag / Block policy
│   ├── risk/                         # Risk scoring engine
│   │   ├── __init__.py
│   │   └── risk_engine.py            # 0-100 score mapping & reasons
│   ├── services/                     # Business logic services
│   │   ├── __init__.py
│   │   ├── analysis.py               # Unified analysis orchestration
│   │   ├── api_keys.py               # SHA-256 API key management
│   │   ├── behavior.py               # Behavioral intelligence context
│   │   ├── dashboard.py              # Telemetry aggregation
│   │   ├── event_contract.py         # Bounded event contract
│   │   ├── event_ingestion.py        # Ingestion validation & storage
│   │   ├── incidents.py              # Deterministic incident correlation
│   │   └── security_logger.py        # Database event persistence
│   ├── static/                       # Static web assets
│   │   ├── css/style.css             # UI styling & light/dark theme
│   │   └── js/script.js              # Theme switcher & UI helpers
│   └── templates/                    # Jinja2 presentation templates
│       ├── api_docs.html
│       ├── base.html
│       ├── base_console.html
│       ├── base_product.html
│       ├── benchmark.html
│       ├── dashboard.html
│       ├── dashboard_applications.html
│       ├── dashboard_behavior.html
│       ├── dashboard_events.html
│       ├── dashboard_incidents.html
│       ├── demo.html
│       ├── event_detail.html
│       ├── event_not_found.html
│       ├── home.html
│       ├── how_it_works.html
│       ├── rules.html
│       └── scanner.html
├── data/                             # Dataset storage
│   ├── processed/                    # Cleaned training & benchmark splits
│   │   ├── xss_train_final.csv       # Final training corpus (24,327 samples)
│   │   ├── xss_test.csv              # Frozen evaluation benchmark (3,967 samples)
│   │   └── dataset_report.json
│   └── raw/                          # Raw source data manifests
├── docs/                             # Engineering documentation
│   ├── XShield_Technical_Documentation.md
│   ├── architecture.md
│   ├── demo_guide.md
│   ├── security.md
│   └── setup.md
├── models/                           # Trained ML artifacts (.joblib gitignored)
│   ├── ml_training_report.json       # Training metadata & hyperparams
│   └── .gitkeep
├── reports/                          # Evaluation reports & confusion matrices
│   ├── evaluation_results.json
│   ├── evaluation_report.txt
│   ├── hybrid_confusion_matrix.json
│   ├── ml_confusion_matrix.json
│   └── rule_confusion_matrix.json
├── scripts/                          # Administration & evaluation utilities
│   ├── evaluate_all.py               # Complete benchmark evaluation
│   ├── manage_applications.py        # Application & API key CLI
│   ├── reset_demo_data.py            # Clean telemetry reset utility
│   └── train_ml_model.py             # Reproducible model training
├── tests/                            # Automated test suite (157 tests)
│   ├── test_action_engine.py
│   ├── test_application_management.py
│   ├── test_dashboard.py
│   ├── test_database.py
│   ├── test_detector.py
│   ├── test_hybrid_detector.py
│   ├── test_ml_prediction.py
│   ├── test_phase4_api.py
│   ├── test_phase6_behavior.py
│   ├── test_phase7_incidents.py
│   ├── test_reset_demo_data.py
│   ├── test_risk_engine.py
│   ├── test_rule_engine.py
│   └── test_security_hardening.py
├── .gitignore                        # Git exclusion rules
├── README.md                         # Project documentation
└── requirements.txt                  # Python dependencies
```

---

## 16. Requirements

- **Operating System:** Windows 10/11, Linux, or macOS.
- **Python Runtime:** Python 3.10, 3.11, or 3.12 (Python 3.11+ recommended).
- **Core Dependencies:**
  - `Flask` (Web framework and REST routing)
  - `scikit-learn` (TF-IDF vectorizer and Logistic Regression)
  - `joblib` (Model persistence)
  - `numpy` & `pandas` (Matrix and tabular operations)

---

## 17. Installation

### 1. Clone the Repository
```powershell
git clone https://github.com/Veldora-0/XShield.git
cd XShield
```

### 2. Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 18. Running XShield

Start the XShield web application and Security Console:

```powershell
cd D:\XShield
.\.venv\Scripts\python.exe -m app
```

Once started, the following interfaces will be available:
- **Public Product Portal:** <http://127.0.0.1:5000/>
- **Interactive Payload Scanner:** <http://127.0.0.1:5000/scanner>
- **Security Operations Console:** <http://127.0.0.1:5000/dashboard>
- **Events Ledger:** <http://127.0.0.1:5000/dashboard/events>
- **Correlated Incidents:** <http://127.0.0.1:5000/dashboard/incidents>
- **API Documentation:** <http://127.0.0.1:5000/api>
- **System Health Check:** <http://127.0.0.1:5000/health>

### Managing Applications and API Keys
To generate API keys for client applications, use the CLI utility:

```powershell
# List registered applications
.\.venv\Scripts\python.exe scripts\manage_applications.py list-applications

# Create a new client application
.\.venv\Scripts\python.exe scripts\manage_applications.py create-application demo-client "Demo Client Application"

# Generate an authenticated API key (key is displayed ONCE)
.\.venv\Scripts\python.exe scripts\manage_applications.py create-api-key --slug demo-client
```

### Resetting Demonstration Telemetry
To reset the demonstration telemetry ledger to a clean state while preserving registered applications and API keys:

```powershell
.\.venv\Scripts\python.exe scripts\reset_demo_data.py
# Type 'RESET' when prompted
```

---

## 19. Running ApexTestWebsite (External Integration)

To launch the separate client application:

```powershell
cd D:\ApexTestWebsite
python run.py
```

The client application will start on <http://127.0.0.1:3000> and communicate with XShield on port 5000.

---

## 20. Testing

Run the complete automated test suite across all modules:

```powershell
# Run all XShield unit and integration tests (157 expected)
.\.venv\Scripts\python.exe -m unittest discover -s tests -v

# Run reproducible evaluation across the frozen benchmark
.\.venv\Scripts\python.exe scripts\evaluate_all.py
```

---

## 21. Example Workflow

1. **Ingest Payload:** A client submits user input to a protected web form.
2. **API Dispatch:** The client forwards the input to `POST /api/v1/events` with its `X-API-Key`.
3. **Authentication:** XShield computes the SHA-256 hash of the key, checks the database in constant time, and verifies the application status.
4. **Heuristic Evaluation:** Rules R001–R006 inspect the decoded text for markup, script tags, event handlers, and encoding tricks.
5. **ML Prediction:** The character TF-IDF vectorizer extracts n-grams and computes the probability of malicious intent.
6. **Signal Fusion:** Max-Signal Fusion combines the evidence into an explainable 0–100 risk score.
7. **Action Dispatch:** If risk is High or Critical, the API returns a blocking directive.
8. **Forensic Logging:** Telemetry is written to the SQLite ledger and immediately appears in the Security Console.

---

## 22. Limitations

- **Input-Layer Scope:** XShield evaluates inputs before processing. It cannot verify whether an input is safely handled by downstream application templates or context-aware encoding.
- **Offline Benchmark Evaluation:** Benchmark metrics (99.92% accuracy, 0% FP) reflect evaluation on the curated benchmark dataset; real-world obfuscation and zero-day evasion techniques may yield different performance.
- **Single-Host Database:** Uses SQLite for local persistence, which is appropriate for prototype demonstrations and single-node instances, but requires PostgreSQL or distributed storage for enterprise workloads.
- **Console Authentication:** The local security console operates unauthenticated for demonstration purposes; production deployments require enterprise identity providers (IdP) and RBAC.

---

## 23. Future Scope

- **Deep Learning Comparison:** Benchmarking against transformer-based tokenizers (e.g., CodeBERT, SecBERT) for complex JavaScript evasion patterns.
- **Distributed Ingestion:** Migration to asynchronous event brokers (e.g., Apache Kafka, Redis Streams) for distributed microservice deployments.
- **Automated Rule Synthesis:** Dynamic generation of heuristic rules based on emerging attack clusters identified by the incident correlation engine.
- **Context-Aware Output Verification:** Integrating client-side instrumentation to verify whether blocked payloads would have executed in specific DOM contexts.

---

## 24. Project Information

- **Project:** XShield — Hybrid XSS Attack Detection & Risk Intelligence Platform
- **Author:** Varun Goel
- **Academic Context:** B.Tech Computer Science & Engineering
- **Institution:** ABES Engineering College, Ghaziabad (Affiliated to AKTU, Lucknow)
- **Project Guide:** Mr. Priyan S
- **Repository:** [https://github.com/Veldora-0/XShield.git](https://github.com/Veldora-0/XShield.git)
