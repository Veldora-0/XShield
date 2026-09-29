# XShield

## AI/ML-Based XSS Attack Detection and Risk Assessment System

## 1. Overview

XShield is a defensive cybersecurity research and college-project prototype
that analyzes user-controlled text for characteristics associated with
cross-site scripting (XSS). It combines an explainable rule detector with a
saved machine-learning baseline, converts their signals into a project-defined
risk score, applies a local response policy, records security events in
SQLite, and presents them through a protected dashboard.

XShield is a detection and risk-assessment demonstration. It does not
guarantee detection of every XSS attack and does not replace context-aware
output encoding, trusted sanitization, secure application design, or a
production web-application firewall.

### XShield 2.0 preparation status

The project is being evolved incrementally toward an integration-ready
platform. Phase 1 defines a validated internal security-event contract and
shared integration limits. Phase 2 adds an idempotent SQLite schema migration
and application registry without enabling an external API or changing the
existing browser pipeline. Phase 3 adds local application/API-key management
and a reusable API-key validation service. Event ingestion, behavior
signals, incidents, and the separate demo website are planned for later
phases.

## 2. Problem Statement

User-controlled input can contain markup, script-related constructs,
event-handler patterns, suspicious URL schemes, or encoded representations.
Identifying suspicious input is difficult because legitimate text can contain
unusual characters and attack strings can be obfuscated or context-dependent.
Static rules are interpretable but incomplete, while an ML classifier depends
on the data used to train and evaluate it. XShield demonstrates how these
signals can be examined together without treating a detector prediction as
proof of an attack.

## 3. Objectives

- Build a beginner-friendly Flask application for local defensive analysis.
- Implement modular, explainable rule-based XSS indicators.
- Train and reuse a TF-IDF and Logistic Regression baseline.
- Combine rule and ML evidence with configurable experimental weights.
- Convert the hybrid signal into project-defined risk levels and actions.
- Record completed security events without executing submitted text.
- Provide a protected dashboard for local event review.
- Evaluate rule-based, ML, and hybrid methods on the same held-out test set.
- Document limitations, security controls, and reproducible project commands.

## 4. Key Features

- Flask application factory with `/`, `/health`, `/dashboard`, and
  `/dashboard/event/<id>` routes.
- Server-side validation for username, search query, and comment fields.
- Rule detector with six indicator categories and explanations.
- Saved character-level TF-IDF vectorizer and Logistic Regression classifier.
- Hybrid signal with normalized rule and ML contributions.
- Risk score, risk level, reasons, and response action.
- SQLite security-event persistence and dashboard aggregates.
- HTTP Basic Authentication for dashboard routes.
- Local application registration and hashed API-key management for future
  integrations; no event-ingestion route is enabled yet.
- Jinja autoescaping, request-size limits, parameterized SQL, controlled model
  errors, and basic security headers.
- Automated unit, integration, security-hardening, and evaluation tests.

## 5. Architecture

```text
User Input
    |
    +------------------+
    |                  |
Rule Detector      ML Detector
    |                  |
    +--------+---------+
             |
      Hybrid Detector
             |
       Risk Engine
             |
      Action Engine
             |
       SQLite Logger
             |
        Dashboard
```

The form submission is handled by `app/routes.py`. The rule and ML detectors
produce evidence, the hybrid detector combines it, the risk engine classifies
the signal, and the response engine determines the local application action.
The completed event is then stored and can be reviewed through the
authenticated dashboard.

## 6. Rule-Based Detection

The rule detector is implemented in `app/detector/rules.py` and
`app/detector/rule_engine.py`. It creates bounded, case-insensitive views of
the input, performs one layer of URL/entity decoding for comparison, and
never executes or renders the decoded data.

Implemented rule categories:

| ID | Category | Weight |
|---|---|---:|
| R001 | Unexpected HTML-like markup | 12 |
| R002 | Script-related constructs, including selected execution functions | 30 |
| R003 | Event-handler-style attributes | 25 |
| R004 | Potentially script-capable URL schemes | 25 |
| R005 | Encoded characters decoding to suspicious constructs | 15 |
| R006 | Combination of multiple independent indicators | 15 |

The score is the sum of matched rule weights, capped at 100. Results include
matched IDs, reasons, and rule details. For comparative evaluation, the
explicit experimental binary threshold was `score >= 1`, meaning any positive
rule score was classified as suspicious. These rules are indicators rather
than complete XSS coverage and may miss new, fragmented, context-dependent, or
obfuscated inputs.

## 7. Machine Learning

```text
Dataset
   |
Preprocessing
   |
Train/Test Split
   |
Character TF-IDF
   |
Logistic Regression
   |
Prediction and XSS Probability
```

The model uses the cleaned `HttpParamsDataset` split. Character-level TF-IDF
represents recurring character sequences, which is useful for short input
where punctuation, delimiters, encodings, and fragments can matter. The
baseline classifier is Logistic Regression because it is relatively simple,
fast, interpretable as a probability-producing linear baseline, and suitable
for a beginner-friendly project.

Actual training configuration:

- `analyzer="char"`
- `ngram_range=(3, 5)`
- `min_df=2`
- `sublinear_tf=True`
- `class_weight="balanced"`
- Logistic Regression solver: `liblinear`
- `max_iter=1000`
- random seed: `42`
- TF-IDF features: `54,919`

The vectorizer is fitted only on training text. The saved artifacts are
`models/xss_tfidf_vectorizer.joblib` and
`models/xss_logistic_regression.joblib`. They are loaded only from these fixed
project paths and must come from a trusted project source.

## 8. Hybrid Detection

The hybrid detector runs both detectors for the same text. The rule score is
normalized from `0-100` to `0.0-1.0`, and the ML score is the probability of
the XSS class:

```text
normalized_rule_score = rule_score / 100
ml_score = XSS probability

hybrid_signal =
    rule_weight * normalized_rule_score
    + ml_weight * ml_score
```

The current default configuration is:

```text
rule_weight = 0.5
ml_weight   = 0.5
```

The implementation normalizes non-negative supplied weights so that they sum
to one. These values are project configuration for experimentation, not
industry standards or optimized claims.

## 9. Risk Assessment

The risk engine converts the bounded hybrid signal to a `0-100` score:

```text
risk_score = hybrid_signal * 100
```

The project-defined experimental thresholds are:

| Score | Risk level |
|---:|---|
| 0-29 | Low |
| 30-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

These thresholds are not universal cybersecurity standards.

## 10. Response Policy

| Risk level | Action | Local prototype behavior |
|---|---|---|
| Low | `allow` | Continue the safe escaped-text demonstration flow. |
| Medium | `flag` | Continue only through the safe escaped-text flow and mark it for attention. |
| High | `block` | Reject the input in the local demonstration and do not display the submitted content. |
| Critical | `block_and_alert` | Reject it and mark that a future alert would be required. |

The prototype does not block IP addresses, change a firewall, terminate
network connections, or send external alerts.

## 11. Database Logging

`app/database/db.py` stores events in `data/xshield.sqlite3` in the
`security_events` table. A completed event includes:

- auto-incrementing ID
- UTC timestamp
- submitted combined input text
- rule score
- ML probability and prediction
- hybrid signal
- risk score and risk level
- action
- detector agreement
- JSON-encoded matched rules and reasons

The database layer provides recent-event retrieval, event lookup, total
counts, risk-level counts, dashboard statistics, and bounded filters. SQL
values are passed as parameters. Raw input is retained for this local
demonstration; production use would require data minimization, privacy,
retention, access, encryption, and backup decisions.

## 12. Dashboard

- Dashboard: `GET /dashboard`
- Event details: `GET /dashboard/event/<id>`

The dashboard shows total events, Low/Medium/High/Critical counts, blocked
events, a risk distribution, up to 50 newest events, risk/action filters, text
search, and event details. Event text is rendered through normal Jinja
escaping.

Dashboard routes require HTTP Basic Authentication. Configure credentials
before starting the application:

```powershell
$env:XSHIELD_DASHBOARD_USERNAME = "admin"
$env:XSHIELD_DASHBOARD_PASSWORD = "choose-a-local-password"
.\.venv\Scripts\python.exe -m app
```

If no password is configured, the dashboard returns `503` rather than
exposing stored events. Basic Authentication is a minimal local-prototype
control, not a complete production identity system.

## 13. Dataset

XShield uses `HttpParamsDataset` from the original
[Morzeux/HttpParamsDataset repository](https://github.com/Morzeux/HttpParamsDataset)
and its Kaggle distribution. The project records the original source license
as MIT.

The source includes `payload`, `length`, `attack_type`, and `label` fields.
XShield uses only:

- `attack_type=norm` -> label `0` -> `BENIGN`
- `attack_type=xss` -> label `1` -> `XSS`

SQL injection, command injection, and path-traversal records are excluded
instead of being relabeled as XSS. The preparation script:

- checks required columns;
- removes missing/blank or unsupported records;
- removes exact duplicates;
- removes case-folded, whitespace-normalized duplicate text;
- creates `text` and binary `label` columns;
- makes a reproducible 80/20 per-class split with seed `42`;
- checks for normalized train/test overlap.

Actual preparation values:

| Quantity | Value |
|---|---:|
| Source rows | 31,067 |
| Missing source records | 0 |
| Unsupported attack records excluded | 11,231 |
| Final cleaned rows | 19,836 |
| Benign rows | 19,304 |
| XSS rows | 532 |
| Training rows | 15,869 |
| Test rows | 3,967 |
| Test benign/XSS | 3,861 / 106 |
| Normalized train-test overlap | 0 |

The report also records 15 source length metadata mismatches; the model uses
the payload text rather than treating the source length field as a feature.

## 14. Model Evaluation

Phase 13 evaluated all methods on the same held-out
`data/processed/xss_test.csv`. No model or vectorizer was fitted on the test
set. The positive class is XSS (`label=1`).

Evaluation thresholds were experimental and fixed before reporting:

- Rule score: `>= 1`
- ML XSS probability: `>= 0.5`
- Hybrid signal: `>= 0.5`

| Method | Accuracy | Precision (XSS) | Recall (XSS) | F1 (XSS) |
|---|---:|---:|---:|---:|
| Rule-Based | 0.9979833627 | 1.0000000000 | 0.9245283019 | 0.9607843137 |
| ML | 0.9989916814 | 1.0000000000 | 0.9622641509 | 0.9807692308 |
| Hybrid | 0.9979833627 | 1.0000000000 | 0.9245283019 | 0.9607843137 |

Confusion matrices use rows as actual labels `[0, 1]` and columns as predicted
labels `[0, 1]`:

| Method | TN | FP | FN | TP |
|---|---:|---:|---:|---:|
| Rule-Based | 3,861 | 0 | 8 | 98 |
| ML | 3,861 | 0 | 4 | 102 |
| Hybrid | 3,861 | 0 | 8 | 98 |

These are results for this dataset and split only. They do not establish
real-world detection performance or make one method universally superior.
Representative false-negative examples and machine-readable results are in
`reports/evaluation_results.json`.

## 15. Security Review

Phase 14 verified and hardened:

- server-side field validation and per-field limits;
- a 16 KiB Flask request-size limit;
- Jinja output escaping and no unsafe application HTML/JavaScript sinks;
- parameterized SQLite queries and allowlisted dashboard filters;
- fixed-path trusted model loading with controlled missing/corrupt errors;
- generic user-facing database failure messages;
- disabled debug mode by default;
- Content Security Policy, `nosniff`, `X-Frame-Options`, and
  `Referrer-Policy` headers;
- HTTP Basic Authentication for dashboard routes, failing closed if no
  password is configured;
- safe logging and preservation of existing database records.

The review report is `reports/security_review.md`.

## 16. Known Limitations

- Results depend on the selected dataset and its strongly imbalanced test set.
- Rules and ML can produce false negatives and may not generalize to every
  browser context, encoding, or application.
- Rule, hybrid, and risk thresholds are project-defined experimental values.
- The response policy is application-level demonstration behavior.
- SQLite and raw input retention are not production-scale privacy or storage
  designs.
- HTTPS/TLS is not configured.
- Production identity, authorization roles, and audit controls are not
  implemented.
- Dashboard credentials would require secure storage, rotation, and stronger
  identity management in production.
- Requirements are not pinned or hash-locked.
- CSRF and production deployment controls require a deliberate future design.

## 17. Future Scope

Appropriate future work includes larger and more diverse datasets, additional
ML and deep-learning comparisons, adversarial robustness testing, calibrated
threshold studies, optional threat-intelligence integration, production
authentication/authorization, HTTPS deployment, centralized logging,
privacy/retention policies, a scalable database, and real-time monitoring.
These features are not currently implemented.

## 18. Installation

From the project root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The repository includes the prepared dataset and saved model artifacts for
demonstration. To reproduce preparation or training locally:

```powershell
.\.venv\Scripts\python.exe scripts\prepare_dataset.py
.\.venv\Scripts\python.exe scripts\train_ml_model.py
```

Training is not required for ordinary application startup when the saved
artifacts already exist.

## 19. Running XShield

Configure dashboard credentials and start the application:

```powershell
$env:XSHIELD_DASHBOARD_USERNAME = "admin"
$env:XSHIELD_DASHBOARD_PASSWORD = "choose-a-local-password"
.\.venv\Scripts\python.exe -m app
```

Open:

- Application: <http://127.0.0.1:5000/>
- Health check: <http://127.0.0.1:5000/health>
- Dashboard: <http://127.0.0.1:5000/dashboard>

The development entry point keeps debug mode disabled unless
`XSHIELD_DEBUG=true` is explicitly set.

## 20. Testing

Run the complete test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Run comparative evaluation without retraining:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_all.py
```

Run the earlier ML-only evaluation:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_model.py
```

The test suite includes detector, ML artifact, risk, action, database,
dashboard, pipeline, evaluation, and security-hardening coverage.

## 21. Project Structure

```text
XShield/
|-- app/
|   |-- __init__.py
|   |-- __main__.py
|   |-- routes.py
|   |-- validation.py
|   |-- database/
|   |-- detector/
|   |-- ml/
|   |-- risk/
|   |-- response/
|   |-- services/
|   |-- static/
|   |-- templates/
|-- data/
|   |-- raw/
|   |-- processed/
|-- docs/
|-- logs/
|-- models/
|-- reports/
|-- scripts/
|-- tests/
|-- .gitignore
|-- README.md
|-- requirements.txt
```

Generated/local files such as SQLite databases, Joblib artifacts, logs, byte
code, and virtual-environment contents are covered by `.gitignore`. The
prepared data and saved artifacts may be present locally for demonstration.

## 22. Ethical and Security Considerations

All analysis is local and defensive. Dataset strings are treated as data and
are not executed or sent to external websites. XShield should be used only on
input and systems for which the user has authorization. Detection output is
not proof of malicious intent, and stored input may contain sensitive
information; retention and access should be minimized.

More detailed documentation is available in:

- `docs/XShield_Technical_Documentation.md`
- `docs/architecture.md`
- `docs/setup.md`
- `docs/security.md`
- `docs/parameters.md`

## XShield 2.0 Event Contract and Database Foundation

The Phase 1 internal contract is implemented in
`app/services/event_contract.py`. It is intended to become the shared
boundary for the existing browser form and the future `/api/v1/events`
integration endpoint.

The contract supports:

- `event_type`: currently `input_analysis` or `request_observation`;
- named `input_fields`;
- optional application slug, request ID, HTTP method, and endpoint;
- metadata values explicitly labeled `observed`, `supplied`, or `derived`;
- bounded/truncated retention mode selection.

Phase 2 adds the following SQLite structures:

- `schema_migrations` for idempotent schema-version tracking;
- `applications` for future multi-application registration;
- `security_events.application_id` linking events to an application;
- an automatically created `legacy-local` application for existing and
  current browser-originated events.

Existing event rows are preserved and backfilled to `legacy-local`. Repeating
application startup or `initialize_database` does not duplicate the
application or events.

Phase 3 extends the foundation with:

- `applications.updated_at` and application status management;
- `api_keys`, containing only SHA-256 hashes, ownership, status, creation,
  optional expiration, and optional last-used timestamps;
- a local management script at `scripts/manage_applications.py`;
- `app.services.api_keys.authenticate_api_key`, which future API endpoints can
  call without changing the existing browser flow.

Create and manage local applications and keys:

```powershell
.\.venv\Scripts\python.exe scripts\manage_applications.py create-application demo-site "Demo Site"
.\.venv\Scripts\python.exe scripts\manage_applications.py list-applications
.\.venv\Scripts\python.exe scripts\manage_applications.py create-api-key --slug demo-site
.\.venv\Scripts\python.exe scripts\manage_applications.py list-api-keys
.\.venv\Scripts\python.exe scripts\manage_applications.py revoke-api-key 1
```

The full API key is printed once by `create-api-key`; it is not stored in the
database and cannot be recovered later. Store it in a future integrating
application through an environment variable, for example:

```powershell
$env:XSHIELD_API_KEY = "xsh_<copy-the-one-time-value-here>"
```

No `/api/v1/events` route, event ingestion, dashboard registration UI, or
detector/pipeline behavior is part of Phase 3.

Phase 4 adds `POST /api/v1/events` as a JSON-only, API-key-authenticated
ingestion endpoint. It normalizes requests through
`SecurityEventContract`, derives application ownership from the authenticated
key, applies bounded retention, and stores accepted events in the existing
`security_events` table. It does not add behavioral analysis, incidents,
dashboard redesign, or external integrations.

Example local request:

```powershell
$headers = @{ "X-API-Key" = $env:XSHIELD_API_KEY }
$body = @{
  event_type = "request_observation"
  endpoint = "/search"
  method = "POST"
  input_fields = @{ query = "untrusted text" }
  metadata = @{
    client_ip = @{ value = "127.0.0.1"; trust = "observed" }
  }
  retention_mode = "truncated"
} | ConvertTo-Json -Depth 6
Invoke-WebRequest -Uri http://127.0.0.1:5000/api/v1/events `
  -Method Post -Headers $headers -ContentType "application/json" -Body $body
```

Accepted events return `201` with `accepted`, `event_id`, `application`, and
`status`. Missing/invalid credentials return `401`; revoked or expired
credentials return `403`; malformed JSON returns `400`; invalid event fields
return `422`; wrong content type returns `415`; and oversized requests return
`413`. Rate limiting is not implemented in this local phase.

### XShield 2.0 Phase 5 shared analysis

Browser submissions and authenticated API events now use the same
`app.services.analysis.analyze_security_input` orchestration. It calls the
existing hybrid detector, risk engine, and action engine once per accepted
analyzable event. API input is the bounded, normalized `input_fields` mapping;
metadata, timestamps, request IDs, and application context are not analyzed as
payloads. The resulting rule, ML, hybrid, risk, action, and explanation data
is stored in the existing `security_events` record.

If analysis fails, the API returns a controlled `500` response and does not
persist an event that appears safe or allowed. Persistence failures also
return a controlled `500`; no second analysis invocation or background queue
is used.
