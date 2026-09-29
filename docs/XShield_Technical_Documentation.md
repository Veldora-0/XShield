# XShield Technical Documentation

## Introduction

XShield is a local Flask prototype for studying AI/ML-assisted detection and
risk assessment of potentially XSS-related input. It is designed for a
college-project setting where the implementation, assumptions, and
limitations should be visible and reproducible.

## Background

Cross-site scripting occurs when attacker-controlled data is interpreted by a
browser as executable markup or script in an unsafe application context.
Detection is difficult because the same characters can be legitimate in
documentation or ordinary text, while payloads can be encoded, fragmented, or
context-dependent. Safe output encoding remains a prevention control even when
a detector is present.

## Problem Statement and Objectives

The project addresses the problem of analyzing user-controlled fields for
potential XSS indicators while keeping the application itself safe. Its
objectives are to provide a modular rule baseline, a reproducible ML baseline,
an explainable hybrid score, project-defined response levels, SQLite event
logging, a protected local dashboard, and actual comparative evaluation.

## Existing Approach Limitations

A keyword-only rule is too narrow and can be bypassed by variation or
encoding. A larger rule set improves explainability but still cannot model
every browser context. An ML model can learn patterns from examples but is
limited by dataset coverage, class imbalance, feature representation, and
distribution changes. XShield therefore treats rule and ML outputs as
evidence, not proof.

## Proposed Approach

```text
Input -> Validation -> Rule + ML -> Hybrid -> Risk -> Action -> SQLite -> Dashboard
```

The public form accepts username, search query, and comment fields. After
validation, the combined fields are analyzed. High-risk content is not
displayed in the result page, and all normal displayed text uses Jinja
escaping.

## System Architecture

The detailed flow is documented in `docs/architecture.md`. The main modules
are:

- `app/routes.py`: HTTP routes and pipeline orchestration.
- `app/validation.py`: server-side field validation.
- `app/detector/rules.py`: rule definitions, normalization, and limits.
- `app/detector/rule_engine.py`: explainable rule scoring.
- `app/ml/predictor.py`: fixed-path saved-artifact loading and prediction.
- `app/detector/hybrid_detector.py`: weighted signal combination.
- `app/risk/risk_engine.py`: score conversion, thresholds, and reasons.
- `app/response/action_engine.py`: response-policy mapping.
- `app/services/security_logger.py`: pipeline-to-event conversion.
- `app/database/db.py`: SQLite schema, persistence, queries, and statistics.
- `app/templates/` and `app/static/`: escaped UI and styling.
- `scripts/`: dataset preparation, training, and evaluation.

## Rule-Based Algorithm

Input is bounded to 10,000 characters for analysis. The detector creates an
original, normalized, and one-layer-decoded comparison view. It checks:

1. HTML-like markup.
2. Script tags and selected execution function patterns.
3. Event-handler-style attributes.
4. `javascript:`, `vbscript:`, and `data:` schemes.
5. Encoded characters that decode into suspicious constructs.
6. Multiple independent indicators together.

Each match contributes its configured weight. The final score is capped at
100 and returned with rule IDs, details, and reasons.

## Dataset Methodology

The source is `HttpParamsDataset` from the Morzeux repository/Kaggle source,
recorded as MIT licensed in the project. The preparation script uses the
`payload`, `attack_type`, and `label` fields, selecting only `norm` and `xss`.
It maps `norm` to benign (`0`) and `xss` to XSS (`1`), removes unsupported
categories, exact duplicates, normalized duplicate text, and invalid/blank
records.

The final dataset has 19,836 rows: 19,304 benign and 532 XSS. A reproducible
80/20 per-class split with random seed 42 creates 15,869 training rows and
3,967 test rows. The test set contains 3,861 benign and 106 XSS rows. No
case-folded, whitespace-normalized text overlap was found across splits.

## ML Methodology

The vectorizer is character-level TF-IDF with 3-5 character n-grams,
`min_df=2`, and sublinear term frequency. It is fitted only on training text.
The Logistic Regression baseline uses balanced class weights, the `liblinear`
solver, `max_iter=1000`, and random state 42. The fitted vectorizer produces
54,919 features and is saved with the classifier using Joblib.

Prediction returns the class label, `benign`/`xss` name, and XSS probability.
Loading is restricted to fixed project paths; users cannot upload or select
model files.

## Hybrid Methodology

The hybrid detector calls the rule and ML detectors on one combined text:

```text
normalized_rule_score = rule_score / 100
ml_score = P(XSS)
hybrid_signal = 0.5 * normalized_rule_score + 0.5 * ml_score
```

The implementation accepts configurable non-negative weights and normalizes
them to sum to one. The current 0.5/0.5 configuration is experimental.
Agreement is reported as `both_benign`, `both_suspicious`, `rule_only`, or
`ml_only`.

## Risk Scoring

The risk engine clamps the hybrid signal to `0.0-1.0`, multiplies it by 100,
rounds to two decimal places, and applies:

```text
0-29 Low
30-59 Medium
60-79 High
80-100 Critical
```

These are project-defined thresholds, not universal standards. The result
preserves detector components and reasons for explanation.

## Response Mechanism

The response engine maps risk levels as follows:

```text
Low      -> allow
Medium   -> flag
High     -> block
Critical -> block_and_alert
```

Blocking suppresses submitted content in the local result page. The
`block_and_alert` action records that a future alert would be required; no
external alert is sent. No firewall or network control is performed.

## Database Design

SQLite database file: `data/xshield.sqlite3`.

Table: `security_events`.

Fields include ID, UTC timestamp, combined input text, rule score, ML
probability/prediction, hybrid signal, risk score/level, action, detector
agreement, matched-rule JSON, and reason JSON. Inserts and filters use
parameterized statements. Startup creates the table if absent and preserves
existing records.

### Phase 3 application registration and API keys

Applications are registered locally with a stable numeric ID, unique slug,
name, status, and lifecycle timestamps. `legacy-local` remains active for the
existing browser flow. The `api_keys` table stores the owning application,
one-way SHA-256 key hash, active/revoked status, creation time, optional
expiration, and optional last-used timestamp; it never stores plaintext keys.

Use the lightweight management script:

```powershell
.\.venv\Scripts\python.exe scripts\manage_applications.py create-application demo-site "Demo Site"
.\.venv\Scripts\python.exe scripts\manage_applications.py create-api-key --slug demo-site
.\.venv\Scripts\python.exe scripts\manage_applications.py revoke-api-key 1
```

The generated `xsh_...` value is displayed once, then must be copied into a
future integrating application through an environment variable such as
`XSHIELD_API_KEY`. It cannot be recovered from XShield after creation.
`app.services.api_keys.authenticate_api_key` is the Phase 4 integration
boundary: it accepts request headers, validates status and expiration, and
returns a structured application identity. Phase 3 does not implement
`/api/v1/events`.

## Phase 5 shared analysis

The browser flow and authenticated API ingestion now converge on
`app.services.analysis.analyze_security_input`. The service calls the existing
hybrid detector, risk engine, and action engine once and returns their native
`rule_result`, `ml_result`, `hybrid`, `risk_result`, and `action_result`
structures.

API events use only bounded `input_fields` as analysis input, in deterministic
request order. Metadata, request IDs, timestamps, client identity, and
application identity are not analyzed as XSS payloads. Both
`input_analysis` and `request_observation` use this path. Real analysis
results are stored in the existing `security_events` table with the
authenticated application association.

If analysis fails, the API returns a controlled error and does not persist an
event that appears safe. Database failures return a separate controlled error.
There is no background queue or second detector/model in this phase.

## Dashboard

The dashboard is available at `/dashboard`, with event details at
`/dashboard/event/<id>`. It shows totals, risk counts, blocked counts, a risk
distribution, recent events, filters, search, and escaped event details.
Both routes require HTTP Basic Authentication configured through
`XSHIELD_DASHBOARD_USERNAME` and `XSHIELD_DASHBOARD_PASSWORD`. Missing
password configuration returns 503 rather than exposing events.

## Security Controls

The application includes server-side validation, field limits, a 16 KiB
request limit, Jinja autoescaping, no unsafe DOM HTML sinks, parameterized
SQLite access, fixed-path model loading, controlled model/database errors,
default-disabled debug mode, CSP, `nosniff`, `X-Frame-Options`,
`Referrer-Policy`, and dashboard authentication.

The Phase 14 review is recorded in `reports/security_review.md`. HTTPS,
production identity management, credential rotation, dependency locking,
privacy policies, and retention controls remain outside this prototype.

## Testing Methodology

The project tests individual detectors and engines, safe rendering, SQLite
persistence, dashboard filters/authentication, missing/corrupt model handling,
request limits, full pipeline logging, and comparative evaluation. The
complete suite is run with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Evaluation Results

All three methods use the same 3,967-row held-out test set. The documented
experimental thresholds are rule score `>=1`, ML probability `>=0.5`, and
hybrid signal `>=0.5`.

| Method | Accuracy | Precision | Recall | F1 | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Rule-Based | 0.9979833627 | 1.0000000000 | 0.9245283019 | 0.9607843137 | 3861 | 0 | 8 | 98 |
| ML | 0.9989916814 | 1.0000000000 | 0.9622641509 | 0.9807692308 | 3861 | 0 | 4 | 102 |
| Hybrid | 0.9979833627 | 1.0000000000 | 0.9245283019 | 0.9607843137 | 3861 | 0 | 8 | 98 |

These results describe this dataset and split only. They are not production
performance claims, and no method is declared universally best.

## Limitations

Limitations include dataset dependence and imbalance, false positives and
false negatives, incomplete rule coverage, ML distribution dependence,
experimental thresholds, prototype-only response behavior, SQLite scale,
lack of HTTPS/TLS, minimal rather than production identity/access control,
credential rotation requirements, unpinned dependencies, and the need for
privacy and retention design.

## Future Scope

Future work can evaluate broader datasets, additional classifiers, deep
learning, calibrated thresholds, adversarial robustness, optional threat
intelligence, production authentication and authorization, HTTPS, centralized
logging, retention policies, scalable storage, and real-time monitoring.

## Conclusion

XShield demonstrates a complete local pipeline from validated input through
rule/ML analysis, hybrid risk scoring, response policy, SQLite logging, and
protected dashboard review. Its most important result is an explainable and
testable prototype with explicitly stated boundaries, not a claim of complete
XSS prevention.
