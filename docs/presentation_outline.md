# XShield Presentation Outline

Target length: approximately 10-12 slides and 8-12 minutes. Keep slide text
short and use speaker notes for explanation.

## Slide 1 - Title

**Bullets**

- XShield
- AI/ML-Based XSS Attack Detection and Risk Assessment System
- College project
- Defensive local prototype

**Visual**

- XShield title and the complete pipeline diagram.

**Speaker notes**

XShield analyzes potentially XSS-related user input with rules and a saved ML
baseline, combines the evidence, applies a project-defined risk policy, logs
the event, and displays it through a protected dashboard.

## Slide 2 - Introduction: What Is XSS?

**Bullets**

- Cross-site scripting involves unsafe interpretation of attacker-controlled
  data by a browser.
- Markup, script constructs, handlers, and URL schemes can be relevant.
- Safe output encoding is a prevention control.
- Detection is evidence, not proof.

**Visual**

- Simple input-to-browser-context diagram; do not show an executable payload.

**Speaker notes**

The project discusses XSS defensively. The same characters may be legitimate
in documentation, so context matters and detection alone is insufficient.

## Slide 3 - Problem Statement

**Bullets**

- User-controlled text is difficult to classify reliably.
- Static rules are explainable but incomplete.
- Encodings and unusual forms complicate detection.
- ML depends on representative training data.

**Visual**

- Two-column comparison: static indicators and learned patterns.

**Speaker notes**

The goal is not to create a universal XSS oracle. The goal is to demonstrate a
transparent, testable combination of complementary evidence.

## Slide 4 - Existing Approach and Limitation

**Bullets**

- One-keyword checks are too narrow.
- Larger rules can still miss new or context-dependent inputs.
- Rules may create false positives.
- ML can create false positives and false negatives.

**Visual**

- Table of strengths and limitations for rules and ML.

**Speaker notes**

This motivates measuring rule-only, ML-only, and hybrid behavior on exactly the
same held-out test data.

## Slide 5 - Proposed System

**Bullets**

- Server-side validation
- Rule detector
- TF-IDF and Logistic Regression
- Hybrid signal
- Risk, response, logging, dashboard

**Visual**

```text
Input -> Rule + ML -> Hybrid -> Risk -> Action -> SQLite -> Dashboard
```

**Speaker notes**

The application is implemented as separate modules so each stage can be
tested and explained independently.

## Slide 6 - System Architecture

**Bullets**

- Flask routes orchestrate the pipeline.
- Rules return scores and matched explanations.
- ML returns a label and XSS probability.
- Dashboard reads stored events only.

**Visual**

- `docs/architecture.md` high-level architecture diagram.

**Speaker notes**

The dashboard does not rerun detection. It queries SQLite, applies bounded
filters, and renders escaped values. Dashboard routes require Basic
Authentication.

## Slide 7 - Machine Learning

**Bullets**

- Dataset: `HttpParamsDataset`
- Final cleaned rows: 19,836
- Train/test: 15,869 / 3,967
- Character TF-IDF: 3-5 grams, 54,919 features
- Logistic Regression baseline

**Visual**

```text
Dataset -> preprocessing -> split -> TF-IDF -> Logistic Regression
```

**Speaker notes**

Only `norm` and `xss` records are used. The vectorizer is fitted on training
text only. The model uses balanced class weights and is loaded from saved
trusted artifacts.

## Slide 8 - Hybrid Detection

**Bullets**

- Rule score is normalized to 0.0-1.0.
- ML score is XSS probability.
- Current weights: rule 0.5, ML 0.5.
- Weights are configurable and experimental.

**Visual**

```text
0.5 * normalized rule score + 0.5 * ML probability
```

**Speaker notes**

The hybrid result also records detector agreement: both benign, both
suspicious, rule-only, or ML-only.

## Slide 9 - Risk Assessment and Response

**Bullets**

- `risk_score = hybrid_signal * 100`
- 0-29 Low
- 30-59 Medium
- 60-79 High
- 80-100 Critical
- Actions: allow, flag, block, block_and_alert

**Visual**

- Horizontal 0-100 threshold bar.

**Speaker notes**

These thresholds and actions are project-defined experimental settings. A
block suppresses content in this local demonstration; it does not block an IP
or change a firewall.

## Slide 10 - SQLite and Dashboard

**Bullets**

- Events store timestamp, detector outputs, risk, action, and reasons.
- Dashboard shows totals and risk distribution.
- Recent events and filters support review.
- Event details remain escaped.
- Dashboard uses Basic Authentication.

**Visual**

- Screenshot captured from the actual local dashboard during the demo.

**Speaker notes**

Raw combined input is retained for this local project demonstration. A
production system would need privacy, retention, and access policies.

## Slide 11 - Evaluation

**Bullets**

- Same held-out test set: 3,967 records.
- Benign/XSS: 3,861 / 106.
- Rule F1: 0.9607843137.
- ML F1: 0.9807692308.
- Hybrid F1: 0.9607843137.
- FP/FN: Rule 0/8, ML 0/4, Hybrid 0/8.

**Visual**

- Comparative metrics table and three confusion matrices from `reports/`.

**Speaker notes**

The results are specific to the selected split and thresholds. The project
does not claim a universally superior approach or production performance.

## Slide 12 - Conclusion and Future Scope

**Bullets**

- Complete local detection-to-dashboard pipeline implemented.
- Explainability is preserved at rule, hybrid, risk, and action stages.
- Evaluation and limitations are documented.
- Future: broader data, calibration, robustness, HTTPS, stronger identity,
  centralized logging.

**Visual**

- Final architecture plus limitations callout.

**Speaker notes**

The contribution is a complete, understandable prototype rather than a claim
of complete XSS prevention or worldwide research novelty.
