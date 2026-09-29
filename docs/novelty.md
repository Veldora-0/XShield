# XShield Contribution and Novelty Explanation

## Project Contribution

XShield's contribution is an integrated, explainable implementation for a
college-project defensive prototype:

- modular rule-based indicators with matched-rule explanations;
- a character-level TF-IDF and Logistic Regression baseline;
- ML classification and XSS probability;
- configurable hybrid combination of rule and ML signals;
- project-defined 0-100 risk scoring and risk levels;
- a response policy separating assessment from local application action;
- persistent SQLite security-event logging;
- an authenticated dashboard for event review;
- comparative evaluation of rule, ML, and hybrid methods on the same test set;
- security-hardening tests and documentation of limitations.

The value of the project is the complete, understandable pipeline and the
explicit connection between detection evidence, risk assessment, response,
logging, and evaluation.

## Research Novelty

This project does **not** claim that combining rules and machine learning is
globally novel. Hybrid detection, TF-IDF, Logistic Regression, risk scoring,
logging, and dashboards are established ideas. A literature review and
comparative research study would be required before making a research novelty
claim.

## Appropriate Presentation Wording

Use:

> “XShield implements an explainable hybrid rule-and-ML detection pipeline
> for a local defensive XSS-risk assessment prototype.”

Avoid:

> “XShield introduces a globally novel XSS detection algorithm.”

The first statement accurately describes the implementation contribution
without overstating research originality.
