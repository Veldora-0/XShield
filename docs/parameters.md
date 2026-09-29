# XShield Project Parameters

The values below are **PROJECT CONFIGURATION** for this prototype. They are
not industry standards, universal security thresholds, or production tuning
claims.

| Parameter | Current value | Implementation |
|---|---|---|
| R001 rule weight | 12 | `app/detector/rules.py` |
| R002 rule weight | 30 | `app/detector/rules.py` |
| R003 rule weight | 25 | `app/detector/rules.py` |
| R004 rule weight | 25 | `app/detector/rules.py` |
| R005 rule weight | 15 | `app/detector/rules.py` |
| R006 rule weight | 15 | `app/detector/rules.py` |
| Rule score cap | 100 | `app/detector/rule_engine.py` |
| Analysis text bound | 10,000 characters | `app/detector/rules.py` |
| Default rule weight | 0.5 | `app/detector/hybrid_detector.py` |
| Default ML weight | 0.5 | `app/detector/hybrid_detector.py` |
| Rule evaluation threshold | score `>= 1` | `scripts/evaluate_all.py` |
| ML evaluation threshold | probability `>= 0.5` | `scripts/evaluate_all.py` |
| Hybrid evaluation threshold | signal `>= 0.5` | `scripts/evaluate_all.py` |
| Low risk | 0-29 | `app/risk/risk_engine.py` |
| Medium risk | 30-59 | `app/risk/risk_engine.py` |
| High risk | 60-79 | `app/risk/risk_engine.py` |
| Critical risk | 80-100 | `app/risk/risk_engine.py` |
| Low action | `allow` | `app/response/action_engine.py` |
| Medium action | `flag` | `app/response/action_engine.py` |
| High action | `block` | `app/response/action_engine.py` |
| Critical action | `block_and_alert` | `app/response/action_engine.py` |
| Username limit | 100 characters | `app/validation.py` |
| Search query limit | 200 characters | `app/validation.py` |
| Comment limit | 1,000 characters | `app/validation.py` |
| Flask request limit | 16 KiB | `app/__init__.py` |
| Dashboard event list limit | 50 events | `app/routes.py` |
| Integration API version | `v1` | `app/config.py` |
| Supported event types | `input_analysis`, `request_observation` | `app/config.py` |
| Maximum integration input | 10,000 characters combined | `app/config.py` |
| Maximum stored-input target | 2,000 characters | `app/config.py` |
| Maximum event fields | 32 | `app/config.py` |
| Maximum metadata items | 32 | `app/config.py` |
| Metadata trust labels | `observed`, `supplied`, `derived` | `app/config.py` |
| Retention modes | `full`, `truncated`, `hash_only`, `redacted`, `disabled` | `app/config.py` |

The rule threshold means that any matched rule is treated as suspicious for
the comparative report. The ML and hybrid thresholds were documented
evaluation parameters and were not optimized on the same test set.

The integration values above are Phase 1 contract limits. They are not
industry standards and do not enable API ingestion by themselves.
