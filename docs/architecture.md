# XShield Architecture

## 1. High-Level Architecture

```text
Browser
   |
   | GET / or POST /
   v
Flask Routes and Validation
   |
   +--------------------------+
   |                          |
   v                          v
Rule Detector            ML Predictor
   |                          |
   +------------+-------------+
                v
        Hybrid Detector
                |
                v
          Risk Engine
                |
                v
         Response Engine
                |
       +--------+--------+
       |                 |
       v                 v
   SQLite Logger     Safe Result UI
       |
       v
Authenticated Dashboard
```

## 2. Detection Pipeline

```text
username + search_query + comment
                 |
                 v
        Server-side validation
                 |
                 v
       Combined text for analysis
                 |
       +---------+---------+
       |                   |
       v                   v
 Rule score/details   ML label/probability
       |                   |
       +---------+---------+
                 v
          Hybrid signal
```

The form route runs `detect_hybrid_fields`, then `assess_risk`,
`assess_action`, and `log_security_event`. Blocked content is not displayed in
the result page.

## 3. ML Pipeline

```text
data/processed/xss_train.csv
              |
              v
     Character TF-IDF fit
              |
              v
     54,919 sparse features
              |
              v
   LogisticRegression(class_weight=balanced)
              |
              +--> models/xss_tfidf_vectorizer.joblib
              +--> models/xss_logistic_regression.joblib
```

The test split is transformed with the saved vectorizer. It is never used to
fit the vectorizer or classifier.

## 4. Hybrid Pipeline

```text
rule_score / 100 ------------------+
                                    +--> 0.5 rule + 0.5 ML
ML XSS probability -----------------+
                                             |
                                             v
                                      hybrid_signal 0..1
```

Weights are configurable in `app/detector/hybrid_detector.py` and normalized
to sum to one.

## 5. Risk Pipeline

```text
hybrid_signal
     |
     v
clamp to 0..1
     |
     v
risk_score = signal * 100
     |
     v
Low / Medium / High / Critical
     |
     v
allow / flag / block / block_and_alert
```

Thresholds are `0-29`, `30-59`, `60-79`, and `80-100`. They are project
configuration, not standards.

## 6. Database Flow

```text
Completed pipeline result
          |
          v
_event_from_pipeline()
          |
          v
Parameterized INSERT with application association
          |
          v
data/xshield.sqlite3
          |
          +--> applications
          +--> security_events.application_id
          +--> recent events
          +--> risk counts
          +--> filtered events
          +--> event by ID
```

The schema is managed by an idempotent version marker in
`schema_migrations`. Startup creates the `applications` registry and the
`legacy-local` application when needed. Existing `security_events` rows are
preserved and assigned to that application. Current browser events use the
same association by default. No second database system is introduced.

## 7. Dashboard Flow

```text
GET /dashboard
      |
      v
HTTP Basic Authentication
      |
      +-- no password configured --> 503
      +-- invalid credentials ----> 401
      +-- valid credentials ------> database queries
                                      |
                                      v
                               escaped Jinja templates
```

`GET /dashboard/event/<id>` uses the same access-control decorator and returns
a 404 template when the numeric event ID does not exist.

## 8. Security Boundaries

- User input is data and is never executed.
- Dashboard values come from SQLite but remain untrusted and are escaped.
- Model artifacts are loaded only from fixed application paths.
- SQL values are bound parameters.
- The dashboard is intended for trusted local use; HTTPS and production
  identity management are not configured.

## 9. XShield Integration Boundary

Phase 1 introduces a validated internal event contract without changing the
current browser pipeline. Phase 2 adds the database foundation:

```text
Browser Form or Future Integration API
                 |
                 v
        SecurityEventContract
                 |
                 v
       Shared Analysis Pipeline
                 |
                 v
       Application Registry
                 |
                 v
        Application-Linked Events
```

The contract currently validates supported event types, non-empty named input
fields, combined input length, bounded request IDs and endpoints, bounded
metadata, explicit metadata trust labels, and bounded retention modes.

The future API, API-key authentication, behavioral engine, incident engine,
and demo website are not enabled in Phase 2. Phase 3 adds an additive
application credential boundary:

```text
Local management script
       |
       +--> applications (name, slug, status, timestamps)
       |
       +--> api_keys (application_id, one-way hash, status, timestamps)
                              |
                              v
                authenticate_api_key(headers)
                              |
                   structured application result
```

`authenticate_api_key` reads `X-API-Key`, hashes the supplied value, checks
key/application status and optional expiration, and returns an
`AuthenticationResult`. It never returns or logs the plaintext key. Phase 4
uses that service in a dedicated API blueprint:

```text
POST /api/v1/events
        |
        v
Phase 3 API-key authentication
        |
        v
SecurityEventContract validation
        |
        v
Retention normalization
        |
        v
security_events + application_id
```

The API accepts only a bounded JSON object and derives `application_id` from
the authenticated application. It does not trust an application identifier in
the body. Accepted integration events are stored in the existing event table
with `source="api"` and normalized event-contract fields. Behavioral analysis
and incident processing remain future phases.

## Phase 5 shared analysis pipeline

Both supported integration event types, `input_analysis` and
`request_observation`, use the same synchronous service:

```text
Browser fields --------------------+
                                    |
API input_fields -> contract ------+--> analyze_security_input()
                                             |
                                             v
                                  detect_hybrid_fields()
                                             |
                                             v
                                      assess_risk()
                                             |
                                             v
                                      assess_action()
                                             |
                                             v
                                  shared analysis result
                                             |
                                             v
                                  security_events persistence
```

`analyze_security_input` returns the existing `rule_result`, `ml_result`,
`hybrid`, `risk_result`, and `action_result` structures. API analysis uses
only the explicitly supplied `input_fields`, joined deterministically in
request order by the existing hybrid field detector. Metadata such as client
IP, timestamps, request IDs, and application identity is never sent to the
XSS detectors.

API events are analyzed once before persistence. On detector, ML, risk, or
action failure, the route returns a generic `500` analysis error and does not
write a misleading safe event. Database failures return a separate generic
storage error. Existing browser persistence and historical events remain
compatible.

## 10. Behavioral and Context Signals

Phase 6 adds `app.services.behavior` as a separate, deterministic context
layer. It operates on bounded recent `security_events` history for one
application and does not replace or modify the rule, ML, hybrid, risk, or
action results.

The service reports repeated suspicious activity, repeated targeting of a
normalized endpoint, short-window event bursts, detection-pattern diversity,
recent event counts, bounded window settings, and explanations. The
thresholds are project-defined prototype heuristics rather than universal
security standards. Application identity comes from event association; IP
addresses and request metadata remain observed or supplied context and are not
treated as proof of human attacker identity.

Persisted history is loaded with one bounded parameterized query. Raw payloads
are not the primary behavioral signal, and no additional event table is
required.

## 11. Incident Correlation

Phase 7 adds `app.services.incidents` as a separate deterministic service.
It derives explainable incidents from one current event and a bounded,
application-scoped recent history. It does not change detector, risk, action,
or Phase 6 behavior.

Two events are related when they are in the configured time window and share
at least one strong relationship: the same request ID, the same normalized
endpoint, or an overlapping matched-rule pattern. Matching event type is
recorded as supporting context only; it is not sufficient by itself.

High- or Critical-risk current events may form explicit single-event
incidents. Otherwise, an incident requires at least one related recent event.
The representation includes a stable hash-based incident ID, application,
event IDs, start/latest timestamps, risk levels, actions, event types,
normalized endpoints, matched patterns, Phase 6 context, and correlation
reasons. Correlation windows, history bounds, and endpoint matching are
project-defined heuristics rather than security standards.
