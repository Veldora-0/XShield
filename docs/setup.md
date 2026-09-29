# XShield Setup Guide

## Requirements

- Windows with PowerShell.
- Python 3 with `venv` support.
- Local disk space for the prepared data and saved model artifacts.

The project dependencies are listed in `requirements.txt`:
Flask, joblib, NumPy, pandas, and scikit-learn. Versions are currently
unpinned, so production use would require dependency locking.

## Create the Environment

From `D:\XShield` or the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The repository already contains prepared data and saved model files for the
demonstration. The following commands reproduce those artifacts when the
source data is present:

```powershell
.\.venv\Scripts\python.exe scripts\prepare_dataset.py
.\.venv\Scripts\python.exe scripts\train_ml_model.py
```

Dataset preparation reads:

```text
data/raw/httpparamsdataset/payload_full.csv
```

It writes the processed dataset and split files under `data/processed/`.
Training reads the train/test CSV files and writes the vectorizer, classifier,
and training report under `models/`.

## Database Initialization

The Flask application calls `initialize_database` during app creation. It
creates or upgrades `data/xshield.sqlite3` without erasing existing events.
The idempotent migration creates:

- `schema_migrations` for the current schema version;
- `applications` for registered applications;
- `security_events.application_id` for the application-to-event relationship.
- `applications.updated_at` for application lifecycle updates;
- `api_keys` for hashed integration credentials.

The migration automatically creates the `legacy-local` application and assigns
existing unassigned security events to it. Re-running application startup or `initialize_database` does not duplicate
applications, API keys, or events. The database is local/generated data and is
ignored by Git.

### Local application and API-key management

Phase 3 intentionally provides a local script instead of registration routes
or dashboard UI:

```powershell
.\.venv\Scripts\python.exe scripts\manage_applications.py create-application demo-site "Demo Site"
.\.venv\Scripts\python.exe scripts\manage_applications.py list-applications
.\.venv\Scripts\python.exe scripts\manage_applications.py create-api-key --slug demo-site
.\.venv\Scripts\python.exe scripts\manage_applications.py list-api-keys
.\.venv\Scripts\python.exe scripts\manage_applications.py revoke-api-key 1
```

The create command displays the full `xsh_...` key once. XShield stores only
its one-way SHA-256 hash, so an operator must copy the value into the future
integrating application at creation time. A future application should supply
it from an environment variable such as `XSHIELD_API_KEY`; do not commit it
to source control or print it in logs.

## Evaluation

Run comparative evaluation without retraining:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_all.py
```

This loads the existing held-out test set, saved vectorizer, and saved model.
It writes the comparative JSON/text reports and one JSON confusion matrix per
method under `reports/`.

The earlier ML-only evaluation is also available:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_model.py
```

## Application Startup

Set credentials before starting if the dashboard is needed:

```powershell
$env:XSHIELD_DASHBOARD_USERNAME = "admin"
$env:XSHIELD_DASHBOARD_PASSWORD = "choose-a-local-password"
.\.venv\Scripts\python.exe -m app
```

The default entry point runs Flask with debug disabled. Set
`XSHIELD_DEBUG=true` only for intentional local debugging.

Open:

- <http://127.0.0.1:5000/>
- <http://127.0.0.1:5000/health>
- <http://127.0.0.1:5000/dashboard>

The dashboard uses HTTP Basic Authentication. If the password is missing, it
returns 503 instead of exposing stored events. HTTP Basic Authentication is
not a substitute for HTTPS or production identity management.

## Test Execution

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite covers rule, ML, hybrid, risk, action, database, dashboard,
pipeline, evaluation, and Phase 14 hardening behavior.

## XShield Phase 1 and Phase 2

Phase 1 adds the internal event contract and shared configuration limits:

```text
app/config.py
app/services/event_contract.py
tests/test_event_contract.py
```

Phase 2 adds the database foundation and migration tests:

```text
app/database/db.py
app/database/__init__.py
tests/test_database.py
```

Phase 3 does not add `/api/v1/events`. It adds the local management script and
the reusable `app.services.api_keys.authenticate_api_key` service for Phase 4.
The existing application remains runnable with the normal startup command, and
all migration behavior is covered by the complete test suite.

### XShield Phase 4 event ingestion

Phase 4 adds `POST /api/v1/events`. Create an application and key with the
Phase 3 commands, set the key locally, then send a bounded JSON request:

```powershell
$env:XSHIELD_API_KEY = "xsh_<one-time-key-value>"
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

The authenticated key determines the application association. Client fields
cannot assign an application. Requests are bounded by the Phase 1 contract:
event type, input field count and lengths, combined input length, request ID,
endpoint, metadata count/key/value lengths, trust labels, and retention mode.
The endpoint returns `201` for accepted events, `401` for missing/invalid
credentials, `403` for revoked/expired credentials or applications, `400` for
invalid JSON, `415` for a non-JSON content type, `422` for invalid fields,
and `413` for oversized requests.

Phase 4 does not implement behavioral analysis, incidents, dashboard changes,
rate limiting, or external integrations.

### XShield Phase 6 behavioral context

Phase 6 provides bounded context analysis through
`app.services.behavior.analyze_behavior_context`. It summarizes recent
application-associated events for repeated suspicious activity, normalized
endpoint repetition, short-window bursts, and detection-pattern diversity.
The settings in `app/config.py` are conservative project-defined heuristics,
not industry standards. The service does not change existing detector or risk
results, does not use raw payloads as its primary signal, and does not infer
human attacker identity from application keys, IP addresses, or request
metadata.

### XShield Phase 7 incident correlation

Phase 7 provides reusable incident derivation through
`app.services.incidents`. Events are grouped only within the configured
application-scoped correlation window and bounded recent-event limit. Strong
relationships are shared request IDs, normalized endpoints, or overlapping
matched-rule patterns; event type alone is not enough.

High- and Critical-risk current events may produce an explicit single-event
incident. The result includes a deterministic incident ID and explains the
events, timestamps, risk levels, actions, endpoints, patterns, and Phase 6
context involved. These are project-defined monitoring heuristics, not
security standards, and they do not identify human attackers.
