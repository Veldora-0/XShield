# XShield Security Notes

## Threat Model

The threat model is limited to a local college-project prototype receiving
untrusted text through its Flask form. Relevant concerns are unsafe rendering,
malformed or oversized requests, SQL injection through dashboard filters,
unsafe model artifact loading, accidental error disclosure, and unauthorized
access to stored event data.

XShield does not model a production deployment, internet-facing service,
multi-user identity system, or complete browser/application security context.

## Input Handling

The server validates all three form fields:

- username: required, maximum 100 characters, letters/numbers/underscore/
  hyphen format;
- search query: required, maximum 200 characters;
- comment: required, maximum 1,000 characters.

Flask also limits the entire request to 16 KiB. The rule detector separately
bounds analyzed text to 10,000 characters. Empty and malformed form values
are rejected with validation errors rather than passed into the pipeline.

## XSS Prevention in XShield

Submitted and stored text is displayed through normal Jinja autoescaping.
The application does not use `|safe`, `Markup`, `innerHTML`, `outerHTML`,
`insertAdjacentHTML`, `eval`, `new Function`, or `document.write` for
untrusted content. Blocked submitted content is suppressed from the result
page. Dataset strings are treated as offline data and are never executed.

Detection is not prevention. The application must continue to encode output
and use trusted sanitization where a future feature genuinely requires
rendering permitted HTML.

## SQL Injection Prevention

SQLite operations use parameterized SQL values. Dashboard risk/action values
are restricted to allowlists, and search text is supplied as a bound `LIKE`
parameter. User-controlled values are not concatenated into SQL statements.

## Model Security

`joblib.load` is compatible with pickle-style deserialization and must only be
used with trusted artifacts. XShield loads the vectorizer and classifier from
fixed paths under `models/`. There is no model-upload route and no
request-controlled artifact path. Missing artifacts produce a clear error;
corrupt artifacts produce a generic controlled error without exposing loader
details.

## Database Security and Privacy

The SQLite file is local and ignored by Git. Existing records are preserved
when the application starts. The logger returns a generic user-facing failure
message when persistence fails.

The prototype stores combined submitted text to support event review. This is
not a production privacy design. A real deployment would need data
minimization, sensitive-data handling, retention/deletion rules, encryption,
backups, access auditing, and appropriate database permissions.

## Application API-key security

Registered applications have a unique slug and an active/revoked status.
Integration keys are generated with Python's cryptographically secure
`secrets` generator and a recognizable `xsh_` prefix. Only a SHA-256 hash is
stored in `api_keys`, along with application ownership, status, creation time,
optional expiration, and optional last-use time. The full key is displayed
only once by the local management command:

```powershell
.\.venv\Scripts\python.exe scripts\manage_applications.py create-api-key --slug demo-site
```

After creation, a future integrating application should read the copied value
from an environment variable such as `XSHIELD_API_KEY`. Never commit it or
write it to logs. `authenticate_api_key` uses a constant-time comparison after
the database hash lookup, rejects missing/unknown/revoked/inactive/expired
credentials, and returns generic reason codes that do not contain secret
values. Revocation takes effect for subsequent validation calls. Historical
security events are not deleted.

## Event ingestion API security

`POST /api/v1/events` requires `X-API-Key` and uses the Phase 3 validation
service; the route does not duplicate credential lookup logic. It accepts only
JSON and a fixed set of bounded fields. The Phase 1 contract enforces event
types, input field limits, combined input size, request ID and endpoint
limits, metadata count/key/value limits, explicit trust labels, and allowed
retention modes.

The authenticated key is the only authority for `application_id`. Any client
application identifier is rejected and cannot redirect an event to another
application. SQL values are parameterized. Error responses are generic and do
not reflect submitted payloads or API keys. Accepted events use the existing
`security_events` table and preserve historical browser events.

Retention is applied before persistence: `truncated` caps stored input,
`hash_only` stores SHA-256 digests, `redacted` stores placeholders, and
`disabled` stores no input or metadata values. Rate limiting, TLS, centralized
secret management, and production deployment controls remain future
requirements.

## Shared analysis security behavior

Phase 5 routes API events through the existing analysis implementation rather
than accepting client-provided risk, action, detector, or ML results. The
request allowlist rejects those fields. Only bounded `input_fields` are sent
to the detectors; metadata and application context remain non-analysis
context.

Analysis is synchronous and invoked exactly once before persistence. If the
detector, ML model, risk engine, or action engine fails, the API returns a
generic analysis failure and stores no event. It never reports an unanalysed
event as `allow`. Persistence errors also use generic responses without
database details or API-key values.

## Dashboard Access Control

`/dashboard` and `/dashboard/event/<id>` require HTTP Basic Authentication.
Credentials are configured with:

```powershell
$env:XSHIELD_DASHBOARD_USERNAME = "admin"
$env:XSHIELD_DASHBOARD_PASSWORD = "choose-a-local-password"
```

Missing password configuration fails closed with 503. Invalid credentials
return 401 with a Basic-authentication challenge. This is a minimal local
prototype control. Production use requires HTTPS/TLS, secret storage and
rotation, stronger identity and authorization, roles, auditing, and session
design.

## Flask and Browser Controls

Debug mode is disabled by default. Responses include:

- Content Security Policy;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`.

These controls reduce common browser exposure but do not make the prototype a
complete production security boundary.

## Logging Considerations

Security events contain detector outputs, actions, reasons, timestamps, and
combined input text. Stored payloads remain untrusted data and must be escaped
when displayed. Logs should not be treated as safe HTML or as proof of user
intent. Production logging should define retention, access, redaction, and
tamper/audit requirements.

## Production Limitations

- HTTPS/TLS is not configured.
- Credentials are not rotated automatically.
- Production identity/authorization is not implemented.
- Dependencies are not pinned or hash-locked.
- SQLite is not a production-scale centralized event store.
- CSRF/session controls would need design if authenticated state-changing
  features are added.
- Detector performance depends on the selected dataset and does not guarantee
  complete XSS coverage.

This document is defensive documentation for the local application; it does
not provide instructions for attacking external systems.

## XShield 2.0 Event Contract Security

The Phase 1 contract bounds event fields, request IDs, endpoints, metadata
items, and metadata values before a future integration API can process them.
Metadata is explicitly labeled:

- `observed`: obtained by the XShield request/application boundary;
- `supplied`: provided by an integrating application and not independently
  authoritative;
- `derived`: parsed or inferred from another value and not guaranteed exact.

The contract supports bounded retention modes, including `truncated` and
`hash_only`. Phase 1 defines these values but does not yet change the existing
SQLite logger or add the API that will apply them. No supplied IP or browser
value should be treated as proof of real-world attacker identity.
