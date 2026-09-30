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

## Console Access & API Ingestion Authentication

XShield console is unauthenticated in local demonstration mode. API ingestion remains authenticated using X-API-Key.

The Security Operations Console (`/dashboard` and its subroutes `/dashboard/events`, `/dashboard/incidents`, `/dashboard/behavior`, `/dashboard/applications`, `/dashboard/event/<id>`) is directly accessible locally without credentials to support frictionless local exploration and controlled demonstration. This unauthenticated console configuration is intended strictly for local development and demonstration; it is not designed or represented as a production-secure deployment model. Production deployment would require HTTPS/TLS, secret storage and rotation, robust identity and access management (IAM), multi-factor authentication, role-based access control (RBAC), auditing, and secure session management.

In contrast, the external telemetry ingestion API (`POST /api/v1/events`) strictly enforces authentication via the `X-API-Key` request header. API keys are validated using one-way cryptographic SHA-256 hashes against stored active keys, ensuring that API-key authentication, tenant isolation, and application scoping remain fully protected and enforced.

The dashboard displays only API-key status and counts. Plaintext API keys,
key hashes, raw request payloads, and secret values are not included in its
snapshot. Event and application values are rendered through escaped Jinja
templates. The Phase 6 behavioral and Phase 7 incident sections consume
bounded, application-scoped service results without changing detection or
response decisions.

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

## XShield Event Contract Security

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

## Behavioral and Context Security

Phase 6 adds bounded, explainable behavioral context signals in
`app.services.behavior`. The service summarizes recent events associated with
one application and can identify repeated suspicious activity, repeated
normalized endpoint targeting, short-window event bursts, and multiple
matched detection patterns.

These are deterministic, project-defined heuristics rather than security
standards or universal scores. Configured history and burst windows and a
maximum event count limit processing. Raw payload text is not the primary
behavioral signal. Application association identifies the registered
application, not a human attacker; IP addresses and other request metadata
remain context with their declared trust level.

## Incident Correlation Security

Phase 7 correlation is implemented in `app.services.incidents` and uses
application-scoped, bounded event history. It never combines events from
different applications and does not use raw payload content as its primary
correlation key.

The service requires a close time window plus a strong explainable
relationship: shared request ID, equal normalized endpoint, or overlapping
matched detection pattern. Event type is supporting context only. High- and
Critical-risk current events can be represented as explicit single-event
incidents; this is a project rule, not proof of an attack.

Incident IDs are deterministic hashes of the application and event keys.
Correlation does not identify attackers. API keys, request IDs, IP addresses,
and metadata identify application or observed context only and are not proof
of human identity. No firewall or network-blocking action is performed.
