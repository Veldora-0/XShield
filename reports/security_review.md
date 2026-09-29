# XShield Security Review

## Scope

This review covered the local Flask application, request validation, Jinja
templates, static JavaScript, rule/ML/hybrid detectors, risk engine, response
engine, SQLite database layer, security logger, dashboard, evaluation scripts,
dependencies, `.gitignore`, and tests.

The review was performed for the Phase 14 local college-project hardening
scope. No external targets were contacted and no model or dataset was
modified.

## Findings

### XR-001 — High — Debug mode was enabled unconditionally

- **Component:** `app/__main__.py`
- **Description:** The application entry point always passed `debug=True` to
  `app.run()`.
- **Impact:** If the development server were exposed beyond localhost, an
  unhandled exception could expose the Werkzeug debugger and sensitive
  implementation details.
- **Remediation:** Debug mode now defaults to disabled and can only be enabled
  intentionally with `XSHIELD_DEBUG=true`.
- **Status:** Fixed.

### XR-002 — Low — Raw database exception text was shown to users

- **Component:** `app/services/security_logger.py`
- **Description:** Database-write exception text was returned in the response
  data and rendered by the template.
- **Impact:** Local paths or implementation details could be disclosed during
  storage failures.
- **Remediation:** The UI now receives a generic failure message. Detailed
  exception information is not returned to the requester.
- **Status:** Fixed.

### XR-003 — Medium — Dashboard had no authentication or authorization

- **Component:** `/dashboard` and `/dashboard/event/<id>`
- **Description:** Before hardening, any client that could reach this local
  Flask process could view dashboard statistics and enumerate stored events.
- **Impact:** Stored submitted input and security-event details are not
  protected from other users if the service is exposed beyond the intended
  local demonstration context.
- **Remediation:** Dashboard routes now require HTTP Basic Authentication
  using credentials supplied through application configuration/environment
  variables. The dashboard returns `503` when no password is configured rather
  than exposing stored events.
- **Status:** Fixed for the local prototype; HTTPS, credential rotation, and
  a production identity/access-management system remain required.

## Security Controls Verified

- Jinja autoescaping protects submitted and stored event text.
- No unsafe `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`,
  `new Function`, `document.write`, `|safe`, or `Markup()` sink is used by the
  application UI.
- Server-side field validation and per-field length limits are present.
- A 16 KiB Flask request-size limit is configured.
- SQLite statements use parameterized values.
- Dashboard filter values are allowlisted and search values are bound
  parameters.
- Model files are loaded only from fixed application paths, not request input.
- Missing and corrupted model artifacts produce controlled errors.
- SQLite files and generated artifacts are excluded by `.gitignore`.
- Existing database records are preserved at startup.
- Stored input remains escaped when displayed in event details.
- Basic security headers are added:
  `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, and `Referrer-Policy`.
- Dashboard and event-detail routes require configured HTTP Basic
  Authentication and fail closed when no password is configured.
- No project-source credential or secret value was identified by the
  repository scan. Dependency and virtual-environment source files were not
  treated as application code.

## Testing

The complete test suite passed:

```text
Ran 66 tests

OK
```

Security-focused coverage includes:

- HTML and JavaScript-safe output behavior.
- Oversized request rejection.
- SQL-injection-like dashboard filter values.
- Missing model artifact behavior.
- Corrupted model artifact behavior.
- Generic database failure messages.
- Invalid dashboard event IDs.
- Dashboard escaping and event rendering.
- Dashboard authentication and fail-closed configuration behavior.
- Action and full-pipeline regression tests.

The Phase 13 comparative evaluation also completed successfully without
retraining or changing the evaluation data.

## Remaining Limitations

- Dashboard authentication is intentionally minimal HTTP Basic Authentication;
  production use needs HTTPS, credential rotation, stronger identity
  management, authorization roles, and audit controls.
- CSRF protection is not implemented because the dashboard uses read-only GET
  routes and the prototype has no authenticated state-changing session model.
- Requirements are not pinned or hash-locked; production use needs a
  controlled dependency and artifact supply chain.
- SQLite and raw input retention are suitable only for this demonstration
  unless privacy, retention, access control, and backup policies are added.
- The XSS detectors and risk thresholds are experimental and do not guarantee
  protection against all XSS attacks.
