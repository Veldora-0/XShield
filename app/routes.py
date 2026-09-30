from functools import wraps
import hmac

from flask import Blueprint, current_app, jsonify, render_template, request

from app.database import get_event_by_id
from app.services import (
    analyze_security_input,
    get_dashboard_snapshot,
    log_security_event,
)
from app.validation import validate_input


main = Blueprint("main", __name__)


def dashboard_auth_required(view):
    """Require configured HTTP Basic credentials for monitoring routes."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        configured_password = current_app.config.get("DASHBOARD_PASSWORD")
        if not configured_password:
            return jsonify(
                {
                    "error": (
                        "Dashboard access is not configured. Set "
                        "XSHIELD_DASHBOARD_PASSWORD."
                    )
                }
            ), 503

        credentials = request.authorization
        valid = (
            credentials is not None
            and hmac.compare_digest(
                credentials.username,
                current_app.config["DASHBOARD_USERNAME"],
            )
            and hmac.compare_digest(credentials.password, configured_password)
        )
        if not valid:
            response = jsonify({"error": "Dashboard authentication required."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Basic realm="XShield Dashboard"'
            return response
        return view(*args, **kwargs)

    return wrapped


@main.route("/", methods=["GET", "POST"])
def index():
    submitted_input = None
    detection_result = None
    form_values = {"username": "", "search_query": "", "comment": ""}
    errors = {}

    if request.method == "POST":
        form_values, errors = validate_input(request.form)
        if not errors:
            submitted_input = form_values
            detection_result = analyze_security_input(submitted_input)
            action_result = detection_result["action_result"]
            detection_result["logging_result"] = log_security_event(
                "\n".join(form_values.values()),
                detection_result,
                current_app.config["DATABASE_PATH"],
            )
            if action_result["blocked"]:
                submitted_input = None
                form_values = {"username": "", "search_query": "", "comment": ""}

    return render_template(
        "index.html",
        submitted_input=submitted_input,
        detection_result=detection_result,
        form_values=form_values,
        errors=errors,
    ), 400 if errors else 200


@main.get("/health")
def health_check():
    return {"status": "ok", "application": "XShield"}


@main.get("/dashboard")
@dashboard_auth_required
def dashboard():
    risk_level = request.args.get("risk_level") or None
    action = request.args.get("action") or None
    search = request.args.get("search", "").strip()
    snapshot = get_dashboard_snapshot(
        limit=50,
        risk_level=risk_level,
        action=action,
        search=search or None,
        database_path=current_app.config["DATABASE_PATH"],
    )
    return render_template(
        "dashboard.html",
        **snapshot,
        selected_risk=risk_level or "All",
        selected_action=action or "All",
        search=search,
    )


@main.get("/dashboard/event/<int:event_id>")
@dashboard_auth_required
def dashboard_event(event_id: int):
    event = get_event_by_id(event_id, current_app.config["DATABASE_PATH"])
    if event is None:
        return render_template("event_not_found.html", event_id=event_id), 404
    return render_template("event_detail.html", event=event)
