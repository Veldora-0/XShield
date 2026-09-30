import json
from pathlib import Path
import time

from flask import Blueprint, current_app, jsonify, render_template, request

from app.database import (
    DEFAULT_DATABASE_PATH,
    get_dashboard_stats,
    get_event_by_id,
    get_filtered_events,
    list_applications,
)
from app.detector.rules import RULES
from app.services import (
    analyze_security_input,
    get_dashboard_snapshot,
    log_security_event,
)
from app.services.api_keys import list_api_keys
from app.services.behavior import analyze_behavior_context
from app.services.event_ingestion import persist_ingestion_event
from app.services.incidents import correlate_incident
from app.validation import validate_input


main = Blueprint("main", __name__)


def _process_analysis_form():
    form_values, errors = validate_input(request.form)
    submitted_input = None
    detection_result = None

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

    return {
        "submitted_input": submitted_input,
        "detection_result": detection_result,
        "form_values": form_values,
        "errors": errors,
        "status_code": 400 if errors else 200,
    }


# ============================================================================
# Public / Product Experience Routes
# ============================================================================

@main.route("/", methods=["GET", "POST"])
def home():
    """Modern product landing page; handles legacy POST for tests."""
    if request.method == "POST":
        res = _process_analysis_form()
        return render_template(
            "scanner.html",
            submitted_input=res["submitted_input"],
            detection_result=res["detection_result"],
            form_values=res["form_values"],
            errors=res["errors"],
        ), res["status_code"]
    return render_template("home.html")


@main.route("/scanner", methods=["GET", "POST"])
def scanner():
    """First-class dedicated Interactive Payload Scanner."""
    submitted_input = None
    detection_result = None
    form_values = {"username": "", "search_query": "", "comment": ""}
    errors = {}
    status_code = 200

    if request.method == "POST":
        res = _process_analysis_form()
        submitted_input = res["submitted_input"]
        detection_result = res["detection_result"]
        form_values = res["form_values"]
        errors = res["errors"]
        status_code = res["status_code"]

    return render_template(
        "scanner.html",
        submitted_input=submitted_input,
        detection_result=detection_result,
        form_values=form_values,
        errors=errors,
    ), status_code


@main.get("/how-it-works")
def how_it_works():
    """Defensive architecture and multi-stage detection pipeline explanation."""
    return render_template("how_it_works.html")


@main.get("/benchmark")
def benchmark():
    """Reproducible evaluation report based on held-out test split."""
    report_data = None
    report_file = Path("reports/evaluation_results.json")
    if report_file.exists():
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                report_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            report_data = None
    return render_template("benchmark.html", report=report_data)


@main.get("/api")
def api_docs():
    """Developer API documentation for POST /api/v1/events."""
    return render_template("api_docs.html")


@main.get("/rules")
def rules_catalog():
    """Catalog of active heuristic rules currently enforced."""
    return render_template("rules.html", rules=RULES)


@main.route("/demo", methods=["GET", "POST"])
def demo_app():
    """Controlled mock client web application demonstrating real-time XShield interception."""
    demo_result = None
    submitted_payload = ""
    endpoint = "/portal/search"

    if request.method == "POST":
        sim_type = request.form.get("simulation_type", "custom")
        database_path = current_app.config["DATABASE_PATH"]
        applications = list_applications(database_path)
        app_obj = applications[0] if applications else {"id": 1, "slug": "legacy-local"}

        if sim_type == "benign":
            endpoint = "/portal/search"
            submitted_payload = "quarterly security compliance documentation"
            input_fields = {"query": submitted_payload}
        elif sim_type == "xss_probe":
            endpoint = "/portal/tickets"
            submitted_payload = "<script>alert('XSS Exploit Simulation')</script>"
            input_fields = {"comment": submitted_payload}
        elif sim_type == "attack_burst":
            # Rapid 4-event burst to trigger Phase 6 burst heuristic and Phase 7 incident correlation
            endpoint = "/portal/search"
            submitted_payload = "<img src=x onerror=alert('Burst Attack')>"
            for idx in range(4):
                burst_fields = {"query": f"{submitted_payload} [probe {idx+1}]"}
                persist_ingestion_event(
                    {
                        "event_type": "request_observation",
                        "endpoint": "/portal/search",
                        "http_method": "POST",
                        "request_id": f"burst-req-{int(time.time())}",
                        "input_fields": burst_fields,
                        "retention_mode": "truncated",
                    },
                    application=app_obj,
                    database_path=database_path,
                )
            # Final analysis for display
            demo_result = analyze_security_input({"query": submitted_payload})
            demo_result["logging_result"] = {
                "stored": True,
                "event_id": "Burst (4 events)",
            }
            return render_template(
                "demo.html",
                demo_result=demo_result,
                submitted_payload=submitted_payload,
                endpoint=endpoint,
            )
        else:
            endpoint = request.form.get("endpoint", "/portal/search")
            submitted_payload = request.form.get("payload", "").strip()
            input_fields = {"input": submitted_payload}

        if submitted_payload:
            stored = persist_ingestion_event(
                {
                    "event_type": "request_observation",
                    "endpoint": endpoint,
                    "http_method": "POST",
                    "request_id": f"demo-{int(time.time()*1000)}",
                    "input_fields": input_fields,
                    "retention_mode": "truncated",
                },
                application=app_obj,
                database_path=database_path,
            )
            demo_result = analyze_security_input(input_fields)
            demo_result["logging_result"] = {
                "stored": True,
                "event_id": stored["id"],
            }

    return render_template(
        "demo.html",
        demo_result=demo_result,
        submitted_payload=submitted_payload,
        endpoint=endpoint,
    )


@main.get("/health")
def health_check():
    """System health check endpoint."""
    return {"status": "ok", "application": "XShield"}


# ============================================================================
# Security Console Routes (Local Demonstration Mode)
# ============================================================================

@main.get("/dashboard")
def dashboard():
    """Security operations overview with all summary telemetry."""
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


@main.get("/dashboard/events")
def dashboard_events():
    """Dedicated Security Events view."""
    risk_level = request.args.get("risk_level") or None
    action = request.args.get("action") or None
    search = request.args.get("search", "").strip()
    snapshot = get_dashboard_snapshot(
        limit=100,
        risk_level=risk_level,
        action=action,
        search=search or None,
        database_path=current_app.config["DATABASE_PATH"],
    )
    return render_template(
        "dashboard_events.html",
        **snapshot,
        selected_risk=risk_level or "All",
        selected_action=action or "All",
        search=search,
    )


@main.get("/dashboard/incidents")
def dashboard_incidents():
    """Dedicated Correlated Incidents view."""
    snapshot = get_dashboard_snapshot(
        limit=50,
        database_path=current_app.config["DATABASE_PATH"],
    )
    return render_template(
        "dashboard_incidents.html",
        **snapshot,
    )


@main.get("/dashboard/behavior")
def dashboard_behavior():
    """Dedicated Phase 6 Behavioral Intelligence view."""
    snapshot = get_dashboard_snapshot(
        limit=50,
        database_path=current_app.config["DATABASE_PATH"],
    )
    return render_template(
        "dashboard_behavior.html",
        **snapshot,
    )


@main.get("/dashboard/applications")
def dashboard_applications():
    """Dedicated Application Registry view."""
    snapshot = get_dashboard_snapshot(
        limit=50,
        database_path=current_app.config["DATABASE_PATH"],
    )
    return render_template(
        "dashboard_applications.html",
        **snapshot,
    )


@main.get("/dashboard/event/<int:event_id>")
def dashboard_event(event_id: int):
    """Event detail view with escaped payload inspection."""
    event = get_event_by_id(event_id, current_app.config["DATABASE_PATH"])
    if event is None:
        return render_template("event_not_found.html", event_id=event_id), 404
    return render_template("event_detail.html", event=event)
