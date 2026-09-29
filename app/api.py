"""Versioned HTTP API routes for XShield integrations."""

from __future__ import annotations

import json
import sqlite3
from functools import wraps

from flask import Blueprint, current_app, jsonify, request
from werkzeug.exceptions import BadRequest

from app.services.api_keys import authenticate_flask_request
from app.services.event_ingestion import EventAnalysisError, persist_ingestion_event


api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def _json_error(message: str, status: int):
    return jsonify({"accepted": False, "error": message}), status


def api_key_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        result = authenticate_flask_request(
            request,
            current_app.config["DATABASE_PATH"],
        )
        if result.authenticated:
            return view(result.application, *args, **kwargs)
        if result.reason in {
            "revoked_api_key",
            "expired_api_key",
            "inactive_application",
        }:
            return _json_error("API key is not authorized.", 403)
        return _json_error("API key authentication required.", 401)

    return wrapped


@api_v1.post("/events")
@api_key_required
def ingest_event(application):
    if not request.is_json:
        return _json_error("Content-Type must be application/json.", 415)
    if request.content_length is not None and request.content_length > current_app.config[
        "MAX_CONTENT_LENGTH"
    ]:
        return _json_error("Request body is too large.", 413)
    try:
        payload = request.get_json(silent=False)
    except (json.JSONDecodeError, ValueError, BadRequest):
        return _json_error("Request body must contain valid JSON.", 400)
    if not isinstance(payload, dict):
        return _json_error("Request body must be a JSON object.", 422)
    try:
        stored = persist_ingestion_event(
            payload,
            application=application,
            database_path=current_app.config["DATABASE_PATH"],
        )
    except ValueError:
        return _json_error("Event payload is invalid.", 422)
    except EventAnalysisError:
        return _json_error("Event analysis failed.", 500)
    except (KeyError, TypeError, ValueError, OSError, sqlite3.Error):
        return _json_error("Event could not be stored.", 500)
    return jsonify(
        {
            "accepted": True,
            "event_id": stored["id"],
            "application": application["slug"],
            "status": "accepted",
        }
    ), 201
