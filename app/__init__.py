import os

from flask import Flask

from app.config import (
    INTEGRATION_API_VERSION,
    MAX_EVENT_INPUT_LENGTH,
    MAX_STORED_INPUT_LENGTH,
)
from app.database import DEFAULT_DATABASE_PATH, initialize_database
from app.api import api_v1
from app.routes import main


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the XShield Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE_PATH=str(DEFAULT_DATABASE_PATH),
        MAX_CONTENT_LENGTH=16 * 1024,
        INTEGRATION_API_VERSION=INTEGRATION_API_VERSION,
        MAX_EVENT_INPUT_LENGTH=MAX_EVENT_INPUT_LENGTH,
        MAX_STORED_INPUT_LENGTH=MAX_STORED_INPUT_LENGTH,
        DASHBOARD_USERNAME=os.getenv("XSHIELD_DASHBOARD_USERNAME", "admin"),
        DASHBOARD_PASSWORD=os.getenv("XSHIELD_DASHBOARD_PASSWORD"),
    )
    if test_config:
        app.config.update(test_config)
    initialize_database(app.config["DATABASE_PATH"])

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    app.register_blueprint(main)
    app.register_blueprint(api_v1)
    return app
