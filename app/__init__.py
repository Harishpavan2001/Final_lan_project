import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from flask import Flask, jsonify
from app.config import config_by_name


def setup_logging(app):
    """Configure application logging using file handlers."""
    log_dir = app.config.get("LOG_DIR")
    if not log_dir:
        return

    # Ensure the log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Base log formatter
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s [%(pathname)s:%(lineno)d]: %(message)s"
    )

    # Set logger level
    if app.config.get("DEBUG"):
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    
    app.logger.setLevel(log_level)

    # Main Application Log Handler (covers general app logs & errors)
    app_log_path = os.path.join(log_dir, "app.log")
    app_handler = RotatingFileHandler(
        app_log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    app_handler.setFormatter(formatter)
    app_handler.setLevel(log_level)
    app.logger.addHandler(app_handler)

    # Audit Log Handler (specifically for tracking access control, logins, whitelisting)
    audit_logger = logging.getLogger("audit")
    audit_log_path = os.path.join(log_dir, "audit.log")
    audit_handler = RotatingFileHandler(
        audit_log_path, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    audit_handler.setFormatter(formatter)
    audit_logger.setLevel(logging.INFO)
    audit_logger.addHandler(audit_handler)
    # Prevent audit logs from duplicating in standard application stdout/stderr logs
    audit_logger.propagate = False

    app.logger.info(f"Logging initialized at level {logging.getLevelName(log_level)}")


def verify_whitelist_config(app):
    """Ensure the whitelist JSON file exists or log a warning if it does not."""
    whitelist_path = app.config.get("WHITELIST_PATH")
    if not whitelist_path:
        app.logger.warning("WHITELIST_PATH is not configured.")
        return

    path = Path(whitelist_path)
    if not path.exists():
        app.logger.warning(
            f"Whitelist file not found at: {whitelist_path}. "
            "Please create this file to configure access control rules."
        )
        # Note: In a later step, we can choose to auto-create an empty configuration
        # structure here if necessary to avoid file-read exceptions during request handling.


def create_app(config_name="default"):
    """Flask Application Factory.
    
    Args:
        config_name (str): The configuration profile to load ('development', 'testing', 'production', 'default').
        
    Returns:
        Flask: The configured Flask application instance.
    """
    app = Flask(__name__)

    # Load configurations from object
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Set up file logging
    setup_logging(app)

    # Verify that whitelist path configuration exists
    verify_whitelist_config(app)

    # Initialize database & login manager extensions
    from app.extensions import db, login_manager
    db.init_app(app)
    login_manager.init_app(app)

    # Register blueprints (imported locally to avoid circular dependencies)
    from app.app import main_bp, auth_bp, student_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(student_bp)

    # Core internal routes for health checking
    @app.route("/health", methods=["GET"])
    def health_check():
        """Basic health check API to verify system responsiveness."""
        return jsonify({
            "status": "healthy",
            "environment": config_name,
            "debug": app.config.get("DEBUG"),
            "testing": app.config.get("TESTING")
        }), 200

    app.logger.info(f"Application created successfully in '{config_name}' environment.")
    return app
