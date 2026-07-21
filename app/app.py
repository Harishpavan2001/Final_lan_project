import json
import logging
import os
import ipaddress
from datetime import datetime
from flask import Blueprint, request, redirect, url_for, flash, render_template, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, User

# Define Blueprints
main_bp = Blueprint("main", __name__)
auth_bp = Blueprint("auth", __name__)


# Whitelist JSON database helper functions
def load_whitelist():
    """Load whitelisted IP addresses from the configured JSON file."""
    path = current_app.config.get("WHITELIST_PATH")
    if not path:
        return {"ips": []}
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "ips" not in data:
                data = {"ips": []}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {"ips": []}


def save_whitelist(data):
    """Write whitelisted IP entries back to the configured JSON file."""
    path = current_app.config.get("WHITELIST_PATH")
    if not path:
        return False
        
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to write whitelist file: {e}")
        return False


# Whitelist access control hook registered inside main Blueprint
@main_bp.before_app_request
def check_client_ip_whitelist():
    """Global request hook checking remote client IP against access whitelist."""
    # Exclude development assets, health check, login, and logout endpoints from check
    bypass_paths = ["/health", "/login", "/logout", "/api/client-ip"]
    if request.path.startswith("/static") or request.path in bypass_paths:
        return

    # Extract client IP address, handling proxy headers (like X-Forwarded-For)
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Normalize local loopback
    if client_ip == "::1":
        client_ip = "127.0.0.1"

    whitelist = load_whitelist()
    entries = whitelist.get("ips", [])

    # If the whitelist is completely empty, act in bootstrap/bypass mode so admins
    # can access the system to register the first client IP.
    if not entries:
        return

    # Check if client IP is registered
    whitelisted_ips = [entry["ip"] for entry in entries]
    if client_ip not in whitelisted_ips:
        # Log this intrusion attempt to the audit log
        audit_logger = logging.getLogger("audit")
        audit_logger.warning(
            f"ACCESS DENIED: Unauthorized IP: {client_ip} tried to access path: {request.path}"
        )
        return render_template("denied.html", ip=client_ip), 403


# --- Main Dashboard Routes ---

@main_bp.route("/", methods=["GET"])
@login_required
def dashboard():
    """Main whitelisting dashboard interface."""
    whitelist = load_whitelist()
    return render_template("dashboard.html", ips=whitelist.get("ips", []))


@main_bp.route("/whitelist/add", methods=["POST"])
@login_required
def add_ip():
    """Handle request to register a new IP to the whitelist (supports form & JSON/AJAX requests)."""
    if request.is_json:
        data = request.get_json()
        ip_str = data.get("ip", "").strip()
        description = data.get("description", "").strip()
        is_ajax = True
    else:
        ip_str = request.form.get("ip", "").strip()
        description = request.form.get("description", "").strip()
        is_ajax = False

    if not ip_str or not description:
        msg = "Both IP Address and Description are required."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.dashboard"))

    # Validate IP address syntax
    try:
        ip = ipaddress.ip_address(ip_str)
        ip_str = str(ip)
    except ValueError:
        msg = "Invalid IP Address format. Please input a valid IPv4 or IPv6 address."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.dashboard"))

    whitelist = load_whitelist()
    entries = whitelist.get("ips", [])

    # Check for duplicate
    if any(entry["ip"] == ip_str for entry in entries):
        msg = f"IP address {ip_str} is already whitelisted."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.dashboard"))

    # Add new entry
    new_entry = {
        "ip": ip_str,
        "description": description,
        "added_by": current_user.username,
        "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    entries.append(new_entry)
    whitelist["ips"] = entries

    if save_whitelist(whitelist):
        audit_logger = logging.getLogger("audit")
        audit_logger.info(
            f"IP ADDED: {ip_str} ({description}) by admin {current_user.username}"
        )
        msg = f"Successfully whitelisted IP address {ip_str}."
        if is_ajax:
            return jsonify({"success": True, "message": msg, "entry": new_entry}), 200
        flash(msg, "success")
    else:
        msg = "System error saving whitelist data."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 500
        flash(msg, "error")

    return redirect(url_for("main.dashboard"))


@main_bp.route("/whitelist/delete", methods=["POST"])
@login_required
def delete_ip():
    """Handle request to delete a registered IP from the whitelist (supports form & JSON/AJAX requests)."""
    if request.is_json:
        data = request.get_json()
        ip_str = data.get("ip", "").strip()
        is_ajax = True
    else:
        ip_str = request.form.get("ip", "").strip()
        is_ajax = False

    if not ip_str:
        msg = "IP Address is required to delete an entry."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.dashboard"))

    whitelist = load_whitelist()
    entries = whitelist.get("ips", [])
    
    # Filter out target IP
    new_entries = [entry for entry in entries if entry["ip"] != ip_str]

    if len(new_entries) == len(entries):
        msg = f"IP address {ip_str} was not found in the whitelist."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 404
        flash(msg, "error")
        return redirect(url_for("main.dashboard"))

    whitelist["ips"] = new_entries

    if save_whitelist(whitelist):
        audit_logger = logging.getLogger("audit")
        audit_logger.info(f"IP REMOVED: {ip_str} by admin {current_user.username}")
        msg = f"Successfully removed IP address {ip_str} from whitelist."
        if is_ajax:
            return jsonify({"success": True, "message": msg}), 200
        flash(msg, "success")
    else:
        msg = "System error updating whitelist data."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 500
        flash(msg, "error")

    return redirect(url_for("main.dashboard"))


@main_bp.route("/api/client-ip", methods=["GET"])
@login_required
def get_client_ip():
    """API endpoint returning detected client IP for auto-fill dashboard helper."""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    
    # Normalize local loopback
    if client_ip == "::1":
        client_ip = "127.0.0.1"
        
    return jsonify({"ip": client_ip}), 200


# --- Administrative Authentication Routes ---

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle Administrator Authentication and view."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            # Log successful login to audit
            audit_logger = logging.getLogger("audit")
            audit_logger.info(f"USER LOGIN: Admin '{username}' logged in successfully.")
            return redirect(url_for("main.dashboard"))
        
        # Log failed login attempt to audit
        audit_logger = logging.getLogger("audit")
        audit_logger.warning(
            f"LOGIN FAILED: Admin login failed for username '{username}' from IP {request.remote_addr}"
        )
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET"])
@login_required
def logout():
    """Handle Administrator logout session cleanup."""
    username = current_user.username
    logout_user()
    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"USER LOGOUT: Admin '{username}' logged out.")
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
