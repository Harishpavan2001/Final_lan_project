import json
import logging
import os
import ipaddress
import csv
import io
from functools import wraps
from datetime import datetime, timedelta
from flask import Blueprint, request, redirect, url_for, flash, render_template, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, User, Exam, Question, ExamAttempt, Answer

# Define Blueprints
main_bp = Blueprint("main", __name__)
auth_bp = Blueprint("auth", __name__)
student_bp = Blueprint("student", __name__)


def admin_required(view_func):
    """Route decorator: requires an authenticated session AND an administrator account.
    Authenticated students hitting an admin-only route are redirected to their own
    dashboard rather than the admin one."""
    @wraps(view_func)
    @login_required
    def wrapped_view(*args, **kwargs):
        if not current_user.is_admin:
            flash("You do not have permission to access that page.", "error")
            return redirect(url_for("student.dashboard"))
        return view_func(*args, **kwargs)
    return wrapped_view


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


def get_client_ip():
    """Extract and normalize the requesting client's IP address, handling proxy headers."""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    if client_ip == "::1":
        client_ip = "127.0.0.1"
    return client_ip


def is_ip_whitelisted(client_ip):
    """Check a client IP against the configured whitelist.
    An empty whitelist means the system is in bootstrap mode and allows everything."""
    whitelist = load_whitelist()
    entries = whitelist.get("ips", [])
    if not entries:
        return True
    return client_ip in [entry["ip"] for entry in entries]


# Whitelist access control hook registered inside main Blueprint
@main_bp.before_app_request
def check_client_ip_whitelist():
    """Global request hook checking remote client IP against access whitelist."""
    # Exclude development assets, health check, login, and logout endpoints from check
    bypass_paths = ["/health", "/login", "/logout", "/api/client-ip"]
    if request.path.startswith("/static") or request.path in bypass_paths:
        return

    client_ip = get_client_ip()

    if not is_ip_whitelisted(client_ip):
        # Log this intrusion attempt to the audit log
        audit_logger = logging.getLogger("audit")
        audit_logger.warning(
            f"ACCESS DENIED: Unauthorized IP: {client_ip} tried to access path: {request.path}"
        )
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"success": False, "message": "Access denied: unauthorized network location."}), 403
        return render_template("denied.html", ip=client_ip), 403


# --- Main Dashboard Routes ---

@main_bp.route("/", methods=["GET"])
@admin_required
def dashboard():
    """Main whitelisting dashboard interface."""
    whitelist = load_whitelist()
    return render_template("dashboard.html", ips=whitelist.get("ips", []))


@main_bp.route("/whitelist/add", methods=["POST"])
@admin_required
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
@admin_required
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
@admin_required
def client_ip_lookup():
    """API endpoint returning detected client IP for auto-fill dashboard helper."""
    return jsonify({"ip": get_client_ip()}), 200


# --- Administrative Authentication Routes ---

def _redirect_for_role(user):
    """Return the correct landing-page redirect for a given authenticated user."""
    return redirect(url_for("main.dashboard") if user.is_admin else url_for("student.dashboard"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handle Administrator and Student Authentication and view (shared login form)."""
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            # Log successful login to audit
            audit_logger = logging.getLogger("audit")
            audit_logger.info(f"USER LOGIN: {user.role.capitalize()} '{username}' logged in successfully.")
            return _redirect_for_role(user)
        
        # Log failed login attempt to audit
        audit_logger = logging.getLogger("audit")
        audit_logger.warning(
            f"LOGIN FAILED: Login failed for username '{username}' from IP {request.remote_addr}"
        )
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Handle new Student self-registration. Administrator accounts are never created
    through this public route; they remain provisioned only via scripts/create_admin.py."""
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        form_values = {"username": username, "full_name": full_name, "email": email}

        if not username or not full_name or not email or not password or not confirm_password:
            flash("All fields are required.", "error")
            return render_template("register.html", **form_values)

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html", **form_values)

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("register.html", **form_values)

        if User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
            return render_template("register.html", **form_values)

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html", **form_values)

        student = User(username=username, full_name=full_name, email=email, is_admin=False)
        student.set_password(password)
        db.session.add(student)
        db.session.commit()

        audit_logger = logging.getLogger("audit")
        audit_logger.info(f"STUDENT REGISTERED: New student account '{username}' created.")

        flash("Registration successful. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout", methods=["GET"])
@login_required
def logout():
    """Handle logout session cleanup for both administrators and students."""
    username = current_user.username
    role_label = current_user.role.capitalize()
    logout_user()
    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"USER LOGOUT: {role_label} '{username}' logged out.")
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


# --- Student Routes ---

def student_required(view_func):
    """Route decorator: requires an authenticated session AND a non-admin (student) account.
    Administrators hitting a student-only route are redirected to their own dashboard."""
    @wraps(view_func)
    @login_required
    def wrapped_view(*args, **kwargs):
        if current_user.is_admin:
            return redirect(url_for("main.dashboard"))
        return view_func(*args, **kwargs)
    return wrapped_view


def exam_ip_guard(view_func):
    """LAN Security: explicit, loudly-logged IP whitelist re-check for exam-taking routes.

    The global before_app_request hook already blocks unwhitelisted IPs on every route,
    but exam integrity is critical enough to warrant a second, dedicated check right at
    the point of use, with its own audit trail distinguishing exam-access denials from
    generic page-access denials."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        client_ip = get_client_ip()
        if not is_ip_whitelisted(client_ip):
            audit_logger = logging.getLogger("audit")
            username = current_user.username if current_user.is_authenticated else "unauthenticated"
            audit_logger.warning(
                f"EXAM ACCESS DENIED: Unauthorized IP {client_ip} blocked from exam route "
                f"'{request.path}' (user: '{username}')."
            )
            if request.is_json or "application/json" in request.headers.get("Accept", ""):
                return jsonify({"success": False, "message": "Access denied: unauthorized network location."}), 403
            return render_template("denied.html", ip=client_ip), 403
        return view_func(*args, **kwargs)
    return wrapped_view


def _verify_attempt_device(attempt):
    """LAN Security: verify the current request originates from the same IP the attempt
    was started on. Returns None if OK, or a Flask response to short-circuit with if not.
    A mismatch is logged distinctly so hijacked/relocated attempts are auditable."""
    current_ip = get_client_ip()
    if attempt.locked_ip and current_ip != attempt.locked_ip:
        audit_logger = logging.getLogger("audit")
        audit_logger.warning(
            f"DEVICE MISMATCH: exam attempt id={attempt.id} for exam '{attempt.exam.title}' "
            f"was started from {attempt.locked_ip} but a request came from {current_ip} "
            f"(student: '{attempt.student.username}')."
        )
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({
                "success": False,
                "message": "Access denied: this exam session is locked to the device/network it was started from.",
            }), 403
        return render_template("denied.html", ip=current_ip), 403
    return None


@student_bp.route("/student/dashboard", methods=["GET"])
@student_required
def dashboard():
    """Student dashboard: lists every published exam alongside this student's attempt status."""
    published_exams = Exam.query.filter_by(is_published=True).order_by(Exam.start_time.asc()).all()
    my_attempts = {a.exam_id: a for a in ExamAttempt.query.filter_by(student_id=current_user.id).all()}

    exam_rows = []
    for exam in published_exams:
        exam_rows.append({
            "exam": exam,
            "attempt": my_attempts.get(exam.id),
        })

    return render_template("student_dashboard.html", exam_rows=exam_rows)


@student_bp.route("/student/exams/<int:exam_id>/start", methods=["POST"])
@student_required
@exam_ip_guard
def start_exam(exam_id):
    """Create (or resume) this student's attempt for an exam, then enter the exam-taking view."""
    exam = Exam.query.get_or_404(exam_id)

    if exam.status != "live":
        flash("This exam is not currently open for attempts.", "error")
        return redirect(url_for("student.dashboard"))

    attempt = ExamAttempt.query.filter_by(exam_id=exam.id, student_id=current_user.id).first()

    if attempt and attempt.is_submitted:
        flash("You have already submitted this exam.", "error")
        return redirect(url_for("student.exam_result", exam_id=exam.id))

    if not attempt:
        if not exam.questions:
            flash("This exam has no questions yet. Please check back later.", "error")
            return redirect(url_for("student.dashboard"))
        # Lock this attempt to the device/network it was started from (LAN security: device verification).
        attempt = ExamAttempt(
            exam_id=exam.id,
            student_id=current_user.id,
            locked_ip=get_client_ip(),
            user_agent=(request.headers.get("User-Agent") or "")[:255],
        )
        db.session.add(attempt)
        db.session.commit()

        audit_logger = logging.getLogger("audit")
        audit_logger.info(
            f"EXAM ATTEMPT STARTED: exam '{exam.title}' by student {current_user.username} "
            f"from IP {attempt.locked_ip} (device locked)."
        )

    return redirect(url_for("student.take_exam", exam_id=exam.id))


def _auto_submit_if_expired(attempt):
    """Finalize and score an attempt if its time window has elapsed. Returns True if it was
    (already or just now) submitted."""
    if attempt.is_submitted:
        return True
    if attempt.is_expired:
        _finalize_attempt(attempt)
        return True
    return False


def _finalize_attempt(attempt):
    """Compute the score for an attempt from its saved answers and mark it submitted.

    Uses an atomic conditional UPDATE (WHERE is_submitted = false) as the actual
    submission gate, so that two near-simultaneous submit requests (e.g. the
    auto-submit timer firing at the same moment as a manual click, or duplicate
    tabs) cannot both finalize/score the attempt — only the first one wins."""
    answers_by_question = {a.question_id: a for a in attempt.answers}
    total_score = 0.0
    for question in attempt.exam.questions:
        answer = answers_by_question.get(question.id)
        if answer and answer.selected_option:
            if answer.selected_option == question.correct_option:
                total_score += question.marks
            else:
                total_score -= question.negative_marks

    computed_score = round(total_score, 2)
    submitted_at = datetime.utcnow()

    # Atomic guard: only rows still unsubmitted get updated. If another request
    # already finalized this attempt, rowcount will be 0 and we simply no-op.
    result = db.session.execute(
        db.update(ExamAttempt)
        .where(ExamAttempt.id == attempt.id, ExamAttempt.is_submitted.is_(False))
        .values(score=computed_score, is_submitted=True, submitted_at=submitted_at)
    )
    db.session.commit()

    if result.rowcount == 0:
        # Someone else already finalized this attempt between our checks; refresh
        # local state and stop here without re-logging a duplicate submission.
        db.session.refresh(attempt)
        return

    attempt.score = computed_score
    attempt.is_submitted = True
    attempt.submitted_at = submitted_at

    audit_logger = logging.getLogger("audit")
    audit_logger.info(
        f"EXAM ATTEMPT SUBMITTED: exam '{attempt.exam.title}' by student {attempt.student.username} "
        f"(score={attempt.score})"
    )


@student_bp.route("/student/exams/<int:exam_id>/attempt", methods=["GET"])
@student_required
@exam_ip_guard
def take_exam(exam_id):
    """The one-question-at-a-time exam-taking interface."""
    exam = Exam.query.get_or_404(exam_id)
    attempt = ExamAttempt.query.filter_by(exam_id=exam.id, student_id=current_user.id).first()

    if not attempt:
        flash("You have not started this exam yet.", "error")
        return redirect(url_for("student.dashboard"))

    device_check = _verify_attempt_device(attempt)
    if device_check:
        return device_check

    if _auto_submit_if_expired(attempt):
        if attempt.is_submitted and attempt.submitted_at and attempt.submitted_at >= datetime.utcnow() - timedelta(seconds=5):
            flash("Time is up — your exam was automatically submitted.", "info")
        return redirect(url_for("student.exam_result", exam_id=exam.id))

    ordered_questions = Question.query.filter_by(exam_id=exam.id).order_by(Question.id.asc()).all()
    saved_answers = {a.question_id: a.selected_option for a in attempt.answers}

    questions_payload = [
        {
            "id": q.id,
            "question_text": q.question_text,
            "options": {"A": q.option_a, "B": q.option_b, "C": q.option_c, "D": q.option_d},
            "selected": saved_answers.get(q.id),
        }
        for q in ordered_questions
    ]

    return render_template(
        "exam_attempt.html",
        exam=exam,
        questions_json=questions_payload,
        deadline_iso=attempt.deadline.isoformat() + "Z",
    )


@student_bp.route("/student/exams/<int:exam_id>/answer", methods=["POST"])
@student_required
@exam_ip_guard
def save_answer(exam_id):
    """Auto-save endpoint: upserts the student's selected option for one question."""
    exam = Exam.query.get_or_404(exam_id)
    attempt = ExamAttempt.query.filter_by(exam_id=exam.id, student_id=current_user.id).first()

    if not attempt:
        return jsonify({"success": False, "message": "No active attempt found."}), 404

    device_check = _verify_attempt_device(attempt)
    if device_check:
        return device_check

    if _auto_submit_if_expired(attempt):
        return jsonify({"success": False, "message": "Time is up. This exam has been submitted.", "expired": True}), 409

    data = request.get_json(silent=True) or {}
    question_id = data.get("question_id")
    selected_option = (data.get("selected_option") or "").strip().upper()

    question = Question.query.filter_by(id=question_id, exam_id=exam.id).first()
    if not question:
        return jsonify({"success": False, "message": "Question not found for this exam."}), 404

    if selected_option not in VALID_OPTIONS:
        return jsonify({"success": False, "message": "Invalid option selected."}), 400

    answer = Answer.query.filter_by(attempt_id=attempt.id, question_id=question.id).first()
    if answer:
        answer.selected_option = selected_option
    else:
        answer = Answer(attempt_id=attempt.id, question_id=question.id, selected_option=selected_option)
        db.session.add(answer)
    db.session.commit()

    return jsonify({"success": True, "message": "Answer saved."}), 200


@student_bp.route("/student/exams/<int:exam_id>/submit", methods=["POST"])
@student_required
@exam_ip_guard
def submit_exam(exam_id):
    """Finalize and score the student's attempt."""
    exam = Exam.query.get_or_404(exam_id)
    attempt = ExamAttempt.query.filter_by(exam_id=exam.id, student_id=current_user.id).first()

    if not attempt:
        return jsonify({"success": False, "message": "No active attempt found."}), 404

    if not attempt.is_submitted:
        device_check = _verify_attempt_device(attempt)
        if device_check:
            return device_check
        _finalize_attempt(attempt)

    return jsonify({"success": True, "message": "Exam submitted successfully.",
                     "redirect_url": url_for("student.exam_result", exam_id=exam.id)}), 200


@student_bp.route("/student/exams/<int:exam_id>/result", methods=["GET"])
@student_required
@exam_ip_guard
def exam_result(exam_id):
    """Show the student's score summary for a submitted attempt."""
    exam = Exam.query.get_or_404(exam_id)
    attempt = ExamAttempt.query.filter_by(exam_id=exam.id, student_id=current_user.id).first()

    if not attempt:
        flash("You have not attempted this exam.", "error")
        return redirect(url_for("student.dashboard"))

    if not attempt.is_submitted:
        return redirect(url_for("student.take_exam", exam_id=exam.id))

    total_possible = sum(q.marks for q in exam.questions)
    answered_count = sum(1 for a in attempt.answers if a.selected_option)

    return render_template(
        "exam_result.html",
        exam=exam,
        attempt=attempt,
        total_possible=total_possible,
        answered_count=answered_count,
        total_questions=len(exam.questions),
    )


# --- Exam Management Routes (Administrator only) ---

DATETIME_INPUT_FORMAT = "%Y-%m-%dT%H:%M"  # matches HTML <input type="datetime-local">


def _parse_exam_form(source):
    """Parse and validate raw exam form/JSON fields into typed values.
    Returns (values_dict, errors_list). On error, values_dict still contains
    whatever raw strings were supplied, for re-populating the form."""
    title = (source.get("title") or "").strip()
    description = (source.get("description") or "").strip()
    duration_raw = str(source.get("duration_minutes") or "").strip()
    start_raw = (source.get("start_time") or "").strip()
    end_raw = (source.get("end_time") or "").strip()
    pass_percentage_raw = str(source.get("pass_percentage") or "").strip()

    raw_values = {
        "title": title,
        "description": description,
        "duration_minutes": duration_raw,
        "start_time": start_raw,
        "end_time": end_raw,
        "pass_percentage": pass_percentage_raw,
    }

    errors = []
    if not title:
        errors.append("Exam title is required.")

    duration_minutes = None
    if not duration_raw:
        errors.append("Exam duration is required.")
    else:
        try:
            duration_minutes = int(duration_raw)
            if duration_minutes <= 0:
                errors.append("Exam duration must be a positive number of minutes.")
        except ValueError:
            errors.append("Exam duration must be a whole number of minutes.")

    start_time = None
    end_time = None
    if not start_raw or not end_raw:
        errors.append("Both start and end date/time are required.")
    else:
        try:
            start_time = datetime.strptime(start_raw, DATETIME_INPUT_FORMAT)
        except ValueError:
            errors.append("Start date/time is not in a recognized format.")
        try:
            end_time = datetime.strptime(end_raw, DATETIME_INPUT_FORMAT)
        except ValueError:
            errors.append("End date/time is not in a recognized format.")

        if start_time and end_time and end_time <= start_time:
            errors.append("End date/time must be after the start date/time.")

    pass_percentage = 40.0
    if pass_percentage_raw:
        try:
            pass_percentage = float(pass_percentage_raw)
            if not (0 <= pass_percentage <= 100):
                errors.append("Passing percentage must be between 0 and 100.")
        except ValueError:
            errors.append("Passing percentage must be a valid number.")

    return {
        "title": title,
        "description": description,
        "duration_minutes": duration_minutes,
        "start_time": start_time,
        "end_time": end_time,
        "pass_percentage": pass_percentage,
        "raw": raw_values,
    }, errors


def _exam_to_dict(exam):
    """Serialize an Exam instance to a JSON-friendly dict for AJAX responses."""
    return {
        "id": exam.id,
        "title": exam.title,
        "description": exam.description,
        "duration_minutes": exam.duration_minutes,
        "start_time": exam.start_time.strftime(DATETIME_INPUT_FORMAT),
        "end_time": exam.end_time.strftime(DATETIME_INPUT_FORMAT),
        "pass_percentage": exam.pass_percentage,
        "is_published": exam.is_published,
        "status": exam.status,
    }


@main_bp.route("/exams", methods=["GET"])
@admin_required
def exams():
    """Exam management dashboard listing all exams."""
    all_exams = Exam.query.order_by(Exam.start_time.desc()).all()
    return render_template("exams.html", exams=all_exams)


@main_bp.route("/exams/create", methods=["POST"])
@admin_required
def create_exam():
    """Create a new exam (draft, unpublished by default)."""
    source = request.get_json(silent=True) if request.is_json else request.form
    is_ajax = request.is_json

    values, errors = _parse_exam_form(source)

    if errors:
        if is_ajax:
            return jsonify({"success": False, "message": " ".join(errors)}), 400
        for err in errors:
            flash(err, "error")
        return redirect(url_for("main.exams"))

    exam = Exam(
        title=values["title"],
        description=values["description"],
        duration_minutes=values["duration_minutes"],
        start_time=values["start_time"],
        end_time=values["end_time"],
        pass_percentage=values["pass_percentage"],
        is_published=False,
        created_by=current_user.id,
    )
    db.session.add(exam)
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"EXAM CREATED: '{exam.title}' (id={exam.id}) by admin {current_user.username}")

    msg = f"Exam '{exam.title}' created successfully as a draft."
    if is_ajax:
        return jsonify({"success": True, "message": msg, "exam": _exam_to_dict(exam)}), 200
    flash(msg, "success")
    return redirect(url_for("main.exams"))


@main_bp.route("/exams/<int:exam_id>/edit", methods=["POST"])
@admin_required
def edit_exam(exam_id):
    """Edit an existing exam's details."""
    exam = Exam.query.get_or_404(exam_id)
    source = request.get_json(silent=True) if request.is_json else request.form
    is_ajax = request.is_json

    values, errors = _parse_exam_form(source)

    if errors:
        if is_ajax:
            return jsonify({"success": False, "message": " ".join(errors)}), 400
        for err in errors:
            flash(err, "error")
        return redirect(url_for("main.exams"))

    exam.title = values["title"]
    exam.description = values["description"]
    exam.duration_minutes = values["duration_minutes"]
    exam.start_time = values["start_time"]
    exam.end_time = values["end_time"]
    exam.pass_percentage = values["pass_percentage"]
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"EXAM UPDATED: '{exam.title}' (id={exam.id}) by admin {current_user.username}")

    msg = f"Exam '{exam.title}' updated successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg, "exam": _exam_to_dict(exam)}), 200
    flash(msg, "success")
    return redirect(url_for("main.exams"))


@main_bp.route("/exams/<int:exam_id>/delete", methods=["POST"])
@admin_required
def delete_exam(exam_id):
    """Delete an exam permanently."""
    exam = Exam.query.get_or_404(exam_id)
    is_ajax = request.is_json or request.accept_mimetypes.best == "application/json"

    title = exam.title
    db.session.delete(exam)
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"EXAM DELETED: '{title}' (id={exam_id}) by admin {current_user.username}")

    msg = f"Exam '{title}' deleted successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg}), 200
    flash(msg, "success")
    return redirect(url_for("main.exams"))


@main_bp.route("/exams/<int:exam_id>/publish", methods=["POST"])
@admin_required
def publish_exam(exam_id):
    """Toggle an exam's published state (publish if draft, unpublish if published)."""
    exam = Exam.query.get_or_404(exam_id)
    is_ajax = request.is_json or request.accept_mimetypes.best == "application/json"

    exam.is_published = not exam.is_published
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    action = "PUBLISHED" if exam.is_published else "UNPUBLISHED"
    audit_logger.info(f"EXAM {action}: '{exam.title}' (id={exam.id}) by admin {current_user.username}")

    msg = f"Exam '{exam.title}' {'published' if exam.is_published else 'unpublished'} successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg, "exam": _exam_to_dict(exam)}), 200
    flash(msg, "success")
    return redirect(url_for("main.exams"))


@main_bp.route("/exams/<int:exam_id>/results", methods=["GET"])
@admin_required
def exam_results(exam_id):
    """Admin Result Dashboard: every student attempt for one exam, with score,
    percentage, and pass/fail, plus summary statistics."""
    exam = Exam.query.get_or_404(exam_id)
    attempts = (
        ExamAttempt.query.filter_by(exam_id=exam.id)
        .join(User, ExamAttempt.student_id == User.id)
        .order_by(ExamAttempt.submitted_at.desc().nullslast(), ExamAttempt.started_at.desc())
        .all()
    )

    submitted_attempts = [a for a in attempts if a.is_submitted]
    total_attempts = len(attempts)
    submitted_count = len(submitted_attempts)
    in_progress_count = total_attempts - submitted_count
    passed_count = sum(1 for a in submitted_attempts if a.passed)
    failed_count = submitted_count - passed_count
    average_score = round(sum(a.score for a in submitted_attempts) / submitted_count, 2) if submitted_count else 0
    average_percentage = round(sum(a.percentage for a in submitted_attempts) / submitted_count, 2) if submitted_count else 0

    return render_template(
        "exam_results.html",
        exam=exam,
        attempts=attempts,
        total_attempts=total_attempts,
        submitted_count=submitted_count,
        in_progress_count=in_progress_count,
        passed_count=passed_count,
        failed_count=failed_count,
        average_score=average_score,
        average_percentage=average_percentage,
    )


# --- Question Management Routes (Administrator only) ---

VALID_OPTIONS = {"A", "B", "C", "D"}


def _parse_question_form(source):
    """Parse and validate raw question form/JSON fields into typed values.
    Returns (values_dict, errors_list)."""
    question_text = (source.get("question_text") or "").strip()
    option_a = (source.get("option_a") or "").strip()
    option_b = (source.get("option_b") or "").strip()
    option_c = (source.get("option_c") or "").strip()
    option_d = (source.get("option_d") or "").strip()
    correct_option = (source.get("correct_option") or "").strip().upper()
    marks_raw = str(source.get("marks") or "").strip()
    negative_marks_raw = str(source.get("negative_marks") or "").strip()

    errors = []
    if not question_text:
        errors.append("Question text is required.")
    if not option_a or not option_b or not option_c or not option_d:
        errors.append("All four options (A, B, C, D) are required.")
    if correct_option not in VALID_OPTIONS:
        errors.append("Correct answer must be one of A, B, C, or D.")

    marks = 1.0
    if marks_raw:
        try:
            marks = float(marks_raw)
            if marks <= 0:
                errors.append("Marks must be a positive number.")
        except ValueError:
            errors.append("Marks must be a valid number.")

    negative_marks = 0.0
    if negative_marks_raw:
        try:
            negative_marks = float(negative_marks_raw)
            if negative_marks < 0:
                errors.append("Negative marks cannot be a negative value itself (enter as positive, e.g. 0.5).")
        except ValueError:
            errors.append("Negative marks must be a valid number.")

    return {
        "question_text": question_text,
        "option_a": option_a,
        "option_b": option_b,
        "option_c": option_c,
        "option_d": option_d,
        "correct_option": correct_option,
        "marks": marks,
        "negative_marks": negative_marks,
    }, errors


def _question_to_dict(question):
    """Serialize a Question instance to a JSON-friendly dict for AJAX responses."""
    return {
        "id": question.id,
        "exam_id": question.exam_id,
        "question_text": question.question_text,
        "option_a": question.option_a,
        "option_b": question.option_b,
        "option_c": question.option_c,
        "option_d": question.option_d,
        "correct_option": question.correct_option,
        "marks": question.marks,
        "negative_marks": question.negative_marks,
    }


@main_bp.route("/exams/<int:exam_id>/questions", methods=["GET"])
@admin_required
def questions(exam_id):
    """Question management dashboard for a single exam."""
    exam = Exam.query.get_or_404(exam_id)
    exam_questions = Question.query.filter_by(exam_id=exam.id).order_by(Question.id.asc()).all()
    total_marks = sum(q.marks for q in exam_questions)
    return render_template("questions.html", exam=exam, questions=exam_questions, total_marks=total_marks)


@main_bp.route("/exams/<int:exam_id>/questions/create", methods=["POST"])
@admin_required
def create_question(exam_id):
    """Add a new multiple-choice question to an exam."""
    exam = Exam.query.get_or_404(exam_id)
    source = request.get_json(silent=True) if request.is_json else request.form
    is_ajax = request.is_json

    values, errors = _parse_question_form(source)

    if errors:
        if is_ajax:
            return jsonify({"success": False, "message": " ".join(errors)}), 400
        for err in errors:
            flash(err, "error")
        return redirect(url_for("main.questions", exam_id=exam.id))

    question = Question(exam_id=exam.id, **values)
    db.session.add(question)
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"QUESTION CREATED: id={question.id} for exam '{exam.title}' by admin {current_user.username}")

    msg = "Question added successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg, "question": _question_to_dict(question)}), 200
    flash(msg, "success")
    return redirect(url_for("main.questions", exam_id=exam.id))


@main_bp.route("/questions/<int:question_id>/edit", methods=["POST"])
@admin_required
def edit_question(question_id):
    """Edit an existing question's details."""
    question = Question.query.get_or_404(question_id)
    source = request.get_json(silent=True) if request.is_json else request.form
    is_ajax = request.is_json

    values, errors = _parse_question_form(source)

    if errors:
        if is_ajax:
            return jsonify({"success": False, "message": " ".join(errors)}), 400
        for err in errors:
            flash(err, "error")
        return redirect(url_for("main.questions", exam_id=question.exam_id))

    for field, value in values.items():
        setattr(question, field, value)
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"QUESTION UPDATED: id={question.id} by admin {current_user.username}")

    msg = "Question updated successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg, "question": _question_to_dict(question)}), 200
    flash(msg, "success")
    return redirect(url_for("main.questions", exam_id=question.exam_id))


@main_bp.route("/questions/<int:question_id>/delete", methods=["POST"])
@admin_required
def delete_question(question_id):
    """Delete a question permanently."""
    question = Question.query.get_or_404(question_id)
    exam_id = question.exam_id
    is_ajax = request.is_json or request.accept_mimetypes.best == "application/json"

    db.session.delete(question)
    db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(f"QUESTION DELETED: id={question_id} by admin {current_user.username}")

    msg = "Question deleted successfully."
    if is_ajax:
        return jsonify({"success": True, "message": msg}), 200
    flash(msg, "success")
    return redirect(url_for("main.questions", exam_id=exam_id))


@main_bp.route("/exams/<int:exam_id>/questions/import", methods=["POST"])
@admin_required
def import_questions(exam_id):
    """Bulk-import questions from an uploaded CSV file.

    Expected columns (header row required):
    question_text, option_a, option_b, option_c, option_d, correct_option, marks, negative_marks
    (marks defaults to 1, negative_marks defaults to 0 when omitted or blank)
    """
    exam = Exam.query.get_or_404(exam_id)
    is_ajax = request.accept_mimetypes.best == "application/json" or "application/json" in request.headers.get("Accept", "")

    upload = request.files.get("csv_file")
    if not upload or not upload.filename:
        msg = "No CSV file was selected."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.questions", exam_id=exam.id))

    if not upload.filename.lower().endswith(".csv"):
        msg = "Uploaded file must be a .csv file."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.questions", exam_id=exam.id))

    try:
        raw_bytes = upload.read()
        text_stream = io.StringIO(raw_bytes.decode("utf-8-sig"))
        reader = csv.DictReader(text_stream)
    except (UnicodeDecodeError, csv.Error) as exc:
        msg = f"Could not parse CSV file: {exc}"
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.questions", exam_id=exam.id))

    required_columns = {"question_text", "option_a", "option_b", "option_c", "option_d", "correct_option"}
    if not reader.fieldnames or not required_columns.issubset(set(h.strip() for h in reader.fieldnames)):
        msg = ("CSV header row must include: question_text, option_a, option_b, option_c, "
               "option_d, correct_option (marks and negative_marks are optional).")
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("main.questions", exam_id=exam.id))

    imported_count = 0
    row_errors = []
    new_questions = []

    for row_num, row in enumerate(reader, start=2):  # row 1 is the header
        normalized_row = {(k.strip() if k else k): (v.strip() if v else v) for k, v in row.items()}
        values, errors = _parse_question_form(normalized_row)
        if errors:
            row_errors.append(f"Row {row_num}: {' '.join(errors)}")
            continue
        new_questions.append(Question(exam_id=exam.id, **values))
        imported_count += 1

    if new_questions:
        db.session.add_all(new_questions)
        db.session.commit()

    audit_logger = logging.getLogger("audit")
    audit_logger.info(
        f"QUESTIONS IMPORTED: {imported_count} question(s) imported into exam '{exam.title}' "
        f"by admin {current_user.username} ({len(row_errors)} row error(s))"
    )

    if imported_count and not row_errors:
        msg = f"Successfully imported {imported_count} question(s)."
        category = "success"
    elif imported_count and row_errors:
        msg = f"Imported {imported_count} question(s) with {len(row_errors)} row error(s): " + " | ".join(row_errors[:5])
        category = "error"
    else:
        msg = "No questions were imported. " + " | ".join(row_errors[:5])
        category = "error"

    if is_ajax:
        return jsonify({
            "success": imported_count > 0,
            "message": msg,
            "imported_count": imported_count,
            "row_errors": row_errors,
        }), (200 if imported_count else 400)

    flash(msg, category)
    return redirect(url_for("main.questions", exam_id=exam.id))
