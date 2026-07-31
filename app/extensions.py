from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Configure Login Manager
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"


class User(UserMixin, db.Model):
    """User model representing both administrator and student accounts,
    distinguished by the is_admin flag (see the role property below)."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)

    # Student-only profile fields (left null for administrator accounts)
    full_name = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)

    @property
    def role(self):
        """Human-readable role label derived from is_admin, for use in templates/logs."""
        return "admin" if self.is_admin else "student"

    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify the user's password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return User.query.get(int(user_id))


class Exam(db.Model):
    """Exam model representing an administrator-managed examination window."""

    __tablename__ = "exams"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    duration_minutes = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_published = db.Column(db.Boolean, default=False, nullable=False)
    pass_percentage = db.Column(db.Float, nullable=False, default=40.0)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    creator = db.relationship("User", backref=db.backref("exams_created", lazy=True))

    @property
    def status(self):
        """Compute a human-readable lifecycle status for display purposes."""
        if not self.is_published:
            return "draft"
        now = datetime.utcnow()
        if now < self.start_time:
            return "scheduled"
        if self.start_time <= now <= self.end_time:
            return "live"
        return "closed"

    @property
    def total_marks(self):
        """Sum of marks across all questions in this exam (the maximum possible score)."""
        return sum(q.marks for q in self.questions)

    def __repr__(self):
        return f"<Exam {self.title}>"


class Question(db.Model):
    """Multiple-choice question belonging to an Exam."""

    __tablename__ = "questions"

    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exams.id"), nullable=False, index=True)

    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(500), nullable=False)
    option_b = db.Column(db.String(500), nullable=False)
    option_c = db.Column(db.String(500), nullable=False)
    option_d = db.Column(db.String(500), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)  # 'A', 'B', 'C', or 'D'

    marks = db.Column(db.Float, nullable=False, default=1.0)
    negative_marks = db.Column(db.Float, nullable=False, default=0.0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    exam = db.relationship("Exam", backref=db.backref("questions", lazy=True, cascade="all, delete-orphan"))

    def options_dict(self):
        """Return the four options keyed by letter, for convenient template iteration."""
        return {"A": self.option_a, "B": self.option_b, "C": self.option_c, "D": self.option_d}

    def __repr__(self):
        return f"<Question {self.id} for Exam {self.exam_id}>"


class ExamAttempt(db.Model):
    """Tracks a single student's attempt at an exam (one attempt per student per exam)."""

    __tablename__ = "exam_attempts"
    __table_args__ = (db.UniqueConstraint("exam_id", "student_id", name="uq_attempt_exam_student"),)

    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey("exams.id"), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=True)
    is_submitted = db.Column(db.Boolean, default=False, nullable=False)
    score = db.Column(db.Float, nullable=True)

    # Device/network binding captured when the attempt is started, used to detect
    # mid-exam IP changes (e.g. attempt hijacked from a different machine).
    locked_ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    exam = db.relationship("Exam", backref=db.backref("attempts", lazy=True, cascade="all, delete-orphan"))
    student = db.relationship("User", backref=db.backref("exam_attempts", lazy=True))

    @property
    def deadline(self):
        """The moment this attempt must be auto-submitted by: whichever comes first,
        the attempt's own duration-based cutoff or the exam's published end_time."""
        duration_cutoff = self.started_at + timedelta(minutes=self.exam.duration_minutes)
        return min(duration_cutoff, self.exam.end_time)

    @property
    def is_expired(self):
        return datetime.utcnow() >= self.deadline

    @property
    def percentage(self):
        """Score expressed as a percentage of the exam's total possible marks.
        Returns 0.0 if the attempt isn't submitted yet or the exam has no marks."""
        if not self.is_submitted or self.score is None:
            return 0.0
        total = self.exam.total_marks
        if not total:
            return 0.0
        # Clamp to 0 minimum: negative-marking attempts shouldn't show a negative percentage.
        return round(max(self.score, 0.0) / total * 100, 2)

    @property
    def passed(self):
        """Whether this (submitted) attempt met the exam's passing percentage threshold."""
        if not self.is_submitted:
            return None
        return self.percentage >= self.exam.pass_percentage

    def __repr__(self):
        return f"<ExamAttempt exam={self.exam_id} student={self.student_id}>"


class Answer(db.Model):
    """A student's saved answer to a single question within an exam attempt."""

    __tablename__ = "answers"
    __table_args__ = (db.UniqueConstraint("attempt_id", "question_id", name="uq_answer_attempt_question"),)

    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey("exam_attempts.id"), nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey("questions.id"), nullable=False, index=True)
    selected_option = db.Column(db.String(1), nullable=True)  # 'A'/'B'/'C'/'D', null if unanswered
    answered_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    attempt = db.relationship("ExamAttempt", backref=db.backref("answers", lazy=True, cascade="all, delete-orphan"))
    question = db.relationship("Question")

    def __repr__(self):
        return f"<Answer attempt={self.attempt_id} question={self.question_id} -> {self.selected_option}>"
