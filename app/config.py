import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=BASE_DIR / ".env")
except ImportError:
    # If python-dotenv is not installed yet, we rely on environment variables
    # set directly in the OS or Docker container.
    pass


class Config:
    """Base configuration settings shared by all environments."""

    # Secret key for signing sessions and cookies
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-insecure-secret-key-change-me")

    # Database settings
    # Default to SQLite file in the project directory if not specified
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'database' / 'app.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Path to the whitelist configuration file
    WHITELIST_PATH = os.getenv("WHITELIST_PATH", str(BASE_DIR / "whitelist" / "whitelist.json"))

    # Directory for system logs
    LOG_DIR = os.getenv("LOG_DIR", str(BASE_DIR / "logs"))

    # Flask specific controls
    DEBUG = False
    TESTING = False


class DevelopmentConfig(Config):
    """Configuration for local development environment."""

    DEBUG = True
    # In development, we can use a more verbose or specific database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DEV_DATABASE_URL", f"sqlite:///{BASE_DIR / 'database' / 'dev_app.db'}"
    )


class TestingConfig(Config):
    """Configuration for running automated tests."""

    TESTING = True
    DEBUG = True
    # Use in-memory SQLite database for fast isolated tests
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    # Path to test whitelist to avoid modifying production whitelist
    WHITELIST_PATH = os.getenv("TEST_WHITELIST_PATH", str(BASE_DIR / "whitelist" / "whitelist.json"))


class ProductionConfig(Config):
    """Configuration for production deployment."""

    # Production must have debug turned off
    DEBUG = False
    TESTING = False

    # Force a stronger check on the secret key in production
    @property
    def SECRET_KEY(self):
        key = os.getenv("SECRET_KEY")
        if not key or key == "fallback-insecure-secret-key-change-me":
            raise ValueError("SECRET_KEY must be explicitly set to a secure value in production!")
        return key

    # Database URI should ideally be PostgreSQL or MySQL in production
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")


# Mapping of configuration names to their respective classes
config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
