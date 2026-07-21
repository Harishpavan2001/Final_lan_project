import os
import sys
from pathlib import Path

# Add project root to Python search path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db


def init_database(env="development"):
    """Initialize the database schema for the given environment."""
    print(f"Loading app instance in '{env}' configuration...")
    app = create_app(env)
    
    with app.app_context():
        db_url = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        
        # Ensure target database directory exists if using SQLite
        if db_url.startswith("sqlite:///"):
            db_path_raw = db_url.replace("sqlite:///", "")
            
            # Extract absolute path
            if os.path.isabs(db_path_raw):
                db_path = db_path_raw
            else:
                db_path = str(PROJECT_ROOT / db_path_raw)
                
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            print(f"Ensuring database directory: {os.path.dirname(db_path)}")

        print("Provisioning database tables...")
        db.create_all()
        print("Database schema initialized successfully!")


if __name__ == "__main__":
    # Allow overriding default environment via CLI arguments
    target_env = "development"
    if len(sys.argv) > 1:
        target_env = sys.argv[1]
        
    try:
        init_database(target_env)
    except Exception as e:
        print(f"Error provisioning database schema: {e}", file=sys.stderr)
        sys.exit(1)
