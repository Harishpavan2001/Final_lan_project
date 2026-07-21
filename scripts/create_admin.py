import sys
import getpass
from pathlib import Path

# Add project root to Python search path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db, User


def create_admin_user(username, password, env="development"):
    """Provision a new administrator user in the database."""
    app = create_app(env)
    
    with app.app_context():
        # Check if username is already taken
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"Error: A user with username '{username}' already exists.", file=sys.stderr)
            sys.exit(1)

        # Create user database record
        admin = User(username=username, is_admin=True)
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        print(f"Successfully created administrator account: '{username}' in '{env}' env.")


if __name__ == "__main__":
    # If parameters are supplied via Command Line Interface (CLI)
    if len(sys.argv) >= 3:
        target_username = sys.argv[1]
        target_password = sys.argv[2]
        target_env = sys.argv[3] if len(sys.argv) > 3 else "development"
    else:
        # Prompt user interactively
        print("--- LAN Gateway Administrator Creation Utility ---")
        target_username = input("Username: ").strip()
        if not target_username:
            print("Error: Username cannot be blank.", file=sys.stderr)
            sys.exit(1)
            
        target_password = getpass.getpass("Password: ")
        if not target_password:
            print("Error: Password cannot be blank.", file=sys.stderr)
            sys.exit(1)
            
        target_env = input("Environment [development]: ").strip() or "development"

    try:
        create_admin_user(target_username, target_password, target_env)
    except Exception as e:
        print(f"Error provisioning user account: {e}", file=sys.stderr)
        sys.exit(1)
