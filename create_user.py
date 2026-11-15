"""
PhishShield Pro — Command Line User Management Utility

Allows administrators to safely create new user accounts with
bcrypt password hashing directly from the terminal or PowerShell.

Usage:
    Interactive mode:
        python create_user.py

    Command line arguments:
        python create_user.py --username <username> --password <password> --role <admin|analyst|auditor>
"""

import argparse
import sys
from datetime import datetime, timezone
import getpass
import bcrypt

import config
from services.db import get_db, init_db


def hash_password(password: str) -> str:
    """Return a secure Blowfish bcrypt salt-hashed password string."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_user(username: str, password: str, role: str = "analyst") -> bool:
    """Create a new user account in MongoDB."""
    username = username.strip()
    role = role.strip().lower()

    if not username:
        print("[!] Error: Username cannot be blank.")
        return False

    if len(password) < 6:
        print("[!] Error: Password must be at least 6 characters long.")
        return False

    if role not in ("admin", "analyst", "auditor"):
        print("[!] Error: Role must be one of: admin, analyst, auditor.")
        return False

    try:
        init_db()
        db = get_db()

        # Check for existing username
        existing = db.users.find_one({"username": username})
        if existing:
            print(f"[!] Error: User '{username}' already exists in the database.")
            return False

        hashed = hash_password(password)
        doc = {
            "username": username,
            "password": hashed,
            "role": role,
            "created_at": datetime.now(timezone.utc)
        }
        res = db.users.insert_one(doc)

        # Audit log entry
        db.audit_logs.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "user": "cli_admin",
            "action": "user_create",
            "details": f"Created user '{username}' with role '{role}' via CLI"
        })

        print(f"[+] Success! User '{username}' created with role '{role}' (ID: {res.inserted_id}).")
        return True

    except Exception as e:
        print(f"[!] Database connection error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Create a new PhishShield Pro user account.")
    parser.add_argument("--username", "-u", type=str, help="Username for the new account")
    parser.add_argument("--password", "-p", type=str, help="Password for the new account")
    parser.add_argument("--role", "-r", type=str, default="analyst", choices=["admin", "analyst", "auditor"],
                        help="Role for the account (default: analyst)")

    args = parser.parse_args()

    # If arguments not provided, prompt interactively
    if not args.username or not args.password:
        print("=" * 60)
        print("  PhishShield Pro — Interactive User Creation Console")
        print("=" * 60)

        username = input("Enter username: ").strip()
        while not username:
            print("Username cannot be empty.")
            username = input("Enter username: ").strip()

        password = getpass.getpass("Enter password (min 6 characters): ")
        while len(password) < 6:
            print("Password must be at least 6 characters.")
            password = getpass.getpass("Enter password: ")

        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("[!] Error: Passwords do not match. Aborted.")
            sys.exit(1)

        print("\nAvailable roles:")
        print("  1. admin   - Full administrative privileges and rule management")
        print("  2. analyst - Standard URL scanning and triage privileges (Default)")
        print("  3. auditor - Read-only access to audit trail and reports")
        role_choice = input("Select role [1/2/3] (default 2): ").strip()
        role_map = {"1": "admin", "2": "analyst", "3": "auditor"}
        role = role_map.get(role_choice, "analyst")

        success = create_user(username, password, role)
        sys.exit(0 if success else 1)
    else:
        success = create_user(args.username, args.password, args.role)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

