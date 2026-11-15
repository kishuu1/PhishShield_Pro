"""
PhishShield Pro — Audit Logging Service

Provides a simple helper to record user actions in the audit_logs collection.
"""

from datetime import datetime, timezone


def log_action(db, user, action, details=None):
    """Insert an audit-log entry.

    Parameters
    ----------
    db : pymongo.database.Database
        The MongoDB database handle.
    user : str
        Username (or system identifier) performing the action.
    action : str
        Short label for the action (e.g. ``"login"``, ``"scan_url"``).
    details : dict | str | None
        Optional extra context stored alongside the log entry.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc),
        "user": user,
        "action": action,
    }
    if details is not None:
        entry["details"] = details

    db.audit_logs.insert_one(entry)
