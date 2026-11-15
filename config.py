"""
PhishShield Pro — Application Configuration

Loads settings from a .env file and exposes them as module-level constants.
"""

import os
import warnings
from dotenv import load_dotenv

# Load .env file from the project root
load_dotenv()

# ---------------------------------------------------------------------------
# Secret key
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = "dev-fallback-secret-key-DO-NOT-USE-IN-PRODUCTION"
    warnings.warn(
        "SECRET_KEY is not set! Using an insecure fallback. "
        "Set SECRET_KEY in your .env file for production.",
        stacklevel=2,
    )

# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
MONGODB_DB = os.getenv("MONGODB_DB", "phishshield_pro")

# ---------------------------------------------------------------------------
# Default admin credentials (used for initial seed only)
# ---------------------------------------------------------------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@123")
