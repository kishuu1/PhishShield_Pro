"""
PhishShield Pro — Database Service

MongoDB connection handling, collection index creation,
and initial demo seeding.
"""

from datetime import datetime, timedelta, timezone
import bcrypt
from pymongo import MongoClient, ASCENDING, DESCENDING
import config

_client = None


def _get_client():
    """Return a cached MongoClient instance."""
    global _client
    if _client is None:
        _client = MongoClient(config.MONGODB_URI, serverSelectionTimeoutMS=5000)
    return _client


def get_db():
    """Return the configured PyMongo database handle."""
    return _get_client()[config.MONGODB_DB]


def init_db():
    """Create all required MongoDB indexes across collections."""
    db = get_db()

    # 1. users: unique index on username
    db.users.create_index("username", unique=True)

    # 2. scan_history: indexes on scanned_at, risk_level, and url
    db.scan_history.create_index([("scanned_at", DESCENDING)])
    db.scan_history.create_index("risk_level")
    db.scan_history.create_index("url")

    # 3. threat_intelligence: unique index on indicator
    db.threat_intelligence.create_index("indicator", unique=True)
    db.threat_intelligence.create_index("indicator_type")
    db.threat_intelligence.create_index("status")

    # 4. security_alerts: index on created_at, severity, and status
    db.security_alerts.create_index([("created_at", DESCENDING)])
    db.security_alerts.create_index("severity")
    db.security_alerts.create_index("status")

    # 5. audit_logs: index on timestamp and action
    db.audit_logs.create_index([("timestamp", DESCENDING)])
    db.audit_logs.create_index("action")

    # 6. detection_rules: unique index on rule_id
    db.detection_rules.create_index("rule_id", unique=True)


_DEFAULT_RULES = [
    {
        "rule_id": "ip_address_host",
        "name": "IP Address Host",
        "description": "URL uses an IP address as the hostname instead of a domain name",
        "weight": 20,
        "enabled": True,
    },
    {
        "rule_id": "suspicious_keywords",
        "name": "Suspicious Keywords",
        "description": "URL contains common phishing/credential harvesting keywords (login, verify, secure, account, update, banking, password, etc.)",
        "weight": 15,
        "enabled": True,
    },
    {
        "rule_id": "excessive_subdomains",
        "name": "Excessive Subdomains",
        "description": "More than 3 subdomains in the hostname, indicating abnormal domain nesting",
        "weight": 15,
        "enabled": True,
    },
    {
        "rule_id": "at_symbol",
        "name": "At Symbol in URL",
        "description": "URL contains '@' symbol which can redirect traffic to subsequent host while spoofing credentials",
        "weight": 20,
        "enabled": True,
    },
    {
        "rule_id": "url_shortener",
        "name": "URL Shortener",
        "description": "URL uses a link shortening service that masks true target destination",
        "weight": 15,
        "enabled": True,
    },
    {
        "rule_id": "long_url",
        "name": "Long URL",
        "description": "URL length exceeds 75 characters, often used to hide target paths on mobile devices",
        "weight": 10,
        "enabled": True,
    },
    {
        "rule_id": "insecure_http",
        "name": "Insecure HTTP",
        "description": "URL uses plaintext HTTP instead of secure HTTPS encryption",
        "weight": 5,
        "enabled": True,
    },
    {
        "rule_id": "suspicious_tld",
        "name": "Suspicious TLD",
        "description": "URL uses a top-level domain frequently associated with low-cost spam/phishing campaigns (.tk, .ml, .ga, .cf, .xyz, etc.)",
        "weight": 15,
        "enabled": True,
    },
    {
        "rule_id": "double_slashes_in_path",
        "name": "Double Slashes in Path",
        "description": "URL path contains '//' redirection pattern",
        "weight": 10,
        "enabled": True,
    },
    {
        "rule_id": "hex_encoded_chars",
        "name": "Hex-Encoded Characters",
        "description": "URL contains percent-encoded hex characters used to evade textual filtering",
        "weight": 15,
        "enabled": True,
    },
]


def _hash_password(plain: str) -> str:
    """Return a bcrypt hash string of plain password."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def seed_demo_data():
    """Populate database with default configuration and realistic initial demo data."""
    db = get_db()

    # 1. Detection rules
    if db.detection_rules.count_documents({}) == 0:
        db.detection_rules.insert_many(_DEFAULT_RULES)

    # 2. Default admin user
    if db.users.count_documents({}) == 0:
        db.users.insert_one({
            "username": config.ADMIN_USERNAME,
            "password": _hash_password(config.ADMIN_PASSWORD),
            "role": "admin",
            "created_at": datetime.now(timezone.utc)
        })

    # 3. Threat intelligence indicators
    if db.threat_intelligence.count_documents({}) == 0:
        now = datetime.now(timezone.utc)
        ti_indicators = [
            {
                "indicator": "192.168.1.100",
                "indicator_type": "ip",
                "type": "ip",
                "severity": "high",
                "source": "Local Security Team",
                "description": "Known internal phishing lab test host",
                "status": "active",
                "active": True,
                "added_by": "admin",
                "added_at": now - timedelta(days=25)
            },
            {
                "indicator": "secure-login.update-banking.tk",
                "indicator_type": "domain",
                "type": "domain",
                "severity": "high",
                "source": "Local Threat Intelligence",
                "description": "Reported fake banking credential-harvesting domain",
                "status": "active",
                "active": True,
                "added_by": "admin",
                "added_at": now - timedelta(days=20)
            },
            {
                "indicator": "paypal-secure.login.verify.cf",
                "indicator_type": "domain",
                "type": "domain",
                "severity": "high",
                "source": "Local Threat Intelligence",
                "description": "Impersonation domain targeting financial login portals",
                "status": "active",
                "active": True,
                "added_by": "admin",
                "added_at": now - timedelta(days=15)
            },
            {
                "indicator": "billing-update-account",
                "indicator_type": "keyword",
                "type": "keyword",
                "severity": "medium",
                "source": "Local Keyword Blocklist",
                "description": "Suspicious URI keyword pattern used in invoice phishing",
                "status": "active",
                "active": True,
                "added_by": "admin",
                "added_at": now - timedelta(days=10)
            },
            {
                "indicator": "bit.ly/malicious-payload",
                "indicator_type": "domain",
                "type": "domain",
                "severity": "medium",
                "source": "Local Threat Intelligence",
                "description": "Shortened redirector leading to fake portal",
                "status": "active",
                "active": True,
                "added_by": "admin",
                "added_at": now - timedelta(days=5)
            }
        ]
        db.threat_intelligence.insert_many(ti_indicators)

    # 4. Realistic demo scan records
    if db.scan_history.count_documents({}) == 0:
        now = datetime.now(timezone.utc)
        demo_scans = [
            # High Risk Scans
            {
                "url": "http://192.168.1.100/login/verify-account",
                "normalized_url": "http://192.168.1.100/login/verify-account",
                "risk_score": 75,
                "risk_level": "High",
                "triggered_rules": [
                    {"rule_id": "ip_address_host", "rule_name": "IP Address Host", "weight": 20, "description": "URL uses raw IP address instead of domain."},
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'login', 'verify', 'account'."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "URL uses unencrypted HTTP."},
                    {"rule_id": "local_threat_intel_match", "rule_name": "Local Threat Intelligence Hit", "weight": 40, "description": "Matched local indicator '192.168.1.100'."}
                ],
                "analysis_details": {"hostname": "192.168.1.100", "scheme": "http", "path": "/login/verify-account", "length": 42},
                "scanned_at": now - timedelta(days=1, hours=2),
                "scanned_by": "admin"
            },
            {
                "url": "http://secure-login.update-banking.tk/signin?user=admin%40bank",
                "normalized_url": "http://secure-login.update-banking.tk/signin?user=admin%40bank",
                "risk_score": 90,
                "risk_level": "High",
                "triggered_rules": [
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'secure', 'login', 'banking', 'signin'."},
                    {"rule_id": "suspicious_tld", "rule_name": "Suspicious TLD", "weight": 15, "description": "Uses suspicious TLD .tk."},
                    {"rule_id": "hex_encoded_chars", "rule_name": "Hex-Encoded Characters", "weight": 15, "description": "Contains %40 hex encoding."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "Unencrypted HTTP."},
                    {"rule_id": "local_threat_intel_match", "rule_name": "Local Threat Intelligence Hit", "weight": 40, "description": "Matched local indicator 'secure-login.update-banking.tk'."}
                ],
                "analysis_details": {"hostname": "secure-login.update-banking.tk", "scheme": "http", "path": "/signin", "length": 65},
                "scanned_at": now - timedelta(days=2, hours=4),
                "scanned_by": "admin"
            },
            {
                "url": "http://www.a.b.c.d.account-security-portal.xyz/verify/account/login",
                "normalized_url": "http://www.a.b.c.d.account-security-portal.xyz/verify/account/login",
                "risk_score": 75,
                "risk_level": "High",
                "triggered_rules": [
                    {"rule_id": "excessive_subdomains", "rule_name": "Excessive Subdomains", "weight": 15, "description": "Contains 5 subdomain labels."},
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'account', 'security', 'verify', 'login'."},
                    {"rule_id": "suspicious_tld", "rule_name": "Suspicious TLD", "weight": 15, "description": "Uses .xyz TLD."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "Unencrypted HTTP."}
                ],
                "analysis_details": {"hostname": "www.a.b.c.d.account-security-portal.xyz", "scheme": "http", "path": "/verify/account/login", "length": 76},
                "scanned_at": now - timedelta(days=3, hours=1),
                "scanned_by": "admin"
            },
            {
                "url": "https://paypal-secure.login.verify.cf/update?token=%3Cscript%3E",
                "normalized_url": "https://paypal-secure.login.verify.cf/update?token=%3Cscript%3E",
                "risk_score": 85,
                "risk_level": "High",
                "triggered_rules": [
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'secure', 'login', 'verify', 'update'."},
                    {"rule_id": "suspicious_tld", "rule_name": "Suspicious TLD", "weight": 15, "description": "Uses .cf TLD."},
                    {"rule_id": "excessive_subdomains", "rule_name": "Excessive Subdomains", "weight": 15, "description": "More than 3 subdomains."},
                    {"rule_id": "hex_encoded_chars", "rule_name": "Hex-Encoded Characters", "weight": 15, "description": "Contains hex-encoded characters."},
                    {"rule_id": "local_threat_intel_match", "rule_name": "Local Threat Intelligence Hit", "weight": 40, "description": "Matched local indicator 'paypal-secure.login.verify.cf'."}
                ],
                "analysis_details": {"hostname": "paypal-secure.login.verify.cf", "scheme": "https", "path": "/update", "length": 62},
                "scanned_at": now - timedelta(days=4, hours=6),
                "scanned_by": "admin"
            },
            {
                "url": "http://admin@login-banking-service.top/confirm-password",
                "normalized_url": "http://admin@login-banking-service.top/confirm-password",
                "risk_score": 75,
                "risk_level": "High",
                "triggered_rules": [
                    {"rule_id": "at_symbol", "rule_name": "At Symbol in URL", "weight": 20, "description": "Contains '@' symbol in authority."},
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'login', 'banking', 'confirm', 'password'."},
                    {"rule_id": "suspicious_tld", "rule_name": "Suspicious TLD", "weight": 15, "description": "Uses .top TLD."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "Unencrypted HTTP."}
                ],
                "analysis_details": {"hostname": "login-banking-service.top", "scheme": "http", "path": "/confirm-password", "length": 54},
                "scanned_at": now - timedelta(days=5, hours=3),
                "scanned_by": "admin"
            },
            # Medium Risk Scans
            {
                "url": "http://account-update-notice.com/billing",
                "normalized_url": "http://account-update-notice.com/billing",
                "risk_score": 35,
                "risk_level": "Medium",
                "triggered_rules": [
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'account', 'update'."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "Unencrypted HTTP."}
                ],
                "analysis_details": {"hostname": "account-update-notice.com", "scheme": "http", "path": "/billing", "length": 40},
                "scanned_at": now - timedelta(days=6, hours=5),
                "scanned_by": "admin"
            },
            {
                "url": "https://company-bulletin.xyz/resources/downloads",
                "normalized_url": "https://company-bulletin.xyz/resources/downloads",
                "risk_score": 40,
                "risk_level": "Medium",
                "triggered_rules": [
                    {"rule_id": "suspicious_tld", "rule_name": "Suspicious TLD", "weight": 15, "description": "Uses .xyz TLD."}
                ],
                "analysis_details": {"hostname": "company-bulletin.xyz", "scheme": "https", "path": "/resources/downloads", "length": 48},
                "scanned_at": now - timedelta(days=7, hours=2),
                "scanned_by": "admin"
            },
            {
                "url": "http://tinyurl.com/free-cloud-storage-promo",
                "normalized_url": "http://tinyurl.com/free-cloud-storage-promo",
                "risk_score": 35,
                "risk_level": "Medium",
                "triggered_rules": [
                    {"rule_id": "url_shortener", "rule_name": "URL Shortener", "weight": 15, "description": "Uses tinyurl.com link shortener."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "Unencrypted HTTP."}
                ],
                "analysis_details": {"hostname": "tinyurl.com", "scheme": "http", "path": "/free-cloud-storage-promo", "length": 42},
                "scanned_at": now - timedelta(days=8, hours=8),
                "scanned_by": "admin"
            },
            {
                "url": "https://cloud-portal-verify.club/signin",
                "normalized_url": "https://cloud-portal-verify.club/signin",
                "risk_score": 45,
                "risk_level": "Medium",
                "triggered_rules": [
                    {"rule_id": "suspicious_keywords", "rule_name": "Suspicious Keywords", "weight": 15, "description": "Contains 'verify', 'signin'."},
                    {"rule_id": "suspicious_tld", "rule_name": "Suspicious TLD", "weight": 15, "description": "Uses .club TLD."}
                ],
                "analysis_details": {"hostname": "cloud-portal-verify.club", "scheme": "https", "path": "/signin", "length": 40},
                "scanned_at": now - timedelta(days=10, hours=1),
                "scanned_by": "admin"
            },
            {
                "url": "http://service-redirect.org//portal//dashboard",
                "normalized_url": "http://service-redirect.org//portal//dashboard",
                "risk_score": 35,
                "risk_level": "Medium",
                "triggered_rules": [
                    {"rule_id": "double_slashes_in_path", "rule_name": "Double Slashes in Path", "weight": 10, "description": "Contains double slashes in path."},
                    {"rule_id": "insecure_http", "rule_name": "Insecure HTTP", "weight": 5, "description": "Unencrypted HTTP."}
                ],
                "analysis_details": {"hostname": "service-redirect.org", "scheme": "http", "path": "//portal//dashboard", "length": 45},
                "scanned_at": now - timedelta(days=12, hours=6),
                "scanned_by": "admin"
            },
            # Low Risk / Safe Scans
            {
                "url": "https://www.google.com",
                "normalized_url": "https://www.google.com/",
                "risk_score": 0,
                "risk_level": "Low",
                "triggered_rules": [],
                "analysis_details": {"hostname": "www.google.com", "scheme": "https", "path": "/", "length": 22},
                "scanned_at": now - timedelta(days=1, hours=7),
                "scanned_by": "admin"
            },
            {
                "url": "https://github.com/phishshield/pro",
                "normalized_url": "https://github.com/phishshield/pro",
                "risk_score": 0,
                "risk_level": "Low",
                "triggered_rules": [],
                "analysis_details": {"hostname": "github.com", "scheme": "https", "path": "/phishshield/pro", "length": 34},
                "scanned_at": now - timedelta(days=3, hours=5),
                "scanned_by": "admin"
            },
            {
                "url": "https://docs.python.org/3/library/urllib.parse.html",
                "normalized_url": "https://docs.python.org/3/library/urllib.parse.html",
                "risk_score": 0,
                "risk_level": "Low",
                "triggered_rules": [],
                "analysis_details": {"hostname": "docs.python.org", "scheme": "https", "path": "/3/library/urllib.parse.html", "length": 51},
                "scanned_at": now - timedelta(days=5, hours=9),
                "scanned_by": "admin"
            },
            {
                "url": "https://en.wikipedia.org/wiki/Phishing",
                "normalized_url": "https://en.wikipedia.org/wiki/Phishing",
                "risk_score": 0,
                "risk_level": "Low",
                "triggered_rules": [],
                "analysis_details": {"hostname": "en.wikipedia.org", "scheme": "https", "path": "/wiki/Phishing", "length": 38},
                "scanned_at": now - timedelta(days=7, hours=4),
                "scanned_by": "admin"
            },
            {
                "url": "https://www.mongodb.com/docs/manual/",
                "normalized_url": "https://www.mongodb.com/docs/manual/",
                "risk_score": 0,
                "risk_level": "Low",
                "triggered_rules": [],
                "analysis_details": {"hostname": "www.mongodb.com", "scheme": "https", "path": "/docs/manual/", "length": 35},
                "scanned_at": now - timedelta(days=9, hours=3),
                "scanned_by": "admin"
            },
            {
                "url": "https://flask.palletsprojects.com/en/3.0.x/",
                "normalized_url": "https://flask.palletsprojects.com/en/3.0.x/",
                "risk_score": 0,
                "risk_level": "Low",
                "triggered_rules": [],
                "analysis_details": {"hostname": "flask.palletsprojects.com", "scheme": "https", "path": "/en/3.0.x/", "length": 42},
                "scanned_at": now - timedelta(days=14, hours=2),
                "scanned_by": "admin"
            }
        ]
        insert_res = db.scan_history.insert_many(demo_scans)
        inserted_ids = insert_res.inserted_ids

        # 5. Seed corresponding security alerts for Medium and High scans
        alerts = []
        for idx, scan in enumerate(demo_scans):
            if scan["risk_level"] in ("Medium", "High"):
                alerts.append({
                    "scan_id": inserted_ids[idx],
                    "url": scan["url"],
                    "risk_score": scan["risk_score"],
                    "risk_level": scan["risk_level"],
                    "severity": scan["risk_level"],
                    "message": f"Suspicious URL detected: {scan['url']} (Risk Score: {scan['risk_score']})",
                    "status": "new" if idx % 2 == 0 else "reviewed",
                    "created_at": scan["scanned_at"],
                    "reviewed_by": "admin" if idx % 2 != 0 else None,
                    "reviewed_at": (scan["scanned_at"] + timedelta(hours=1)) if idx % 2 != 0 else None
                })
        if alerts:
            db.security_alerts.insert_many(alerts)

    # 6. Audit logs initial seed
    if db.audit_logs.count_documents({}) == 0:
        db.audit_logs.insert_one({
            "timestamp": datetime.now(timezone.utc) - timedelta(days=26),
            "user": "system",
            "action": "system_init",
            "details": "PhishShield Pro platform database initialized with detection rules and seed data."
        })
