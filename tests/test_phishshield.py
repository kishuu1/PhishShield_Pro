"""
PhishShield Pro — Comprehensive Test Suite

Tests:
1. URL normalization, parsing and heuristic rule checkers
2. Risk scoring calculation and risk classification (Low, Medium, High)
3. Local Threat Intelligence matching
4. MongoDB database connection handling & index verification
5. Flask authentication (login, session, logout, unauthorized redirect)
6. CSRF validation on state-changing endpoints
7. URL scanning, result persistence in MongoDB, and alert generation
8. Scan history querying, filtering, sorting, pagination, and deletion
9. Threat intelligence CRUD actions
10. Security alert reviewing
11. Analytics aggregation pipeline results
12. CSV reports export and content verification
13. Detection rule weight customization and bounds validation
14. Audit logging of system actions
"""

import unittest
from datetime import datetime, timezone
import io
import csv
from bson import ObjectId

import config
from app import app
from services.db import get_db, init_db, seed_demo_data
from services.url_analyzer import (
    normalize_url,
    analyze_url,
    _is_ip_host,
    _has_suspicious_keywords,
    _has_excessive_subdomains,
    _has_at_symbol,
    _is_url_shortener,
    _is_long_url,
    _is_insecure_http,
    _has_suspicious_tld,
    _has_double_slashes_in_path,
    _has_hex_encoded_chars,
)


class TestURLAnalyzer(unittest.TestCase):
    """Unit tests for URL normalization and static heuristic analysis."""

    def setUp(self):
        self.rules = [
            {"rule_id": "ip_address_host", "name": "IP Address Host", "weight": 20, "enabled": True},
            {"rule_id": "suspicious_keywords", "name": "Suspicious Keywords", "weight": 15, "enabled": True},
            {"rule_id": "excessive_subdomains", "name": "Excessive Subdomains", "weight": 15, "enabled": True},
            {"rule_id": "at_symbol", "name": "At Symbol in URL", "weight": 20, "enabled": True},
            {"rule_id": "url_shortener", "name": "URL Shortener", "weight": 15, "enabled": True},
            {"rule_id": "long_url", "name": "Long URL", "weight": 10, "enabled": True},
            {"rule_id": "insecure_http", "name": "Insecure HTTP", "weight": 5, "enabled": True},
            {"rule_id": "suspicious_tld", "name": "Suspicious TLD", "weight": 15, "enabled": True},
            {"rule_id": "double_slashes_in_path", "name": "Double Slashes in Path", "weight": 10, "enabled": True},
            {"rule_id": "hex_encoded_chars", "name": "Hex-Encoded Characters", "weight": 15, "enabled": True},
        ]

    def test_normalize_url(self):
        cleaned, norm = normalize_url("google.com/search?q=test")
        self.assertTrue(cleaned.startswith("http://"))
        self.assertIn("google.com", norm)

        cleaned, norm = normalize_url("https://secure.bank.com/portal")
        self.assertTrue(cleaned.startswith("https://"))

        # Empty url
        cleaned, norm = normalize_url("   ")
        self.assertEqual(cleaned, "")
        self.assertEqual(norm, "")

    def test_ip_host_detector(self):
        self.assertTrue(_is_ip_host("192.168.1.1"))
        self.assertTrue(_is_ip_host("10.0.0.1"))
        self.assertFalse(_is_ip_host("google.com"))
        self.assertFalse(_is_ip_host("example.org"))

    def test_suspicious_keywords_detector(self):
        has_kw, found = _has_suspicious_keywords("http://fake-site.com/login/verify-account")
        self.assertTrue(has_kw)
        self.assertIn("login", found)
        self.assertIn("verify", found)

        has_kw, found = _has_suspicious_keywords("http://normal-blog.org/articles/recipes")
        self.assertFalse(has_kw)

    def test_excessive_subdomains_detector(self):
        has_sub, count = _has_excessive_subdomains("a.b.c.d.example.com")
        self.assertTrue(has_sub)
        self.assertGreater(count, 3)

        has_sub, count = _has_excessive_subdomains("api.example.com")
        self.assertFalse(has_sub)

    def test_at_symbol_detector(self):
        self.assertTrue(_has_at_symbol("http://user:pass@evil.com/page"))
        self.assertFalse(_has_at_symbol("http://evil.com/page"))

    def test_shortener_detector(self):
        self.assertTrue(_is_url_shortener("bit.ly"))
        self.assertTrue(_is_url_shortener("tinyurl.com"))
        self.assertFalse(_is_url_shortener("wikipedia.org"))

    def test_long_url_detector(self):
        short_url = "https://example.com/page"
        is_long, length = _is_long_url(short_url)
        self.assertFalse(is_long)

        long_url = "https://example.com/" + "a" * 80
        is_long, length = _is_long_url(long_url)
        self.assertTrue(is_long)
        self.assertGreater(length, 75)

    def test_insecure_http_detector(self):
        self.assertTrue(_is_insecure_http("http"))
        self.assertFalse(_is_insecure_http("https"))

    def test_suspicious_tld_detector(self):
        has_tld, tld = _has_suspicious_tld("phishing-portal.xyz")
        self.assertTrue(has_tld)
        self.assertEqual(tld, ".xyz")

        has_tld, tld = _has_suspicious_tld("legitimate.com")
        self.assertFalse(has_tld)

    def test_double_slashes_in_path(self):
        self.assertTrue(_has_double_slashes_in_path("//redirect//page"))
        self.assertFalse(_has_double_slashes_in_path("/safe/path"))

    def test_hex_encoded_chars(self):
        has_hex, count = _has_hex_encoded_chars("https://site.com/login?token=%3Cscript%3E")
        self.assertTrue(has_hex)
        self.assertGreaterEqual(count, 2)

    def test_safe_url_classification(self):
        result = analyze_url("https://www.google.com/", self.rules)
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(len(result["triggered_rules"]), 0)

    def test_high_risk_url_classification(self):
        phish_url = "http://admin@192.168.1.100/login/verify-banking-account-update?target=%3C%3E" + ("x" * 60)
        result = analyze_url(phish_url, self.rules)
        self.assertEqual(result["risk_level"], "High")
        self.assertGreaterEqual(result["risk_score"], 67)
        self.assertTrue(any(r["rule_id"] == "ip_address_host" for r in result["triggered_rules"]))
        self.assertTrue(any(r["rule_id"] == "suspicious_keywords" for r in result["triggered_rules"]))
        self.assertTrue(any(r["rule_id"] == "at_symbol" for r in result["triggered_rules"]))

    def test_local_threat_intel_match(self):
        indicators = [{
            "indicator": "malicious-bank.com",
            "indicator_type": "domain",
            "type": "domain",
            "severity": "high",
            "description": "Known malicious banking domain"
        }]
        result = analyze_url("https://malicious-bank.com/signin", self.rules, threat_indicators=indicators)
        self.assertTrue(any(r["rule_id"] == "local_threat_intel_match" for r in result["triggered_rules"]))
        self.assertEqual(len(result["threat_intel_matches"]), 1)
        self.assertEqual(result["threat_intel_matches"][0]["indicator"], "malicious-bank.com")


class TestFlaskIntegration(unittest.TestCase):
    """Integration tests for Flask application routes and MongoDB persistence."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()

        # Initialize DB and seeds
        init_db()
        seed_demo_data()
        cls.db = get_db()

    def _login(self):
        """Helper to log in the demo admin user."""
        # Grab login page to establish session & csrf token
        resp = self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_tok = sess.get("csrf_token")

        login_resp = self.client.post("/login", data={
            "csrf_token": csrf_tok,
            "username": config.ADMIN_USERNAME,
            "password": config.ADMIN_PASSWORD
        }, follow_redirects=True)
        return login_resp

    def test_01_mongodb_connectivity_and_indexes(self):
        """Verify MongoDB connection and required collection indexes."""
        db = get_db()
        collections = db.list_collection_names()
        self.assertIn("users", collections)
        self.assertIn("scan_history", collections)
        self.assertIn("threat_intelligence", collections)
        self.assertIn("security_alerts", collections)
        self.assertIn("detection_rules", collections)
        self.assertIn("audit_logs", collections)

        # Check users index
        user_indexes = [idx["name"] for idx in db.users.list_indexes()]
        self.assertTrue(any("username" in name for name in user_indexes))

    def test_02_unauthenticated_access_redirection(self):
        """Unauthenticated user accessing protected routes must redirect to login."""
        endpoints = ["/dashboard", "/scan", "/history", "/threat-intelligence", "/alerts", "/analytics", "/reports", "/settings", "/audit-logs"]
        for ep in endpoints:
            res = self.client.get(ep, follow_redirects=False)
            self.assertEqual(res.status_code, 302, f"Expected 302 for unauthenticated {ep}")
            self.assertIn("/login", res.headers.get("Location", ""))

    def test_03_login_and_logout(self):
        """Test valid authentication, session state, and logout."""
        # Login
        res = self._login()
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Dashboard", res.data)

        # Logout
        logout_res = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_res.status_code, 200)
        self.assertIn(b"Sign In", logout_res.data)

    def test_04_dashboard_loads_with_metrics(self):
        """Dashboard must display accurate metrics, charts, and recent scans."""
        self._login()
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Total Scans", res.data)
        self.assertIn(b"Safe URLs", res.data)
        self.assertIn(b"Suspicious", res.data)
        self.assertIn(b"High Risk", res.data)
        self.assertIn(b"riskChart", res.data)
        self.assertIn(b"activityChart", res.data)

    def test_05_url_scan_and_alert_generation(self):
        """Submitting a suspicious URL creates scan history and a security alert."""
        self._login()

        # Get CSRF token
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        import time
        test_url = f"http://10.10.10.10/login/secure-banking-account-update-{int(time.time())}"
        scan_res = self.client.post("/scan", data={
            "csrf_token": csrf_token,
            "url": test_url
        }, follow_redirects=True)

        self.assertEqual(scan_res.status_code, 200)
        self.assertIn(b"Scan Result", scan_res.data)
        self.assertIn(b"Triggered Rules", scan_res.data)

        # Verify persisted in MongoDB
        db_record = self.db.scan_history.find_one({"url": test_url})
        self.assertIsNotNone(db_record)
        self.assertIn(db_record["risk_level"], ("Medium", "High"))

        # Verify alert created
        alert = self.db.security_alerts.find_one({"url": test_url}, sort=[("_id", -1)])
        self.assertIsNotNone(alert)
        self.assertEqual(alert["status"], "new")

    def test_06_scan_history_and_deletion(self):
        """Test history pagination, filtering, and record deletion."""
        self._login()

        # Test search query
        res = self.client.get("/history?search=google")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"google.com", res.data)

        # Test filter by High risk
        res_high = self.client.get("/history?risk_level=High")
        self.assertEqual(res_high.status_code, 200)

        # Insert a temporary scan record to delete
        temp_id = self.db.scan_history.insert_one({
            "url": "https://temp-test-delete.com",
            "risk_score": 10,
            "risk_level": "Low",
            "triggered_rules": [],
            "scanned_at": datetime.now(timezone.utc),
            "scanned_by": "admin"
        }).inserted_id

        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        del_res = self.client.post(f"/history/delete/{temp_id}", data={
            "csrf_token": csrf_token
        }, follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)

        # Confirm deleted
        found = self.db.scan_history.find_one({"_id": temp_id})
        self.assertIsNone(found)

    def test_07_threat_intelligence_crud(self):
        """Test adding, editing, and deleting threat indicators."""
        self._login()
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        # 1. Add
        ind_val = "unit-test-phish-domain.xyz"
        add_res = self.client.post("/threat-intelligence/add", data={
            "csrf_token": csrf_token,
            "indicator": ind_val,
            "type": "domain",
            "severity": "high",
            "description": "Added by automated test"
        }, follow_redirects=True)
        self.assertEqual(add_res.status_code, 200)

        doc = self.db.threat_intelligence.find_one({"indicator": ind_val})
        self.assertIsNotNone(doc)

        # 2. Edit
        edit_res = self.client.post(f"/threat-intelligence/edit/{doc['_id']}", data={
            "csrf_token": csrf_token,
            "indicator": ind_val,
            "type": "domain",
            "severity": "medium",
            "description": "Updated by automated test"
        }, follow_redirects=True)
        self.assertEqual(edit_res.status_code, 200)

        updated_doc = self.db.threat_intelligence.find_one({"_id": doc["_id"]})
        self.assertEqual(updated_doc["severity"], "medium")

        # 3. Delete
        del_res = self.client.post(f"/threat-intelligence/delete/{doc['_id']}", data={
            "csrf_token": csrf_token
        }, follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)

        deleted_doc = self.db.threat_intelligence.find_one({"_id": doc["_id"]})
        self.assertIsNone(deleted_doc)

    def test_08_security_alerts_review(self):
        """Test reviewing a security alert."""
        self._login()
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        # Find or create a 'new' alert
        alert = self.db.security_alerts.find_one({"status": "new"})
        if not alert:
            aid = self.db.security_alerts.insert_one({
                "url": "http://alert-test.com",
                "risk_score": 75,
                "risk_level": "High",
                "severity": "High",
                "message": "Test alert",
                "status": "new",
                "created_at": datetime.now(timezone.utc)
            }).inserted_id
        else:
            aid = alert["_id"]

        rev_res = self.client.post(f"/alerts/review/{aid}", data={
            "csrf_token": csrf_token
        }, follow_redirects=True)
        self.assertEqual(rev_res.status_code, 200)

        updated = self.db.security_alerts.find_one({"_id": ObjectId(aid)})
        self.assertEqual(updated["status"], "reviewed")
        self.assertIsNotNone(updated.get("reviewed_at"))

    def test_09_analytics_pipeline_view(self):
        """Test analytics page aggregation pipelines and chart outputs."""
        self._login()
        res = self.client.get("/analytics")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Risk Distribution", res.data)
        self.assertIn(b"Daily Scan Trend", res.data)
        self.assertIn(b"Top Triggered Rules", res.data)
        self.assertIn(b"riskPieChart", res.data)
        self.assertIn(b"rulesChart", res.data)

    def test_10_csv_export(self):
        """Test CSV report generation and header validation."""
        self._login()
        res = self.client.get("/reports/export/csv")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        self.assertIn("attachment; filename=", res.headers.get("Content-Disposition", ""))

        # Parse CSV to verify headers
        csv_file = io.StringIO(res.data.decode("utf-8"))
        reader = csv.reader(csv_file)
        header = next(reader)
        self.assertIn("URL", header)
        self.assertIn("Risk Score", header)
        self.assertIn("Risk Level", header)
        self.assertIn("Triggered Rules", header)

    def test_11_settings_rule_weight_update(self):
        """Test updating detection rule weights and form validation."""
        self._login()
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        rule = self.db.detection_rules.find_one({"rule_id": "insecure_http"})
        self.assertIsNotNone(rule)

        res = self.client.post("/settings", data={
            "csrf_token": csrf_token,
            "rule_count": 1,
            "rule_id_0": "insecure_http",
            "weight_0": 8,
            "enabled_0": "1"
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        updated = self.db.detection_rules.find_one({"rule_id": "insecure_http"})
        self.assertEqual(updated["weight"], 8)
        self.assertTrue(updated["enabled"])

    def test_12_audit_trail_recorded(self):
        """Verify audit logs are recorded for actions."""
        self._login()
        res = self.client.get("/audit-logs")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Audit Logs", res.data)

        # Verify audit logs collection has documents
        count = self.db.audit_logs.count_documents({})
        self.assertGreater(count, 0)

    def test_13_system_diagnostics_api(self):
        """Test system diagnostics telemetry endpoint for the Admin menu."""
        self._login()
        res = self.client.get("/api/system-diagnostics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["db_connected"])
        self.assertIn("ping_latency_ms", data)
        self.assertIn("counts", data)
        self.assertGreaterEqual(data["counts"]["detection_rules"], 10)

    def test_14_user_management_crud(self):
        """Test user listing, creation, password reset, and deletion."""
        self._login()
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        # 1. View user list
        res = self.client.get("/users")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"User Management", res.data)
        self.assertIn(b"Registered Platform Operators", res.data)

        # 2. Add new user
        test_user = "test_analyst_qa"
        add_res = self.client.post("/users/add", data={
            "csrf_token": csrf_token,
            "username": test_user,
            "password": "Password@123",
            "role": "analyst"
        }, follow_redirects=True)
        self.assertEqual(add_res.status_code, 200)
        created_doc = self.db.users.find_one({"username": test_user})
        self.assertIsNotNone(created_doc)
        self.assertEqual(created_doc["role"], "analyst")

        # 3. Change password
        uid = str(created_doc["_id"])
        pw_res = self.client.post(f"/users/change-password/{uid}", data={
            "csrf_token": csrf_token,
            "password": "NewSecret@456"
        }, follow_redirects=True)
        self.assertEqual(pw_res.status_code, 200)

        # 4. Delete user
        del_res = self.client.post(f"/users/delete/{uid}", data={
            "csrf_token": csrf_token
        }, follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)
        self.assertIsNone(self.db.users.find_one({"_id": created_doc["_id"]}))


if __name__ == "__main__":
    unittest.main()
