"""
PhishShield Pro — Main Flask Application

A professional cybersecurity platform for phishing URL heuristic analysis,
risk scoring, threat intelligence management, and security analytics.
"""

from functools import wraps
from datetime import datetime, timedelta, timezone
import io
import csv
import secrets
from bson import ObjectId
import bcrypt
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response
)

import config
from services.db import get_db, init_db, seed_demo_data
from services.url_analyzer import analyze_url, normalize_url
from services.audit import log_action

# ---------------------------------------------------------------------------
# App Initialization & Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------------------------------------------------------------------
# CSRF Protection
# ---------------------------------------------------------------------------

@app.before_request
def csrf_protect():
    """Verify CSRF token for all state-changing POST requests."""
    if request.method == "POST":
        token = session.get("csrf_token")
        form_token = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
        )
        if not token or token != form_token:
            flash("Security check failed: Invalid or missing CSRF token.", "danger")
            return redirect(request.referrer or url_for("dashboard"))


def generate_csrf_token():
    """Generate or retrieve the session CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ---------------------------------------------------------------------------
# Authentication Decorator
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Authentication required. Please sign in to access PhishShield Pro.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ===========================================================================
# 1. AUTHENTICATION MODULE
# ===========================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("login.html")

        try:
            db = get_db()
            user = db.users.find_one({"username": username})

            if user:
                stored_hash = user.get("password", "")
                if isinstance(stored_hash, str):
                    stored_hash = stored_hash.encode("utf-8")

                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    session["user_id"] = str(user["_id"])
                    session["username"] = user["username"]
                    session["role"] = user.get("role", "analyst")
                    log_action(db, username, "login", {"status": "success", "ip": request.remote_addr})
                    flash(f"Welcome back, {username}! Authentication successful.", "success")
                    return redirect(url_for("dashboard"))

            # Failed login
            flash("Invalid credentials. Please verify your username and password.", "danger")
            log_action(db, username or "unknown", "failed_login", {"ip": request.remote_addr})

        except Exception as e:
            flash(f"Database error during authentication: {str(e)}", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    try:
        db = get_db()
        log_action(db, username, "logout", {"status": "success"})
    except Exception:
        pass
    session.clear()
    flash("You have successfully signed out of PhishShield Pro.", "info")
    return redirect(url_for("login"))


# ===========================================================================
# 1.5. USER MANAGEMENT MODULE
# ===========================================================================

@app.route("/users")
@login_required
def user_list():
    """List all registered users."""
    try:
        db = get_db()
        users = list(db.users.find({}, {"password": 0}).sort("created_at", -1))
        return render_template("users.html", users=users)
    except Exception as e:
        flash(f"Error loading users: {str(e)}", "danger")
        return render_template("users.html", users=[])


@app.route("/users/add", methods=["POST"])
@login_required
def add_user():
    """Create a new operator account with bcrypt password hashing."""
    if session.get("role") != "admin":
        flash("Permission denied: Only administrators can create users.", "danger")
        return redirect(url_for("user_list"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "analyst").strip().lower()

    if not username:
        flash("Username cannot be empty.", "warning")
        return redirect(url_for("user_list"))

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "warning")
        return redirect(url_for("user_list"))

    if role not in ("admin", "analyst", "auditor"):
        role = "analyst"

    try:
        db = get_db()
        existing = db.users.find_one({"username": username})
        if existing:
            flash(f"User '{username}' already exists.", "warning")
            return redirect(url_for("user_list"))

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        doc = {
            "username": username,
            "password": hashed,
            "role": role,
            "created_at": datetime.now(timezone.utc)
        }
        db.users.insert_one(doc)

        log_action(
            db,
            session.get("username", "admin"),
            "user_create",
            f"Created user '{username}' with role '{role}'"
        )
        flash(f"User '{username}' created successfully with role '{role}'.", "success")

    except Exception as e:
        flash(f"Error creating user: {str(e)}", "danger")

    return redirect(url_for("user_list"))


@app.route("/users/delete/<user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    """Delete a user account."""
    if session.get("role") != "admin":
        flash("Permission denied: Only administrators can delete users.", "danger")
        return redirect(url_for("user_list"))

    try:
        db = get_db()
        try:
            oid = ObjectId(user_id)
        except Exception:
            flash("Invalid user identifier.", "danger")
            return redirect(url_for("user_list"))

        target = db.users.find_one({"_id": oid})
        if not target:
            flash("User not found.", "warning")
            return redirect(url_for("user_list"))

        # Safety check: Cannot delete self
        if target["username"] == session.get("username"):
            flash("Action forbidden: You cannot delete your own active administrator account.", "danger")
            return redirect(url_for("user_list"))

        db.users.delete_one({"_id": oid})
        log_action(
            db,
            session.get("username", "admin"),
            "user_delete",
            f"Deleted user '{target['username']}'"
        )
        flash(f"User '{target['username']}' has been deleted.", "success")

    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "danger")

    return redirect(url_for("user_list"))


@app.route("/users/change-password/<user_id>", methods=["POST"])
@login_required
def change_password(user_id):
    """Reset or update a user's password."""
    if session.get("role") != "admin":
        flash("Permission denied: Only administrators can reset passwords.", "danger")
        return redirect(url_for("user_list"))

    new_password = request.form.get("password", "").strip()
    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "warning")
        return redirect(url_for("user_list"))

    try:
        db = get_db()
        try:
            oid = ObjectId(user_id)
        except Exception:
            flash("Invalid user identifier.", "danger")
            return redirect(url_for("user_list"))

        target = db.users.find_one({"_id": oid})
        if not target:
            flash("User not found.", "warning")
            return redirect(url_for("user_list"))

        hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db.users.update_one({"_id": oid}, {"$set": {"password": hashed}})

        log_action(
            db,
            session.get("username", "admin"),
            "user_password_change",
            f"Reset password for user '{target['username']}'"
        )
        flash(f"Password for user '{target['username']}' updated successfully.", "success")

    except Exception as e:
        flash(f"Error updating password: {str(e)}", "danger")

    return redirect(url_for("user_list"))


# ===========================================================================
# 2. DASHBOARD MODULE
# ===========================================================================

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        db = get_db()

        # Aggregate counts
        total_scans = db.scan_history.count_documents({})
        safe_count = db.scan_history.count_documents({"risk_level": "Low"})
        suspicious_count = db.scan_history.count_documents({"risk_level": "Medium"})
        high_risk_count = db.scan_history.count_documents({"risk_level": "High"})

        # Recent 5 scans
        recent_scans = list(
            db.scan_history.find()
            .sort("scanned_at", -1)
            .limit(5)
        )

        # Risk distribution for Chart.js
        risk_distribution = {
            "Low": safe_count,
            "Medium": suspicious_count,
            "High": high_risk_count,
        }

        # Daily scanning activity (past 7 days) via MongoDB aggregation
        now = datetime.now(timezone.utc)
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        seven_days_ago = today - timedelta(days=6)

        daily_pipeline = [
            {"$match": {"scanned_at": {"$gte": seven_days_ago}}},
            {"$group": {
                "_id": {
                    "$dateToString": {"format": "%Y-%m-%d", "date": "$scanned_at"}
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        daily_res = list(db.scan_history.aggregate(daily_pipeline))
        daily_map = {item["_id"]: item["count"] for item in daily_res}

        daily_labels = []
        daily_counts = []
        for i in range(7):
            day_dt = seven_days_ago + timedelta(days=i)
            day_str = day_dt.strftime("%Y-%m-%d")
            daily_labels.append(day_dt.strftime("%b %d"))
            daily_counts.append(daily_map.get(day_str, 0))

        # Recent unreviewed alerts (limit 5)
        recent_alerts = list(
            db.security_alerts.find({"status": "new"})
            .sort("created_at", -1)
            .limit(5)
        )

        return render_template(
            "dashboard.html",
            total_scans=total_scans,
            safe_count=safe_count,
            suspicious_count=suspicious_count,
            high_risk_count=high_risk_count,
            recent_scans=recent_scans,
            risk_distribution=risk_distribution,
            daily_labels=daily_labels,
            daily_counts=daily_counts,
            recent_alerts=recent_alerts,
        )

    except Exception as e:
        flash(f"Error loading dashboard security metrics: {str(e)}", "danger")
        return render_template(
            "dashboard.html",
            total_scans=0,
            safe_count=0,
            suspicious_count=0,
            high_risk_count=0,
            recent_scans=[],
            risk_distribution={"Low": 0, "Medium": 0, "High": 0},
            daily_labels=[],
            daily_counts=[],
            recent_alerts=[],
        )


# ===========================================================================
# 3. URL SCANNER MODULE
# ===========================================================================

@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        raw_url = request.form.get("url", "").strip()
        if not raw_url:
            flash("Please specify a URL to evaluate.", "warning")
            return render_template("scan.html")

        try:
            db = get_db()
            rules = list(db.detection_rules.find())
            threat_indicators = list(db.threat_intelligence.find({"status": "active"}))

            # Perform static heuristic inspection & local threat intel matching
            result = analyze_url(raw_url, rules, threat_indicators)

            scan_record = {
                "url": result["url"],
                "normalized_url": result["normalized_url"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "triggered_rules": result["triggered_rules"],
                "threat_intel_matches": result.get("threat_intel_matches", []),
                "analysis_details": result["analysis_details"],
                "disclaimer": result["disclaimer"],
                "scanned_at": datetime.now(timezone.utc),
                "scanned_by": session.get("username", "analyst"),
            }
            insert_result = db.scan_history.insert_one(scan_record)
            scan_id = insert_result.inserted_id

            # Generate security alert for Medium and High risk detections
            if result["risk_level"] in ("Medium", "High"):
                alert_doc = {
                    "scan_id": scan_id,
                    "url": result["url"],
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"],
                    "severity": result["risk_level"],
                    "message": f"Suspicious URL detected: {result['url']} (Risk Score: {result['risk_score']})",
                    "status": "new",
                    "created_at": datetime.now(timezone.utc),
                    "reviewed_by": None,
                    "reviewed_at": None,
                }
                db.security_alerts.insert_one(alert_doc)

            # Record audit event
            log_action(
                db,
                session.get("username", "analyst"),
                "scan",
                {
                    "url": result["url"],
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"]
                }
            )

            flash(
                f"URL Analysis Completed — Score: {result['risk_score']}/100 ({result['risk_level']} Risk)",
                "success" if result["risk_level"] == "Low" else "warning"
            )
            return redirect(url_for("scan_result", scan_id=str(scan_id)))

        except Exception as e:
            flash(f"Scan analysis encountered an error: {str(e)}", "danger")
            return render_template("scan.html")

    return render_template("scan.html")


@app.route("/scan/result/<scan_id>")
@app.route("/scan/<scan_id>")
@login_required
def scan_result(scan_id):
    try:
        db = get_db()
        try:
            oid = ObjectId(scan_id)
        except Exception:
            flash("Invalid scan identifier requested.", "danger")
            return redirect(url_for("history"))

        record = db.scan_history.find_one({"_id": oid})
        if not record:
            flash("Scan analysis record not found.", "warning")
            return redirect(url_for("history"))

        return render_template(
            "scan_result.html",
            scan=record,
            result=record,
            scan_record=record
        )
    except Exception as e:
        flash(f"Error retrieving scan details: {str(e)}", "danger")
        return redirect(url_for("history"))


# ===========================================================================
# 4. SCAN HISTORY MODULE
# ===========================================================================

@app.route("/history")
@login_required
def history():
    try:
        db = get_db()

        search = request.args.get("search", "").strip()
        risk_level = request.args.get("risk_level", "").strip()
        sort_param = request.args.get("sort", "newest").strip()
        page = request.args.get("page", 1, type=int)
        per_page = 15

        query = {}
        if search:
            query["url"] = {"$regex": search, "$options": "i"}
        if risk_level and risk_level != "All":
            query["risk_level"] = risk_level

        sort_map = {
            "newest": ("scanned_at", -1),
            "date_desc": ("scanned_at", -1),
            "oldest": ("scanned_at", 1),
            "date_asc": ("scanned_at", 1),
            "highest": ("risk_score", -1),
            "score_desc": ("risk_score", -1),
            "lowest": ("risk_score", 1),
            "score_asc": ("risk_score", 1),
        }
        sort_field, sort_dir = sort_map.get(sort_param, ("scanned_at", -1))

        total = db.scan_history.count_documents(query)
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))

        scans = list(
            db.scan_history.find(query)
            .sort(sort_field, sort_dir)
            .skip((page - 1) * per_page)
            .limit(per_page)
        )

        return render_template(
            "history.html",
            scans=scans,
            page=page,
            current_page=page,
            total_pages=total_pages,
            total=total,
            total_records=total,
            search=search,
            risk_level=risk_level,
            sort=sort_param,
        )
    except Exception as e:
        flash(f"Error retrieving history: {str(e)}", "danger")
        return render_template(
            "history.html",
            scans=[],
            page=1,
            current_page=1,
            total_pages=1,
            total=0,
            total_records=0,
            search="",
            risk_level="",
            sort="newest",
        )


@app.route("/history/delete/<scan_id>", methods=["POST"])
@app.route("/history/<scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    try:
        db = get_db()
        try:
            oid = ObjectId(scan_id)
        except Exception:
            flash("Invalid scan ID for deletion.", "danger")
            return redirect(url_for("history"))

        deleted = db.scan_history.find_one_and_delete({"_id": oid})
        if deleted:
            db.security_alerts.delete_many({"scan_id": oid})
            log_action(
                db,
                session.get("username", "analyst"),
                "delete",
                f"Deleted scan record {scan_id} for URL {deleted.get('url', '')[:60]}"
            )
            flash("Scan record and associated alerts deleted successfully.", "success")
        else:
            flash("Target record not found.", "warning")

    except Exception as e:
        flash(f"Error deleting scan record: {str(e)}", "danger")

    return redirect(url_for("history"))


# ===========================================================================
# 5. THREAT INTELLIGENCE MODULE
# ===========================================================================

@app.route("/threat-intelligence")
@login_required
def threat_intelligence():
    try:
        db = get_db()
        indicators = list(db.threat_intelligence.find().sort("added_at", -1))
        return render_template("threat_intelligence.html", indicators=indicators)
    except Exception as e:
        flash(f"Error loading threat intelligence repository: {str(e)}", "danger")
        return render_template("threat_intelligence.html", indicators=[])


@app.route("/threat-intelligence/add", methods=["POST"])
@login_required
def add_indicator():
    try:
        db = get_db()
        indicator = request.form.get("indicator", "").strip()
        indicator_type = (request.form.get("type") or request.form.get("indicator_type", "")).strip().lower()
        severity = request.form.get("severity", "medium").strip().lower()
        description = request.form.get("description", "").strip()

        if not indicator or not indicator_type:
            flash("Indicator value and type are required.", "warning")
            return redirect(url_for("threat_intelligence"))

        if indicator_type not in ("domain", "ip", "keyword"):
            flash("Indicator type must be 'domain', 'ip', or 'keyword'.", "danger")
            return redirect(url_for("threat_intelligence"))

        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"

        # Check for duplicate
        existing = db.threat_intelligence.find_one({"indicator": indicator})
        if existing:
            flash(f"Indicator '{indicator}' is already cataloged in the repository.", "warning")
            return redirect(url_for("threat_intelligence"))

        doc = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "type": indicator_type,
            "severity": severity,
            "description": description or "User-maintained threat indicator",
            "source": "Local Threat Repository (User-Maintained)",
            "added_by": session.get("username", "analyst"),
            "added_at": datetime.now(timezone.utc),
            "status": "active",
            "active": True
        }
        db.threat_intelligence.insert_one(doc)

        log_action(
            db,
            session.get("username", "analyst"),
            "threat_intel_add",
            f"Added {indicator_type} indicator '{indicator}' ({severity} severity)"
        )
        flash(f"Indicator '{indicator}' successfully added to local threat repository.", "success")

    except Exception as e:
        flash(f"Error creating threat indicator: {str(e)}", "danger")

    return redirect(url_for("threat_intelligence"))


@app.route("/threat-intelligence/edit/<indicator_id>", methods=["POST"])
@app.route("/threat-intelligence/edit/<id>", methods=["POST"])
@login_required
def edit_indicator(indicator_id=None, id=None):
    target_id = indicator_id or id
    try:
        db = get_db()
        try:
            oid = ObjectId(target_id)
        except Exception:
            flash("Invalid indicator identifier.", "danger")
            return redirect(url_for("threat_intelligence"))

        indicator = request.form.get("indicator", "").strip()
        indicator_type = (request.form.get("type") or request.form.get("indicator_type", "")).strip().lower()
        severity = request.form.get("severity", "medium").strip().lower()
        description = request.form.get("description", "").strip()

        if not indicator or not indicator_type:
            flash("Indicator and type are required fields.", "warning")
            return redirect(url_for("threat_intelligence"))

        update_doc = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "type": indicator_type,
            "severity": severity,
            "description": description,
        }
        db.threat_intelligence.update_one({"_id": oid}, {"$set": update_doc})

        log_action(
            db,
            session.get("username", "analyst"),
            "threat_intel_edit",
            f"Updated threat indicator '{indicator}'"
        )
        flash("Threat indicator successfully updated.", "success")

    except Exception as e:
        flash(f"Error updating indicator: {str(e)}", "danger")

    return redirect(url_for("threat_intelligence"))


@app.route("/threat-intelligence/delete/<indicator_id>", methods=["POST"])
@app.route("/threat-intelligence/delete/<id>", methods=["POST"])
@login_required
def delete_indicator(indicator_id=None, id=None):
    target_id = indicator_id or id
    try:
        db = get_db()
        try:
            oid = ObjectId(target_id)
        except Exception:
            flash("Invalid indicator identifier.", "danger")
            return redirect(url_for("threat_intelligence"))

        del_res = db.threat_intelligence.find_one_and_delete({"_id": oid})
        if del_res:
            log_action(
                db,
                session.get("username", "analyst"),
                "threat_intel_delete",
                f"Deleted indicator '{del_res.get('indicator', '')}'"
            )
            flash("Indicator removed from threat intelligence repository.", "success")
        else:
            flash("Indicator not found.", "warning")

    except Exception as e:
        flash(f"Error deleting indicator: {str(e)}", "danger")

    return redirect(url_for("threat_intelligence"))


# ===========================================================================
# 6. SECURITY ALERTS MODULE
# ===========================================================================

@app.route("/alerts")
@login_required
def alerts():
    try:
        db = get_db()
        status_filter = request.args.get("status", "").strip()

        query = {}
        if status_filter and status_filter != "all":
            query["status"] = status_filter

        alert_list = list(db.security_alerts.find(query).sort("created_at", -1))
        return render_template("alerts.html", alerts=alert_list, status=status_filter)
    except Exception as e:
        flash(f"Error loading security alerts: {str(e)}", "danger")
        return render_template("alerts.html", alerts=[], status="")


@app.route("/alerts/review/<alert_id>", methods=["POST"])
@login_required
def review_alert(alert_id):
    try:
        db = get_db()
        try:
            oid = ObjectId(alert_id)
        except Exception:
            flash("Invalid alert identifier.", "danger")
            return redirect(url_for("alerts"))

        res = db.security_alerts.update_one(
            {"_id": oid},
            {"$set": {
                "status": "reviewed",
                "reviewed_by": session.get("username", "analyst"),
                "reviewed_at": datetime.now(timezone.utc)
            }}
        )
        if res.modified_count > 0:
            log_action(
                db,
                session.get("username", "analyst"),
                "alert_review",
                f"Marked alert {alert_id} as reviewed"
            )
            flash("Security alert status updated to Reviewed.", "success")
        else:
            flash("Alert already reviewed or not found.", "info")

    except Exception as e:
        flash(f"Error processing alert review: {str(e)}", "danger")

    return redirect(url_for("alerts"))


# Register alias for url_for('mark_alert_reviewed')
app.add_url_rule(
    "/alerts/review/<alert_id>",
    endpoint="mark_alert_reviewed",
    view_func=review_alert,
    methods=["POST"]
)


# ===========================================================================
# 7. ANALYTICS MODULE (MongoDB Aggregation Pipelines)
# ===========================================================================

@app.route("/analytics")
@login_required
def analytics():
    try:
        db = get_db()

        # Date range filtering
        date_from_str = request.args.get("date_from", "").strip()
        date_to_str = request.args.get("date_to", "").strip()

        date_match = {}
        if date_from_str:
            try:
                date_match["$gte"] = datetime.strptime(date_from_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if date_to_str:
            try:
                date_match["$lte"] = (
                    datetime.strptime(date_to_str, "%Y-%m-%d") + timedelta(days=1)
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        base_match = {}
        if date_match:
            base_match["scanned_at"] = date_match

        # 1. Total Scans & Average Risk Score
        summary_pipeline = [
            {"$match": base_match} if base_match else {"$match": {}},
            {"$group": {
                "_id": None,
                "total": {"$sum": 1},
                "avg_score": {"$avg": "$risk_score"},
                "high_count": {
                    "$sum": {"$cond": [{"$eq": ["$risk_level", "High"]}, 1, 0]}
                }
            }}
        ]
        summary_raw = list(db.scan_history.aggregate(summary_pipeline))
        total_scans = summary_raw[0]["total"] if summary_raw else 0
        avg_risk_score = round(summary_raw[0]["avg_score"], 1) if summary_raw and summary_raw[0]["avg_score"] is not None else 0.0
        high_risk_scans = summary_raw[0]["high_count"] if summary_raw else 0
        high_risk_percentage = round((high_risk_scans / total_scans * 100), 1) if total_scans > 0 else 0.0

        # Total alerts count
        total_alerts = db.security_alerts.count_documents({})

        # 2. Risk Level Distribution (Low, Medium, High)
        risk_pipeline = [
            {"$match": base_match} if base_match else {"$match": {}},
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]
        risk_dist_raw = list(db.scan_history.aggregate(risk_pipeline))
        risk_distribution = {"Low": 0, "Medium": 0, "High": 0}
        for item in risk_dist_raw:
            if item["_id"] in risk_distribution:
                risk_distribution[item["_id"]] = item["count"]

        # 3. Daily Scanning Trend (Last 30 Days)
        now = datetime.now(timezone.utc)
        thirty_days_ago = (now - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
        daily_match = {"scanned_at": {"$gte": thirty_days_ago}}
        if base_match:
            daily_match = base_match

        daily_pipeline = [
            {"$match": daily_match},
            {"$group": {
                "_id": {
                    "$dateToString": {"format": "%Y-%m-%d", "date": "$scanned_at"}
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        daily_raw = list(db.scan_history.aggregate(daily_pipeline))
        daily_map = {d["_id"]: d["count"] for d in daily_raw}

        daily_trend_labels = []
        daily_trend_counts = []
        for i in range(30):
            day_dt = thirty_days_ago + timedelta(days=i)
            day_key = day_dt.strftime("%Y-%m-%d")
            daily_trend_labels.append(day_dt.strftime("%b %d"))
            daily_trend_counts.append(daily_map.get(day_key, 0))

        # 4. Top 10 Triggered Detection Rules
        rules_pipeline = [
            {"$match": base_match} if base_match else {"$match": {}},
            {"$unwind": "$triggered_rules"},
            {"$group": {
                "_id": "$triggered_rules.rule_name",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_rules_raw = list(db.scan_history.aggregate(rules_pipeline))
        top_rules_labels = [r["_id"] for r in top_rules_raw]
        top_rules_counts = [r["count"] for r in top_rules_raw]

        # 5. Scans by Hour of Day (0 to 23)
        hour_pipeline = [
            {"$match": base_match} if base_match else {"$match": {}},
            {"$group": {
                "_id": {"$hour": "$scanned_at"},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        hour_raw = list(db.scan_history.aggregate(hour_pipeline))
        hour_map = {d["_id"]: d["count"] for d in hour_raw}
        hourly_labels = [f"{h:02d}:00" for h in range(24)]
        hourly_counts = [hour_map.get(h, 0) for h in range(24)]

        return render_template(
            "analytics.html",
            total_scans=total_scans,
            avg_risk_score=avg_risk_score,
            high_risk_percentage=high_risk_percentage,
            total_alerts=total_alerts,
            risk_distribution=risk_distribution,
            daily_trend_labels=daily_trend_labels,
            daily_trend_counts=daily_trend_counts,
            daily_labels=daily_trend_labels,
            daily_counts=daily_trend_counts,
            top_rules=top_rules_raw,
            top_rules_labels=top_rules_labels,
            top_rules_counts=top_rules_counts,
            hourly_labels=hourly_labels,
            hourly_counts=hourly_counts,
            date_from=date_from_str,
            date_to=date_to_str,
        )

    except Exception as e:
        flash(f"Error computing analytics aggregation: {str(e)}", "danger")
        return render_template(
            "analytics.html",
            total_scans=0,
            avg_risk_score=0.0,
            high_risk_percentage=0.0,
            total_alerts=0,
            risk_distribution={"Low": 0, "Medium": 0, "High": 0},
            daily_trend_labels=[],
            daily_trend_counts=[],
            daily_labels=[],
            daily_counts=[],
            top_rules=[],
            top_rules_labels=[],
            top_rules_counts=[],
            hourly_labels=[f"{h:02d}:00" for h in range(24)],
            hourly_counts=[0] * 24,
            date_from="",
            date_to="",
        )


# ===========================================================================
# 8. REPORTS & CSV EXPORT MODULE
# ===========================================================================

@app.route("/reports")
@login_required
def reports():
    try:
        db = get_db()
        total_scans = db.scan_history.count_documents({})
        safe_count = db.scan_history.count_documents({"risk_level": "Low"})
        suspicious_count = db.scan_history.count_documents({"risk_level": "Medium"})
        high_risk_count = db.scan_history.count_documents({"risk_level": "High"})

        # Get date range of scans
        oldest_scan = db.scan_history.find_one(sort=[("scanned_at", 1)])
        newest_scan = db.scan_history.find_one(sort=[("scanned_at", -1)])
        date_range = "No scans recorded"
        if oldest_scan and newest_scan:
            o_date = oldest_scan.get("scanned_at")
            n_date = newest_scan.get("scanned_at")
            if o_date and n_date:
                date_range = f"{o_date.strftime('%b %d, %Y')} – {n_date.strftime('%b %d, %Y')}"

        return render_template(
            "reports.html",
            total_scans=total_scans,
            safe_count=safe_count,
            suspicious_count=suspicious_count,
            high_risk_count=high_risk_count,
            date_range=date_range,
        )
    except Exception as e:
        flash(f"Error preparing report summaries: {str(e)}", "danger")
        return render_template(
            "reports.html",
            total_scans=0,
            safe_count=0,
            suspicious_count=0,
            high_risk_count=0,
            date_range="N/A",
        )


@app.route("/reports/export/csv")
@login_required
def export_csv():
    try:
        db = get_db()
        scans = list(db.scan_history.find().sort("scanned_at", -1))

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Scan ID", "URL", "Normalized URL", "Risk Score", "Risk Level",
            "Triggered Rules", "Scanned At (UTC)", "Scanned By"
        ])

        for s in scans:
            rules_str = "; ".join([
                r.get("rule_name") or r.get("rule_id", "")
                for r in s.get("triggered_rules", [])
            ])
            scanned_at_str = s.get("scanned_at", "").isoformat() if hasattr(s.get("scanned_at"), "isoformat") else str(s.get("scanned_at", ""))
            writer.writerow([
                str(s.get("_id", "")),
                s.get("url", ""),
                s.get("normalized_url", ""),
                s.get("risk_score", 0),
                s.get("risk_level", "Low"),
                rules_str,
                scanned_at_str,
                s.get("scanned_by", "analyst")
            ])

        csv_content = output.getvalue()
        log_action(db, session.get("username", "analyst"), "export_csv", f"Exported {len(scans)} scan records")

        filename = f"phishshield_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "text/csv; charset=utf-8"
            }
        )

    except Exception as e:
        flash(f"Error generating CSV export: {str(e)}", "danger")
        return redirect(url_for("reports"))


# ===========================================================================
# 9. SETTINGS MODULE (Detection Rule Weights)
# ===========================================================================

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    try:
        db = get_db()

        if request.method == "POST":
            rules = list(db.detection_rules.find())
            errors = []
            updates_count = 0

            # Support both loop index and rule_id parameter schemas
            rule_count = request.form.get("rule_count", type=int)

            if rule_count is not None:
                for idx in range(rule_count):
                    rid = request.form.get(f"rule_id_{idx}")
                    w_val = request.form.get(f"weight_{idx}")
                    enabled_val = request.form.get(f"enabled_{idx}")
                    if rid and w_val is not None:
                        try:
                            weight = int(w_val)
                            if 0 <= weight <= 100:
                                db.detection_rules.update_one(
                                    {"rule_id": rid},
                                    {"$set": {"weight": weight, "enabled": bool(enabled_val)}}
                                )
                                updates_count += 1
                            else:
                                errors.append(f"Weight for '{rid}' must be between 0 and 100.")
                        except ValueError:
                            errors.append(f"Invalid integer weight for '{rid}'.")
            else:
                for rule in rules:
                    rid = rule["rule_id"]
                    w_val = request.form.get(f"weight_{rid}")
                    enabled_val = request.form.get(f"enabled_{rid}")
                    if w_val is not None:
                        try:
                            weight = int(w_val)
                            if 0 <= weight <= 100:
                                db.detection_rules.update_one(
                                    {"_id": rule["_id"]},
                                    {"$set": {"weight": weight, "enabled": enabled_val == "on" or enabled_val == "1"}}
                                )
                                updates_count += 1
                            else:
                                errors.append(f"Weight for '{rid}' must be between 0 and 100.")
                        except ValueError:
                            errors.append(f"Invalid integer weight for '{rid}'.")

            if errors:
                for err in errors:
                    flash(err, "danger")
            else:
                log_action(
                    db,
                    session.get("username", "analyst"),
                    "settings",
                    f"Configured weights for {updates_count} detection rules"
                )
                flash("Heuristic detection rule weights updated successfully.", "success")

            return redirect(url_for("settings"))

        rules = list(db.detection_rules.find().sort("name", 1))
        # Ensure rule_name is populated if name exists
        for r in rules:
            if "rule_name" not in r:
                r["rule_name"] = r.get("name", r.get("rule_id", ""))

        return render_template("settings.html", rules=rules)

    except Exception as e:
        flash(f"Error loading system settings: {str(e)}", "danger")
        return render_template("settings.html", rules=[])


# ===========================================================================
# 10. AUDIT LOGS MODULE
# ===========================================================================

@app.route("/audit-logs")
@login_required
def audit_logs():
    try:
        db = get_db()
        page = request.args.get("page", 1, type=int)
        per_page = 20

        total = db.audit_logs.count_documents({})
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))

        logs = list(
            db.audit_logs.find()
            .sort("timestamp", -1)
            .skip((page - 1) * per_page)
            .limit(per_page)
        )

        return render_template(
            "audit_logs.html",
            logs=logs,
            page=page,
            total_pages=total_pages,
            total=total,
            has_next=(page < total_pages)
        )

    except Exception as e:
        flash(f"Error retrieving audit trail: {str(e)}", "danger")
        return render_template(
            "audit_logs.html",
            logs=[],
            page=1,
            total_pages=1,
            total=0,
            has_next=False
        )


# ===========================================================================
# 11. API ENDPOINT — DASHBOARD LIVE METRICS
# ===========================================================================

@app.route("/api/dashboard-stats")
@login_required
def api_dashboard_stats():
    try:
        db = get_db()
        total_scans = db.scan_history.count_documents({})
        safe_count = db.scan_history.count_documents({"risk_level": "Low"})
        suspicious_count = db.scan_history.count_documents({"risk_level": "Medium"})
        high_risk_count = db.scan_history.count_documents({"risk_level": "High"})
        unreviewed_alerts = db.security_alerts.count_documents({"status": "new"})

        return jsonify({
            "status": "success",
            "total_scans": total_scans,
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "high_risk_count": high_risk_count,
            "unreviewed_alerts": unreviewed_alerts,
            "risk_distribution": {
                "Low": safe_count,
                "Medium": suspicious_count,
                "High": high_risk_count,
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/system-diagnostics")
@login_required
def api_system_diagnostics():
    """Live system diagnostics for the Admin command options."""
    import time
    import platform
    try:
        db = get_db()
        t0 = time.time()
        ping_res = db.command("ping")
        latency = round((time.time() - t0) * 1000, 2)

        total_scans = db.scan_history.count_documents({})
        total_users = db.users.count_documents({})
        total_ti = db.threat_intelligence.count_documents({})
        total_alerts = db.security_alerts.count_documents({})
        total_rules = db.detection_rules.count_documents({})
        active_rules = db.detection_rules.count_documents({"enabled": True})
        total_logs = db.audit_logs.count_documents({})

        return jsonify({
            "status": "healthy",
            "db_connected": ping_res.get("ok") == 1.0,
            "ping_latency_ms": latency,
            "database": config.MONGODB_DB,
            "server_uri": config.MONGODB_URI,
            "engine": "PhishShield Heuristic Analyzer v2.4",
            "execution_mode": "Zero-Execution Static Parser (SSRF-Protected)",
            "python_version": platform.python_version(),
            "os": platform.platform(),
            "counts": {
                "users": total_users,
                "scans": total_scans,
                "threat_indicators": total_ti,
                "alerts": total_alerts,
                "detection_rules": total_rules,
                "active_rules": active_rules,
                "audit_logs": total_logs,
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Application Initialization Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    seed_demo_data()
    app.run(host="0.0.0.0", port=5000, debug=True)
