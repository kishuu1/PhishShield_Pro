# PhishShield Pro — Phishing URL Analysis & Threat Intelligence Platform

PhishShield Pro is an enterprise-grade, explainable cybersecurity web application designed to evaluate suspicious URLs through multi-vector static heuristic analysis, calculate real-time bounded risk scores (0–100), cross-reference user-curated local threat intelligence indicators, store audit-trailed results in MongoDB, and deliver executive-grade visual security telemetry.

---

## 1. System Architecture & Core Philosophy

### Safe, Non-Executing Inspection
A foundational tenet of PhishShield Pro is **zero-execution inspection**. Malicious URLs frequently host browser exploits, credential-harvesting kits, drive-by malware downloads, or tracking web bugs. PhishShield Pro **never performs network requests, DNS resolutions, HTTP fetching, or socket connections to submitted URLs**. Analysis is conducted purely on URL lexical structures, hostname syntax, authority metadata, and pattern encodings.

### Explainable AI / Rule-Based Heuristics
Unlike opaque black-box machine learning models, PhishShield Pro computes a **transparent, auditable risk score**. Each detection trigger produces an explicit, understandable rationale explaining *why* a particular URL attribute was flagged and how much it contributed to the final score.

### Explicit Disclaimer
*Heuristic scores are risk indicators rather than probabilistic guarantees. A low-risk score does not guarantee absolute safety, and a high-risk score indicates structural anomalies common in deceptive infrastructure.*

---

## 2. Technology Stack

- **Backend Runtime**: Python 3 (Tested on Python 3.13)
- **Web Framework**: Flask 3.1
- **Database Engine**: MongoDB Community Server 8.3
- **Python Driver**: PyMongo 4.12
- **Password Security**: bcrypt (Blowfish-based salt-hashed storage)
- **Session & CSRF Security**: Flask sessions with cryptographically random tokens (`secrets.token_hex(32)`)
- **Frontend Presentation**: HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons
- **Visual Analytics**: Chart.js 4.4 (Dark cyber telemetry theme)

---

## 3. Project File Structure

```text
D:\PhishShield_Pro\
├── app.py                      # Main Flask application and route controllers
├── config.py                   # Environment configuration loader
├── requirements.txt            # Python package dependencies
├── README.md                   # Complete architectural and operational documentation
├── .env.example                # Template for environment secrets
├── .env                        # Local active configuration (MongoDB URI, secret keys)
├── .gitignore                  # Git exclusions for Python virtual environments and caches
├── services/
│   ├── __init__.py             # Python package marker
│   ├── db.py                   # MongoDB connection client, index creation, demo seeder
│   ├── url_analyzer.py         # Static heuristic analysis engine and rule checkers
│   └── audit.py                # Centralized audit logging helper
├── static/
│   ├── css/
│   │   └── style.css           # Custom dark cybersecurity dashboard styling
│   └── js/
│       └── main.js             # Interactive client-side enhancements and UI feedback
├── templates/
│   ├── base.html               # Master layout containing sidebar and top bar
│   ├── login.html              # Secure authentication interface
│   ├── dashboard.html          # High-level metrics, charts, recent scans & alerts
│   ├── scan.html               # URL submission and heuristic checklist
│   ├── scan_result.html        # Detailed score gauge, rule breakdown & details
│   ├── history.html            # Paginated scan table with search, filter & sort
│   ├── threat_intelligence.html# Local indicator repository management (CRUD)
│   ├── alerts.html             # High/Medium risk alert queue and review actions
│   ├── analytics.html          # MongoDB aggregation telemetry (charts & trends)
│   ├── reports.html            # Scan summaries and one-click CSV export
│   ├── settings.html           # Live rule weight configuration and toggle
│   └── audit_logs.html         # Immutable system security event trail
└── tests/
    ├── __init__.py
    └── test_phishshield.py     # Automated unit & integration test suite (26 tests)
```

---

## 4. Quick Start & Run Commands (Windows)

### Prerequisites
1. **Python 3.10+** (Available at `python.exe` or `py.exe`)
2. **MongoDB Community Server** running locally on port `27017`

### Step 1: Open PowerShell as Administrator or Normal User
Navigate to the project directory:
```powershell
cd D:\PhishShield_Pro
```

### Step 2: Create and Activate Virtual Environment (Optional but Recommended)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Packages
```powershell
pip install -r requirements.txt
```

### Step 4: Verify Environment Configuration
Ensure `.env` exists (created from `.env.example`):
```text
SECRET_KEY=c3629471f49635e8093116a4df9ce9bbf5a9c0172e09641775f0a2ba14a79df8
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=phishshield_pro
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Admin@123
```

### Step 5: Run the Automated Test Suite
Verify that all 26 unit and integration tests pass:
```powershell
python -m unittest tests/test_phishshield.py -v
```

### Step 6: Launch PhishShield Pro Server
```powershell
python app.py
```
The server will bind to `http://127.0.0.1:5000` (or `http://localhost:5000`).

---

## 4.1. Adding New Users (3 Methods)

### Method 1: Web Interface (Recommended)
1. Log in as an Administrator (`admin` / `Admin@123`).
2. Click on the top-right **Admin dropdown button** or the **User Management** link in the left sidebar (`/users`).
3. Click the **"+ Add New User"** button.
4. Enter:
   - **Username**: Desired operator username (e.g. `analyst_jane`)
   - **Password**: Secure password (minimum 6 characters)
   - **Security Role**:
     - `SOC Analyst`: Full URL scanning and alert triage rights.
     - `Administrator`: Full system settings, rule weights, and user management privileges.
     - `Auditor`: Read-only access to audit logs and compliance reports.
5. Click **Save Account**. Passwords are automatically hashed using **Blowfish bcrypt** before being stored in MongoDB.

### Method 2: Command Line (CLI Utility)
You can create accounts directly from PowerShell or the terminal using `create_user.py`:

- **Interactive Mode**:
  ```powershell
  python create_user.py
  ```
  *(Prompts for username, hidden password entry, confirmation, and role selection)*

- **Direct One-Line Command**:
  ```powershell
  python create_user.py --username jdoe --password "SecurePass@123" --role analyst
  ```

### Method 3: MongoDB Compass / Direct Insertion
To inspect or manage users directly in MongoDB Compass:
1. Connect Compass to `mongodb://localhost:27017/`.
2. Open database `phishshield_pro` > collection `users`.
3. Note: Passwords must be valid bcrypt hashes. Using Method 1 (Web UI) or Method 2 (CLI) is strongly recommended to guarantee proper cryptographic salting.

---

## 5. Connecting MongoDB Compass

1. Open **MongoDB Compass**.
2. In the connection string field, paste:
   ```text
   mongodb://localhost:27017/
   ```
3. Click **Connect**.
4. In the left database navigation pane, select **`phishshield_pro`**.
5. You will see 6 collections:
   - `users`: Contains credential hashes for operators.
   - `scan_history`: Contains all past URL heuristic evaluations.
   - `threat_intelligence`: User-curated suspicious indicators (domains, IPs, keywords).
   - `security_alerts`: Alert queue generated for Medium and High risk scans.
   - `detection_rules`: Editable heuristic rule weights and activation flags.
   - `audit_logs`: Chronological log of logins, scans, updates, and deletes.

---

## 6. MongoDB Schema Design & Indexing Strategy

### 1. `users` Collection
Stores analyst credentials with bcrypt-hashed passwords.
```json
{
  "_id": {"$oid": "..."},
  "username": "admin",
  "password": "$2b$12$e...",
  "role": "admin",
  "created_at": {"$date": "2026-11-12T18:00:00Z"}
}
```
* **Index**: `{ "username": 1 }` with `unique: true`.

### 2. `scan_history` Collection
Persists every URL scan event, lexical breakdown, and matched rules.
```json
{
  "_id": {"$oid": "..."},
  "url": "http://192.168.1.100/login/verify-account",
  "normalized_url": "http://192.168.1.100/login/verify-account",
  "risk_score": 75,
  "risk_level": "High",
  "triggered_rules": [
    {
      "rule_id": "ip_address_host",
      "rule_name": "IP Address Host",
      "weight": 20,
      "description": "URL uses raw IP address instead of domain."
    }
  ],
  "threat_intel_matches": [],
  "analysis_details": {
    "hostname": "192.168.1.100",
    "scheme": "http",
    "path": "/login/verify-account",
    "port": null,
    "query": "",
    "fragment": "",
    "length": 42
  },
  "scanned_at": {"$date": "2026-11-12T12:00:00Z"},
  "scanned_by": "admin"
}
```
* **Indexes**:
  - `{ "scanned_at": -1 }` (Optimizes chronological sorting and pagination).
  - `{ "risk_level": 1 }` (Optimizes risk category filtering).
  - `{ "url": 1 }` (Accelerates regex and exact-match searches).

### 3. `threat_intelligence` Collection
Stores local, user-maintained threat indicators.
```json
{
  "_id": {"$oid": "..."},
  "indicator": "secure-login.update-banking.tk",
  "indicator_type": "domain",
  "type": "domain",
  "severity": "high",
  "source": "Local Threat Intelligence",
  "description": "Reported fake banking credential-harvesting domain",
  "status": "active",
  "added_by": "admin",
  "added_at": {"$date": "2026-11-10T15:30:00Z"}
}
```
* **Indexes**: `{ "indicator": 1 }` (`unique: true`), `{ "indicator_type": 1 }`, `{ "status": 1 }`.

### 4. `security_alerts` Collection
Tracks security incidents requiring SOC analyst triage.
```json
{
  "_id": {"$oid": "..."},
  "scan_id": {"$oid": "..."},
  "url": "http://secure-login.update-banking.tk/signin",
  "risk_score": 90,
  "risk_level": "High",
  "severity": "High",
  "message": "Suspicious URL detected: ...",
  "status": "new",
  "created_at": {"$date": "2026-11-12T10:00:00Z"},
  "reviewed_by": null,
  "reviewed_at": null
}
```
* **Indexes**: `{ "created_at": -1 }`, `{ "severity": 1 }`, `{ "status": 1 }`.

### 5. `detection_rules` Collection
Maintains dynamic weights for the heuristic detection engine.
```json
{
  "_id": {"$oid": "..."},
  "rule_id": "suspicious_keywords",
  "name": "Suspicious Keywords",
  "description": "URL contains common phishing/credential harvesting keywords",
  "weight": 15,
  "enabled": true
}
```
* **Index**: `{ "rule_id": 1 }` (`unique: true`).

### 6. `audit_logs` Collection
Immutable record of security and administrative actions.
```json
{
  "_id": {"$oid": "..."},
  "timestamp": {"$date": "2026-11-12T18:20:00Z"},
  "user": "admin",
  "action": "scan",
  "details": {"url": "https://example.com", "risk_score": 0, "risk_level": "Low"}
}
```
* **Indexes**: `{ "timestamp": -1 }`, `{ "action": 1 }`.

---

## 7. Explainable Heuristic Detection Rules

| Rule ID | Rule Name | Default Weight | Cybersecurity Rationale |
| :--- | :--- | :---: | :--- |
| `ip_address_host` | IP Address Host | 20 | Legit sites use DNS hostnames. Direct IP addresses bypass reputation systems and conceal domain registration data. |
| `suspicious_keywords` | Suspicious Keywords | 15 | Phishing campaigns frequently employ deceptive terms (`login`, `verify`, `account`, `banking`, `secure`, `password`). |
| `excessive_subdomains` | Excessive Subdomains | 15 | Attackers nest subdomains (e.g. `paypal.com.verify.attacker.com`) to mislead users on truncated mobile browser bars. |
| `at_symbol` | At Symbol (`@`) in URL | 20 | The `@` symbol in standard URI syntax causes user agents to treat preceding text as userinfo and navigate to the following host. |
| `url_shortener` | URL Shortener | 15 | Shortening services (`bit.ly`, `tinyurl.com`, `t.co`) conceal genuine landing domains from user preview. |
| `long_url` | Long URL (> 75 chars) | 10 | Excessively long URLs are routinely used to push malicious hostnames out of view on mobile address bars. |
| `insecure_http` | Insecure HTTP | 5 | Modern legitimate login and banking interfaces mandate TLS/HTTPS encryption. |
| `suspicious_tld` | Suspicious TLD | 15 | Free or low-cost TLDs (`.tk`, `.ml`, `.xyz`, `.top`, `.club`) exhibit disproportionately high abuse rates. |
| `double_slashes_in_path`| Double Slashes in Path | 10 | `//` in the URI path is frequently exploited for open-redirect attacks (`https://example.com//malicious.com`). |
| `hex_encoded_chars` | Hex-Encoded Chars | 15 | URL percent-encoding (`%3C`, `%20`) is used to obfuscate script tags, redirects, and evasion tokens. |
| `local_threat_intel_match`| Local Threat Intel Hit | 40 | Exact match against the user-curated local threat intelligence database. |

### Mathematical Risk Score Formulation
The composite risk score $S$ is calculated as the clamped sum of triggered enabled rule weights:
$$S = \min\left(100, \sum_{i \in \text{Triggered Rules}} w_i\right)$$

Classification boundaries:
- **Low Risk**: $0 \le S \le 33$ (Green)
- **Medium Risk**: $34 \le S \le 66$ (Amber)
- **High Risk**: $67 \le S \le 100$ (Red)

---

## 8. Demonstration Workflow for Professor / Evaluation

### Step 1: Login & Authentication (Module 1)
1. Navigate to `http://localhost:5000/login`.
2. Demonstrate session security: try navigating directly to `http://localhost:5000/dashboard` in an incognito window — confirm it redirects to `/login`.
3. Log in using the seeded credentials:
   - **Username**: `admin`
   - **Password**: `Admin@123`
4. Show the success notification and redirection to the Dashboard.

### Step 2: Dashboard Telemetry (Module 2)
1. Point out the four top KPI metric cards (Total Scans, Safe URLs, Suspicious URLs, High Risk URLs) rendered from real MongoDB counts.
2. Highlight the interactive **Chart.js Risk Distribution doughnut chart** and the **Daily Scanning Activity line chart** (computed via MongoDB `$group` aggregation).
3. Review the **Recent Scans** table and active **Security Alerts**.

### Step 3: Run Live URL Scans (Module 3)
1. Click **URL Scanner** on the sidebar.
2. **Scan Safe URL**:
   - Enter `https://github.com/phishshield/pro`
   - Observe Score: `0/100`, **Low Risk** (Green).
   - Point out that 0 heuristic rules were triggered.
3. **Scan Deceptive Phishing URL**:
   - Enter `http://admin@192.168.1.100/login/verify-banking-account-update?token=%3Cscript%3E`
   - Click **Analyze URL** — note the button loading spinner state.
   - Observe Score: `85/100`, **High Risk** (Red).
   - Point out the triggered rules breakdown: IP Address Host (+20), Suspicious Keywords (+15), At Symbol (+20), Hex-Encoded (+15), Long URL (+10), Insecure HTTP (+5).
   - Emphasize the **Explainability** and the **Cybersecurity Disclaimer**.

### Step 4: Scan History Management (Module 4)
1. Click **Scan History** on the sidebar.
2. Demonstrate **Search**: type `192.168` and press Enter to filter.
3. Demonstrate **Filter by Risk**: select `High Risk`.
4. Demonstrate **Sorting**: change sort to `Highest Risk`.
5. Demonstrate **Delete Record**: click the red trash icon on any record, view the confirmation modal with URL preview, and confirm deletion.

### Step 5: Threat Intelligence Repository (Module 5)
1. Click **Threat Intelligence** on the sidebar.
2. Explain the difference: **These are user-curated local indicators**, distinct from external commercial feeds.
3. Add a new indicator:
   - **Indicator**: `phish-test-lab.xyz`
   - **Type**: `Domain`
   - **Severity**: `High`
   - **Description**: `Simulated adversary domain for academic test`
4. Now return to **URL Scanner** and scan `http://phish-test-lab.xyz/portal`.
5. Observe the **Local Threat Intelligence Hit (+40)** triggered rule!

### Step 6: Security Alert Triage (Module 6)
1. Click **Security Alerts** on the sidebar.
2. Review the alert generated for the scan conducted in Step 5.
3. Click **Mark Reviewed** — observe badge changing from blue `New` to green `Reviewed`.

### Step 7: Advanced MongoDB Analytics (Module 7)
1. Click **Analytics** on the sidebar.
2. Demonstrate the 4 charts powered by MongoDB aggregation pipelines:
   - Risk Distribution (Pie Chart)
   - Daily Scan Trend (Line Chart)
   - Top 10 Triggered Rules (Horizontal Bar Chart using `$unwind`)
   - Scans by Hour of Day (Bar Chart using `$hour`)
3. Apply a date filter (`From` and `To`) to demonstrate real-time pipeline query constraints.

### Step 8: Reports & CSV Export (Module 8)
1. Click **Reports** on the sidebar.
2. Review the aggregated summary card.
3. Click **Download CSV** — open the downloaded `.csv` file in Excel or Notepad to verify complete data fields (Scan ID, URL, Normalized URL, Risk Score, Triggered Rules, Timestamp, User).

### Step 9: Settings & Detection Rule Tuning (Module 9)
1. Click **Settings** on the sidebar.
2. Demonstrate dynamic weight adjustment: change `Insecure HTTP` weight from `5` to `10`.
3. Click **Save Settings** and observe confirmation flash message.

### Step 10: Audit Logs Verification (Module 10)
1. Click **Audit Logs** on the sidebar.
2. Show the complete immutable event log recording: user logins, scans, indicator modifications, alert reviews, settings changes, and record deletions.

---

## 9. Security Engineering Safeguards

1. **Defense Against SSRF & Malicious Payloads**: Submitted URLs are parsed strictly using URL grammar expressions (`urllib.parse` and regex). Under no circumstances does the application resolve DNS, open sockets, or send HTTP GET/POST packets to user-supplied targets.
2. **XSS & HTML Injection Prevention**: User inputs are escaped by Jinja2 (`| e`) and rendered in `<pre>` or `<code>` blocks, completely neutralizing stored XSS vectors.
3. **CSRF Protection**: All POST requests (`/login`, `/scan`, `/history/delete`, `/threat-intelligence/*`, `/alerts/review`, `/settings`) enforce session-token verification.
4. **Credential Hashing**: User passwords are encrypted with bcrypt and gensalt work factor 12. Plaintext credentials are never stored.

---

## 10. Limitations & Future Roadmap

- **Static Lexical Limitations**: Lexical heuristic engines analyze syntactic features. Sophisticated targeted phishing on legitimate multi-tenant clouds (e.g., `docs.google.com/forms/...`) will exhibit low structural risk scores unless flagged by threat intelligence.
- **Dynamic Content Analysis**: Future versions could integrate an isolated sandbox crawler (e.g. headless Playwright in an ephemeral container) to safely capture DOM snapshots and screenshot similarity without exposing host networks.
- **External Threat Feeds**: Future iterations can integrate automated TAXII/STIX feeds from AlienVault OTX, PhishTank, and URLhaus alongside the existing local repository.

