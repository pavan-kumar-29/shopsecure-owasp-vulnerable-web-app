# ShopSecure — Demonstration Guide
### Step-by-Step Attack and Fix Walkthroughs
### Designed for Manager / TCS-ION Evaluator Presentation

**Project     :** 
**Prepared by :
**Prerequisite:** App running at http://localhost:5000
**Date        :** May 2026

---

## Pre-Demo Setup

```bash
# Start the application
cd ~/shopsecure
source venv/bin/activate
python3 app.py

# Open two browser tabs:
# Tab 1: http://localhost:5000           (main app)
# Tab 2: http://localhost:5000/debug     (for A05 demo)

# Open a terminal for log monitoring:
tail -f security.log

# Default mode: VULNERABLE (red banner at top)
# Demo credentials: admin/admin123 | alice/password | bob/password
```

---

## DEMO 1 — SQL Injection (A03)

**OWASP Category:** A03:2021-2025 — Injection
**Risk Level:** Critical | **Tools Needed:** Just a browser

### Steps to Perform Attack (Vulnerable Mode)

1. Open http://localhost:5000
2. Ensure red **⚠️ VULNERABLE** banner is visible at the top
3. Click on the search bar in the navigation bar
4. Type the following payload EXACTLY and press Enter:

```sql
%' UNION SELECT 1,username,password,email,role,address,phone,created_at,last_login FROM users--
```

5. Observe the product grid — it now shows database records as "products"

### Expected Output — Vulnerable Mode

The product grid will display rows from the **users table**:
```
Product Name:     admin
Product Category: admin
Product Price:    alice
Description:      $2b$12$... (bcrypt hash — the password!)

Product Name:     alice
Category:         user
...
```

The red info box on the page shows the exact SQL that was executed:
```sql
SELECT * FROM products WHERE name LIKE '%' UNION SELECT 1,username,password,
email,role,address,phone,created_at,last_login FROM users--%'
```

**All usernames, password hashes, emails, and roles are visible in one request.**

### Expected Output — Secure Mode

1. Click the **⚠️ VULNERABLE** button → switches to **🔒 SECURE**
2. Repeat the exact same search with the identical payload
3. Result: **Empty product grid** — no results, no error, no data leaked
4. Green banner shows: "Parameterized query — input treated as plain text, not SQL"

### Talking Points for Evaluator

- "In vulnerable mode, one search query dumped the entire user credential table"
- "No hacking tool was needed — just a browser and typing in a text box"
- "The fix was changing 3 characters of code: `%{q}%` to `?` with parameters"
- "This exact attack technique was used in the TalkTalk breach — 156,000 customers affected"

---

## DEMO 2 — Broken Access Control / IDOR (A01)

**OWASP Category:** A01:2021-2025 — Broken Access Control
**Risk Level:** Critical | **Tools Needed:** Just a browser

### Steps to Perform Attack (Vulnerable Mode)

#### Part A: Admin Panel Bypass (Missing Function-Level Auth)

1. Open a **private/incognito browser window** (to ensure you are NOT logged in)
2. Navigate directly to: `http://localhost:5000/admin`
3. Observe: Full admin dashboard loads with all user data — NO login required

#### Part B: IDOR on Orders

1. Login as **alice** (password: password) at http://localhost:5000/login
2. Place an order or note that Order #1 exists (admin's order)
3. Navigate to: `http://localhost:5000/orders/1`
4. Observe: alice sees order #1 which belongs to admin

#### Part C: IDOR on User Profile

1. While logged in as alice, navigate to: `http://localhost:5000/profile/1`
2. Observe: alice sees the admin's complete profile including **password hash**

### Expected Output — Vulnerable Mode

```
GET /admin (not logged in):
→ HTTP 200 — Full admin dashboard
→ Shows ALL users: admin, alice, bob
→ Shows ALL password hashes (MD5/bcrypt)
→ Shows ALL emails and roles

GET /orders/1 (as alice):
→ HTTP 200 — admin's order details
→ Shows address, total, items ordered

GET /profile/1 (as alice):
→ HTTP 200 — admin's profile
→ Email: admin@shop.local
→ Password hash: $2b$12$... (visible!)
→ Red warning: "🚨 UNAUTHORIZED ACCESS!"
```

### Expected Output — Secure Mode

1. Click **⚠️ VULNERABLE** → **🔒 SECURE**
2. Repeat all three attempts:

```
GET /admin (not logged in):
→ HTTP 403 Forbidden
→ "You do not have permission to access this page."
→ Log entry: [UNAUTH-ADMIN] user_id=None ip=127.0.0.1

GET /orders/1 (as alice):
→ HTTP 403 Forbidden / Redirect
→ "Order not found or access denied."
→ Log entry: [IDOR-BLOCKED] user=2 tried order=1

GET /profile/1 (as alice):
→ HTTP 403 Forbidden
→ "You do not have permission to access this page."
→ Log entry: [IDOR-BLOCKED] user=2 tried profile=1
```

### Talking Points for Evaluator

- "IDOR — Insecure Direct Object Reference — is the #1 OWASP vulnerability"
- "The attacker just changes a number in the URL — no special tools needed"
- "In secure mode: the server checks both the resource ID AND the owner's identity"
- "Parler, 2021-2025: No access control on media API — all 70TB of user data harvested this way"
- "94% of tested applications have some form of this vulnerability (OWASP 2021-2025)"

---

## DEMO 3 — Security Misconfiguration / Debug Info Leak (A05)

**OWASP Category:** A05:2021-2025 — Security Misconfiguration
**Risk Level:** High | **Tools Needed:** Just a browser

### Steps to Perform Attack (Vulnerable Mode)

1. Open http://localhost:5000/debug (no login required)
2. Observe what is visible on the page

### Expected Output — Vulnerable Mode

The page displays:
```
┌─ Flask SECRET_KEY (⚠️ EXPOSED) ──────────────┐
│ "secret"                                       │
└───────────────────────────────────────────────┘

┌─ Environment Variables (⚠️ EXPOSED) ──────────┐
│ HOME=/home/ubuntu                              │
│ PATH=/usr/local/bin:/usr/bin:/bin              │
│ DATABASE_URL=sqlite:///ecommerce.db            │
│ (any API keys or passwords here would show)   │
└───────────────────────────────────────────────┘

┌─ Session Contents (⚠️ EXPOSED) ───────────────┐
│ { "user_id": null, "mode": "vulnerable" }     │
└───────────────────────────────────────────────┘

┌─ Full Flask Config (⚠️ EXPOSED) ──────────────┐
│ DEBUG: True                                    │
│ DATABASE: /home/ubuntu/shopsecure/ecommerce.db│
│ SECRET_KEY: secret                             │
└───────────────────────────────────────────────┘
```

**With SECRET_KEY = "secret", an attacker can now:**
```python
# Forge an admin session cookie from any machine:
python3 -c "
from itsdangerous import URLSafeTimedSerializer
s = URLSafeTimedSerializer('secret')
print(s.dumps({'user_id': 1, 'role': 'admin', 'username': 'admin'}))
"
# → Paste the output as the 'session' cookie → Instant admin access
```

### Expected Output — Secure Mode

1. Switch to **🔒 SECURE** mode
2. Visit http://localhost:5000/debug
3. Result: **HTTP 404 — Page Not Found**
4. The debug endpoint literally does not exist in secure mode

### Talking Points for Evaluator

- "The secret key was literally the word 'secret' — with it, I can become any user"
- "Uber's 2016 breach started with hardcoded AWS credentials found in their GitHub — 57 million records"
- "In secure mode, the debug endpoint returns 404 — it simply doesn't exist"
- "The fix is two things: generate a random key, and delete the debug endpoint in production"

---

## DEMO 4 — SSRF — Server-Side Request Forgery (A10)

**OWASP Category:** A10:2021-2025 — SSRF
**Risk Level:** Critical | **Tools Needed:** Just a browser

### Steps to Perform Attack (Vulnerable Mode)

1. Open http://localhost:5000/fetch-url
2. In the URL field, try each of the following (one at a time):

**Probe 1 — AWS Cloud Metadata:**
```
http://169.254.169.254/latest/meta-data/
```

**Probe 2 — Internal port scan:**
```
http://127.0.0.1:5000/admin
```

**Probe 3 — OS Command Injection via ping prefix:**
```
ping:127.0.0.1; id
```

```
ping:127.0.0.1; cat /etc/passwd
```

### Expected Output — Vulnerable Mode

```
Probe 2 — http://127.0.0.1:5000/admin:
→ Server fetches its own admin page
→ Returns full HTML of admin dashboard
→ Firewall is completely bypassed — server talks to itself

Probe 3 — ping:127.0.0.1; id:
→ [OS CMD INJECTION via shell=True]
→ $ ping -c 1 127.0.0.1; id
→ uid=1000(ubuntu) gid=1000(ubuntu) groups=...
→ Server executed our operating system command!

Probe 3 — ping:127.0.0.1; cat /etc/passwd:
→ root:x:0:0:root:/root:/bin/bash
→ ubuntu:x:1000:1000:...
→ Full /etc/passwd file content returned
```

### Expected Output — Secure Mode

1. Switch to **🔒 SECURE** mode
2. Try all the same URLs
3. All return:
```
🔒 BLOCKED: Private/internal addresses are not allowed.
Allowed: Only public HTTP/HTTPS URLs to non-private IP ranges.
```

### Talking Points for Evaluator

- "Capital One's 2019 breach: SSRF fetched AWS IAM credentials from 169.254.169.254"
- "100 million customers exposed — $80 million fine"
- "The ping: payload combined SSRF with OS command injection — two vulnerabilities at once"
- "In secure mode, a regex blocklist of private IP ranges prevents all internal access"

---

## DEMO 5 — Cryptographic Failures — MD5 Passwords (A02)

**OWASP Category:** A02:2021-2025 — Cryptographic Failures
**Risk Level:** High | **Tools Needed:** Browser + CrackStation.net

### Steps to Perform Attack (Vulnerable Mode)

1. Register a new account: http://localhost:5000/register
   - Username: testuser
   - Password: mypassword
2. Visit http://localhost:5000/admin (no auth in vulnerable mode)
3. Find testuser in the user table — copy the MD5 hash
4. Open https://crackstation.net in a new tab
5. Paste the hash → Click "Crack Hashes"

### Expected Output — Vulnerable Mode

```
Admin panel shows:
Username:  testuser
Password:  318f7de2dd7f1f46a5c71a1d4e74a8ca  ← MD5 of "mypassword"

CrackStation result (< 1 second):
Hash:   318f7de2dd7f1f46a5c71a1d4e74a8ca
Type:   MD5
Result: mypassword   ← CRACKED INSTANTLY
```

### Expected Output — Secure Mode

1. Switch to **🔒 SECURE** mode
2. Register a new account (password must be 8+ chars, with uppercase and number)
3. Check the database (if accessible) or show the comparison:
```
Vulnerable MD5:   318f7de2dd7f1f46a5c71a1d4e74a8ca   (32 chars)
                  → Cracked in < 1 millisecond

Secure bcrypt:    $2b$12$LQv3c1yqBWVHxkd0LHAkCO...  (60 chars, includes salt)
                  → ~130 years to crack at 100 hashes/second
```

### Talking Points for Evaluator

- "MD5 was designed for file checksums, not password storage — it is intentionally fast"
- "LinkedIn, 2012: 117 million MD5 passwords leaked — 90% cracked within 3 days"
- "bcrypt is 100 MILLION times harder to crack than MD5 — same password, completely different security"
- "The entire fix is two lines of code — just changing which library you call"

---

## DEMO 6 — Authentication Failures — User Enumeration (A07)

**OWASP Category:** A07:2021-2025 — Identification and Authentication Failures
**Risk Level:** Medium | **Tools Needed:** Just a browser

### Steps to Perform Attack (Vulnerable Mode)

1. Go to http://localhost:5000/login (make sure you are logged out)
2. Try a username that does NOT exist:
   - Username: `doesnotexist123`
   - Password: `anything`
   - Note the error message carefully

3. Try the admin username with a wrong password:
   - Username: `admin`
   - Password: `wrongpassword`
   - Note the error message — it is DIFFERENT

### Expected Output — Vulnerable Mode

```
Attempt 1 — Non-existent username:
→ Flash message: "Username 'doesnotexist123' not found."
→ (Confirms: this username does NOT exist in the database)

Attempt 2 — Valid username, wrong password:
→ Flash message: "Incorrect password."
→ (Confirms: 'admin' DOES exist — wrong password only)

Attack chain:
1. Enumerate valid usernames using the two different messages
2. Build confirmed username list: ["admin", "alice", "bob"]
3. Brute-force only confirmed usernames — 3x more efficient
4. No lockout = unlimited attempts
```

### Expected Output — Secure Mode

1. Switch to **🔒 SECURE** mode
2. Repeat both attempts
3. Both show IDENTICAL message:
```
→ Flash message: "Invalid credentials."
→ (Same message regardless of whether username exists)
→ Attacker cannot determine if username is valid or not
→ Log entry: [LOGIN-FAIL] username=doesnotexist123 ip=127.0.0.1
```

### Talking Points for Evaluator

- "User enumeration is step 1 in every credential stuffing attack"
- "With a confirmed username, brute-forcing is dramatically more targeted"
- "The fix is trivially simple: use the exact same error message for both cases"
- "Snapchat, 2014: User enumeration API exposed 4.6 million usernames and phone numbers"

---

## DEMO 7 — Insecure Design — Password Reset Without Auth (A04)

**OWASP Category:** A04:2021-2025 — Insecure Design
**Risk Level:** Critical | **Tools Needed:** Just a browser

### Steps to Perform Attack (Vulnerable Mode)

1. Open an incognito window — ensure you are NOT logged in
2. Navigate to: http://localhost:5000/reset-password
3. Fill in:
   - Username: `admin`
   - New Password: `hacked123`
4. Click **Reset Password**
5. Go to http://localhost:5000/login
6. Login with: admin / hacked123
7. Observe: You are now logged in as admin!

### Expected Output — Vulnerable Mode

```
Step 4 — Flash message: "Password for 'admin' reset (no verification required ⚠️)"
Step 6 — Flash message: "Welcome back, admin! 👋"
Step 7 — Admin account fully compromised, no forensic trace left
          Full admin dashboard accessible
```

### Expected Output — Secure Mode

1. Switch to **🔒 SECURE** mode
2. Visit /reset-password without being logged in
3. Result:
```
→ "You must be logged in to change your password."
→ Redirected to /login page

Even when logged in, current password is required:
→ "Current password is incorrect." (if current password not provided)
→ Cannot change password without knowing the current one
```

### Talking Points for Evaluator

- "This is an ARCHITECTURAL flaw — it cannot be fixed by better coding of the same design"
- "No tools, no hacking, no expertise — just a browser and 10 seconds"
- "The entire admin account was taken over before breakfast"
- "The fix requires RE-DESIGNING the feature, not just patching code"

---

## DEMO 8 — No Security Logging (A09)

**OWASP Category:** A09:2021-2025 — Security Logging and Monitoring Failures
**Risk Level:** Medium | **Tools Needed:** Terminal + browser

### Steps to Perform Attack (Vulnerable Mode)

1. Open a terminal and run:
   ```bash
   tail -f ~/shopsecure/security.log
   ```

2. In the browser (Vulnerable Mode), perform:
   - 5 failed login attempts
   - Access /admin without logging in
   - Access /orders/1 as alice (IDOR)
   - Access /profile/1 as alice (IDOR)
   - Submit the SQL injection payload

3. Watch the terminal

### Expected Output — Vulnerable Mode

```
Terminal shows: (absolutely nothing)
security.log file: 0 bytes — empty

"All of those attacks happened — SQL injection, IDOR attempts, admin bypass —
and there is ZERO evidence. The organization would never know."
```

### Expected Output — Secure Mode

1. Switch to **🔒 SECURE** mode
2. Repeat the same actions
3. Terminal fills with:

```
2026-05-01 10:23:14 [INFO] [LOGIN-FAIL] username=admin ip=192.168.1.105
2026-05-01 10:23:17 [INFO] [LOGIN-FAIL] username=admin ip=192.168.1.105
2026-05-01 10:23:20 [INFO] [LOGIN-FAIL] username=admin ip=192.168.1.105
2026-05-01 10:23:24 [INFO] [LOGIN-OK] user=alice ip=192.168.1.105
2026-05-01 10:23:31 [INFO] [IDOR-BLOCKED] user=2 tried order=1 ip=192.168.1.105
2026-05-01 10:23:45 [INFO] [UNAUTH-ADMIN] user_id=None ip=192.168.1.105
2026-05-01 10:23:52 [INFO] [IDOR-BLOCKED] user=2 tried profile=1 ip=192.168.1.105
2026-05-01 10:24:10 [INFO] [SEARCH] user=alice q=%' UNION SELECT... ip=192.168.1.105
```

### Talking Points for Evaluator

- "IBM 2024: Average time to identify a breach is 194 days — because there are no logs"
- "Without logs, there is no incident response, no forensics, no accountability"
- "These log entries would trigger a SIEM alert within seconds in a properly monitored environment"
- "The fix is 3 lines of Python — logging is one of the highest-ROI security investments possible"

---

## Closing Summary Slide (For Presentation)

### Before (Vulnerable Mode) vs After (Secure Mode)

| Vulnerability | Before | After | Fix |
|---------------|--------|-------|-----|
| SQL Injection | Full DB dump in one request | Zero data leaked | Parameterized queries |
| IDOR | Any user's data by changing URL number | 403 Forbidden | Ownership check in SQL |
| Admin Access | Open to anyone | role=admin required | Decorator + role check |
| Password Hashing | MD5 — cracked in 1ms | bcrypt — 130 years | Change one library |
| Password Reset | Any account takeover in 10 seconds | Login + current password required | Design change |
| Debug Info | Secret key + env vars exposed | 404 — doesn't exist | Remove endpoint |
| SSRF | Internal network fully accessible | All private IPs blocked | URL validation |
| Security Logging | Zero evidence of any attack | Full audit trail with IPs | 3 lines of Python |
| CSRF | Forms submittable cross-site | Token validated on every form | CSRF token generation |
| User Enumeration | Username existence confirmed | Generic "Invalid credentials" | Same error message |

---

*Document End — ShopSecure Demonstration Guide v1.0 | TCS-ION Industry Project 2026*
