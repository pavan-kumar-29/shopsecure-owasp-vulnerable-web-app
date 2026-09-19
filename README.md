# 🛡️ ShopSecure — OWASP Top 10 Vulnerable Web Application

> ⚠️ **WARNING:** This application contains **intentional security vulnerabilities**.
> Run ONLY in an isolated lab environment (VM or local machine).
> **NEVER** expose to the internet or deploy in production.

---

## 📖 Description

**ShopSecure** is a dual-mode educational e-commerce web application built with Python Flask
that demonstrates all **OWASP Top 10 (2021,2025)** security vulnerabilities with live, interactive
exploits — and their complete, working fixes — all within the same codebase.

Toggle between **Vulnerable Mode** (🔴 red) and **Secure Mode** (🟢 green) with a single
button click in the navigation bar. Every URL, every form, every endpoint instantly changes
its security behavior — no server restart required.

This project was built as a **TCS-ION Industry Project** for the purpose of security education,
developer training, and OWASP vulnerability awareness.

---

## ✨ Features

| Feature | Details |
|---------|---------|
| 🛍️ Full E-Commerce | Products, search, cart, checkout, orders, user profiles |
| 🔄 Mode Toggle | Single-click switch between Vulnerable and Secure — no restart |
| 🔓 10 Vulnerabilities | All OWASP Top 10 (2021,2025) — live and exploitable in Vulnerable Mode |
| 🔒 10 Security Fixes | Every vulnerability has a complete working fix in Secure Mode |
| 📋 Audit Logging | Secure Mode logs all security events to security.log |
| 🗄️ Auto-Seeded DB | 8 products and 3 users created automatically on first run |
| 🎯 Quick Demo Links | Footer and OWASP info panel with direct vulnerability links |
| 📱 Responsive UI | Tailwind CSS — works on mobile, tablet, and desktop |
| 🎓 Beginner Friendly | Each page shows which OWASP vulnerability is active and how to test it |

---

## 🛡️ OWASP Top 10 Coverage

| Code | Vulnerability | Demo Location |
|------|--------------|---------------|
| A01 | Broken Access Control | /admin, /orders/1, /profile/1 |
| A02 | Cryptographic Failures | Register + /admin (MD5 hash visible) |
| A03 | Injection (SQLi + OS Cmd) | Search bar, /fetch-url |
| A04 | Insecure Design | /reset-password |
| A05 | Security Misconfiguration | /debug, DEBUG=True |
| A06 | Vulnerable Components | MD5 usage, Werkzeug debug mode |
| A07 | Auth Failures | /login (user enumeration) |
| A08 | Data Integrity Failures | Any form (no CSRF token) |
| A09 | Logging Failures | security.log (empty in vuln mode) |
| A10 | SSRF | /fetch-url |

---

## 🚀 Installation (Ubuntu / Linux)

### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3 and pip
sudo apt install -y python3 python3-pip python3-venv git

# Verify Python version (must be 3.10+)
python3 --version
```

### Setup Steps

**Step 1: Create project directory and navigate into it**
```bash
mkdir ~/shopsecure
cd ~/shopsecure
```

**Step 2: Copy app.py and requirements.txt into this directory**

If using git:
```bash
git clone https://github.com/pandugadu69/shopsecure.git .
```

Or manually copy the files.

**Step 3: Create a Python virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
# Your prompt changes to: (venv) user@machine:~/shopsecure$
```

**Step 4: Install all dependencies**
```bash
pip install -r requirements.txt
```

Expected output:
```
Successfully installed Flask-3.1.1 Werkzeug-3.1.3 bcrypt-4.2.1 requests-2.32.3 MarkupSafe-3.0.2
```

---

## ▶️ How to Run

```bash
# Make sure virtual environment is active
source venv/bin/activate

# Run the application
python3 app.py
```

Expected startup output:
```
✅  Database seeded: 8 products, 3 users (admin/admin123, alice/password, bob/password)
╔══════════════════════════════════════════════════════════════════╗
║           ShopSecure — OWASP Top 10 Demo App                    ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  VULNERABLE MODE starts by default                          ║
║  🔒  Click the red button in navbar to switch to SECURE MODE    ║
╠══════════════════════════════════════════════════════════════════╣
║  Demo Credentials:                                               ║
║    admin / admin123  |  alice / password  |  bob / password     ║
║  Key Demo URLs:                                                  ║
║    /admin          A01: Broken Access Control                    ║
║    /search?q=...   A03: SQL Injection                            ║
║    /fetch-url      A10: SSRF                                     ║
║    /debug          A05: Security Misconfiguration                ║
╚══════════════════════════════════════════════════════════════════╝
 * Running on http://0.0.0.0:5000
```

**Open your browser:**
```
http://localhost:5000          ← Local access
http://<YOUR-IP>:5000          ← Access from another machine on the network
```

---

## 🔑 Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Administrator |
| `alice` | `password` | Regular User |
| `bob` | `password` | Regular User |

---

## 🔄 How to Switch Modes

1. Look at the **top-right corner** of the navigation bar
2. **Red button** (⚠️ VULNERABLE) = Vulnerable Mode — active by default
3. **Green button** (🔒 SECURE) = Secure Mode — all fixes applied
4. Click the button → page reloads with new mode active
5. The **colored banner** at the very top of every page also changes

**All changes are instant — no server restart needed.**

---

## 🔥 Example Attacks (Vulnerable Mode)

### SQL Injection — Search Bar
```
Payload: %' UNION SELECT 1,username,password,email,role,address,phone,created_at,last_login FROM users--
Location: Search bar on home page
Result:   All user credentials displayed as "product" cards
```

### IDOR — Access Any Order
```
URL:    http://localhost:5000/orders/1
Login:  alice (regular user)
Result: Sees admin's private order details
```

### Admin Panel — No Authentication
```
URL:    http://localhost:5000/admin
Login:  Not required — works from incognito!
Result: Full user table with password hashes
```

### SSRF — Internal Network Access
```
URL:        http://localhost:5000/fetch-url
Input URL:  http://127.0.0.1:5000/admin
Result:     Server fetches its own admin page — firewall bypassed
```

### OS Command Injection — Via SSRF Ping Feature
```
URL:        http://localhost:5000/fetch-url
Input URL:  ping:127.0.0.1; id; cat /etc/passwd
Result:     Server executes OS commands and returns output
```

### Debug Info Leak
```
URL:    http://localhost:5000/debug
Login:  Not required
Result: SECRET_KEY, environment variables, session contents, all config
```

### Password Reset — Account Takeover
```
URL:      http://localhost:5000/reset-password
Username: admin
New PW:   hacked123
Result:   Admin account password changed — login with hacked123
```

### User Enumeration
```
Login attempt with username=admin, wrong password:
→ "Incorrect password." (confirms admin EXISTS)

Login attempt with username=xyz, any password:
→ "Username 'xyz' not found." (confirms xyz does NOT exist)
```

---

## 🔒 What Secure Mode Does

| Area | Vulnerable | Secure |
|------|-----------|--------|
| Passwords | MD5 (cracked in 1ms) | bcrypt cost=12 (~130 years/hash) |
| SQL Queries | String concatenation | Parameterized queries (?) |
| Admin Access | Open to anyone | role=admin required |
| User Data | Any user accesses any user's data | Ownership verified in every query |
| CSRF Protection | None | Token on every state-changing form |
| Error Pages | Full Python stack trace | Generic "something went wrong" |
| Debug Endpoint | All config and secrets exposed | Returns HTTP 404 |
| SSRF | Fetches any URL | Private IPs blocked |
| Session Secret | "secret" (hardcoded) | 32-byte cryptographic random value |
| Login Errors | Two distinct messages (enumeration) | Single generic "Invalid credentials" |
| Security Logs | Nothing logged — blind | All events in security.log with IP + timestamp |
| HTTP Headers | None | X-Frame-Options, CSP, X-Content-Type-Options |

---

## 📁 Project Structure

```
shopsecure/
├── app.py                         ← Complete application (~1,986 lines)
├── requirements.txt               ← Python dependencies (pinned)
├── README.md                      ← This file
├── ecommerce.db                   ← SQLite database (auto-created on first run)
├── security.log                   ← Audit log (created automatically in Secure Mode)
├── static/                        ← Static assets (minimal — mostly CDN)
├── templates/                     ← Templates embedded in app.py via DictLoader
└── report/
    ├── 01_project_overview.md     ← Project overview document
    ├── 02_vulnerabilities.md      ← OWASP vulnerability documentation
    ├── 03_project_report.md       ← Formal academic report
    └── 04_demo_guide.md           ← Step-by-step demo guide for evaluators
```

---

## 🌐 Access from Another Machine (Kali → Ubuntu VM)

```bash
# On Ubuntu VM, find the IP address:
ip a | grep "inet " | grep -v "127.0.0.1"
# Example: inet 192.168.56.101/24

# On Kali or any other machine, open browser:
http://192.168.56.101:5000

# The application binds to 0.0.0.0:5000 — accessible from all network interfaces
```

---

## 📦 Dependencies

```
Flask==3.1.1
Werkzeug==3.1.3
bcrypt==4.2.1
requests==2.32.3
MarkupSafe==3.0.2
```

Install all with: `pip install -r requirements.txt`

---

## 🔍 Monitoring Security Events

```bash
# In a separate terminal, watch the security log in real time:
tail -f security.log

# This shows nothing in Vulnerable Mode (A09 demonstration)
# In Secure Mode, shows all events:
# 2026-05-01 10:23:14 [INFO] [LOGIN-FAIL] username=admin ip=127.0.0.1
# 2026-05-01 10:23:31 [INFO] [IDOR-BLOCKED] user=2 tried order=1 ip=127.0.0.1
```

---

## ⚠️ Legal Disclaimer

This application is designed **exclusively for educational purposes** in controlled, isolated
environments. It contains intentional security vulnerabilities. The authors and TCS assume no
liability for misuse. Never deploy this application on public networks. Never use the attack
techniques demonstrated here against systems you do not own or have explicit, written permission
to test. Unauthorized testing of systems is illegal in most jurisdictions.

---

## 📚 References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [bcrypt Python Library](https://pypi.org/project/bcrypt/)

---

*ShopSecure — TCS-ION Industry Project | OWASP Top 10 | May 2026*
