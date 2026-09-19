# ShopSecure — Project Overview Document

Document Type :** Project Overview
**Version       :** 1.0
**Project Title :**Securing a vulnerable web application(ShopSecure — A Dual-Mode Vulnerable Web Application for OWASP Top 10 Security Education)
**Prepared By   :*[STUDENT_ID], [YOUR_NAME].
**College       :**
**TCS Mentor    :**
**Date          :** 

---

## 1. Project Title

**ShopSecure — A Dual-Mode Vulnerable Web Application for OWASP Top 10 Security Education**

---

## 2. Objective

The primary objective of this project is to design, develop, and demonstrate a fully functional
e-commerce web application that operates in two distinct modes:

### Vulnerable Mode
Intentionally contains real, exploitable security flaws based on the OWASP Top 10 (2021-2025) standard.
This allows students, developers, and security trainees to observe and understand how real-world
attacks are performed against a realistic-looking application — in a safe, controlled lab environment.

### Secure Mode
Implements industry-standard security fixes for every demonstrated vulnerability. It shows the correct,
production-ready approach to building secure web applications using the same codebase and same URLs —
making the before/after comparison immediate and visually clear.

The application acts as a hands-on learning platform. Instead of reading about SQL Injection or SSRF in
a textbook, a learner can:

1. Perform the attack live in the browser
2. Observe the result and understand the real impact
3. Click one button to switch to Secure Mode
4. See exactly how the fix works — same page, same URL, completely different security behavior

---

## 3. Scope

| Area | Details |
|------|---------|
| Web Application | Complete e-commerce site: product listing, search, login/register, cart, checkout, admin panel, user profiles |
| Vulnerability Coverage | All OWASP Top 10 (2021-2025) — 10 vulnerability classes, each with a live working exploit |
| Security Fixes | Every vulnerability has a complete, working secure implementation in the same codebase |
| Toggle Mechanism | Single button in the navigation bar switches all server-side behavior at runtime |
| Database | SQLite with auto-seeded product and user data on first launch |
| Audit Logging | Secure mode logs all security events to security.log with IP and timestamp |
| Target Audience | Security students, junior developers, QA engineers, TCS-ION trainees, and mentors |

**Out of Scope:**
- Production or internet-facing deployment
- Real payment gateway integration
- Cloud hosting or containerization
- Mobile application development

---

## 4. Technologies Used

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.10+ | Backend server-side language |
| Flask | 3.1.x | Lightweight Python web framework |
| SQLite | Built-in | Relational database (users, products, orders) |
| Jinja2 | 3.x | Server-side HTML templating engine |
| Werkzeug | 3.1.x | WSGI utility library used by Flask |
| bcrypt | 4.x | Secure password hashing (Secure Mode) |
| requests | 2.32.x | HTTP client library (SSRF demonstration) |
| Tailwind CSS | CDN 3.x | Utility-first CSS framework for responsive UI |
| Font Awesome | 6.5.x | Icon library for visual elements |
| HTML5 / CSS3 | — | Frontend markup and styling |
| JavaScript (Vanilla) | ES6 | Mode toggle, AJAX cart, toast notifications |
| hashlib / MD5 | Python stdlib | Weak hashing shown in Vulnerable Mode (intentional) |
| MarkupSafe | 3.x | Auto-escaping to prevent XSS (Secure Mode) |

---

## 5. Description of Dual-Mode Architecture

The dual-mode design is the foundational architectural decision of this project. A single Flask session
variable called `mode` (value: `"vulnerable"` or `"secure"`) controls every security-relevant decision at runtime.

### How It Works

```
User clicks mode toggle button in navigation bar
                    ↓
        POST /toggle-mode endpoint
                    ↓
    session["mode"] flips between values
                    ↓
    All route handlers call is_vulnerable()
         ↓                            ↓
  Vulnerable Branch              Secure Branch
  ─────────────────              ─────────────
  Raw SQL string concat          Parameterized queries
  MD5 password hash              bcrypt (cost factor 12)
  No CSRF tokens                 CSRF token on every form
  Open /admin endpoint           role=admin check enforced
  No ownership check             User can only access own data
  Full error stack traces        Generic error messages
  Zero security logging          Full audit trail to security.log
  SSRF on any URL                Private IP blocklist applied
  User enumeration               Generic "invalid credentials"
```

### Core Toggle Function

```python
def is_vulnerable():
    return session.get("mode", "vulnerable") == "vulnerable"

# Every route uses this pattern:
if is_vulnerable():
    # intentionally insecure code path (OWASP vulnerability)
else:
    # industry-standard secure code path (OWASP fix)
```

The toggle requires **no server restart** — a simple page reload is all that is needed.
This makes it perfect for live classroom demos and manager presentations.

---

## 6. OWASP Top 10 (2021-2025) Full Coverage

| Code | Category | ShopSecure Demonstration |
|------|----------|--------------------------|
| A01 | Broken Access Control | /admin (unauthenticated), /profile/ID (IDOR), /orders/ID (IDOR) |
| A02 | Cryptographic Failures | MD5 passwords, hash exposed in admin panel, no HTTPS enforcement |
| A03 | Injection | SQLi in search bar, OS command injection via /fetch-url ping: prefix |
| A04 | Insecure Design | Password reset without any verification — anyone resets any account |
| A05 | Security Misconfiguration | DEBUG=True, hardcoded SECRET_KEY, /debug exposes all config + env vars |
| A06 | Vulnerable Components | MD5 (broken), Werkzeug debugger (RCE risk), no pinned dependencies |
| A07 | Auth Failures | User enumeration on login, no account lockout, weak session secret |
| A08 | Data Integrity Failures | No CSRF protection on any form in Vulnerable Mode |
| A09 | Logging Failures | Zero security events logged in Vulnerable Mode — no audit trail |
| A10 | SSRF | /fetch-url fetches any URL including 169.254.169.254 metadata, localhost |

---

## 7. Why Web Application Security Matters

### Global Impact Statistics
- **43%** of all data breaches involve web applications (Verizon DBIR 2023)
- **$4.88 million** — average cost of a single data breach in 2024 (IBM)
- SQL Injection has been in OWASP Top 10 for over **20 consecutive years**
- **94%** of tested applications had some form of Broken Access Control (OWASP 2021)
- Log4Shell (2021) affected hundreds of **millions** of systems globally

### Relevance to TCS-ION Projects

TCS serves clients across banking, insurance, healthcare, government, and e-commerce — sectors that
handle some of the world's most sensitive financial and personal data.

A single unpatched SQL Injection vulnerability can:
- Expose millions of customer records in a single HTTP request
- Allow attackers to bypass authentication entirely
- Enable complete database takeover

Understanding, detecting, and fixing OWASP Top 10 vulnerabilities is a **core competency** for TCS
application security, penetration testing, code review, and DevSecOps service lines.

---

## 8. Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| alice | password | Regular User |
| bob | password | Regular User |

---

## 9. Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python3 app.py

# Open browser
http://localhost:5000
```

Default mode is **Vulnerable** (red banner). Click the toggle button in the navbar to switch.

---

*Document End — ShopSecure Project Overview v1.0 | TCS-ION Industry Project 2026*
