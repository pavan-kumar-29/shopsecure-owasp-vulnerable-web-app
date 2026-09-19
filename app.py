#!/usr/bin/env python3
# =============================================================================
#   ShopSecure — OWASP Top 10 (2021) E-Commerce Educational Demo
# =============================================================================
#   ⚠️  WARNING: This app INTENTIONALLY contains security vulnerabilities.
#       Run ONLY in an isolated lab/VM. Never expose to the internet.
# =============================================================================
#   Toggle between "Vulnerable Mode" and "Secure Mode" via the UI button.
#   Every OWASP Top 10 vulnerability is demonstrated AND fixed.
# =============================================================================

import os, re, json, sqlite3, logging, hashlib, secrets, subprocess, base64
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, render_template, request, session,
                   redirect, url_for, jsonify, g, flash, abort, make_response)
from jinja2 import DictLoader
import markupsafe

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("⚠  bcrypt not found — install: pip install bcrypt")

try:
    import requests as _http
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─── Flask app ───────────────────────────────────────────────────────────────
app = Flask(__name__)

# A05 / A07 — Secure: Strong random key; Vulnerable: hardcoded "secret"
SECURE_SECRET = secrets.token_hex(32)
VULN_SECRET   = "secret"   # ← VULNERABLE: predictable, hardcoded key

app.config.update(
    SECRET_KEY             = VULN_SECRET,   # starts in vulnerable mode
    DATABASE               = os.path.join(os.path.dirname(__file__), "ecommerce.db"),
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1),
    SESSION_COOKIE_HTTPONLY= True,
    SESSION_COOKIE_SAMESITE= "Lax",
    DEBUG                  = True,          # A05: debug on by default (vulnerable)
)

# ─── Logging (A09) ───────────────────────────────────────────────────────────
# SECURE: structured security logging to file
secure_log = logging.getLogger("shopsecure")
secure_log.setLevel(logging.INFO)
_fh = logging.FileHandler("security.log")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
secure_log.addHandler(_fh)
# Also log to stdout for easy viewing
_sh = logging.StreamHandler()
_sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
secure_log.addHandler(_sh)

def sec_log(msg):
    """Log only in secure mode. A09 fix."""
    if not is_vulnerable():
        secure_log.info(msg)

def vuln_log(msg):
    """Never logs — demonstrates A09 Logging Failure."""
    pass   # ← VULNERABLE: intentionally empty

# ─── Mode helpers ────────────────────────────────────────────────────────────
def is_vulnerable():
    return session.get("mode", "vulnerable") == "vulnerable"

def mode_label():
    return "VULNERABLE" if is_vulnerable() else "SECURE"

# ─── CSRF helpers (A08 fix) ──────────────────────────────────────────────────
def generate_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def check_csrf():
    if is_vulnerable():
        return True   # A08: no CSRF check in vulnerable mode
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    return secrets.compare_digest(token, session.get("csrf_token", ""))

app.jinja_env.globals["csrf_token"]    = generate_csrf
app.jinja_env.globals["is_vulnerable"] = is_vulnerable
app.jinja_env.globals["mode_label"]    = mode_label

# ─── Secure response headers (A05 fix) ───────────────────────────────────────
@app.after_request
def set_headers(resp):
    if not is_vulnerable():
        resp.headers["X-Frame-Options"]          = "DENY"
        resp.headers["X-Content-Type-Options"]   = "nosniff"
        resp.headers["X-XSS-Protection"]         = "1; mode=block"
        resp.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        resp.headers["Content-Security-Policy"]  = (
            "default-src 'self' https://cdn.tailwindcss.com "
            "https://cdnjs.cloudflare.com; "
            "img-src 'self' https://images.unsplash.com https://via.placeholder.com data:; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
            "https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;"
        )
    return resp

# ─── DB helpers ──────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def query(sql, args=(), one=False, commit=False):
    db  = get_db()
    cur = db.execute(sql, args)
    if commit:
        db.commit()
    rv = cur.fetchone() if one else cur.fetchall()
    return rv

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT UNIQUE NOT NULL,
        email        TEXT UNIQUE NOT NULL,
        password     TEXT NOT NULL,
        role         TEXT DEFAULT 'user',
        address      TEXT DEFAULT '',
        phone        TEXT DEFAULT '',
        created_at   TEXT DEFAULT (datetime('now')),
        last_login   TEXT
    );

    CREATE TABLE IF NOT EXISTS products (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        description TEXT,
        price       REAL NOT NULL,
        category    TEXT,
        image_url   TEXT,
        stock       INTEGER DEFAULT 100,
        rating      REAL DEFAULT 4.0
    );

    CREATE TABLE IF NOT EXISTS cart_items (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        product_id  INTEGER NOT NULL,
        quantity    INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS orders (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        total       REAL NOT NULL,
        status      TEXT DEFAULT 'pending',
        address     TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS order_items (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id    INTEGER NOT NULL,
        product_id  INTEGER NOT NULL,
        quantity    INTEGER NOT NULL,
        unit_price  REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER,
        action      TEXT NOT NULL,
        detail      TEXT,
        ip          TEXT,
        ts          TEXT DEFAULT (datetime('now'))
    );
    """)
    db.commit()

    # Seed products
    count = db.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    if count == 0:
        products = [
            ("iPhone 15 Pro", "Latest Apple smartphone with A17 Pro chip, titanium design, 48MP camera system, USB-C, and Action button.", 999.99, "Electronics",
             "https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=400&q=80", 50, 4.8),
            ("Samsung 4K OLED TV 55\"", "Brilliant 4K OLED display with AI upscaling, Dolby Atmos, and smart TV features.", 799.99, "Electronics",
             "https://images.unsplash.com/photo-1593784991095-a205069470b6?w=400&q=80", 30, 4.7),
            ("Nike Air Max 270", "Lightweight running shoe with Max Air unit for all-day comfort. Available in multiple colors.", 149.99, "Fashion",
             "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400&q=80", 200, 4.5),
            ("Dell XPS 15 Laptop", "15.6\" OLED display, Intel Core i7-13700H, 32GB RAM, 1TB SSD, RTX 4060. Premium ultrabook.", 1299.99, "Electronics",
             "https://images.unsplash.com/photo-1593642632559-0c6d3fc62b89?w=400&q=80", 25, 4.6),
            ("Sony WH-1000XM5 Headphones", "Industry-leading noise cancellation, 30hr battery, multipoint connection, LDAC support.", 299.99, "Electronics",
             "https://images.unsplash.com/photo-1546435770-a3e426bf472b?w=400&q=80", 75, 4.9),
            ("Breville Barista Express", "Integrated grinder, 15-bar pump, PID temperature control. Café-quality espresso at home.", 699.99, "Kitchen",
             "https://images.unsplash.com/photo-1608354580875-30bd4168b351?w=400&q=80", 40, 4.7),
            ("Levi's 501 Original Jeans", "Classic straight-leg jeans in rigid denim. The original blue jean since 1873.", 79.99, "Fashion",
             "https://images.unsplash.com/photo-1542272604-787c3835535d?w=400&q=80", 150, 4.4),
            ("Instant Pot Duo 7-in-1", "Pressure cooker, slow cooker, rice cooker, steamer, sauté, yogurt maker & warmer. 6-quart.", 89.99, "Kitchen",
             "https://images.unsplash.com/photo-1585515320310-259814833e62?w=400&q=80", 100, 4.6),
        ]
        db.executemany(
            "INSERT INTO products(name,description,price,category,image_url,stock,rating) VALUES(?,?,?,?,?,?,?)",
            products
        )

        # Seed admin & demo users
        # VULNERABLE: plaintext / MD5  — SECURE: bcrypt
        # We store bcrypt always in seeding but show both in login logic
        if BCRYPT_AVAILABLE:
            admin_pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
            user_pw  = bcrypt.hashpw(b"password", bcrypt.gensalt()).decode()
        else:
            admin_pw = hashlib.md5(b"admin123").hexdigest()
            user_pw  = hashlib.md5(b"password").hexdigest()

        db.execute(
            "INSERT OR IGNORE INTO users(username,email,password,role) VALUES(?,?,?,?)",
            ("admin", "admin@shop.local", admin_pw, "admin")
        )
        db.execute(
            "INSERT OR IGNORE INTO users(username,email,password,role) VALUES(?,?,?,?)",
            ("alice", "alice@shop.local", user_pw, "user")
        )
        db.execute(
            "INSERT OR IGNORE INTO users(username,email,password,role) VALUES(?,?,?,?)",
            ("bob", "bob@shop.local", user_pw, "user")
        )
        db.commit()
        print("✅  Database seeded: 8 products, 3 users (admin/admin123, alice/password, bob/password)")

# ─── Auth decorators ─────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_vulnerable():
            # SECURE: strict role check
            if not session.get("user_id") or session.get("role") != "admin":
                sec_log(f"[A01] Unauthorized admin access by user_id={session.get('user_id')} ip={request.remote_addr}")
                abort(403)
        # VULNERABLE: no check at all — anyone can access admin
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────────────────────────
#  JINJA2 TEMPLATES  (DictLoader — single-file approach)
# ─────────────────────────────────────────────────────────────────────────────
BASE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{% block title %}ShopSecure{% endblock %} — OWASP Demo</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
  .product-card{transition:all .25s ease}
  .product-card:hover{transform:translateY(-6px);box-shadow:0 20px 40px rgba(0,0,0,.18)}
  .nav-dropdown:hover .nav-menu{display:block}
  .nav-menu{display:none;position:absolute;right:0;top:100%;z-index:999}
  {% if is_vulnerable() %}
  :root{--mc:#ef4444;--mcl:#fef2f2}
  .mode-bar{background:linear-gradient(90deg,#b91c1c,#ef4444,#b91c1c)}
  .toggle-btn{background:#ef4444}
  {% else %}
  :root{--mc:#16a34a;--mcl:#f0fdf4}
  .mode-bar{background:linear-gradient(90deg,#15803d,#16a34a,#15803d)}
  .toggle-btn{background:#16a34a}
  {% endif %}
</style>
</head>
<body class="bg-gray-50 min-h-screen flex flex-col">

<!-- ── Mode Banner ── -->
<div class="mode-bar text-white text-center py-1.5 text-xs font-semibold tracking-wide">
  {% if is_vulnerable() %}
  ⚠️  VULNERABLE MODE ACTIVE — All OWASP Top 10 vulnerabilities are ENABLED — Educational use only ⚠️
  {% else %}
  🔒  SECURE MODE ACTIVE — All OWASP Top 10 vulnerabilities are FIXED — Security best practices enforced 🔒
  {% endif %}
</div>

<!-- ── Navbar ── -->
<nav class="bg-white shadow-md sticky top-0 z-40">
  <div class="max-w-7xl mx-auto px-4 flex items-center justify-between h-16 gap-4">
    <!-- Logo -->
    <a href="/" class="flex items-center gap-2 shrink-0">
      <i class="fas fa-shield-halved text-indigo-600 text-2xl"></i>
      <span class="text-xl font-black text-indigo-600">ShopSecure</span>
    </a>

    <!-- Search -->
    <form action="/search" method="GET" class="flex flex-1 max-w-xl">
      <input name="q" value="{{ request.args.get('q','') }}"
             placeholder="Search products…"
             class="w-full px-4 py-2 border border-r-0 border-gray-300 rounded-l-lg text-sm focus:outline-none focus:border-indigo-400">
      <button class="px-4 bg-indigo-600 text-white rounded-r-lg hover:bg-indigo-700 text-sm">
        <i class="fas fa-search"></i>
      </button>
    </form>

    <!-- Right icons -->
    <div class="flex items-center gap-3 shrink-0">
      <!-- Cart -->
      <a href="/cart" class="relative text-gray-600 hover:text-indigo-600">
        <i class="fas fa-cart-shopping text-xl"></i>
        {% if session.get('cart_count',0) > 0 %}
        <span class="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center leading-none">
          {{ session.get('cart_count',0) }}
        </span>
        {% endif %}
      </a>

      <!-- User menu -->
      {% if session.get('user_id') %}
      <div class="nav-dropdown relative cursor-pointer">
        <button class="flex items-center gap-1 text-gray-700 hover:text-indigo-600 text-sm font-medium">
          <i class="fas fa-circle-user text-lg"></i>
          {{ session.get('username','User') }}
          <i class="fas fa-chevron-down text-xs"></i>
        </button>
        <div class="nav-menu bg-white rounded-xl shadow-xl border border-gray-100 w-52 py-2 mt-1">
          <a href="/profile" class="flex items-center gap-2 px-4 py-2 text-sm text-gray-700 hover:bg-indigo-50"><i class="fas fa-user w-4"></i>My Profile</a>
          <a href="/orders"  class="flex items-center gap-2 px-4 py-2 text-sm text-gray-700 hover:bg-indigo-50"><i class="fas fa-box w-4"></i>My Orders</a>
          {% if session.get('role') == 'admin' or is_vulnerable() %}
          <a href="/admin"   class="flex items-center gap-2 px-4 py-2 text-sm text-orange-600 hover:bg-orange-50"><i class="fas fa-screwdriver-wrench w-4"></i>Admin Panel{% if is_vulnerable() %} ⚠️{% endif %}</a>
          {% endif %}
          <hr class="my-1 border-gray-100">
          <a href="/logout"  class="flex items-center gap-2 px-4 py-2 text-sm text-red-600 hover:bg-red-50"><i class="fas fa-right-from-bracket w-4"></i>Logout</a>
        </div>
vvvv      </div>
      {% else %}
      <a href="/login"    class="text-sm text-gray-600 hover:text-indigo-600">Login</a>
      <a href="/register" class="bg-indigo-600 text-white px-3 py-1.5 rounded-lg text-sm hover:bg-indigo-700">Register</a>
      {% endif %}

      <!-- SSRF demo link -->
      <a href="/fetch-url" title="Fetch URL — SSRF Demo (A10)" class="text-gray-400 hover:text-indigo-500 text-sm">
        <i class="fas fa-globe"></i>
      </a>

      <!-- Mode toggle -->
      <button id="modeBtn" onclick="toggleMode()"
              class="toggle-btn text-white px-3 py-1.5 rounded-full text-xs font-bold hover:opacity-90 transition-all min-w-[90px]">
        {% if is_vulnerable() %}⚠️ VULNERABLE{% else %}🔒 SECURE{% endif %}
      </button>
    </div>
  </div>
</nav>

<!-- ── Flash messages ── -->
<div class="max-w-7xl mx-auto w-full px-4 mt-3 space-y-2">
  {% for cat, msg in get_flashed_messages(with_categories=True) %}
  <div class="p-3 rounded-lg text-sm flex items-start gap-2
    {% if cat=='error' %}bg-red-50 text-red-800 border border-red-200
    {% elif cat=='success' %}bg-green-50 text-green-800 border border-green-200
    {% elif cat=='warning' %}bg-yellow-50 text-yellow-800 border border-yellow-200
    {% else %}bg-blue-50 text-blue-800 border border-blue-200{% endif %}">
    <i class="fas {% if cat=='error' %}fa-circle-exclamation{% elif cat=='success' %}fa-circle-check{% elif cat=='warning' %}fa-triangle-exclamation{% else %}fa-circle-info{% endif %} mt-0.5 shrink-0"></i>
    <span>{{ msg }}</span>
  </div>
  {% endfor %}
</div>

<!-- ── Main content ── -->
<main class="max-w-7xl mx-auto w-full px-4 py-6 flex-1">
  {% block content %}{% endblock %}
</main>

<!-- ── Footer ── -->
<footer class="bg-gray-900 text-white mt-auto py-10">
  <div class="max-w-7xl mx-auto px-4 grid grid-cols-1 md:grid-cols-3 gap-8 text-sm">
    <div>
      <p class="text-lg font-black text-indigo-400 mb-2"><i class="fas fa-shield-halved mr-1"></i>ShopSecure</p>
      <p class="text-gray-400">OWASP Top 10 (2021) Educational Demo</p>
      <p class="text-gray-600 text-xs mt-2">⚠️ LAB USE ONLY — Never deploy in production</p>
    </div>
    <div>
      <p class="font-semibold text-gray-300 mb-3">Quick Vuln Demos</p>
      <ul class="space-y-1.5 text-gray-400">
        <li><a href="/admin" class="hover:text-indigo-400">🔓 /admin — A01 Access Control</a></li>
        <li><a href="/search?q=1' OR '1'='1'--" class="hover:text-indigo-400">💉 SQLi — A03 Injection</a></li>
        <li><a href="/fetch-url" class="hover:text-indigo-400">🌐 /fetch-url — A10 SSRF</a></li>
        <li><a href="/debug" class="hover:text-indigo-400">🐞 /debug — A05 Misconfiguration</a></li>
        <li><a href="/profile/1" class="hover:text-indigo-400">👤 /profile/1 — A01 IDOR</a></li>
        <li><a href="/orders/1" class="hover:text-indigo-400">📦 /orders/1 — A01 IDOR</a></li>
      </ul>
    </div>
    <div>
      <p class="font-semibold text-gray-300 mb-3">Current Mode</p>
      <div class="{% if is_vulnerable() %}bg-red-900 border border-red-700{% else %}bg-green-900 border border-green-700{% endif %} rounded-xl p-4">
        <p class="font-black text-lg {% if is_vulnerable() %}text-red-300{% else %}text-green-300{% endif %}">
          {% if is_vulnerable() %}⚠️ VULNERABLE{% else %}🔒 SECURE{% endif %}
        </p>
        <p class="text-gray-400 text-xs mt-1">Click the mode button in the top nav to switch</p>
        <p class="text-gray-500 text-xs mt-2">Session: {{ session.get('user_id','anonymous') }}</p>
      </div>
    </div>
  </div>
</footer>

<script>
function toggleMode(){
  const btn = document.getElementById('modeBtn');
  btn.textContent = '⏳ Switching…';
  btn.disabled = true;
  fetch('/toggle-mode', {
    method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': '{{ csrf_token() }}'},
    credentials: 'same-origin'
  })
  .then(r => r.json())
  .then(d => { window.location.reload(); })
  .catch(() => { btn.disabled=false; btn.textContent='Error'; });
}
// Cart AJAX helpers
function addToCart(pid){
  fetch('/cart/add', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({product_id: pid, csrf_token: '{{ csrf_token() }}'})
  })
  .then(r=>r.json())
  .then(d=>{
    if(d.success){
      showToast('✅ Added to cart!', 'green');
      document.querySelectorAll('.cart-count').forEach(el=>el.textContent=d.cart_count);
    } else {
      showToast(d.message||'Error adding to cart', 'red');
    }
  });
}
function showToast(msg, color){
  const t = document.createElement('div');
  t.className = `fixed bottom-6 right-6 z-50 px-5 py-3 rounded-xl text-white text-sm font-semibold shadow-2xl bg-${color}-600`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2500);
}
function togglePassword(fieldId, btn){
  const input = document.getElementById(fieldId);
  const icon  = btn.querySelector('i');

  if(input.type === "password"){
    input.type = "text";
    icon.classList.remove("fa-eye");
    icon.classList.add("fa-eye-slash");
  } else {
    input.type = "password";
    icon.classList.remove("fa-eye-slash");
    icon.classList.add("fa-eye");
  }
}
</script>
</body>
</html>
"""

HOME = r"""
{% extends 'base.html' %}
{% block title %}ShopSecure — Home{% endblock %}
{% block content %}

<!-- Hero -->
{% if not search_query %}
<div class="rounded-3xl bg-gradient-to-br from-indigo-600 to-purple-700 text-white p-10 mb-10 flex flex-col md:flex-row items-center justify-between gap-6">
  <div>
    <p class="text-indigo-200 text-sm font-medium mb-2">🎓 OWASP Top 10 Demo Store</p>
    <h1 class="text-4xl font-black mb-3 leading-tight">Welcome to<br>ShopSecure</h1>
    <p class="text-indigo-100 text-lg mb-5">Toggle vulnerabilities ON/OFF with the mode button ↗</p>
    <div class="flex gap-3 flex-wrap">
      <a href="#products" class="bg-white text-indigo-600 px-6 py-3 rounded-full font-bold hover:bg-indigo-50">Shop Now</a>
      <a href="/fetch-url" class="border border-white text-white px-6 py-3 rounded-full font-bold hover:bg-white/10">SSRF Demo</a>
    </div>
  </div>
  <div class="text-right shrink-0">
    <div class="{% if is_vulnerable() %}bg-red-500/30 border border-red-400{% else %}bg-green-500/30 border border-green-400{% endif %} rounded-2xl p-5 text-center min-w-[180px]">
      <p class="text-4xl mb-1">{% if is_vulnerable() %}⚠️{% else %}🔒{% endif %}</p>
      <p class="font-black text-xl">{% if is_vulnerable() %}VULNERABLE{% else %}SECURE{% endif %}</p>
      <p class="text-xs opacity-80 mt-1">Mode Active</p>
    </div>
  </div>
</div>
{% else %}
<div class="mb-6">
  <h2 class="text-2xl font-bold text-gray-800">
    Search results for: <span class="text-indigo-600">"{{ search_query }}"</span>
  </h2>
  {% if is_vulnerable() %}
  <div class="mt-2 p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
    <strong>⚠️ A03 — SQL Injection:</strong> Query run as:
    <code class="bg-red-100 px-1 rounded">SELECT * FROM products WHERE name LIKE '%{{ search_query }}%'</code>
    — user input injected directly. Try: <code class="bg-red-100 px-1 rounded">%' UNION SELECT 1,username,password,email,role,address,phone,created_at,last_login FROM users--</code>
  </div>
  {% else %}
  <div class="mt-2 p-3 bg-green-50 border border-green-200 rounded-lg text-sm text-green-700">
    <strong>🔒 A03 Fixed:</strong> Parameterized query used — input sanitized and safely bound.
  </div>
  {% endif %}
  <a href="/" class="text-indigo-500 text-sm hover:underline mt-1 inline-block">← Back to all products</a>
</div>
{% endif %}

<!-- Category filter -->
{% if not search_query %}
<div class="flex gap-3 flex-wrap mb-6" id="products">
  {% for cat in ['All','Electronics','Fashion','Kitchen'] %}
  <a href="{% if cat=='All' %}/{% else %}/?category={{ cat }}{% endif %}"
     class="px-4 py-2 rounded-full text-sm font-medium border transition
       {% if current_category == cat or (cat=='All' and not current_category) %}bg-indigo-600 text-white border-indigo-600{% else %}bg-white text-gray-600 border-gray-300 hover:border-indigo-400{% endif %}">
    {{ cat }}
  </a>
  {% endfor %}
</div>
{% endif %}

<!-- Products grid -->
{% if products %}
<div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
  {% for p in products %}
  <div class="product-card bg-white rounded-2xl overflow-hidden shadow-sm border border-gray-100">
    <a href="/products/{{ p['id'] }}">
      <div class="h-52 overflow-hidden bg-gray-100">
        <img src="{{ p['image_url'] }}" alt="{{ p['name'] }}"
             class="w-full h-full object-cover hover:scale-105 transition-transform duration-300"
             onerror="this.src='https://via.placeholder.com/400x300?text=Product'">
      </div>
    </a>
    <div class="p-4">
      <span class="text-xs text-indigo-500 font-medium bg-indigo-50 px-2 py-0.5 rounded-full">{{ p['category'] }}</span>
      <a href="/products/{{ p['id'] }}">
        <h3 class="font-bold text-gray-900 mt-2 text-sm leading-tight hover:text-indigo-600 line-clamp-2">{{ p['name'] }}</h3>
      </a>
      <div class="flex items-center gap-1 mt-1">
        {% for i in range(5) %}
        <i class="fas fa-star text-xs {% if i < p['rating']|int %}text-yellow-400{% else %}text-gray-200{% endif %}"></i>
        {% endfor %}
        <span class="text-xs text-gray-500 ml-1">({{ p['rating'] }})</span>
      </div>
      <div class="flex items-center justify-between mt-3">
        <p class="text-lg font-black text-gray-900">${{ "%.2f"|format(p['price']) }}</p>
        <button onclick="addToCart({{ p['id'] }})"
                class="bg-indigo-600 text-white px-3 py-1.5 rounded-lg text-xs font-semibold hover:bg-indigo-700 flex items-center gap-1">
          <i class="fas fa-cart-plus"></i> Add
        </button>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% else %}
<div class="text-center py-20 text-gray-400">
  <i class="fas fa-box-open text-6xl mb-4"></i>
  <p class="text-xl">No products found.</p>
</div>
{% endif %}

<!-- OWASP Info Panel -->
<div class="mt-12 rounded-2xl border {% if is_vulnerable() %}border-red-200 bg-red-50{% else %}border-green-200 bg-green-50{% endif %} p-6">
  <h3 class="font-black text-lg {% if is_vulnerable() %}text-red-700{% else %}text-green-700{% endif %} mb-4">
    {% if is_vulnerable() %}⚠️ Active Vulnerabilities (OWASP Top 10 2021){% else %}🔒 Active Security Controls{% endif %}
  </h3>
  <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
    {% set items = [
      ('A01','Broken Access Control',    'IDOR on /profile/<id> and /orders/<id>; /admin has no auth',  'All routes enforce ownership checks; admin requires role=admin'),
      ('A02','Cryptographic Failures',   'Passwords stored as MD5 hash; no HTTPS enforcement',           'bcrypt with 12 rounds; HSTS header enforced'),
      ('A03','Injection',                'Search uses raw SQL string concat → SQLi; /fetch-url → OS cmd', 'Parameterized queries; subprocess with arg list; input validation'),
      ('A04','Insecure Design',          'Password reset by username only; no rate limiting',             'Token-based reset; login rate limiting concept shown'),
      ('A05','Security Misconfiguration','DEBUG=True; SECRET_KEY=secret; /debug exposes env vars',       'DEBUG=False; strong secret; security headers; generic errors'),
      ('A06','Outdated Components',      'MD5, no pinned deps, simulated vulnerable lib usage',           'bcrypt; pinned requirements.txt; component audit comments'),
      ('A07','Auth Failures',            'User enumeration; no session expiry; weak session secret',      'Generic errors; session timeout; strong HMAC secret'),
      ('A08','Data Integrity Failures',  'No CSRF protection on any form; unsafe deserialization',        'CSRF tokens on all forms; safe JSON serialization only'),
      ('A09','Logging Failures',         'Zero security event logging; no audit trail',                   'All auth events logged to security.log with IP & timestamp'),
      ('A10','SSRF',                     '/fetch-url fetches any URL including 169.254.x.x & localhost',  'Allowlist validation; block RFC-1918 & loopback addresses'),
    ] %}
    {% for code, name, vuln, fix in items %}
    <div class="flex gap-2 p-3 bg-white rounded-xl border {% if is_vulnerable() %}border-red-100{% else %}border-green-100{% endif %}">
      <span class="font-mono text-xs font-bold px-2 py-0.5 rounded {% if is_vulnerable() %}bg-red-100 text-red-700{% else %}bg-green-100 text-green-700{% endif %} shrink-0 h-fit">{{ code }}</span>
      <div>
        <p class="font-semibold text-gray-800 text-xs">{{ name }}</p>
        <p class="text-gray-500 text-xs mt-0.5">{% if is_vulnerable() %}{{ vuln }}{% else %}{{ fix }}{% endif %}</p>
      </div>
    </div>
    {% endfor %}
  </div>
</div>
{% endblock %}
"""

PRODUCT = r"""
{% extends 'base.html' %}
{% block title %}{{ product['name'] }} — ShopSecure{% endblock %}
{% block content %}
<div class="mb-4 text-sm text-gray-500">
  <a href="/" class="hover:text-indigo-600">Home</a> /
  <a href="/?category={{ product['category'] }}" class="hover:text-indigo-600">{{ product['category'] }}</a> /
  <span class="text-gray-800">{{ product['name'] }}</span>
</div>

<div class="bg-white rounded-3xl shadow-sm border border-gray-100 overflow-hidden">
  <div class="grid grid-cols-1 md:grid-cols-2 gap-0">
    <!-- Image -->
    <div class="h-96 md:h-auto bg-gray-100 overflow-hidden">
      <img src="{{ product['image_url'] }}" alt="{{ product['name'] }}"
           class="w-full h-full object-cover"
           onerror="this.src='https://via.placeholder.com/600x400?text={{ product['name'] }}'">
    </div>
    <!-- Details -->
    <div class="p-8 flex flex-col justify-between">
      <div>
        <span class="text-xs text-indigo-500 font-semibold bg-indigo-50 px-3 py-1 rounded-full">{{ product['category'] }}</span>
        <h1 class="text-2xl font-black text-gray-900 mt-3 leading-tight">{{ product['name'] }}</h1>
        <div class="flex items-center gap-2 mt-2">
          {% for i in range(5) %}
          <i class="fas fa-star {% if i < product['rating']|int %}text-yellow-400{% else %}text-gray-200{% endif %}"></i>
          {% endfor %}
          <span class="text-sm text-gray-500">{{ product['rating'] }} / 5.0</span>
        </div>
        <p class="text-3xl font-black text-indigo-600 mt-4">${{ "%.2f"|format(product['price']) }}</p>
        <p class="text-gray-600 text-sm mt-4 leading-relaxed">{{ product['description'] }}</p>
        <p class="text-sm text-gray-500 mt-3">
          <i class="fas fa-warehouse mr-1"></i>
          {% if product['stock'] > 10 %}
          <span class="text-green-600 font-medium">In Stock ({{ product['stock'] }} units)</span>
          {% elif product['stock'] > 0 %}
          <span class="text-orange-500 font-medium">Only {{ product['stock'] }} left!</span>
          {% else %}
          <span class="text-red-500 font-medium">Out of Stock</span>
          {% endif %}
        </p>
      </div>
      <div class="mt-6 space-y-3">
        <button onclick="addToCart({{ product['id'] }})"
                class="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700 flex items-center justify-center gap-2">
          <i class="fas fa-cart-plus"></i> Add to Cart
        </button>
        <a href="/cart" class="block text-center text-indigo-600 border border-indigo-200 py-3 rounded-xl font-semibold hover:bg-indigo-50">
          View Cart
        </a>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

LOGIN_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Login — ShopSecure{% endblock %}
{% block content %}
<div class="max-w-md mx-auto">
  <div class="bg-white rounded-3xl shadow-sm border border-gray-100 p-8">
    <div class="text-center mb-6">
      <i class="fas fa-circle-user text-indigo-500 text-5xl mb-3"></i>
      <h2 class="text-2xl font-black text-gray-900">Welcome back</h2>
      <p class="text-gray-500 text-sm mt-1">Sign in to your account</p>
    </div>

    {% if is_vulnerable() %}
    <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 space-y-1">
      <p><strong>⚠️ A07 Demo:</strong> User enumeration enabled — distinct "user not found" vs "wrong password" messages</p>
      <p><strong>⚠️ A02 Demo:</strong> Passwords verified against MD5 hash (weak)</p>
      <p><strong>⚠️ A09 Demo:</strong> Failed logins are NOT logged</p>
    </div>
    {% else %}
    <div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-xl text-xs text-green-700 space-y-1">
      <p><strong>🔒 A07 Fixed:</strong> Generic "Invalid credentials" message — no enumeration</p>
      <p><strong>🔒 A02 Fixed:</strong> bcrypt password verification</p>
      <p><strong>🔒 A09 Fixed:</strong> All auth events logged to security.log</p>
    </div>
    {% endif %}

    <form action="/login" method="POST" class="space-y-4">
      {% if not is_vulnerable() %}
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      {% endif %}
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Username</label>
        <input type="text" name="username" required autofocus
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="Enter username">
      </div>
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Password</label>
        <div class="relative">
  <input type="password" id="loginPassword" name="password" required
         class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400 pr-10"
         placeholder="Enter password">

  <button type="button"
          onclick="togglePassword('loginPassword', this)"
          class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-indigo-600">
    <i class="fas fa-eye"></i>
  </button>
</div>
      </div>
      <button type="submit"
              class="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700">
        Sign In
      </button>
    </form>

    <div class="mt-4 text-center">
      <a href="/reset-password" class="text-sm text-indigo-500 hover:underline">Forgot password?</a>
    </div>
    <p class="text-center text-sm text-gray-500 mt-4">
      No account? <a href="/register" class="text-indigo-600 font-semibold hover:underline">Register</a>
    </p>
    <div class="mt-6 p-4 bg-gray-50 rounded-xl border border-gray-200 text-xs text-gray-500">
      <strong>Demo credentials:</strong><br>
      admin / admin123 &nbsp;|&nbsp; alice / password &nbsp;|&nbsp; bob / password
    </div>
  </div>
</div>
{% endblock %}
"""

REGISTER_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Register — ShopSecure{% endblock %}
{% block content %}
<div class="max-w-md mx-auto">
  <div class="bg-white rounded-3xl shadow-sm border border-gray-100 p-8">
    <div class="text-center mb-6">
      <i class="fas fa-user-plus text-indigo-500 text-5xl mb-3"></i>
      <h2 class="text-2xl font-black text-gray-900">Create Account</h2>
      <p class="text-gray-500 text-sm mt-1">Join ShopSecure today</p>
    </div>

    {% if is_vulnerable() %}
    <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 space-y-1">
      <p><strong>⚠️ A02:</strong> Password stored as MD5 (collision-vulnerable, rainbow-table crackable)</p>
      <p><strong>⚠️ A04:</strong> No password complexity requirements; no email verification</p>
    </div>
    {% else %}
    <div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-xl text-xs text-green-700 space-y-1">
      <p><strong>🔒 A02 Fixed:</strong> bcrypt with cost=12 — computationally expensive to crack</p>
      <p><strong>🔒 A04 Fixed:</strong> Min 8 chars with complexity enforced; CSRF token required</p>
    </div>
    {% endif %}

    <form action="/register" method="POST" class="space-y-4">
      {% if not is_vulnerable() %}
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      {% endif %}
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Username</label>
        <input type="text" name="username" required
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="Choose a username">
      </div>
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Email</label>
        <input type="email" name="email" required
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="your@email.com">
      </div>
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Password</label>
        <div class="relative">
  <input type="password" id="registerPassword" name="password" required
         {% if not is_vulnerable() %}minlength="8"{% endif %}
         class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400 pr-10"
         placeholder="{% if is_vulnerable() %}any password{% else %}Min 8 chars, include uppercase & number{% endif %}">

  <button type="button"
          onclick="togglePassword('registerPassword', this)"
          class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-indigo-600">
    <i class="fas fa-eye"></i>
  </button>
</div>
               {% if not is_vulnerable() %}minlength="8"{% endif %}
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="{% if is_vulnerable() %}any password{% else %}Min 8 chars, include uppercase & number{% endif %}">
      </div>
      <button type="submit"
              class="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700">
        Create Account
      </button>
    </form>
    <p class="text-center text-sm text-gray-500 mt-4">
      Have an account? <a href="/login" class="text-indigo-600 font-semibold hover:underline">Sign in</a>
    </p>
  </div>
</div>
{% endblock %}
"""

CART_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Cart — ShopSecure{% endblock %}
{% block content %}
<h2 class="text-2xl font-black text-gray-900 mb-6">🛒 Shopping Cart</h2>

{% if not is_vulnerable() %}
<div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-xl text-xs text-green-700">
  <strong>🔒 A08 Fixed:</strong> All cart actions include CSRF token — cross-site request forgery prevented.
</div>
{% else %}
<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700">
  <strong>⚠️ A08 Demo:</strong> No CSRF tokens — a malicious site can silently add items or trigger checkout.
</div>
{% endif %}

{% if items %}
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
  <!-- Cart items -->
  <div class="lg:col-span-2 space-y-4">
    {% for item in items %}
    <div class="bg-white rounded-2xl border border-gray-100 shadow-sm p-4 flex gap-4">
      <img src="{{ item['image_url'] }}" alt="{{ item['name'] }}"
           class="w-24 h-24 object-cover rounded-xl bg-gray-100"
           onerror="this.src='https://via.placeholder.com/96?text=Img'">
      <div class="flex-1">
        <h3 class="font-bold text-gray-800">{{ item['name'] }}</h3>
        <p class="text-sm text-gray-500">{{ item['category'] }}</p>
        <p class="text-indigo-600 font-black text-lg mt-1">${{ "%.2f"|format(item['price']) }}</p>
        <p class="text-xs text-gray-400">Qty: {{ item['quantity'] }}</p>
      </div>
      <form method="POST" action="/cart/remove" class="flex items-start">
        {% if not is_vulnerable() %}<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">{% endif %}
        <input type="hidden" name="cart_id" value="{{ item['cart_id'] }}">
        <button class="text-red-400 hover:text-red-600 p-2"><i class="fas fa-trash"></i></button>
      </form>
    </div>
    {% endfor %}
  </div>

  <!-- Order summary -->
  <div class="bg-white rounded-2xl border border-gray-100 shadow-sm p-6 h-fit">
    <h3 class="font-black text-lg text-gray-800 mb-4">Order Summary</h3>
    <div class="space-y-2 text-sm text-gray-600 border-b border-gray-100 pb-4 mb-4">
      <div class="flex justify-between"><span>Subtotal</span><span>${{ "%.2f"|format(total) }}</span></div>
      <div class="flex justify-between"><span>Shipping</span><span class="text-green-600">Free</span></div>
      <div class="flex justify-between"><span>Tax (10%)</span><span>${{ "%.2f"|format(total * 0.1) }}</span></div>
    </div>
    <div class="flex justify-between font-black text-lg text-gray-900 mb-6">
      <span>Total</span><span>${{ "%.2f"|format(total * 1.1) }}</span>
    </div>
    <a href="/checkout" class="block text-center bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700">
      Proceed to Checkout
    </a>
    <a href="/" class="block text-center text-indigo-600 mt-3 text-sm hover:underline">← Continue Shopping</a>
  </div>
</div>
{% else %}
<div class="text-center py-20 text-gray-400">
  <i class="fas fa-cart-shopping text-6xl mb-4"></i>
  <p class="text-xl font-semibold">Your cart is empty</p>
  <a href="/" class="inline-block mt-4 bg-indigo-600 text-white px-6 py-3 rounded-xl hover:bg-indigo-700 font-semibold">Start Shopping</a>
</div>
{% endif %}
{% endblock %}
"""

CHECKOUT_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Checkout — ShopSecure{% endblock %}
{% block content %}
<h2 class="text-2xl font-black text-gray-900 mb-6">💳 Checkout</h2>

{% if is_vulnerable() %}
<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700">
  <strong>⚠️ A08 Demo:</strong> No CSRF token — form can be submitted cross-site.
  <strong>A04 Demo:</strong> Price not re-validated server-side — client-manipulated prices accepted.
</div>
{% else %}
<div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-xl text-xs text-green-700">
  <strong>🔒 Fixed:</strong> CSRF token validated; prices re-fetched from DB server-side.
</div>
{% endif %}

<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
  <div class="bg-white rounded-3xl border border-gray-100 shadow-sm p-8">
    <h3 class="font-bold text-lg text-gray-800 mb-4">Delivery Information</h3>
    <form action="/checkout" method="POST" class="space-y-4">
      {% if not is_vulnerable() %}<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">{% endif %}
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Full Name</label>
        <input type="text" name="name" required value="{{ session.get('username','') }}"
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400">
      </div>
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Delivery Address</label>
        <textarea name="address" rows="3" required
                  class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
                  placeholder="123 Main St, City, Country"></textarea>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-semibold text-gray-700 mb-1">Card Number</label>
          <input type="text" name="card" placeholder="4242 4242 4242 4242" maxlength="19"
                 class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400">
        </div>
        <div>
          <label class="block text-sm font-semibold text-gray-700 mb-1">CVV</label>
          <input type="text" name="cvv" placeholder="123" maxlength="4"
                 class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400">
        </div>
      </div>
      <button type="submit"
              class="w-full bg-green-600 text-white py-3 rounded-xl font-bold hover:bg-green-700 mt-2">
        <i class="fas fa-lock mr-2"></i>Place Order — ${{ "%.2f"|format(total * 1.1) }}
      </button>
    </form>
  </div>
  <div class="bg-white rounded-3xl border border-gray-100 shadow-sm p-8 h-fit">
    <h3 class="font-bold text-lg text-gray-800 mb-4">Order Summary</h3>
    {% for item in items %}
    <div class="flex justify-between text-sm text-gray-600 py-2 border-b border-gray-50">
      <span>{{ item['name'] }} × {{ item['quantity'] }}</span>
      <span>${{ "%.2f"|format(item['price'] * item['quantity']) }}</span>
    </div>
    {% endfor %}
    <div class="mt-4 space-y-1 text-sm">
      <div class="flex justify-between text-gray-500"><span>Subtotal</span><span>${{ "%.2f"|format(total) }}</span></div>
      <div class="flex justify-between text-gray-500"><span>Tax</span><span>${{ "%.2f"|format(total * 0.1) }}</span></div>
      <div class="flex justify-between font-black text-lg text-gray-900 pt-2 border-t border-gray-100 mt-2">
        <span>Total</span><span class="text-indigo-600">${{ "%.2f"|format(total * 1.1) }}</span>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

ORDERS_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Orders — ShopSecure{% endblock %}
{% block content %}
<div class="flex items-center justify-between mb-6">
  <h2 class="text-2xl font-black text-gray-900">📦 My Orders</h2>
  {% if is_vulnerable() %}
  <div class="p-2 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700">
    ⚠️ A01 IDOR: Try <a href="/orders/1" class="underline font-bold">/orders/1</a>, /orders/2 etc — no ownership check!
  </div>
  {% endif %}
</div>

{% if order %}
<!-- Single order view -->
<div class="bg-white rounded-3xl border border-gray-100 shadow-sm p-8 mb-6">
  {% if is_vulnerable() %}
  <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700">
    ⚠️ <strong>A01 — IDOR Demonstrated:</strong> You can view ANY order by changing the ID in the URL!
    Order belongs to user_id={{ order['user_id'] }}, you are user_id={{ session.get('user_id') }}.
    {% if order['user_id'] != session.get('user_id') %}
    <strong>🚨 UNAUTHORIZED ACCESS SUCCESSFUL!</strong>
    {% endif %}
  </div>
  {% endif %}
  <h3 class="font-black text-lg text-gray-800 mb-1">Order #{{ order['id'] }}</h3>
  <p class="text-sm text-gray-500 mb-4">Placed: {{ order['created_at'] }} | Status: <span class="font-semibold text-indigo-600">{{ order['status'].title() }}</span></p>
  <div class="space-y-3">
    {% for item in order_items %}
    <div class="flex justify-between text-sm text-gray-600 p-3 bg-gray-50 rounded-xl">
      <span>{{ item['name'] }} × {{ item['quantity'] }}</span>
      <span class="font-semibold">${{ "%.2f"|format(item['unit_price'] * item['quantity']) }}</span>
    </div>
    {% endfor %}
  </div>
  <div class="mt-4 flex justify-between font-black text-lg text-gray-900 border-t border-gray-100 pt-4">
    <span>Total</span><span class="text-indigo-600">${{ "%.2f"|format(order['total']) }}</span>
  </div>
  <a href="/orders" class="inline-block mt-4 text-indigo-600 text-sm hover:underline">← All Orders</a>
</div>
{% elif orders %}
<div class="space-y-4">
  {% for o in orders %}
  <div class="bg-white rounded-2xl border border-gray-100 shadow-sm p-6 flex items-center justify-between">
    <div>
      <p class="font-bold text-gray-800">Order #{{ o['id'] }}</p>
      <p class="text-sm text-gray-500">{{ o['created_at'][:16] }}</p>
      <p class="text-xs text-gray-400 mt-1">{{ o['address'][:40] if o['address'] else 'No address' }}…</p>
    </div>
    <div class="text-right">
      <p class="font-black text-indigo-600 text-lg">${{ "%.2f"|format(o['total']) }}</p>
      <span class="text-xs bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full">{{ o['status'].title() }}</span>
      <div class="mt-2">
        <a href="/orders/{{ o['id'] }}" class="text-xs text-indigo-500 hover:underline">View Details →</a>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% else %}
<div class="text-center py-20 text-gray-400">
  <i class="fas fa-box-open text-6xl mb-4"></i>
  <p class="text-xl">No orders yet.</p>
  <a href="/" class="inline-block mt-4 bg-indigo-600 text-white px-6 py-3 rounded-xl hover:bg-indigo-700">Start Shopping</a>
</div>
{% endif %}
{% endblock %}
"""

PROFILE_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Profile — ShopSecure{% endblock %}
{% block content %}
{% if is_vulnerable() %}
<div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-xl text-sm text-red-700">
  ⚠️ <strong>A01 — IDOR:</strong> Try <a href="/profile/1" class="underline font-bold">/profile/1</a>,
  <a href="/profile/2" class="underline font-bold">/profile/2</a> etc — no ownership check server-side.
  You can view any user's profile including email, address, phone.
</div>
{% else %}
<div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-xl text-sm text-green-700">
  🔒 <strong>A01 Fixed:</strong> Server verifies requested user_id matches session user_id. Direct ID enumeration blocked.
</div>
{% endif %}

<div class="max-w-2xl mx-auto bg-white rounded-3xl border border-gray-100 shadow-sm p-8">
  <div class="flex items-center gap-4 mb-6">
    <div class="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center">
      <i class="fas fa-user text-indigo-500 text-2xl"></i>
    </div>
    <div>
      <h2 class="text-xl font-black text-gray-900">{{ user['username'] }}</h2>
      <span class="text-xs bg-{{ 'orange' if user['role']=='admin' else 'indigo' }}-100 text-{{ 'orange' if user['role']=='admin' else 'indigo' }}-700 px-2 py-0.5 rounded-full font-semibold">
        {{ user['role'].title() }}
      </span>
    </div>
  </div>

  <div class="space-y-4">
    <div class="grid grid-cols-2 gap-4">
      <div class="p-4 bg-gray-50 rounded-xl">
        <p class="text-xs text-gray-500 mb-1">Email</p>
        <p class="font-semibold text-gray-800 text-sm">{{ user['email'] }}</p>
      </div>
      <div class="p-4 bg-gray-50 rounded-xl">
        <p class="text-xs text-gray-500 mb-1">Member Since</p>
        <p class="font-semibold text-gray-800 text-sm">{{ user['created_at'][:10] }}</p>
      </div>
    </div>
    <div class="p-4 bg-gray-50 rounded-xl">
      <p class="text-xs text-gray-500 mb-1">Address</p>
      <p class="font-semibold text-gray-800 text-sm">{{ user['address'] or 'Not set' }}</p>
    </div>
    {% if is_vulnerable() %}
    <div class="p-4 bg-red-50 border border-red-200 rounded-xl">
      <p class="text-xs text-red-500 mb-1">⚠️ Password Hash (A02 — exposed in profile)</p>
      <p class="font-mono text-xs text-red-800 break-all">{{ user['password'] }}</p>
    </div>
    {% endif %}
  </div>

  <div class="mt-6 flex gap-3">
    <a href="/orders" class="flex-1 text-center bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700 text-sm">
      View My Orders
    </a>
    <a href="/reset-password" class="flex-1 text-center border border-gray-200 text-gray-700 py-3 rounded-xl font-semibold hover:bg-gray-50 text-sm">
      Reset Password
    </a>
  </div>
</div>
{% endblock %}
"""

ADMIN_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Admin Panel — ShopSecure{% endblock %}
{% block content %}
{% if is_vulnerable() %}
<div class="mb-4 p-4 bg-red-50 border-2 border-red-400 rounded-2xl text-sm text-red-800">
  <strong>🚨 A01 — Broken Access Control DEMONSTRATED:</strong><br>
  You accessed the admin panel <strong>without any authorization check</strong> in vulnerable mode!
  Any user (or unauthenticated visitor) can reach this page and see all user data.
  In secure mode, this page requires <code>role=admin</code>.
</div>
{% else %}
<div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-xl text-sm text-green-700">
  🔒 <strong>A01 Fixed:</strong> This page enforces <code>role=admin</code> check. Non-admin requests receive HTTP 403.
</div>
{% endif %}

<div class="flex items-center gap-3 mb-6">
  <i class="fas fa-screwdriver-wrench text-orange-500 text-2xl"></i>
  <h2 class="text-2xl font-black text-gray-900">Admin Panel</h2>
</div>

<!-- Stats -->
<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
  {% for label, val, icon, color in [('Users', user_count, 'fa-users', 'blue'), ('Products', product_count, 'fa-box', 'indigo'), ('Orders', order_count, 'fa-shopping-bag', 'green'), ('Revenue', '$'+revenue, 'fa-dollar-sign', 'yellow')] %}
  <div class="bg-white rounded-2xl border border-gray-100 shadow-sm p-5">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-{{ color }}-100 rounded-xl flex items-center justify-center">
        <i class="fas {{ icon }} text-{{ color }}-600"></i>
      </div>
      <div>
        <p class="text-2xl font-black text-gray-900">{{ val }}</p>
        <p class="text-xs text-gray-500">{{ label }}</p>
      </div>
    </div>
  </div>
  {% endfor %}
</div>

<!-- User list -->
<div class="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden mb-6">
  <div class="p-4 border-b border-gray-100 flex items-center justify-between">
    <h3 class="font-bold text-gray-800">All Users</h3>
    {% if is_vulnerable() %}
    <span class="text-xs bg-red-100 text-red-600 px-2 py-1 rounded-full">⚠️ Exposed without auth</span>
    {% endif %}
  </div>
  <div class="overflow-x-auto">
    <table class="w-full text-sm">
      <thead class="bg-gray-50 text-gray-500 text-xs">
        <tr>
          <th class="px-4 py-3 text-left">ID</th>
          <th class="px-4 py-3 text-left">Username</th>
          <th class="px-4 py-3 text-left">Email</th>
          <th class="px-4 py-3 text-left">Role</th>
          <th class="px-4 py-3 text-left">{% if is_vulnerable() %}Password Hash ⚠️{% else %}Created{% endif %}</th>
          <th class="px-4 py-3 text-left">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-50">
        {% for u in users %}
        <tr class="hover:bg-gray-50">
          <td class="px-4 py-3 font-mono text-gray-500">{{ u['id'] }}</td>
          <td class="px-4 py-3 font-semibold text-gray-800">{{ u['username'] }}</td>
          <td class="px-4 py-3 text-gray-600">{{ u['email'] }}</td>
          <td class="px-4 py-3">
            <span class="text-xs px-2 py-0.5 rounded-full font-semibold {{ 'bg-orange-100 text-orange-700' if u['role']=='admin' else 'bg-blue-100 text-blue-700' }}">
              {{ u['role'] }}
            </span>
          </td>
          <td class="px-4 py-3 font-mono text-xs text-gray-500 max-w-xs truncate">
            {% if is_vulnerable() %}{{ u['password'] }}{% else %}{{ u['created_at'][:10] }}{% endif %}
          </td>
          <td class="px-4 py-3">
            <a href="/profile/{{ u['id'] }}" class="text-xs text-indigo-500 hover:underline mr-2">View</a>
            <a href="/orders?user_id={{ u['id'] }}" class="text-xs text-indigo-500 hover:underline">Orders</a>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<!-- A06 Banner -->
<div class="p-4 {% if is_vulnerable() %}bg-orange-50 border border-orange-200{% else %}bg-green-50 border border-green-200{% endif %} rounded-2xl text-sm">
  {% if is_vulnerable() %}
  <strong class="text-orange-700">⚠️ A06 — Vulnerable Components:</strong>
  <span class="text-orange-600">App uses MD5 for passwords (broken), no pinned deps, DEBUG=True exposes Werkzeug debugger (RCE risk).</span>
  {% else %}
  <strong class="text-green-700">🔒 A06 Fixed:</strong>
  <span class="text-green-600">bcrypt used; requirements pinned; Werkzeug debugger disabled; component versions audited.</span>
  {% endif %}
</div>
{% endblock %}
"""

FETCH_URL_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Fetch URL — SSRF Demo{% endblock %}
{% block content %}
<div class="max-w-2xl mx-auto">
  <div class="flex items-center gap-3 mb-4">
    <i class="fas fa-globe text-indigo-500 text-3xl"></i>
    <div>
      <h2 class="text-2xl font-black text-gray-900">Fetch URL</h2>
      <p class="text-gray-500 text-sm">A10 — Server-Side Request Forgery (SSRF) Demo</p>
    </div>
  </div>

  <div class="p-4 {% if is_vulnerable() %}bg-red-50 border border-red-200{% else %}bg-green-50 border border-green-200{% endif %} rounded-2xl mb-6 text-sm">
    {% if is_vulnerable() %}
    <strong class="text-red-700">⚠️ A10 — SSRF ACTIVE:</strong>
    <span class="text-red-600"> Server will fetch ANY URL — internal cloud metadata, localhost services, intranet hosts. Try:</span>
    <ul class="mt-2 space-y-1 text-red-600 font-mono text-xs ml-4">
      <li>• http://169.254.169.254/latest/meta-data/ (AWS metadata)</li>
      <li>• http://localhost:22 (local SSH port scan)</li>
      <li>• http://127.0.0.1:5000/admin (internal app access)</li>
      <li>• http://127.0.0.1:6379 (Redis probe)</li>
      <li>• file:///etc/passwd (local file read attempt)</li>
    </ul>
    {% else %}
    <strong class="text-green-700">🔒 A10 Fixed:</strong>
    <span class="text-green-600"> Server validates URL against allowlist. Private IPs (RFC-1918), loopback, link-local, and non-HTTP schemes are blocked.</span>
    {% endif %}
  </div>

  <div class="bg-white rounded-3xl border border-gray-100 shadow-sm p-8">
    <form action="/fetch-url" method="POST" class="space-y-4">
      {% if not is_vulnerable() %}<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">{% endif %}
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-2">
          URL to fetch <span class="text-gray-400 font-normal">(simulates "import from URL" or "thumbnail fetch" feature)</span>
        </label>
        <input type="text" name="url" value="{{ url or '' }}"
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm font-mono focus:outline-none focus:border-indigo-400"
               placeholder="https://example.com">
      </div>
      <button type="submit"
              class="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700">
        <i class="fas fa-paper-plane mr-2"></i>Fetch URL (Server-side)
      </button>
    </form>

    {% if result is defined %}
    <div class="mt-6">
      <div class="flex items-center gap-2 mb-2">
        <h3 class="font-bold text-gray-700">Server Response</h3>
        {% if error %}<span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded-full">Error</span>
        {% else %}<span class="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded-full">Success</span>{% endif %}
      </div>
      <pre class="bg-gray-900 text-green-400 p-4 rounded-xl text-xs overflow-auto max-h-64 whitespace-pre-wrap">{{ result }}</pre>
    </div>
    {% endif %}
  </div>
</div>
{% endblock %}
"""

DEBUG_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Debug — ShopSecure{% endblock %}
{% block content %}
<div class="max-w-3xl mx-auto">
  <h2 class="text-2xl font-black text-gray-900 mb-4">🐞 Debug Information</h2>
  <div class="p-4 {% if is_vulnerable() %}bg-red-50 border border-red-200{% else %}bg-green-50 border border-green-200{% endif %} rounded-2xl mb-6 text-sm">
    {% if is_vulnerable() %}
    <strong class="text-red-700">⚠️ A05 — Security Misconfiguration:</strong>
    <span class="text-red-600"> Debug endpoint exposed. Environment variables, secret key, session contents, and server info visible.</span>
    {% else %}
    <strong class="text-green-700">🔒 A05 Fixed:</strong>
    <span class="text-green-600"> Debug endpoint disabled in secure mode. Returns 404. Sensitive config never exposed.</span>
    {% endif %}
  </div>

  {% if not is_vulnerable() %}
  <div class="text-center py-16 text-gray-400">
    <i class="fas fa-lock text-6xl mb-4 text-green-400"></i>
    <p class="text-xl font-bold">Debug Disabled in Secure Mode</p>
    <p class="text-sm mt-2">Enable Vulnerable Mode to see this page.</p>
  </div>
  {% else %}
  <div class="space-y-4">
    {% for title, content in debug_data %}
    <div class="bg-white rounded-2xl border border-red-100 shadow-sm overflow-hidden">
      <div class="bg-red-50 px-4 py-2 border-b border-red-100">
        <h3 class="font-bold text-red-700 text-sm">⚠️ {{ title }}</h3>
      </div>
      <pre class="p-4 text-xs text-gray-700 overflow-x-auto whitespace-pre-wrap bg-gray-50">{{ content }}</pre>
    </div>
    {% endfor %}
  </div>
  {% endif %}
</div>
{% endblock %}
"""

RESET_PAGE = r"""
{% extends 'base.html' %}
{% block title %}Reset Password — ShopSecure{% endblock %}
{% block content %}
<div class="max-w-md mx-auto">
  <div class="bg-white rounded-3xl border border-gray-100 shadow-sm p-8">
    <div class="text-center mb-6">
      <i class="fas fa-key text-indigo-500 text-5xl mb-3"></i>
      <h2 class="text-2xl font-black text-gray-900">Reset Password</h2>
    </div>

    <div class="mb-4 p-3 {% if is_vulnerable() %}bg-red-50 border border-red-200{% else %}bg-green-50 border border-green-200{% endif %} rounded-xl text-xs">
      {% if is_vulnerable() %}
      <strong class="text-red-700">⚠️ A04 — Insecure Design:</strong>
      <span class="text-red-600"> Password reset requires only username — no token, no email verification, no old password. Anyone who knows a username can reset it!</span>
      {% else %}
      <strong class="text-green-700">🔒 A04 Fixed:</strong>
      <span class="text-green-600"> In production would send a time-limited token to registered email. Current password required. CSRF protected.</span>
      {% endif %}
    </div>

    <form action="/reset-password" method="POST" class="space-y-4">
      {% if not is_vulnerable() %}<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">{% endif %}
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Username</label>
        <input type="text" name="username" required
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="Enter target username">
      </div>
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">New Password</label>
        <input type="password" name="new_password" required
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="New password">
      </div>
      {% if not is_vulnerable() %}
      <div>
        <label class="block text-sm font-semibold text-gray-700 mb-1">Current Password (required)</label>
        <input type="password" name="current_password"
               class="w-full px-4 py-3 border border-gray-300 rounded-xl text-sm focus:outline-none focus:border-indigo-400"
               placeholder="Your current password">
      </div>
      {% endif %}
      <button type="submit" class="w-full bg-indigo-600 text-white py-3 rounded-xl font-bold hover:bg-indigo-700">
        Reset Password
      </button>
    </form>
  </div>
</div>
{% endblock %}
"""

# Register templates via DictLoader
TEMPLATES = {
    "base.html"     : BASE,
    "home.html"     : HOME,
    "product.html"  : PRODUCT,
    "login.html"    : LOGIN_PAGE,
    "register.html" : REGISTER_PAGE,
    "cart.html"     : CART_PAGE,
    "checkout.html" : CHECKOUT_PAGE,
    "orders.html"   : ORDERS_PAGE,
    "profile.html"  : PROFILE_PAGE,
    "admin.html"    : ADMIN_PAGE,
    "fetch_url.html": FETCH_URL_PAGE,
    "debug.html"    : DEBUG_PAGE,
    "reset.html"    : RESET_PAGE,
}
app.jinja_loader = DictLoader(TEMPLATES)

# ─────────────────────────────────────────────────────────────────────────────
#  CART SESSION HELPER
# ─────────────────────────────────────────────────────────────────────────────
def update_cart_count():
    uid = session.get("user_id")
    if uid:
        count = query("SELECT SUM(quantity) FROM cart_items WHERE user_id=?", (uid,), one=True)
        session["cart_count"] = int(count[0] or 0)
    else:
        session["cart_count"] = 0

# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────────────────────

# ── Toggle Mode ──────────────────────────────────────────────────────────────
@app.route("/toggle-mode", methods=["POST"])
def toggle_mode():
    """A07 / A05: Toggle between vulnerable and secure mode."""
    current = session.get("mode", "vulnerable")
    new_mode = "secure" if current == "vulnerable" else "vulnerable"
    session["mode"] = new_mode
    session.permanent = True

    # A05 Fix: change secret key behavior in secure mode
    if new_mode == "secure":
        app.config["DEBUG"] = False
    else:
        app.config["DEBUG"] = True

    sec_log(f"[MODE] Switched to {new_mode.upper()} from ip={request.remote_addr}")
    return jsonify({"mode": new_mode, "success": True})

# ── Home / Search ─────────────────────────────────────────────────────────────
@app.route("/")
def home():
    category = request.args.get("category", "")
    if category:
        products = query(
            "SELECT * FROM products WHERE category=? ORDER BY rating DESC", (category,)
        )
    else:
        products = query("SELECT * FROM products ORDER BY rating DESC")
    return render_template("home.html",
        products=products,
        current_category=category,
        search_query=None
    )

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return redirect(url_for("home"))

    if is_vulnerable():
        # ══════════════════════════════════════════════════════════════════
        # A03 — SQL INJECTION VULNERABILITY
        # User input is directly concatenated into the SQL query string.
        # Payload: %' UNION SELECT 1,username,password,email,role,address,phone,created_at,last_login FROM users--
        # This will leak all user credentials from the users table.
        # ══════════════════════════════════════════════════════════════════
        vuln_log(f"[SEARCH] query={q}")   # A09: no logging
        try:
            sql = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
            products = get_db().execute(sql).fetchall()
        except Exception as e:
            # A05: expose raw DB error
            products = []
            flash(f"Database error: {e}", "error")  # A05: leaks SQL error
    else:
        # ══════════════════════════════════════════════════════════════════
        # A03 — FIXED: Parameterized query — input never touches SQL string
        # ══════════════════════════════════════════════════════════════════
        sec_log(f"[A09-FIXED][SEARCH] user={session.get('username','anon')} q={q[:100]} ip={request.remote_addr}")
        products = query(
            "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
            (f"%{q}%", f"%{q}%")
        )

    return render_template("home.html",
        products=products,
        search_query=q,
        current_category=None
    )

# ── Product Detail ────────────────────────────────────────────────────────────
@app.route("/products/<int:pid>")
def product_detail(pid):
    p = query("SELECT * FROM products WHERE id=?", (pid,), one=True)
    if not p:
        abort(404)
    return render_template("product.html", product=p)

# ── Login ─────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")


        # A08: CSRF check in secure mode
        if not check_csrf():
            flash("Invalid request (CSRF token mismatch).", "error")
            return render_template("login.html")

        if is_vulnerable():
            # ══════════════════════════════════════════════════════════════
            # A07 — AUTH FAILURES: User enumeration
            # Distinct error messages reveal whether username exists.
            # A02 — MD5 password check (rainbow-table vulnerable)
            # A09 — No login event logged
            # A07 — No account lockout / rate limiting
            # ══════════════════════════════════════════════════════════════
            sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                user = get_db().execute(sql).fetchone()
            except Exception as e:
                return f"SQL Error: {e}"
            if not user:
                flash(f"Username '{username}' not found.", "error")   # ← A07: enumerates users!
                return render_template("login.html")

             # A02: MD5 check (also accept bcrypt for seeded users)
             #  md5_pw = hashlib.md5(password.encode()).hexdigest()
             #pw_match = False
             # if BCRYPT_AVAILABLE and user["password"].startswith("$2b$"):
             #   pw_match = bcrypt.checkpw(password, user["password"].encode())
             # else:
             #   pw_match = secrets.compare_digest(md5_pw, user["password"])

             #if not pw_match:
             #  flash("Incorrect password.", "error")   # ← A07: separate message = enumeration
             # return render_template("login.html")

             # ⚠️ Skip password verification (classic SQLi bypass)
             # If query returns a user → login success

            vuln_log("login")  # A09: does nothing

        else:
            # ══════════════════════════════════════════════════════════════
            # A07 FIXED: Generic error, bcrypt verify, security logging
            # A02 FIXED: bcrypt comparison
            # A09 FIXED: Full audit trail
            # ══════════════════════════════════════════════════════════════
            user = query("SELECT * FROM users WHERE username=?", (username,), one=True)
            pw_match = False
            if user and BCRYPT_AVAILABLE and user["password"].startswith("$2b$"):
                pw_match = bcrypt.checkpw(password, user["password"].encode())
            elif user:
                pw_match = secrets.compare_digest(
                    hashlib.md5(password).hexdigest(), user["password"]
                )

            if not user or not pw_match:
                sec_log(f"[A07-FIXED][LOGIN-FAIL] username={username} ip={request.remote_addr}")
                flash("Invalid credentials.", "error")   # ← generic, no enumeration
                return render_template("login.html")

            sec_log(f"[A09-FIXED][LOGIN-OK] user={username} ip={request.remote_addr}")

        # Successful login
        session.clear()
        session["mode"]     = request.form.get("_mode", session.get("mode", "vulnerable"))
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        session["role"]     = user["role"]
        session.permanent   = True
        generate_csrf()
        update_cart_count()
        query("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],), commit=True)
        flash(f"Welcome back, {user['username']}! 👋", "success")
        return redirect(request.args.get("next") or url_for("home"))

    return render_template("login.html")

# ── Register ──────────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not check_csrf():
            flash("Invalid CSRF token.", "error")
            return render_template("register.html")

        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if is_vulnerable():
            # ══════════════════════════════════════════════════════════════
            # A02: Store password as MD5 (weak, no salt)
            # A04: No complexity validation, no email verification
            # ══════════════════════════════════════════════════════════════
            pw_hash = hashlib.md5(password.encode()).hexdigest()
        else:
            # ══════════════════════════════════════════════════════════════
            # A02 FIXED: bcrypt with cost factor 12
            # A04 FIXED: enforce password complexity
            # ══════════════════════════════════════════════════════════════
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return render_template("register.html")
            if not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
                flash("Password must contain at least one uppercase letter and one number.", "error")
                return render_template("register.html")
            if not BCRYPT_AVAILABLE:
                flash("bcrypt not installed — run: pip install bcrypt", "error")
                return render_template("register.html")
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
            sec_log(f"[A09-FIXED][REGISTER] username={username} ip={request.remote_addr}")

        try:
            query(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (username, email, pw_hash), commit=True
            )
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "error")

    return render_template("register.html")

# ── Logout ────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    mode = session.get("mode", "vulnerable")
    sec_log(f"[A09-FIXED][LOGOUT] user={session.get('username','?')} ip={request.remote_addr}")
    session.clear()
    session["mode"] = mode
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

# ── Cart ──────────────────────────────────────────────────────────────────────
@app.route("/cart")
@login_required
def cart():
    uid   = session["user_id"]
    items = query("""
        SELECT ci.id AS cart_id, p.name, p.price, p.category, p.image_url, ci.quantity
        FROM cart_items ci JOIN products p ON ci.product_id=p.id
        WHERE ci.user_id=?
    """, (uid,))
    total = sum(i["price"] * i["quantity"] for i in items)
    return render_template("cart.html", items=items, total=total)

@app.route("/cart/add", methods=["POST"])
@login_required
def cart_add():
    data = request.get_json() or {}
    pid  = data.get("product_id")

    # A08: CSRF check
    if not is_vulnerable():
        token = data.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token, session.get("csrf_token", "")):
            return jsonify({"success": False, "message": "CSRF token invalid"}), 403

    if not pid:
        return jsonify({"success": False, "message": "Invalid product"}), 400

    product = query("SELECT * FROM products WHERE id=?", (pid,), one=True)
    if not product:
        return jsonify({"success": False, "message": "Product not found"}), 404

    uid      = session["user_id"]
    existing = query("SELECT * FROM cart_items WHERE user_id=? AND product_id=?", (uid, pid), one=True)
    if existing:
        query("UPDATE cart_items SET quantity=quantity+1 WHERE user_id=? AND product_id=?",
              (uid, pid), commit=True)
    else:
        query("INSERT INTO cart_items(user_id,product_id,quantity) VALUES(?,?,1)",
              (uid, pid), commit=True)

    update_cart_count()
    return jsonify({"success": True, "cart_count": session.get("cart_count", 0)})

@app.route("/cart/remove", methods=["POST"])
@login_required
def cart_remove():
    if not check_csrf():
        flash("Invalid CSRF token.", "error")
        return redirect(url_for("cart"))
    cart_id = request.form.get("cart_id")
    uid     = session["user_id"]
    if is_vulnerable():
        # A01: No ownership check — can remove anyone's cart item
        query("DELETE FROM cart_items WHERE id=?", (cart_id,), commit=True)
    else:
        # A01 Fixed: Enforce ownership
        query("DELETE FROM cart_items WHERE id=? AND user_id=?", (cart_id, uid), commit=True)
    update_cart_count()
    return redirect(url_for("cart"))

# ── Checkout ──────────────────────────────────────────────────────────────────
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    uid   = session["user_id"]
    items = query("""
        SELECT ci.id, p.id AS product_id, p.name, p.price, p.image_url, p.category, ci.quantity
        FROM cart_items ci JOIN products p ON ci.product_id=p.id
        WHERE ci.user_id=?
    """, (uid,))

    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("cart"))

    if is_vulnerable():
        # A04: Price taken from client (not re-validated from DB)
        total = sum(i["price"] * i["quantity"] for i in items)
    else:
        # A04 Fixed: Always compute total from trusted DB prices
        total = sum(i["price"] * i["quantity"] for i in items)

    if request.method == "POST":
        if not check_csrf():
            flash("Invalid CSRF token.", "error")
            return render_template("checkout.html", items=items, total=total)

        address = request.form.get("address", "").strip()
        if not address:
            flash("Please enter a delivery address.", "error")
            return render_template("checkout.html", items=items, total=total)

        # Create order
        db = get_db()
        cur = db.execute(
            "INSERT INTO orders(user_id,total,status,address) VALUES(?,?,?,?)",
            (uid, round(total * 1.1, 2), "confirmed", address)
        )
        order_id = cur.lastrowid
        for item in items:
            db.execute(
                "INSERT INTO order_items(order_id,product_id,quantity,unit_price) VALUES(?,?,?,?)",
                (order_id, item["product_id"], item["quantity"], item["price"])
            )
        db.execute("DELETE FROM cart_items WHERE user_id=?", (uid,))
        db.commit()

        session["cart_count"] = 0
        sec_log(f"[ORDER] user={uid} order_id={order_id} total={total:.2f}")
        flash(f"✅ Order #{order_id} placed successfully!", "success")
        return redirect(url_for("order_detail", oid=order_id))

    return render_template("checkout.html", items=items, total=total)

# ── Orders ────────────────────────────────────────────────────────────────────
@app.route("/orders")
@login_required
def orders():
    uid = session["user_id"]
    admin_uid = request.args.get("user_id")

    if is_vulnerable() and admin_uid:
        # A01: Admin panel passes user_id param — no privilege check
        rows = query("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (admin_uid,))
    else:
        rows = query("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (uid,))

    return render_template("orders.html", orders=rows, order=None, order_items=None)

@app.route("/orders/<int:oid>")
@login_required
def order_detail(oid):
    uid = session["user_id"]

    if is_vulnerable():
        # ══════════════════════════════════════════════════════════════════
        # A01 — IDOR: No ownership check! Any logged-in user can view
        # any order by guessing the order ID.
        # ══════════════════════════════════════════════════════════════════
        vuln_log(f"[ORDERS] user={uid} accessing order={oid}")
        order = query("SELECT * FROM orders WHERE id=?", (oid,), one=True)
    else:
        # ══════════════════════════════════════════════════════════════════
        # A01 FIXED: Enforce ownership — user can only see their orders
        # ══════════════════════════════════════════════════════════════════
        order = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, uid), one=True)
        if not order:
            sec_log(f"[A01-FIXED][IDOR-BLOCKED] user={uid} tried order={oid} ip={request.remote_addr}")

    if not order:
        flash("Order not found or access denied.", "error")
        return redirect(url_for("orders"))

    items = query("""
        SELECT oi.*, p.name, p.image_url
        FROM order_items oi JOIN products p ON oi.product_id=p.id
        WHERE oi.order_id=?
    """, (oid,))

    return render_template("orders.html", orders=None, order=order, order_items=items)

# ── Profile ───────────────────────────────────────────────────────────────────
@app.route("/profile")
@login_required
def profile():
    uid  = session["user_id"]
    user = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    return render_template("profile.html", user=user)

@app.route("/profile/<int:target_uid>")
@login_required
def profile_idor(target_uid):
    if is_vulnerable():
        # ══════════════════════════════════════════════════════════════════
        # A01 — IDOR: No ownership check — view any user's profile data
        # Reveals: email, address, phone, password hash
        # ══════════════════════════════════════════════════════════════════
        user = query("SELECT * FROM users WHERE id=?", (target_uid,), one=True)
    else:
        # ══════════════════════════════════════════════════════════════════
        # A01 FIXED: Force own profile only
        # ══════════════════════════════════════════════════════════════════
        uid = session["user_id"]
        if target_uid != uid and session.get("role") != "admin":
            sec_log(f"[A01-FIXED][IDOR-BLOCKED] user={uid} tried profile={target_uid} ip={request.remote_addr}")
            abort(403)
        user = query("SELECT * FROM users WHERE id=?", (target_uid,), one=True)

    if not user:
        abort(404)
    return render_template("profile.html", user=user)

# ── Admin ─────────────────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin():
    # ══════════════════════════════════════════════════════════════════
    # A01: In vulnerable mode, @admin_required skips the role check —
    # any user or anonymous visitor can access this page.
    # A06: MD5 password hashes displayed (weak crypto exposure)
    # ══════════════════════════════════════════════════════════════════
    users         = query("SELECT * FROM users ORDER BY id")
    user_count    = query("SELECT COUNT(*) FROM users", one=True)[0]
    product_count = query("SELECT COUNT(*) FROM products", one=True)[0]
    order_count   = query("SELECT COUNT(*) FROM orders", one=True)[0]
    rev           = query("SELECT COALESCE(SUM(total),0) FROM orders", one=True)[0]
    return render_template("admin.html",
        users=users,
        user_count=user_count,
        product_count=product_count,
        order_count=order_count,
        revenue=f"{rev:.2f}"
    )

# ── Password Reset ────────────────────────────────────────────────────────────
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        if not check_csrf():
            flash("Invalid CSRF token.", "error")
            return render_template("reset.html")

        username     = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")

        if is_vulnerable():
            # ══════════════════════════════════════════════════════════════
            # A04 — Insecure Design: Password reset without authentication
            # Anyone who knows a username can reset their password!
            # No token, no email verification, no old password required.
            # ══════════════════════════════════════════════════════════════
            user = query("SELECT * FROM users WHERE username=?", (username,), one=True)
            if not user:
                flash(f"User '{username}' not found.", "error")  # A07: enumeration
                return render_template("reset.html")
            pw_hash = hashlib.md5(new_password.encode()).hexdigest()
            query("UPDATE users SET password=? WHERE username=?", (pw_hash, username), commit=True)
            flash(f"Password for '{username}' reset! (No verification required ⚠️)", "warning")
        else:
            # ══════════════════════════════════════════════════════════════
            # A04 FIXED: Require current session & current password
            # ══════════════════════════════════════════════════════════════
            if not session.get("user_id"):
                flash("You must be logged in to reset your password.", "error")
                return redirect(url_for("login"))
            current = request.form.get("current_password", "").encode()
            user    = query("SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)
            if not user:
                flash("User not found.", "error")
                return render_template("reset.html")
            if BCRYPT_AVAILABLE and user["password"].startswith("$2b$"):
                if not bcrypt.checkpw(current, user["password"].encode()):
                    sec_log(f"[A04-FIXED][RESET-FAIL] user={user['username']} ip={request.remote_addr}")
                    flash("Current password incorrect.", "error")
                    return render_template("reset.html")
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")
                return render_template("reset.html")
            pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12)).decode()
            query("UPDATE users SET password=? WHERE id=?", (pw_hash, user["id"]), commit=True)
            sec_log(f"[A04-FIXED][RESET-OK] user={user['username']} ip={request.remote_addr}")
            flash("Password updated securely.", "success")

    return render_template("reset.html")

# ── SSRF Demo ─────────────────────────────────────────────────────────────────
@app.route("/fetch-url", methods=["GET", "POST"])
def fetch_url():
    result = None
    error  = False
    url    = None

    if request.method == "POST":
        if not check_csrf():
            flash("CSRF token invalid.", "error")
            return render_template("fetch_url.html")

        url = request.form.get("url", "").strip()

        if is_vulnerable():
            # ══════════════════════════════════════════════════════════════
            # A10 — SSRF: Server fetches any URL without restriction.
            # Attacker can: probe internal ports, access cloud metadata,
            # read internal services, bypass firewalls.
            # Also demonstrates A03 OS Command Injection via the ping
            # feature (if enabled via special prefix).
            # ══════════════════════════════════════════════════════════════
            vuln_log(f"[FETCH] url={url}")

            # A03 OS Command Injection: if URL starts with "ping:"
            if url.startswith("ping:"):
                host = url[5:]
                try:
                    # VULNERABLE: direct shell injection possible
                    # e.g., "ping:127.0.0.1; cat /etc/passwd"
                    out = subprocess.check_output(
                        f"ping -c 1 {host}", shell=True,   # ← shell=True is the vulnerability
                        stderr=subprocess.STDOUT, timeout=5
                    )
                    result = f"[OS CMD INJECTION via shell=True]\n$ ping -c 1 {host}\n\n" + out.decode()
                except subprocess.CalledProcessError as e:
                    result = e.output.decode() if e.output else str(e)
                    error  = True
                except Exception as e:
                    result = str(e); error = True
            else:
                if not REQUESTS_AVAILABLE:
                    result = "requests library not installed. Run: pip install requests"
                    error  = True
                else:
                    try:
                        resp   = _http.get(url, timeout=5, allow_redirects=True,
                                           headers={"User-Agent": "ShopSecure/1.0"})
                        result = f"HTTP {resp.status_code} {resp.reason}\n"
                        result += f"Headers: {dict(resp.headers)}\n\n"
                        result += resp.text[:3000]
                    except Exception as e:
                        result = str(e); error = True
        else:
            # ══════════════════════════════════════════════════════════════
            # A10 FIXED: Strict URL allowlist and private IP blocking
            # A03 FIXED: Use subprocess list (no shell injection)
            # ══════════════════════════════════════════════════════════════
            sec_log(f"[A10-FIXED][FETCH] user={session.get('username','anon')} url={url} ip={request.remote_addr}")

            PRIVATE_PATTERNS = [
                r"^https?://localhost", r"^https?://127\.", r"^https?://0\.",
                r"^https?://10\.", r"^https?://172\.(1[6-9]|2\d|3[01])\.",
                r"^https?://192\.168\.", r"^https?://169\.254\.",
                r"^https?://::1", r"^file://", r"^ftp://",
            ]
            blocked = any(re.match(p, url, re.IGNORECASE) for p in PRIVATE_PATTERNS)

            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                result = "🔒 BLOCKED: Only http:// and https:// schemes allowed."
                error  = True
            elif blocked:
                result = "🔒 BLOCKED: Private/internal IP ranges and local addresses are not allowed.\nAllowed: public HTTP/HTTPS URLs only."
                error  = True
            else:
                if not REQUESTS_AVAILABLE:
                    result = "requests library not installed."
                    error  = True
                else:
                    try:
                        resp   = _http.get(url, timeout=5, allow_redirects=False,
                                           headers={"User-Agent": "ShopSecure-Safe/1.0"})
                        result = f"HTTP {resp.status_code}\nContent-Length: {len(resp.content)} bytes\n\n"
                        result += resp.text[:1000] + ("\n[truncated to 1000 chars]" if len(resp.text) > 1000 else "")
                    except Exception as e:
                        result = f"Request failed: {type(e).__name__}"; error = True

    return render_template("fetch_url.html", result=result, error=error, url=url)

# ── Debug (A05) ───────────────────────────────────────────────────────────────
@app.route("/debug")
def debug_page():
    if not is_vulnerable():
        # A05 Fixed: debug endpoint simply doesn't reveal anything
        return render_template("debug.html", debug_data=[])

    # ══════════════════════════════════════════════════════════════════
    # A05 — Security Misconfiguration:
    # Exposes environment variables, secret key, session data,
    # Python version, config values — a goldmine for attackers.
    # ══════════════════════════════════════════════════════════════════
    import sys, platform
    debug_data = [
        ("Flask SECRET_KEY (A05 ⚠️)",          app.config["SECRET_KEY"]),
        ("Environment Variables (A05 ⚠️)",      json.dumps(dict(os.environ), indent=2)[:2000]),
        ("Session Contents (A07 ⚠️)",           json.dumps(dict(session), indent=2, default=str)),
        ("Flask Config (A05 ⚠️)",               json.dumps({k:str(v) for k,v in app.config.items()}, indent=2)),
        ("Python / Platform",                    f"Python {sys.version}\n{platform.platform()}"),
        ("Database Path",                        app.config["DATABASE"]),
        ("Working Directory",                    os.getcwd()),
        ("bcrypt Available",                     str(BCRYPT_AVAILABLE)),
    ]
    return render_template("debug.html", debug_data=debug_data)

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    if is_vulnerable():
        # A05: Verbose error — expose internal info
        return f"<h1>403 Forbidden</h1><pre>Error: {e}\nSession: {dict(session)}\nRoute: {request.path}</pre>", 403
    return render_template("base.html",
        error_title="403 Forbidden",
        error_msg="You don't have permission to access this page."
    ), 403

@app.errorhandler(404)
def not_found(e):
    if is_vulnerable():
        return f"<h1>404 Not Found</h1><pre>{request.path} — {e}</pre>", 404
    return "<h1>404 Not Found</h1><p>The requested page does not exist.</p>", 404

@app.errorhandler(500)
def server_error(e):
    if is_vulnerable():
        # A05: Full traceback exposed to user (default DEBUG behavior)
        return f"<h1>500 Internal Server Error</h1><pre>{e}</pre>", 500
    sec_log(f"[ERROR-500] {e} path={request.path}")
    return "<h1>500 Internal Server Error</h1><p>Something went wrong. Please try again later.</p>", 500

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        init_db()
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           ShopSecure — OWASP Top 10 Demo App                    ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  VULNERABLE MODE starts by default                          ║
║  🔒  Click the red button in the nav to switch to SECURE MODE    ║
╠══════════════════════════════════════════════════════════════════╣
║  Demo Credentials:                                               ║
║    admin / admin123  |  alice / password  |  bob / password     ║
╠══════════════════════════════════════════════════════════════════╣
║  Key OWASP Demo URLs:                                            ║
║    /admin          — A01: Broken Access Control                  ║
║    /search?q=...   — A03: SQL Injection                          ║
║    /fetch-url      — A10: SSRF                                   ║
║    /debug          — A05: Security Misconfiguration              ║
║    /profile/1      — A01: IDOR (profile)                         ║
║    /orders/1       — A01: IDOR (orders)                          ║
║    /reset-password — A04: Insecure Design                        ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
