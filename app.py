import os, json, uuid, re, threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright

load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get("SECRET_KEY", "changeme-set-this-in-railway")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# ── Database (Neon Postgres) ──────────────────────────────────
_db_url = os.environ.get("DATABASE_URL", "")
if not _db_url:
    raise RuntimeError("DATABASE_URL env var is not set. Add it in Railway variables.")
# Normalize URL prefix for SQLAlchemy 2.x + psycopg3
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif _db_url.startswith("postgresql://") and "+psycopg" not in _db_url:
    _db_url = _db_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "connect_args": {"sslmode": "require"},
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ── Fernet encryption for cookie jars ────────────────────────
_fk = os.environ.get("FERNET_KEY", "")
if not _fk:
    raise RuntimeError("FERNET_KEY env var is not set. Add it in Railway variables.")
cipher = Fernet(_fk.encode() if isinstance(_fk, str) else _fk)

# ── Playwright browser pool (one shared browser, per-request contexts) ──
_playwright = None
_browser = None
_browser_lock = threading.Lock()


def get_browser():
    global _playwright, _browser
    with _browser_lock:
        if _browser is None:
            _playwright = sync_playwright().start()
            _browser = _playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
        return _browser


# ── Proxy config (IPRoyal) ────────────────────────────────────
PROXY_HOST = os.environ.get("IPROYAL_HOST", "geo.iproyal.com")
PROXY_PORT = os.environ.get("IPROYAL_PORT", "12321")
PROXY_USER = os.environ.get("IPROYAL_USER", "")
PROXY_PASS = os.environ.get("IPROYAL_PASS", "")


# ── Models ────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    proxy_session_id = db.Column(db.String(64), nullable=False,
                                  default=lambda: uuid.uuid4().hex[:16])
    encrypted_cookies = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all(checkfirst=True)


# ── Helpers ───────────────────────────────────────────────────
def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def get_proxy(proxy_session_id):
    if not PROXY_USER or not PROXY_PASS:
        return None
    # Playwright wants server/username/password separately, not a URL string
    return {
        "server": f"http://{PROXY_HOST}:{PROXY_PORT}",
        "username": PROXY_USER,
        "password": PROXY_PASS,
    }


def get_cookies(user):
    try:
        if not user.encrypted_cookies:
            return {}
        return json.loads(cipher.decrypt(user.encrypted_cookies.encode()).decode())
    except Exception:
        return {}


def save_cookies(user, cookies):
    user.encrypted_cookies = cipher.encrypt(json.dumps(cookies).encode()).decode()
    db.session.commit()


# ── Static frontend ───────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ── Auth routes ───────────────────────────────────────────────
@app.route("/api/signup", methods=["POST"])
def signup():
    d = request.json or {}
    username = d.get("username", "").strip()
    email = d.get("email", "").strip().lower()
    password = d.get("password", "")
    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be 8+ characters"}), 400
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "Username or email already taken"}), 409
    pw = bcrypt.generate_password_hash(password).decode()
    empty = cipher.encrypt(b"{}").decode()
    user = User(username=username, email=email, password_hash=pw, encrypted_cookies=empty)
    db.session.add(user)
    db.session.commit()
    session.permanent = True
    session["user_id"] = user.id
    return jsonify({"ok": True, "username": user.username}), 201


@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    identifier = d.get("identifier", "").strip()
    password = d.get("password", "")
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401
    session.permanent = True
    session["user_id"] = user.id
    return jsonify({"ok": True, "username": user.username})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "username": user.username, "email": user.email})


# ── Browse route ──────────────────────────────────────────────
@app.route("/api/browse", methods=["POST"])
def browse():
    d = request.json or {}
    url = d.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    user = current_user()
    proxy = get_proxy(user.proxy_session_id) if user else None
    cookies_dict = get_cookies(user) if user else {}
    domain = re.sub(r"https?://", "", url).split("/")[0]

    context = None
    try:
        browser = get_browser()
        context_args = {
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            "viewport": {"width": 1366, "height": 900},
            "locale": "en-US",
        }
        if proxy:
            context_args["proxy"] = proxy

        context = browser.new_context(**context_args)

        # Restore saved cookies for this domain
        stored = cookies_dict.get(domain, {})
        if stored:
            context.add_cookies([
                {"name": k, "value": v, "domain": domain, "path": "/"}
                for k, v in stored.items()
            ])

        page = context.new_page()
        response = page.goto(url, wait_until="networkidle", timeout=30000)

        final_url = page.url
        html = page.content()
        title = page.title() or url
        status = response.status if response else 200

        # Save cookies back for this domain
        if user:
            all_cookies = context.cookies()
            domain_cookies = {c["name"]: c["value"] for c in all_cookies if domain in c.get("domain", "")}
            if domain_cookies:
                cookies_dict[domain] = domain_cookies
                save_cookies(user, cookies_dict)

        soup = BeautifulSoup(html, "lxml")
        base = soup.new_tag("base", href=final_url)
        head = soup.find("head")
        if head:
            head.insert(0, base)

        return jsonify({
            "ok": True,
            "html": str(soup),
            "final_url": final_url,
            "status": status,
            "title": title,
        })

    except Exception as e:
        msg = str(e)
        if "proxy" in msg.lower() or "ERR_PROXY" in msg or "ERR_TUNNEL" in msg:
            return jsonify({"error": "Proxy connection failed. Check your IPRoyal credentials."}), 502
        if "Timeout" in msg or "timeout" in msg:
            return jsonify({"error": "Request timed out. The site may be slow or unreachable."}), 504
        return jsonify({"error": f"Failed to load: {msg}"}), 500

    finally:
        if context:
            try:
                context.close()
            except Exception:
                pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5555))
    print(f"🖤 void running on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
