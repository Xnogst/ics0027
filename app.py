"""Password manager backend (Flask + SQLite). The server only ever stores ciphertext."""
import hashlib, hmac, base64, logging, os, re, secrets, sqlite3, time
from functools import wraps
from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024            # reject oversized bodies
DB = os.environ.get("VAULT_DB", "vault.db")
KDF_ITER = 600_000                                      # must equal ITER in static/app.js
IDLE_SECONDS = 15 * 60
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60
ph = PasswordHasher()                                   # Argon2id by default
DUMMY_HASH = ph.hash("dummy")                           # equalises timing for unknown users
logging.basicConfig(filename="security.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pm")
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, kdf_salt TEXT NOT NULL,
  kdf_iter INTEGER NOT NULL, auth_hash TEXT NOT NULL,
  fails INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS credentials(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  iv TEXT NOT NULL, ciphertext TEXT NOT NULL, updated REAL NOT NULL);
"""
with sqlite3.connect(DB) as _c:
    _c.executescript(SCHEMA)

def _secret():
    if not os.path.exists(".app_secret"):
        with open(".app_secret", "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(".app_secret", "rb") as f:
        return f.read()
SECRET = _secret()                                      # used for fake salts only

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}

def b64ok(v, length=None, maxlen=None):
    return (isinstance(v, str) and B64_RE.match(v) is not None
            and (length is None or len(v) == length) and (maxlen is None or len(v) <= maxlen))

h = lambda s: hashlib.sha256(s.encode()).hexdigest()    # sessions are stored hashed

# ---------- sessions (server-side, so rotation, idle expiry and logout are real) ----------
def new_session(uid):
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = time.time()
    db().execute("DELETE FROM sessions WHERE last_seen < ?", (now - IDLE_SECONDS,))
    db().execute("INSERT INTO sessions VALUES(?,?,?,?)", (h(tok), uid, csrf, now))
    db().commit()
    return tok, csrf

def current_session():
    tok = request.cookies.get("sid")
    if not tok:
        return None
    row = db().execute("SELECT * FROM sessions WHERE token_hash=?", (h(tok),)).fetchone()
    if not row:
        return None
    now = time.time()
    if now - row["last_seen"] > IDLE_SECONDS:
        db().execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
        db().commit()
        return None
    db().execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, row["token_hash"]))
    db().commit()
    return row

def auth(f):
    """Every protected route: valid session + CSRF token on state-changing requests."""
    @wraps(f)
    def wrapper(*a, **k):
        s = current_session()
        if not s:
            return jsonify(error="unauthorized"), 401
        if request.method != "GET" and not hmac.compare_digest(
                request.headers.get("X-CSRF-Token", ""), s["csrf"]):
            return jsonify(error="forbidden"), 403
        g.uid, g.token_hash = s["user_id"], s["token_hash"]
        return f(*a, **k)
    return wrapper

# ---------- headers and errors ----------
@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    r.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    r.headers["Cache-Control"] = "no-store"
    return r

@app.errorhandler(Exception)
def on_error(e):
    if isinstance(e, HTTPException):
        return jsonify(error=e.name), e.code
    log.exception("unhandled error")                    # details go to the log, never the browser
    return jsonify(error="server error"), 500

# ---------- routes ----------
@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/prelogin")
def prelogin():
    u = body().get("username")
    if not (isinstance(u, str) and USER_RE.match(u)):
        return jsonify(error="invalid input"), 400
    row = db().execute("SELECT kdf_salt, kdf_iter FROM users WHERE username=?", (u,)).fetchone()
    if row:
        return jsonify(salt=row["kdf_salt"], iter=row["kdf_iter"])
    fake = base64.b64encode(hmac.new(SECRET, u.encode(), "sha256").digest()[:16]).decode()
    return jsonify(salt=fake, iter=KDF_ITER)            # unknown users look identical

@app.post("/api/register")
def register():
    d = body()
    u, salt, ak = d.get("username"), d.get("salt"), d.get("auth_key")
    if not (isinstance(u, str) and USER_RE.match(u) and b64ok(salt, 24) and b64ok(ak, 44)):
        return jsonify(error="invalid input"), 400
    try:
        db().execute("INSERT INTO users(username,kdf_salt,kdf_iter,auth_hash) VALUES(?,?,?,?)",
                     (u, salt, KDF_ITER, ph.hash(ak)))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username unavailable"), 409
    log.info("register user=%r", u)
    return jsonify(ok=True), 201

def fail():
    return jsonify(error="invalid credentials or try again later"), 401

@app.post("/api/login")
def login():
    d = body()
    u, ak = d.get("username"), d.get("auth_key")
    if not (isinstance(u, str) and USER_RE.match(u) and b64ok(ak, 44)):
        return fail()
    row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    now = time.time()
    if row is None:
        try: ph.verify(DUMMY_HASH, ak)
        except Exception: pass
        log.warning("login_fail unknown user=%r ip=%s", u, request.remote_addr)
        return fail()
    if row["locked_until"] > now:                       # same message as a wrong password
        log.warning("login_while_locked user=%r ip=%s", u, request.remote_addr)
        return fail()
    try:
        ph.verify(row["auth_hash"], ak)
    except (VerifyMismatchError, InvalidHashError):
        fails = row["fails"] + 1
        locked = now + LOCK_SECONDS if fails >= MAX_FAILS else 0
        db().execute("UPDATE users SET fails=?, locked_until=? WHERE id=?",
                     (0 if locked else fails, locked, row["id"]))
        db().commit()
        log.warning("login_fail user=%r ip=%s fails=%d locked=%s", u, request.remote_addr, fails, bool(locked))
        return fail()
    db().execute("UPDATE users SET fails=0, locked_until=0 WHERE id=?", (row["id"],))
    old = request.cookies.get("sid")
    if old:                                             # drop any pre-login session (anti-fixation)
        db().execute("DELETE FROM sessions WHERE token_hash=?", (h(old),))
    tok, csrf = new_session(row["id"])                  # brand-new ID after every login
    resp = jsonify(csrf=csrf)
    resp.set_cookie("sid", tok, httponly=True, secure=True, samesite="Strict", path="/")
    log.info("login_ok user=%r", u)
    return resp

@app.post("/api/logout")
@auth
def logout():
    db().execute("DELETE FROM sessions WHERE token_hash=?", (g.token_hash,))
    db().commit()
    resp = jsonify(ok=True)
    resp.delete_cookie("sid", path="/")
    return resp

def blob_ok(d):
    return b64ok(d.get("iv"), 16) and b64ok(d.get("ciphertext"), maxlen=16384)

@app.get("/api/credentials")
@auth
def list_creds():
    rows = db().execute("SELECT id, iv, ciphertext FROM credentials WHERE user_id=? ORDER BY id",
                        (g.uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/credentials")
@auth
def add_cred():
    d = body()
    if not blob_ok(d):
        return jsonify(error="invalid input"), 400
    cur = db().execute("INSERT INTO credentials(user_id,iv,ciphertext,updated) VALUES(?,?,?,?)",
                       (g.uid, d["iv"], d["ciphertext"], time.time()))
    db().commit()
    return jsonify(id=cur.lastrowid), 201

@app.put("/api/credentials/<int:cid>")
@auth
def update_cred(cid):
    d = body()
    if not blob_ok(d):
        return jsonify(error="invalid input"), 400
    cur = db().execute("UPDATE credentials SET iv=?, ciphertext=?, updated=? WHERE id=? AND user_id=?",
                       (d["iv"], d["ciphertext"], time.time(), cid, g.uid))   # ownership in the query
    db().commit()
    return (jsonify(ok=True), 200) if cur.rowcount else (jsonify(error="Not Found"), 404)

@app.delete("/api/credentials/<int:cid>")
@auth
def delete_cred(cid):
    cur = db().execute("DELETE FROM credentials WHERE id=? AND user_id=?", (cid, g.uid))
    db().commit()
    return (jsonify(ok=True), 200) if cur.rowcount else (jsonify(error="Not Found"), 404)
