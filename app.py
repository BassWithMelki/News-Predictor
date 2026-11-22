import os
import re
import hmac
import json
import time
import math
import base64
import hashlib
import secrets
import sqlite3
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
import requests
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

try:
    import psycopg2
    from psycopg2 import pool as pg_pool
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    pg_pool = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("amgroup")

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except ValueError:
        return default

# API docs are hidden by default so the endpoint list is not public. Set ENABLE_DOCS=1 to show them.
_docs_on = os.getenv("ENABLE_DOCS", "0").strip() == "1"
app = FastAPI(
    title="A&M Group — Trading & Finance Department",
    docs_url="/docs" if _docs_on else None,
    redoc_url="/redoc" if _docs_on else None,
    openapi_url="/openapi.json" if _docs_on else None,
)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@amgroup.com").strip().lower()
FRED_API_KEY = os.getenv("FRED_API_KEY", "").strip()
RAW_DB_URL = os.getenv("DATABASE_URL", "").strip()
REQUIRE_POSTGRES = os.getenv("REQUIRE_POSTGRES", "0").strip() == "1"
DB_POOL_MAX = max(_env_int("DB_POOL_MAX", 5), 1)
SESSION_DAYS = 7
COOKIE_NAME = "am_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "1" if os.getenv("RENDER") else "0").strip() == "1"

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
SECRET_KEY_EPHEMERAL = not SECRET_KEY
if SECRET_KEY_EPHEMERAL:
    SECRET_KEY = secrets.token_hex(32)
    log.warning("SECRET_KEY is not set: using a temporary key, so everyone is logged out on every restart.")
if not os.getenv("ADMIN_EMAIL"):
    log.warning("ADMIN_EMAIL is not set: the default admin address is publicly guessable. Set it on Render.")

def get_clean_db_url():
    if not RAW_DB_URL:
        return ""
    url = RAW_DB_URL.replace(" ", "%20")
    if "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=prefer"
    return url

DATABASE_URL = get_clean_db_url()
USE_POSTGRES = False
DB_STATUS_MSG = "Not checked yet"
PG_SCHEMA_READY = False
_PG_POOL = None
_POOL_LOCK = threading.Lock()
_PG_NEXT_TRY = 0.0  # after a failed connect, wait a few seconds before trying again

class PoolBusy(Exception):
    pass

def _first_line(err) -> str:
    text = str(err).strip()
    return text.splitlines()[0].strip() if text else type(err).__name__

def _create_tables(cur, postgres: bool):
    if postgres:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                whatsapp TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                calc_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT NOT NULL
            )
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                whatsapp TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                calc_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT NOT NULL
            )
        """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS site_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        )
    """)

class PooledConn:
    """Wraps a pooled Postgres connection so the existing conn.close() calls return it to the pool."""
    def __init__(self, pool, raw):
        self._pool = pool
        self._raw = raw
        self._done = False

    def cursor(self, *args, **kwargs):
        return self._raw.cursor(*args, **kwargs)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        if self._done:
            return
        self._done = True
        try:
            self._raw.rollback()
        except Exception:
            pass
        try:
            self._pool.putconn(self._raw, close=bool(getattr(self._raw, "closed", 0)))
        except Exception:
            pass

    def __del__(self):  # safety net: never leak a pooled connection
        try:
            self.close()
        except Exception:
            pass

def is_pg(conn) -> bool:
    return isinstance(conn, PooledConn)

def ph_for(conn) -> str:
    return "%s" if is_pg(conn) else "?"

def _get_pool():
    global _PG_POOL
    with _POOL_LOCK:
        if _PG_POOL is None:
            _PG_POOL = pg_pool.ThreadedConnectionPool(
                1, DB_POOL_MAX, DATABASE_URL, cursor_factory=RealDictCursor, connect_timeout=10
            )
        return _PG_POOL

def _getconn_wait(pool, timeout: float = 8.0):
    deadline = time.time() + timeout
    while True:
        try:
            return pool.getconn()
        except pg_pool.PoolError:
            if time.time() >= deadline:
                raise PoolBusy("all database connections are busy")
            time.sleep(0.05)

def _checkout_pg() -> PooledConn:
    pool = _get_pool()
    raw = _getconn_wait(pool)
    try:  # drop connections the server has silently closed
        probe = raw.cursor()
        probe.execute("SELECT 1")
        probe.close()
        raw.rollback()
    except Exception:
        try:
            pool.putconn(raw, close=True)
        except Exception:
            pass
        raw = _getconn_wait(pool)
    return PooledConn(pool, raw)

def _ensure_pg_schema(conn):
    """Create tables in Postgres once per process (covers Postgres being down at startup)."""
    global PG_SCHEMA_READY
    try:
        cur = conn.cursor()
        _create_tables(cur, True)
        conn.commit()
        try:
            cur.execute(
                "SELECT c.relname, c.relrowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname IN ('users', 'site_settings')"
            )
            off = [r["relname"] for r in cur.fetchall() if not r["relrowsecurity"]]
            if off:
                log.warning("Row Level Security is OFF on: %s. See the README step 'Lock down Supabase'.", ", ".join(off))
        except Exception:
            conn.rollback()
        cur.close()
        PG_SCHEMA_READY = True
    except Exception as err:
        conn.rollback()
        log.warning("Postgres schema notice: %s", err)

def get_db_conn():
    global USE_POSTGRES, DB_STATUS_MSG, _PG_NEXT_TRY
    if not DATABASE_URL:
        DB_STATUS_MSG = "Fallback: DATABASE_URL environment variable is missing or empty"
    elif psycopg2 is None:
        DB_STATUS_MSG = "Fallback: psycopg2 is not installed (add psycopg2-binary to requirements.txt)"
    elif time.time() < _PG_NEXT_TRY:
        pass  # recently failed: keep the last error message and skip the slow retry
    else:
        try:
            conn = _checkout_pg()
            USE_POSTGRES = True
            DB_STATUS_MSG = "Supabase PostgreSQL (Permanent)"
            _PG_NEXT_TRY = 0.0
            if not PG_SCHEMA_READY:
                _ensure_pg_schema(conn)
            return conn
        except PoolBusy:
            raise HTTPException(status_code=503, detail="The server is busy. Please try again in a moment.")
        except Exception as e:
            DB_STATUS_MSG = f"Fallback: {_first_line(e)}"
            _PG_NEXT_TRY = time.time() + 15
            log.warning("Postgres fallback triggered: %s", e)
    USE_POSTGRES = False
    if REQUIRE_POSTGRES:
        raise HTTPException(status_code=503, detail="Database temporarily unavailable. Please try again shortly.")
    conn = sqlite3.connect("am_group_local.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    _create_tables(cur, is_pg(conn))
    conn.commit()
    cur.close()
    conn.close()

try:
    init_db()
except Exception as startup_err:
    log.warning("Startup DB notice: %s", startup_err)

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

def _scrypt(pwd: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(pwd.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=32)

def hash_pwd(pwd: str) -> str:
    """Salted scrypt hash, stored as scrypt$n$r$p$salt$hash."""
    salt = secrets.token_bytes(16)
    dk = _scrypt(pwd, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return "scrypt$%d$%d$%d$%s$%s" % (
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode(),
    )

def legacy_hash(pwd: str) -> str:
    """The old unsalted SHA-256 format. Only used to recognise existing accounts."""
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

def verify_pwd(pwd: str, stored: str):
    """Returns (is_correct, needs_upgrade). Old SHA-256 accounts are upgraded on their next login."""
    if stored.startswith("scrypt$"):
        try:
            _, n, r, p, salt_b64, hash_b64 = stored.split("$")
            expected = base64.b64decode(hash_b64)
            got = _scrypt(pwd, base64.b64decode(salt_b64), int(n), int(r), int(p))
            return hmac.compare_digest(got, expected), False
        except Exception:
            return False, False
    ok = hmac.compare_digest(legacy_hash(pwd), stored)
    return ok, ok

_DUMMY_HASH = None

def dummy_verify(pwd: str):
    """Spend the same time as a real check so unknown emails cannot be detected by timing."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_pwd("not-a-real-password")
    verify_pwd(pwd, _DUMMY_HASH)

def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# ---- signed session cookie (no extra dependencies) ----
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def make_token(email: str) -> str:
    payload = _b64u(json.dumps({"e": email, "x": int(time.time()) + SESSION_DAYS * 86400},
                               separators=(",", ":")).encode())
    sig = _b64u(hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"

def read_token(token: str):
    try:
        payload, sig = token.split(".", 1)
        expected = _b64u(hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_b64u_decode(payload))
        if data["x"] < time.time():
            return None
        return str(data["e"])
    except Exception:
        return None

def set_session_cookie(response: Response, email: str):
    response.set_cookie(
        key=COOKIE_NAME, value=make_token(email), max_age=SESSION_DAYS * 86400,
        httponly=True, samesite="lax", secure=COOKIE_SECURE, path="/",
    )

def current_user(request: Request) -> str:
    token = request.cookies.get(COOKIE_NAME, "")
    email = read_token(token) if token else None
    if not email:
        raise HTTPException(status_code=401, detail="Please log in to continue.")
    return email

def require_admin(email: str = Depends(current_user)) -> str:
    if email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return email

# ---- simple in-memory rate limiter (resets on restart; fine for a single server) ----
class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, key: str, limit: int, window: int):
        now = time.time()
        with self.lock:
            if len(self.hits) > 5000:
                for k in [k for k, q in self.hits.items() if not q or q[-1] <= now - 3600]:
                    del self.hits[k]
            q = self.hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                raise HTTPException(status_code=429, detail="Too many attempts. Please wait a few minutes and try again.")
            q.append(now)

    def clear(self, key: str):
        with self.lock:
            self.hits.pop(key, None)

limiter = RateLimiter()

def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()  # the entry added by Render's proxy
    return request.client.host if request.client else "unknown"

# ---- input checks ----
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()\-]{6,19}$")

def validate_registration(req):
    full_name = req.full_name.strip()
    email = req.email.strip().lower()
    whatsapp = req.whatsapp.strip()
    if not 2 <= len(full_name) <= 100:
        raise HTTPException(status_code=400, detail="Please enter your full name (2 to 100 characters).")
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if not PHONE_RE.match(whatsapp):
        raise HTTPException(status_code=400, detail="Please enter a valid WhatsApp number, e.g. +254700000000.")
    if not 8 <= len(req.password) <= 128:
        raise HTTPException(status_code=400, detail="Password must be 8 to 128 characters long.")
    return full_name, email, whatsapp

def check_numbers(model):
    """Reject NaN, infinity and absurd values in predictor inputs."""
    data = model.model_dump() if hasattr(model, "model_dump") else model.dict()
    for key, value in data.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and (not math.isfinite(value) or abs(value) > 1_000_000):
            raise HTTPException(status_code=422, detail=f"The value for '{key}' is out of range.")

# ---- security headers on every response ----
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
}

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        resp.headers.setdefault(name, value)
    if COOKIE_SECURE:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp

class RegisterReq(BaseModel):
    full_name: str
    email: str
    whatsapp: str
    password: str

class LoginReq(BaseModel):
    email: str
    password: str

class NFPInput(BaseModel):
    user_email: str
    consensus_nfp: int
    icsa_change_k: float
    ccsa_change_k: float
    ism_services_emp: float
    ism_services_prev: float
    adp_actual: int
    adp_consensus: int
    homebase_hours_pct: float
    ism_mfg_emp: float
    ism_mfg_prev: float
    labor_diff_change: float
    nfib_hiring_actual: float = 18.0
    nfib_hiring_prev: float = 17.0
    prev_govt_edu_swing: float = 0.0
    is_summer_school_month: bool = False
    net_strike_weather_adj: float = 0.0

class CPIInput(BaseModel):
    user_email: str
    cpi_mom_consensus: float
    cleveland_nowcast_mom: float
    gas_oil_pct_change: float
    ism_srv_prices: float
    ism_srv_prices_prev: float
    ism_mfg_prices: float
    ism_mfg_prices_prev: float
    ppi_surprise_mom: float
    manheim_used_car_pct: float
    rent_index_pct: float
    nfib_price_plans: float

class DecodeNFPReq(BaseModel):
    consensus_nfp: float
    actual_nfp: float
    unemp_forecast: float
    unemp_actual: float
    ahe_forecast: float
    ahe_actual: float
    revisions_k: float

class DecodeCPIReq(BaseModel):
    headline_forecast: float
    headline_actual: float
    core_forecast: float
    core_actual: float

def increment_usage(email: str):
    if not email:
        return
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        ph = ph_for(conn)
        cur.execute(f"UPDATE users SET calc_count = calc_count + 1 WHERE email = {ph}", (email.lower(),))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

@app.post("/api/register")
def register_user(req: RegisterReq, request: Request, response: Response):
    limiter.check(f"register-ip:{client_ip(request)}", 10, 3600)
    full_name, email, whatsapp = validate_registration(req)
    now = utc_stamp()
    conn = get_db_conn()
    ph = ph_for(conn)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT 1 FROM users WHERE email = {ph}", (email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered. Please log in.")
        cur.execute(
            f"INSERT INTO users (full_name, email, whatsapp, password_hash, calc_count, created_at, last_login) VALUES ({ph}, {ph}, {ph}, {ph}, 0, {ph}, {ph})",
            (full_name, email, whatsapp, hash_pwd(req.password), now, now)
        )
        conn.commit()
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        if type(e).__name__ in ("UniqueViolation", "IntegrityError"):
            raise HTTPException(status_code=400, detail="Email already registered. Please log in.")
        log.exception("Registration failed")
        raise HTTPException(status_code=500, detail="Could not create your account. Please try again.")
    finally:
        cur.close()
        conn.close()
    set_session_cookie(response, email)
    return {"status": "ok", "full_name": full_name, "email": email, "is_admin": email == ADMIN_EMAIL}

@app.post("/api/login")
def login_user(req: LoginReq, request: Request, response: Response):
    email = req.email.strip().lower()[:254]
    limiter.check(f"login-ip:{client_ip(request)}", 30, 600)
    limiter.check(f"login-email:{email}", 8, 600)
    conn = get_db_conn()
    ph = ph_for(conn)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT * FROM users WHERE email = {ph}", (email,))
        user = cur.fetchone()
        if not user:
            dummy_verify(req.password)
            ok, upgrade = False, False
        else:
            ok, upgrade = verify_pwd(req.password, user["password_hash"])
        if not ok:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        now = utc_stamp()
        if upgrade:  # old SHA-256 account: store a salted scrypt hash instead
            cur.execute(
                f"UPDATE users SET password_hash = {ph}, last_login = {ph} WHERE email = {ph}",
                (hash_pwd(req.password), now, email)
            )
        else:
            cur.execute(f"UPDATE users SET last_login = {ph} WHERE email = {ph}", (now, email))
        conn.commit()
        full_name = user["full_name"]
    finally:
        cur.close()
        conn.close()
    limiter.clear(f"login-email:{email}")
    set_session_cookie(response, email)
    return {"status": "ok", "full_name": full_name, "email": email, "is_admin": email == ADMIN_EMAIL}

@app.post("/api/logout")
def logout_user(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "ok"}

@app.get("/api/me")
def whoami(email: str = Depends(current_user)):
    return {"email": email, "is_admin": email == ADMIN_EMAIL}

@app.get("/healthz")
def healthz():
    conn = get_db_conn()  # raises 503 when REQUIRE_POSTGRES=1 and the database is down
    mode = "postgres" if is_pg(conn) else "fallback-sqlite"
    conn.close()
    return {"status": "ok", "database": mode}

@app.get("/api/admin/users")
def get_admin_users(admin: str = Depends(require_admin)):
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, full_name, email, whatsapp, calc_count, created_at, last_login FROM users ORDER BY id DESC")
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        cur.close()
        conn.close()
    return {"db_mode": DB_STATUS_MSG, "users": rows}

class LogoReq(BaseModel):
    email: str = ""
    logo: str

MAX_LOGO_CHARS = 3_000_000  # roughly a 2 MB image once base64-encoded

@app.get("/api/logo")
def get_logo():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        ph = ph_for(conn)
        cur.execute(f"SELECT setting_value FROM site_settings WHERE setting_key = {ph}", ("brand_logo",))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return {"logo": row["setting_value"] if row else ""}
    except Exception:
        return {"logo": ""}

@app.post("/api/logo")
def save_logo(req: LogoReq, admin: str = Depends(require_admin)):
    if not req.logo.startswith("data:image/"):
        raise HTTPException(status_code=400, detail="Logo must be an image file.")
    if len(req.logo) > MAX_LOGO_CHARS:
        raise HTTPException(status_code=413, detail="Logo is too large (max about 2 MB). Please upload a smaller image.")
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        if is_pg(conn):
            cur.execute(
                "INSERT INTO site_settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
                ("brand_logo", req.logo)
            )
        else:
            cur.execute(
                "INSERT OR REPLACE INTO site_settings (setting_key, setting_value) VALUES (?, ?)",
                ("brand_logo", req.logo)
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=500, detail=f"Could not save logo: {_first_line(e)}")
    cur.close()
    conn.close()
    return {"status": "ok", "storage": DB_STATUS_MSG}

def _fetch_fred_obs_uncached(series_id: str, limit: int = 6):
    try:
        if FRED_API_KEY:
            url = f"https://api.stlouisfed.org/fred/series/observations?series_id={series_id}&api_key={FRED_API_KEY}&file_type=json&sort_order=desc&limit={limit}"
            r = requests.get(url, timeout=4).json()
            return [float(o["value"]) for o in r.get("observations", []) if o["value"] != "."]
        else:
            csv_url = f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}"
            resp = requests.get(csv_url, timeout=4)
            if resp.status_code == 200:
                lines = [ln.split(",") for ln in resp.text.strip().splitlines()[1:] if len(ln.split(",")) == 2 and ln.split(",")[1] != "."]
                vals = [float(x[1]) for x in lines[-limit:]]
                vals.reverse()
                return vals
    except Exception:
        pass
    return []

_FRED_CACHE = {}
_FRED_TTL_SECONDS = 900

def fetch_fred_obs(series_id: str, limit: int = 6):
    key = (series_id, limit)
    hit = _FRED_CACHE.get(key)
    if hit and time.time() - hit[0] < _FRED_TTL_SECONDS:
        return list(hit[1])
    vals = _fetch_fred_obs_uncached(series_id, limit)
    if vals:  # never cache a failed/empty lookup
        _FRED_CACHE[key] = (time.time(), list(vals))
    return vals

def fetch_wti_oil_pct():
    try:
        oil_vals = fetch_fred_obs("DCOILWTICO", 25)
        if len(oil_vals) >= 21 and oil_vals[20] != 0:
            return round(((oil_vals[0] - oil_vals[20]) / oil_vals[20]) * 100.0, 2)
    except Exception:
        pass
    gas_vals = fetch_fred_obs("GASREGW", 5)
    if len(gas_vals) >= 5 and gas_vals[4] != 0:
        return round(((gas_vals[0] - gas_vals[4]) / gas_vals[4]) * 100.0, 2)
    return 0.0

@app.get("/api/autofetch")
def autofetch_data(user: str = Depends(require_admin)):
    icsa_vals = fetch_fred_obs("ICSA", 6)
    ccsa_vals = fetch_fred_obs("CCSA", 6)

    icsa_delta = round((icsa_vals[0] - icsa_vals[4]) / 1000.0, 1) if len(icsa_vals) >= 5 else -6.0
    ccsa_delta = round((ccsa_vals[0] - ccsa_vals[4]) / 1000.0, 1) if len(ccsa_vals) >= 5 else -18.0
    oil_pct = fetch_wti_oil_pct()

    source_note = "Live Federal Reserve (FRED API) & WTI Crude Feed" if FRED_API_KEY else "Live Federal Reserve Public CSV & WTI Crude Feed"
    return {
        "source": source_note,
        "nfp": {"icsa_change_k": icsa_delta, "ccsa_change_k": ccsa_delta},
        "cpi": {"gas_oil_pct_change": oil_pct}
    }

@app.post("/api/predict-nfp")
def predict_nfp(data: NFPInput, user: str = Depends(require_admin)):
    check_numbers(data)
    increment_usage(user)
    clamp = lambda v: max(-1.0, min(1.0, v))

    sig_ism_srv = clamp(((data.ism_services_emp - data.ism_services_prev) + ((data.ism_services_emp - 50.0) * 0.5)) / 3.0)
    sig_icsa = clamp(-data.icsa_change_k / 25.0)
    sig_adp = clamp((data.adp_actual - data.adp_consensus) / 50.0)
    sig_ccsa = clamp(-data.ccsa_change_k / 100.0)
    sig_hb = clamp(data.homebase_hours_pct / 2.5)
    sig_nfib = clamp((data.nfib_hiring_actual - data.nfib_hiring_prev) / 4.0)
    sig_labor = clamp(data.labor_diff_change / 4.0)
    sig_ism_mfg = clamp((data.ism_mfg_emp - data.ism_mfg_prev) / 3.0)

    weighted_signal = (
        (sig_ism_srv * 0.22) +
        (sig_icsa * 0.16) +
        (sig_adp * 0.14) +
        (sig_ccsa * 0.12) +
        (sig_hb * 0.12) +
        (sig_nfib * 0.08) +
        (sig_labor * 0.08) +
        (sig_ism_mfg * 0.08)
    )

    proxy_delta = round(weighted_signal * 100.0, 1)
    school_adj = -0.5 * data.prev_govt_edu_swing if abs(data.prev_govt_edu_swing) >= 35.0 else 0.0
    predicted_nfp = round(data.consensus_nfp + proxy_delta + data.net_strike_weather_adj + school_adj, 1)
    edge = round(predicted_nfp - data.consensus_nfp, 1)

    buffer = 40.0 if data.is_summer_school_month else 25.0
    confidence = min(92, round(52 + abs(edge) * 0.55))

    if abs(edge) < buffer:
        bias = "NEUTRAL"
        tier = f"NO-TRADE / LOW EDGE (±{int(buffer)}K Gate)"
        summary = f"Edge ({edge:+.1f}K) inside ±{int(buffer)}K buffer — skip trade to avoid chop. Projected: {predicted_nfp:+.1f}K vs {data.consensus_nfp:+d}K consensus."
        mult = 0.5
    elif edge >= buffer:
        bias = "HOTTER"
        tier = "TIER 1 BEAT (HIGH CONVICTION)" if edge >= buffer + 20 else "TIER 2 BEAT (MODERATE)"
        summary = f"Model projects {predicted_nfp:+.1f}K vs {data.consensus_nfp:+d}K consensus (Edge: {edge:+.1f}K | School Adj: {school_adj:+.1f}K). Expect USD surge & Gold drop."
        mult = 1.25 if edge >= buffer + 20 else 0.95
    else:
        bias = "COOLER"
        tier = "TIER 1 MISS (HIGH CONVICTION)" if edge <= -(buffer + 20) else "TIER 2 MISS (MODERATE)"
        summary = f"Model projects {predicted_nfp:+.1f}K vs {data.consensus_nfp:+d}K consensus (Edge: {edge:+.1f}K | School Adj: {school_adj:+.1f}K). Expect USD sell-off & Gold rally."
        mult = 1.25 if edge <= -(buffer + 20) else 0.95

    assets = [
        {"pair": "XAU/USD (Gold)", "base": 210, "inv": True,  "note": "Highest liquidity & spike ($18–$26 move); let 1m wick settle before entry"},
        {"pair": "USD/JPY",        "base": 85,  "inv": False, "note": "Tracks 2Y/10Y Treasury yields directly"},
        {"pair": "EUR/USD",        "base": 72,  "inv": True,  "note": "Cleanest trend continuation after 5m candle"},
        {"pair": "NAS100",         "base": 140, "inv": True,  "note": "Rate-sensitive; hot jobs/yields pressure tech equities"}
    ]
    impacts = []
    for a in assets:
        mid = round(a["base"] * mult)
        if bias == "NEUTRAL":
            direction = "NO-TRADE / LOW EDGE"
            rng = f"±{max(15, mid - 10)} pips (Chop)"
        elif bias == "HOTTER":
            direction = "BEARISH (SELL)" if a["inv"] else "BULLISH (BUY)"
            rng = f"{max(25, mid - 15)} – {mid + 20} pips"
        else:
            direction = "BULLISH (BUY)" if a["inv"] else "BEARISH (SELL)"
            rng = f"{max(25, mid - 15)} – {mid + 20} pips"
        impacts.append({"pair": a["pair"], "direction": direction, "range": rng, "note": a["note"]})

    return {"score": edge, "bias": bias, "tier": tier, "confidence": confidence, "summary": summary, "pairs": impacts}

@app.post("/api/predict-cpi")
def predict_cpi(data: CPIInput, user: str = Depends(require_admin)):
    check_numbers(data)
    increment_usage(user)
    clamp = lambda v: max(-1.0, min(1.0, v))
    sig_clev = clamp((data.cleveland_nowcast_mom - data.cpi_mom_consensus) / 0.12)
    sig_gas = clamp(data.gas_oil_pct_change / 6.0)
    sig_srv_p = clamp(((data.ism_srv_prices - data.ism_srv_prices_prev) + ((data.ism_srv_prices - 55.0) * 0.3)) / 4.0)
    sig_mfg_p = clamp(((data.ism_mfg_prices - data.ism_mfg_prices_prev) + ((data.ism_mfg_prices - 52.0) * 0.3)) / 4.0)
    sig_ppi = clamp(data.ppi_surprise_mom / 0.2)
    sig_manheim = clamp(data.manheim_used_car_pct / 2.5)
    sig_rent = clamp((data.rent_index_pct - 0.25) / 0.35)
    sig_nfib = clamp((data.nfib_price_plans - 22.0) / 8.0)

    score = round(
        (sig_clev * 25) + (sig_gas * 18) + (sig_srv_p * 15) + (sig_mfg_p * 12) +
        (sig_ppi * 10) + (sig_manheim * 8) + (sig_rent * 7) + (sig_nfib * 5), 1
    )
    confidence = min(83, round(50 + abs(score) * 0.44))

    if score >= 25:
        bias = "HOTTER"
        tier = "TIER 1 (HIGH CONVICTION)" if score >= 45 else "TIER 2 (MODERATE)"
        summary = f"Inflation proxies sit above {data.cpi_mom_consensus}% consensus. Expect hotter CPI, USD surge & XAU/USD drop."
        mult = 1.25 if score >= 45 else 0.9
    elif score <= -25:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if score <= -45 else "TIER 2 (MODERATE)"
        summary = f"Disinflation signals outweigh {data.cpi_mom_consensus}% consensus. Expect cooler CPI, USD drop & XAU/USD surge."
        mult = 1.25 if score <= -45 else 0.9
    else:
        bias = "NEUTRAL"
        tier = "NO CLEAR EDGE (|Score| < 25)"
        summary = "Inflation proxies are balanced. Wait for Core CPI MoM print before entering XAU/USD or FX."
        mult = 0.55

    pairs = [
        {"pair": "XAU/USD (Gold)", "base": 230, "inv": True,  "note": "Explosive $20–$30 reaction to Core CPI; wait 2m for spread to normalize"},
        {"pair": "USD/JPY",        "base": 90,  "inv": False, "note": "Most sensitive to US 2Y yield repricing"},
        {"pair": "EUR/USD",        "base": 75,  "inv": True,  "note": "Strong directional follow-through if Core aligns"},
        {"pair": "GBP/USD",        "base": 80,  "inv": True,  "note": "High volatility; wait 2 minutes for spread normalization"}
    ]
    impacts = []
    for p in pairs:
        mid = round(p["base"] * mult)
        direction = "WHIPSAW / TWO-WAY"
        if bias == "HOTTER":
            direction = "BEARISH (SELL)" if p["inv"] else "BULLISH (BUY)"
        elif bias == "COOLER":
            direction = "BULLISH (BUY)" if p["inv"] else "BEARISH (SELL)"
        impacts.append({"pair": p["pair"], "direction": direction, "range": f"{max(20, mid-12)} – {mid+15} pips", "note": p["note"]})

    return {"score": score, "bias": bias, "tier": tier, "confidence": confidence, "summary": summary, "pairs": impacts}

@app.post("/api/decode-nfp")
def decode_nfp(d: DecodeNFPReq, user: str = Depends(current_user)):
    check_numbers(d)
    nfp_diff = d.actual_nfp - d.consensus_nfp + (d.revisions_k * 0.5)
    unemp_diff = d.unemp_actual - d.unemp_forecast
    ahe_diff = d.ahe_actual - d.ahe_forecast

    if nfp_diff >= 25 and unemp_diff <= 0 and ahe_diff >= 0:
        verdict = "CLEAN USD BULLISH / GOLD BEARISH BREAKOUT"
        plan = "All 3 pillars (Jobs, Unemployment, Wages) beat expectations. Wait for the first 5-minute pullback to SELL XAU/USD (Gold) & EUR/USD or BUY USD/JPY and ride continuation for 45–60 mins."
    elif nfp_diff <= -25 and unemp_diff >= 0 and ahe_diff <= 0:
        verdict = "CLEAN USD BEARISH / GOLD BULLISH RALLY"
        plan = "Labor market cooled across jobs and wages. Look for 5-minute pullback entries to BUY XAU/USD (Gold) & EUR/USD or SELL USD/JPY."
    elif (nfp_diff > 20 and unemp_diff >= 0.2) or (nfp_diff < -20 and unemp_diff <= -0.2):
        verdict = "WHIPSAW REVERSAL TRAP DETECTED (WATCH XAU/USD)"
        plan = "Headline NFP contradicts the Unemployment Rate! Algorithms will violently reverse XAU/USD and USD pairs within 3–10 minutes. Do NOT chase the first candle; trade the reversal back through the pre-news level."
    else:
        verdict = "MIXED / CHOPPY PRINT — STAND ASIDE"
        plan = "Headline and secondary figures offset each other. XAU/USD spreads will widen with fakeouts—preserve capital for CPI."
    return {"verdict": verdict, "plan": plan}

@app.post("/api/decode-cpi")
def decode_cpi(d: DecodeCPIReq, user: str = Depends(current_user)):
    check_numbers(d)
    head_diff = round(d.headline_actual - d.headline_forecast, 2)
    core_diff = round(d.core_actual - d.core_forecast, 2)

    if core_diff >= 0.1 and head_diff >= 0:
        verdict = "HOT CORE & HEADLINE — USD SURGE / GOLD SELL-OFF"
        plan = "Sticky Core CPI locks in hawkish Fed pricing. SELL XAU/USD (Gold) & EUR/USD or BUY USD/JPY on the first 5m consolidation; trend typically holds into London close."
    elif core_diff <= -0.1 and head_diff <= 0:
        verdict = "COOL CORE & HEADLINE — USD DROP / GOLD BREAKOUT"
        plan = "Disinflation confirmed in Core CPI. BUY XAU/USD (Gold) & EUR/USD or SELL USD/JPY after the initial 2-minute spread settles."
    elif head_diff >= 0.1 and core_diff <= -0.1:
        verdict = "FALSE SPIKE TRAP (HEADLINE HOT, CORE COOL)"
        plan = "Core CPI missed! The Fed ignores energy-driven headline spikes when Core cools. Fade the initial XAU/USD drop and BUY Gold after the 5-minute candle closes."
    else:
        verdict = "INLINE CPI PRINT — FADE EXTREME WICKS"
        plan = "Numbers matched Wall Street consensus. Initial XAU/USD volatility is just stop-hunting; look for mean reversion back to pre-release levels."
    return {"verdict": verdict, "plan": plan}

# ---------------------------------------------------------------------------
# Self-service password reset (email + registered WhatsApp number, no email server needed)
# ---------------------------------------------------------------------------
class ResetPasswordReq(BaseModel):
    email: str
    whatsapp: str
    new_password: str

def _norm_phone(phone: str) -> str:
    return re.sub(r"[\s\-()]", "", phone or "")

@app.post("/api/reset-password")
def reset_password(req: ResetPasswordReq, request: Request):
    limiter.check(f"reset-ip:{client_ip(request)}", 8, 900)
    email = req.email.strip().lower()[:254]
    limiter.check(f"reset-email:{email}", 5, 900)  # also slow down guessing against one account
    if not 8 <= len(req.new_password) <= 128:
        raise HTTPException(status_code=400, detail="Password must be 8 to 128 characters long.")
    mismatch = HTTPException(status_code=400, detail="Email and WhatsApp number did not match our records.")
    submitted = _norm_phone(req.whatsapp)

    conn = get_db_conn()
    ph = ph_for(conn)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT whatsapp FROM users WHERE email = {ph}", (email,))
        row = cur.fetchone()
        stored = _norm_phone(row["whatsapp"]) if row else ""
        numbers_match = hmac.compare_digest(stored.encode("utf-8"), submitted.encode("utf-8"))
        # The admin account is excluded: its WhatsApp number must never be enough to take it over,
        # because the admin can read every customer's number (the secret used by this reset).
        if not (row and submitted and numbers_match) or email == ADMIN_EMAIL:
            raise mismatch
        cur.execute(f"UPDATE users SET password_hash = {ph} WHERE email = {ph}", (hash_pwd(req.new_password), email))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    limiter.clear(f"login-email:{email}")
    log.info("Password reset completed for %s", email)
    return {"status": "ok"}

# ---------------------------------------------------------------------------
# Shared helpers for the new spike matrices
# ---------------------------------------------------------------------------
def _spike_rows(assets, bias_dir, mult, neutral_label="WHIPSAW / TWO-WAY"):
    """bias_dir: +1 = USD bullish, -1 = USD bearish, 0 = no edge."""
    rows = []
    for a in assets:
        mid = round(a["base"] * mult)
        if bias_dir == 0:
            direction = neutral_label
        elif bias_dir > 0:
            direction = "BEARISH (SELL)" if a["inv"] else "BULLISH (BUY)"
        else:
            direction = "BULLISH (BUY)" if a["inv"] else "BEARISH (SELL)"
        rows.append({"pair": a["pair"], "direction": direction,
                     "range": f"{max(20, mid - 12)} – {mid + 15} pips", "note": a["note"]})
    return rows

# ---------------------------------------------------------------------------
# PPI V2 predictor + post-release decoder
# ---------------------------------------------------------------------------
class PPIInput(BaseModel):
    user_email: str
    ppi_mom_consensus: float = 0.3
    ism_srv_prices: float = 73.0
    ism_srv_prices_prev: float = 74.0
    ism_mfg_prices: float = 75.2
    ism_mfg_prices_prev: float = 77.9
    gas_oil_pct_change: float = -10.3
    regional_fed_prices: float = 28.0
    regional_fed_prices_prev: float = 24.0
    freight_rate_pct: float = 2.0
    agri_metals_pct: float = 1.5
    nfib_price_plans: float = 37.0
    import_price_surprise: float = 0.0
    is_jan_or_jul: bool = False

class DecodePPIReq(BaseModel):
    headline_forecast: float
    headline_actual: float
    core_forecast: float
    core_actual: float

@app.post("/api/predict-ppi")
def predict_ppi(data: PPIInput, user: str = Depends(require_admin)):
    check_numbers(data)
    increment_usage(user)
    clamp = lambda v: max(-1.0, min(1.0, v))
    srv_delta = data.ism_srv_prices - data.ism_srv_prices_prev

    sig_srv = clamp((srv_delta + ((data.ism_srv_prices - 55.0) * 0.3)) / 4.0)
    sig_mfg = clamp(((data.ism_mfg_prices - data.ism_mfg_prices_prev) + ((data.ism_mfg_prices - 52.0) * 0.3)) / 4.0)
    sig_oil = clamp(data.gas_oil_pct_change / 6.0)
    sig_fed = clamp(((data.regional_fed_prices - data.regional_fed_prices_prev) + ((data.regional_fed_prices - 20.0) * 0.25)) / 8.0)
    sig_frt = clamp(data.freight_rate_pct / 8.0)
    sig_met = clamp(data.agri_metals_pct / 5.0)
    sig_nfib = clamp((data.nfib_price_plans - 22.0) / 8.0)
    sig_imp = clamp(data.import_price_surprise / 0.3)

    score = round(
        (sig_srv * 22) + (sig_mfg * 18) + (sig_oil * 18) + (sig_fed * 14) +
        (sig_frt * 8) + (sig_met * 8) + (sig_nfib * 7) + (sig_imp * 5), 1
    )

    # V2 safeguard 1: sharp oil drops widen retail fuel margins, which PPI counts as a price gain
    margin_offset = data.gas_oil_pct_change < -10.0
    if margin_offset:
        score = round(score + 4.0, 1)

    # V2 safeguard 2: dynamic no-trade buffer
    buffer = 35.0 if data.is_jan_or_jul else 25.0
    buffer_reason = "Jan/Jul seasonal-reset window" if data.is_jan_or_jul else "standard gate"
    if (data.gas_oil_pct_change > 8.0 and srv_delta < -1.5) or (data.gas_oil_pct_change < -8.0 and srv_delta > 1.5):
        if buffer < 38.0:
            buffer = 38.0
            buffer_reason = "oil and ISM services prices are pulling in opposite directions"

    if abs(score) < buffer:
        bias, bias_dir, mult = "NEUTRAL", 0, 0.55
        verdict = "NO-TRADE / LOW EDGE"
        tier = f"NO-TRADE / LOW EDGE (±{buffer:g} gate: {buffer_reason})"
        summary = f"Score {score:+.1f} is inside the ±{buffer:g} gate ({buffer_reason}). Skip the PPI spike and wait for the print."
    elif score >= buffer:
        strong = score >= buffer + 20
        bias, bias_dir, mult = "HOTTER", 1, (1.2 if strong else 0.9)
        verdict = "HOTTER (USD BULLISH / GOLD BEARISH)"
        tier = ("TIER 1 " if strong else "TIER 2 ") + verdict
        summary = f"Producer-price proxies sit above the {data.ppi_mom_consensus}% consensus (score {score:+.1f} vs ±{buffer:g} gate). Lean USD up, Gold down."
    else:
        strong = score <= -(buffer + 20)
        bias, bias_dir, mult = "COOLER", -1, (1.2 if strong else 0.9)
        verdict = "COOLER (USD BEARISH / GOLD BULLISH)"
        tier = ("TIER 1 " if strong else "TIER 2 ") + verdict
        summary = f"Producer-price proxies sit below the {data.ppi_mom_consensus}% consensus (score {score:+.1f} vs ±{buffer:g} gate). Lean USD down, Gold up."
    if margin_offset:
        summary += " Includes the +4.0 retail-margin offset for the sharp oil drop."

    assets = [
        {"pair": "XAU/USD (Gold)", "base": 145, "inv": True,  "note": "PPI moves are usually smaller than CPI; let the spread settle for 2 minutes"},
        {"pair": "USD/JPY",        "base": 65,  "inv": False, "note": "Follows US 2Y yield repricing after the print"},
        {"pair": "EUR/USD",        "base": 58,  "inv": True,  "note": "Cleaner follow-through when core PPI agrees with headline"},
        {"pair": "GBP/USD",        "base": 62,  "inv": True,  "note": "Wide spreads at 8:30 AM ET; wait for the 5m candle"},
    ]
    return {"score": score, "bias": bias, "verdict": verdict, "tier": tier, "buffer": buffer,
            "buffer_reason": buffer_reason, "margin_offset_applied": margin_offset,
            "summary": summary, "pairs": _spike_rows(assets, bias_dir, mult)}

@app.post("/api/decode-ppi")
def decode_ppi(d: DecodePPIReq, user: str = Depends(current_user)):
    check_numbers(d)
    head_diff = round(d.headline_actual - d.headline_forecast, 2)
    core_diff = round(d.core_actual - d.core_forecast, 2)

    if head_diff >= 0.2 and core_diff <= 0.0:
        verdict = "PPI FALSE SPIKE / TRADE-MARGIN TRAP (HEADLINE HOT, CORE NOT)"
        plan = ("Headline beat without a matching core beat usually means energy or volatile trade margins, not broad pricing pressure. "
                "XAU/USD (Gold): fade the initial drop and look to BUY after the 5-minute candle closes. "
                "USD/JPY: do not chase the first spike higher; wait for a pullback and a clear hold. "
                "EUR/USD: expect the first dip to retrace; BUY only after the 5m close back above the pre-news level.")
    elif head_diff <= -0.2 and core_diff >= 0.1:
        verdict = "PPI MARGIN-DRIVEN HEADLINE MISS TRAP (CORE FIRM)"
        plan = ("Headline missed but core stayed firm, so the weakness is probably volatile margins or energy. "
                "XAU/USD (Gold): fade the initial rally and look to SELL a failed 5-minute breakout. "
                "USD/JPY: the first drop is often bought back; wait for a 5m close back above the pre-news level before buying. "
                "EUR/USD: treat the first push higher as suspect and SELL a failed breakout.")
    elif core_diff >= 0.1 and head_diff >= 0:
        verdict = "HOT CORE & HEADLINE PPI — LEAN USD BULLISH / GOLD BEARISH"
        plan = ("Both measures beat, so the move has support. "
                "XAU/USD (Gold): SELL the first 5-minute pullback. "
                "USD/JPY: BUY the first 5-minute pullback while 2Y yields hold their rise. "
                "EUR/USD: SELL the first 5-minute pullback. PPI usually moves price less than CPI, so keep size modest.")
    elif core_diff <= -0.1 and head_diff <= 0:
        verdict = "COOL CORE & HEADLINE PPI — LEAN USD BEARISH / GOLD BULLISH"
        plan = ("Both measures missed. "
                "XAU/USD (Gold): BUY the first 5-minute pullback once the spread has settled. "
                "USD/JPY: SELL the first 5-minute pullback. "
                "EUR/USD: BUY the first 5-minute pullback. Keep size modest because PPI reactions often fade.")
    else:
        verdict = "INLINE / MIXED PPI PRINT — STAND ASIDE"
        plan = ("Headline and core offset each other or matched forecasts. "
                "XAU/USD (Gold), USD/JPY and EUR/USD: expect two-way wicks with no clean trend, so skip it and keep capital for the next release.")
    return {"verdict": verdict, "plan": plan}

# ---------------------------------------------------------------------------
# FOMC pre-meeting gauge + instant statement / chair press-conference decoder
# ---------------------------------------------------------------------------
FOMC_MOVES = ("CUT_25", "HOLD", "HIKE_25")
FOMC_NFP = ("STRONG", "INLINE", "WEAK")
FOMC_RATE = ("MORE_HAWKISH", "INLINE", "MORE_DOVISH")
FOMC_DOTS = ("HAWKISH_SHIFT", "UNCHANGED", "DOVISH_SHIFT")
FOMC_VOTES = ("UNANIMOUS", "HAWKISH_DISSENT", "DOVISH_DISSENT")
FOMC_CUES = ("PENDING", "PUSHBACK_ON_CUTS", "DATA_DEPENDENT", "OPEN_TO_EASING")

class FOMCPreInput(BaseModel):
    user_email: str
    fedwatch_prob_pct: float = 82.0
    expected_move: str = "HOLD"
    us2y_yield_5d_bps: float = 8.0
    recent_core_cpi_surprise: float = 0.1
    nfp_recent_edge: str = "STRONG"

class DecodeFOMCReq(BaseModel):
    rate_surprise: str
    dot_plot_tone: str
    vote_split: str
    chair_presser_cue: str

def _one_of(name: str, value: str, allowed):
    if value not in allowed:
        raise HTTPException(status_code=422, detail=f"'{name}' must be one of: {', '.join(allowed)}.")

@app.post("/api/predict-fomc")
def predict_fomc(data: FOMCPreInput, user: str = Depends(require_admin)):
    check_numbers(data)
    _one_of("expected_move", data.expected_move, FOMC_MOVES)
    _one_of("nfp_recent_edge", data.nfp_recent_edge, FOMC_NFP)
    if not 0.0 <= data.fedwatch_prob_pct <= 100.0:
        raise HTTPException(status_code=422, detail="'fedwatch_prob_pct' must be between 0 and 100.")
    increment_usage(user)
    clamp = lambda v: max(-1.0, min(1.0, v))

    # Hawkish pressure score: positive = data and rates are leaning hawkish, negative = dovish
    sig_yield = clamp(data.us2y_yield_5d_bps / 15.0)
    sig_cpi = clamp(data.recent_core_cpi_surprise / 0.1)
    sig_nfp = {"STRONG": 1.0, "INLINE": 0.0, "WEAK": -1.0}[data.nfp_recent_edge]
    score = round((sig_yield * 40) + (sig_cpi * 35) + (sig_nfp * 25), 1)

    gate = 30.0
    crowded = data.fedwatch_prob_pct >= 85.0
    if data.fedwatch_prob_pct >= 85.0:
        reversal_risk = "ELEVATED"
    elif data.fedwatch_prob_pct >= 70.0:
        reversal_risk = "MODERATE"
    else:
        reversal_risk = "LOW"

    move_text = {"CUT_25": "a 25 bp cut", "HOLD": "a hold", "HIKE_25": "a 25 bp hike"}[data.expected_move]
    if score >= gate:
        bias, bias_dir, mult = "HAWKISH", 1, (1.25 if score >= 55 else 0.95)
        verdict = "HAWKISH LEAN (USD BULLISH / GOLD BEARISH)"
        summary = (f"Market prices {move_text} at {data.fedwatch_prob_pct:g}%, but 2Y yields, core CPI and payrolls lean hawkish "
                   f"(score {score:+.1f} vs ±{gate:g}). Risk is a hawkish Dot Plot / Statement tone.")
    elif score <= -gate:
        bias, bias_dir, mult = "DOVISH", -1, (1.25 if score <= -55 else 0.95)
        verdict = "DOVISH LEAN (USD BEARISH / GOLD BULLISH)"
        summary = (f"Market prices {move_text} at {data.fedwatch_prob_pct:g}%, but 2Y yields, core CPI and payrolls lean dovish "
                   f"(score {score:+.1f} vs ±{gate:g}). Risk is a dovish Dot Plot / Statement tone.")
    else:
        bias, bias_dir, mult = "NEUTRAL", 0, 0.5
        verdict = "NO-TRADE / INLINE HOLD"
        summary = (f"Score {score:+.1f} is inside the ±{gate:g} gate. Data do not lean against the priced {move_text}; "
                   "wait for the 2:00 PM ET statement before trading.")

    tier = verdict
    if crowded:
        tier = "CROWDED CONSENSUS (BUY RUMOR / SELL FACT RISK) — " + verdict
        summary += (f" FedWatch is at {data.fedwatch_prob_pct:g}% (85%+ is crowded): even an in-line decision can see the first spike fade, "
                    "so do not chase the 2:00 PM move.")

    assets = [
        {"pair": "XAU/USD (Gold)", "base": 260, "inv": True,  "note": "Two-stage spike: 2:00 PM ET Statement + 2:30 PM ET Chair Warsh Presser"},
        {"pair": "USD/JPY",        "base": 110, "inv": False, "note": "Moves with 2Y yields; the presser can reverse the statement move"},
        {"pair": "EUR/USD",        "base": 90,  "inv": True,  "note": "Wait for the 5m close after the statement before entering"},
        {"pair": "NAS100",         "base": 185, "inv": True,  "note": "Rate-sensitive; hawkish surprises pressure tech equities"},
    ]
    return {"score": score, "bias": bias, "verdict": verdict, "tier": tier, "gate": gate,
            "crowded": crowded, "reversal_risk": reversal_risk, "summary": summary,
            "pairs": _spike_rows(assets, bias_dir, mult, neutral_label="NO-TRADE / INLINE HOLD")}

@app.post("/api/decode-fomc")
def decode_fomc(d: DecodeFOMCReq, user: str = Depends(current_user)):
    _one_of("rate_surprise", d.rate_surprise, FOMC_RATE)
    _one_of("dot_plot_tone", d.dot_plot_tone, FOMC_DOTS)
    _one_of("vote_split", d.vote_split, FOMC_VOTES)
    _one_of("chair_presser_cue", d.chair_presser_cue, FOMC_CUES)

    # +1 = hawkish pillar, -1 = dovish pillar (a hawkish dissent means someone wanted tighter policy)
    statement = (
        {"MORE_HAWKISH": 1, "INLINE": 0, "MORE_DOVISH": -1}[d.rate_surprise]
        + {"HAWKISH_SHIFT": 1, "UNCHANGED": 0, "DOVISH_SHIFT": -1}[d.dot_plot_tone]
        + {"HAWKISH_DISSENT": 1, "UNANIMOUS": 0, "DOVISH_DISSENT": -1}[d.vote_split]
    )
    pending = d.chair_presser_cue == "PENDING"
    presser = {"PUSHBACK_ON_CUTS": 1, "DATA_DEPENDENT": 0, "OPEN_TO_EASING": -1, "PENDING": 0}[d.chair_presser_cue]
    total = statement + presser
    suffix = " (PROVISIONAL — WAIT FOR THE 2:30 PM PRESSER)" if pending else ""

    reversal = (not pending) and ((statement >= 2 and presser == -1) or (statement <= -2 and presser == 1))
    if reversal:
        verdict = "CHAIR PRESSER REVERSAL TRAP (FADE THE 2:00 PM SPIKE)"
        if statement > 0:
            plan = ("The statement read hawkish but the Chair sounded open to easing, so the 2:00 PM USD spike is likely to unwind. "
                    "XAU/USD (Gold): BUY the reversal once price reclaims the pre-statement level on a 5m close. "
                    "USD/JPY: SELL a failed breakout back through the pre-statement level. "
                    "EUR/USD: BUY after price reclaims the pre-statement level on a 5m close.")
        else:
            plan = ("The statement read dovish but the Chair pushed back on cuts, so the 2:00 PM USD sell-off is likely to unwind. "
                    "XAU/USD (Gold): SELL a failed rally back through the pre-statement level. "
                    "USD/JPY: BUY after price reclaims the pre-statement level on a 5m close. "
                    "EUR/USD: SELL a failed breakout back through the pre-statement level.")
    elif (pending and statement >= 2) or (not pending and total >= 2):
        verdict = "CLEAN HAWKISH BREAKOUT" + suffix
        plan = ("The pillars agree on a hawkish read. "
                "XAU/USD (Gold): SELL the first 5-minute pullback after the spike. "
                "USD/JPY: BUY the first 5-minute pullback while 2Y yields hold higher. "
                "EUR/USD: SELL the first 5-minute pullback. "
                + ("Do not size up until the Chair confirms at 2:30 PM." if pending else "Trend can run into the New York close; trail stops under the pullback low."))
    elif (pending and statement <= -2) or (not pending and total <= -2):
        verdict = "CLEAN DOVISH RALLY" + suffix
        plan = ("The pillars agree on a dovish read. "
                "XAU/USD (Gold): BUY the first 5-minute pullback after the spike. "
                "USD/JPY: SELL the first 5-minute pullback as 2Y yields slip. "
                "EUR/USD: BUY the first 5-minute pullback. "
                + ("Do not size up until the Chair confirms at 2:30 PM." if pending else "Trail stops under the pullback low."))
    else:
        verdict = "CHOPPY / UNCHANGED HOLD" + suffix
        plan = ("The pillars offset or add nothing new. "
                "XAU/USD (Gold), USD/JPY and EUR/USD: expect two-way wicks and fakeouts between 2:00 and 3:00 PM ET. "
                "Stand aside, or only trade a clear 5m break with the Chair's tone behind it.")
    return {"verdict": verdict, "plan": plan, "statement_score": statement, "presser_score": presser, "total": total}

# ---------------------------------------------------------------------------
# Research Desk: the admin publishes official forecasts, clients read them
# (stored in the site_settings table as signal_nfp / signal_cpi / signal_ppi / signal_fomc)
# ---------------------------------------------------------------------------
SIGNAL_MODULES = ("NFP", "CPI", "PPI", "FOMC")
MAX_SIGNAL_CHARS = 60_000
# Clients never receive the raw proxy inputs, except values the post-release decoder needs.
PUBLIC_INPUT_KEYS = {"NFP": ("consensus_nfp",)}

class PublishSignalReq(BaseModel):
    module: str
    inputs: dict
    result: dict
    updated_at: str = ""

def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

@app.post("/api/admin/publish-signal")
def publish_signal(req: PublishSignalReq, admin: str = Depends(require_admin)):
    module = req.module.strip().upper()
    if module not in SIGNAL_MODULES:
        raise HTTPException(status_code=422, detail="'module' must be one of: NFP, CPI, PPI, FOMC.")
    result = req.result
    pairs = result.get("pairs")
    if not ({"bias", "score", "summary"} <= set(result) and isinstance(pairs, list)
            and all(isinstance(p, dict) for p in pairs)):
        raise HTTPException(status_code=422, detail="'result' is not a valid forecast. Calculate it first, then publish.")
    inputs = {k: v for k, v in req.inputs.items() if k != "user_email"}
    # The server stamps the time, so the "Updated" label clients see cannot be wrong or back-dated.
    payload = {"module": module, "inputs": inputs, "result": result, "updated_at": _utc_iso()}
    text = json.dumps(payload, separators=(",", ":"))
    if len(text) > MAX_SIGNAL_CHARS:
        raise HTTPException(status_code=413, detail="That forecast is too large to publish.")

    conn = get_db_conn()
    cur = conn.cursor()
    try:
        if is_pg(conn):
            cur.execute(
                "INSERT INTO site_settings (setting_key, setting_value) VALUES (%s, %s) "
                "ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
                (f"signal_{module.lower()}", text)
            )
        else:
            cur.execute(
                "INSERT OR REPLACE INTO site_settings (setting_key, setting_value) VALUES (?, ?)",
                (f"signal_{module.lower()}", text)
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        log.exception("Publishing signal failed")
        raise HTTPException(status_code=500, detail=f"Could not publish the signal: {_first_line(e)}")
    finally:
        cur.close()
        conn.close()
    log.info("Desk signal published: %s", module)
    return {"status": "ok", "module": module, "updated_at": payload["updated_at"], "storage": DB_STATUS_MSG}

@app.get("/api/signals")
def get_signals(response: Response, user: str = Depends(current_user)):
    response.headers["Cache-Control"] = "no-store"
    is_admin = user == ADMIN_EMAIL
    keys = [f"signal_{m.lower()}" for m in SIGNAL_MODULES]
    conn = get_db_conn()
    ph = ph_for(conn)
    cur = conn.cursor()
    try:
        cur.execute(
            f"SELECT setting_key, setting_value FROM site_settings WHERE setting_key IN ({', '.join([ph] * len(keys))})",
            tuple(keys)
        )
        rows = cur.fetchall()
    finally:
        cur.close()
        conn.close()
    stored = {}
    for row in rows:
        try:
            stored[row["setting_key"]] = json.loads(row["setting_value"])
        except Exception:
            continue
    signals = {}
    for module in SIGNAL_MODULES:
        item = stored.get(f"signal_{module.lower()}")
        if not item:
            signals[module] = None
            continue
        inputs = item.get("inputs") or {}
        if not is_admin:
            inputs = {k: inputs[k] for k in PUBLIC_INPUT_KEYS.get(module, ()) if k in inputs}
        signals[module] = {"module": module, "result": item.get("result"),
                           "updated_at": item.get("updated_at"), "inputs": inputs}
    return {"signals": signals}

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>A&M Group | Trading & Finance Red-Folder Terminal</title>
<style>
  :root {
    --bg: #051c15; --card: #0a2920; --border: #17493a;
    --gold: #d4af37; --gold-bright: #f3cf65; --text: #f3f6f4;
    --muted: #9cb3ab; --green: #10b981; --red: #ef4444; --amber: #f59e0b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 1.25rem; line-height: 1.5; }
  .container { max-width: 1220px; margin: auto; }
  header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.25rem; }
  .brand { display: flex; align-items: center; gap: 0.85rem; }
  .crest { width: 48px; height: 48px; border-radius: 50%; border: 2px solid var(--gold); background: #04140f; display: flex; align-items: center; justify-content: center; font-weight: 900; color: var(--gold); font-size: 1rem; overflow: hidden; }
  .crest img { width: 100%; height: 100%; object-fit: cover; }
  .dept-tag { font-size: 0.78rem; letter-spacing: 1.5px; color: var(--gold); font-weight: 700; text-transform: uppercase; }
  .top-actions { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  .btn { background: linear-gradient(135deg, var(--gold), #b58e22); color: #051c15; border: none; padding: 0.65rem 1rem; border-radius: 8px; font-weight: 800; cursor: pointer; font-size: 0.88rem; }
  .btn:hover { background: var(--gold-bright); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
  .btn-outline { background: transparent; border: 1px solid var(--gold); color: var(--gold); padding: 0.55rem 0.9rem; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 0.82rem; }
  .tabs { display: flex; gap: 0.75rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
  .tab { padding: 0.7rem 1.4rem; border-radius: 8px; border: 1px solid var(--border); background: var(--card); color: var(--muted); font-weight: 700; cursor: pointer; }
  .tab.active { background: var(--gold); color: #051c15; border-color: var(--gold); }
  .grid { display: grid; grid-template-columns: 1.15fr 1.25fr; gap: 1.25rem; }
  @media (max-width: 920px) { .grid { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; margin-bottom: 1.25rem; }
  h2 { font-size: 1.05rem; color: var(--gold-bright); margin-bottom: 0.9rem; display: flex; justify-content: space-between; align-items: center; }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  label { display: block; font-size: 0.75rem; color: var(--muted); margin-bottom: 0.2rem; }
  input[type="number"], input[type="text"], input[type="email"], input[type="password"] { width: 100%; background: #04140f; border: 1px solid var(--border); color: #fff; padding: 0.5rem; border-radius: 6px; font-size: 0.9rem; }
  select { width: 100%; background: #04140f; border: 1px solid var(--border); color: #fff; padding: 0.5rem; border-radius: 6px; font-size: 0.9rem; }
  .check-row { grid-column: span 2; display: flex; align-items: center; gap: 0.5rem; background: #04140f; padding: 0.6rem; border-radius: 6px; border: 1px solid var(--border); }
  .check-row input { width: auto; accent-color: var(--gold); }
  .verdict-box { padding: 1rem; border-radius: 8px; background: #04140f; border-left: 4px solid var(--gold); margin-bottom: 1rem; }
  .big-score { font-size: 1.3rem; font-weight: 800; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.6rem 0.45rem; border-bottom: 1px solid var(--border); }
  th { color: var(--gold); font-weight: 600; }
  .bull { color: var(--green); font-weight: 700; }
  .bear { color: var(--red); font-weight: 700; }
  .neut { color: var(--amber); font-weight: 700; }
  .auth-wrap { max-width: 440px; margin: 3rem auto; background: var(--card); border: 1px solid var(--gold); border-radius: 14px; padding: 2rem; }
  .hidden { display: none !important; }
  .client-only { display: none; }
  .client-mode .client-only { display: block; }
  .client-mode .desk-only { display: none !important; }
  .client-mode .grid { grid-template-columns: 1fr; }
  .desk-badge { background: #04140f; border: 1px solid var(--gold); color: var(--gold-bright); padding: 0.55rem 0.9rem; border-radius: 8px; font-weight: 800; font-size: 0.82rem; }
  .decoder-box { margin-top: 0.9rem; padding: 0.9rem; background: #04140f; border: 1px solid var(--gold); border-radius: 8px; }
  .source-guide { margin-top: 1rem; padding: 0.85rem; background: #04140f; border: 1px solid var(--border); border-radius: 8px; font-size: 0.8rem; }
  .source-guide summary { cursor: pointer; color: var(--gold-bright); font-weight: 700; }
  .source-guide ul { margin-top: 0.6rem; padding-left: 1.1rem; color: var(--muted); }
  .source-guide li { margin-bottom: 0.35rem; }
  .source-guide a { color: var(--gold); text-decoration: underline; }
</style>
</head>
<body>
<div class="container">
  <div id="authSection" class="auth-wrap">
    <div style="text-align:center; margin-bottom:1.5rem;">
      <div class="crest" style="margin: 0 auto 0.75rem auto; width:64px; height:64px; font-size:1.25rem;" id="authLogoSlot">A&amp;M</div>
      <div class="dept-tag">A&amp;M Group</div>
      <h2 style="justify-content:center; margin-top:0.25rem;">Trading &amp; Finance Department</h2>
      <p style="font-size:0.85rem; color:var(--muted);">Sign in or register to access the Red-Folder Institutional Terminal</p>
    </div>
    <div id="authMain">
    <div id="regFields" class="hidden">
      <label>Full Name</label><input type="text" id="regName" placeholder="e.g. John Kamau" style="margin-bottom:0.75rem;" />
      <label>WhatsApp / Phone Number</label><input type="text" id="regPhone" placeholder="e.g. +254 712 345678" style="margin-bottom:0.75rem;" />
    </div>
    <label>Email Address</label><input type="email" id="authEmail" placeholder="you@example.com" style="margin-bottom:0.75rem;" />
    <label>Password</label><input type="password" id="authPass" placeholder="••••••••" style="margin-bottom:1rem;" />
    <p id="forgotRow" style="text-align:right; font-size:0.8rem; margin:-0.5rem 0 1rem 0;"><a href="#" style="color:var(--gold); font-weight:700;" onclick="showReset(); return false;">Forgot Password?</a></p>
    <button class="btn" style="width:100%;" onclick="submitAuth()" id="authSubmitBtn">Sign In to Terminal</button>
    <p id="authErr" style="color:var(--red); font-size:0.82rem; margin-top:0.6rem; text-align:center;"></p>
    <p style="text-align:center; font-size:0.85rem; margin-top:1rem; color:var(--muted);">
      <span id="togglePrompt">New to A&amp;M Group?</span>
      <a href="#" style="color:var(--gold); font-weight:700;" onclick="toggleAuthMode(); return false;" id="toggleLink">Create Account</a>
    </p>
    </div>

    <div id="resetView" class="hidden">
      <h2 style="justify-content:center; margin-bottom:0.4rem;">Reset Your Password</h2>
      <p style="font-size:0.82rem; color:var(--muted); margin-bottom:1rem; text-align:center;">Enter the email and WhatsApp number you registered with, then choose a new password.</p>
      <label>Registered Email</label><input type="email" id="resetEmail" placeholder="you@example.com" style="margin-bottom:0.75rem;" />
      <label>Registered WhatsApp Number</label><input type="text" id="resetPhone" placeholder="e.g. +254 712 345678" style="margin-bottom:0.75rem;" />
      <label>New Password</label><input type="password" id="resetPass" placeholder="At least 8 characters" style="margin-bottom:1rem;" />
      <button class="btn" style="width:100%;" onclick="submitReset()" id="resetBtn">Reset Password</button>
      <p id="resetErr" style="color:var(--red); font-size:0.82rem; margin-top:0.6rem; text-align:center;"></p>
      <p id="resetOk" style="color:var(--green); font-size:0.85rem; margin-top:0.6rem; text-align:center; font-weight:700;"></p>
      <p style="text-align:center; font-size:0.85rem; margin-top:1rem; color:var(--muted);">
        <a href="#" style="color:var(--gold); font-weight:700;" onclick="hideReset(); return false;">&larr; Back to Sign In</a>
      </p>
    </div>
  </div>

  <div id="appSection" class="hidden">
    <header>
      <div class="brand">
        <div class="crest" id="headerLogoSlot">A&amp;M</div>
        <div>
          <div class="dept-tag">A&amp;M Group — Trading &amp; Finance Department</div>
          <h1 style="font-size:1.3rem;">Institutional Red-Folder News Terminal</h1>
        </div>
      </div>
      <div class="top-actions">
        <span id="userWelcome" style="font-size:0.82rem; color:var(--muted);"></span>
        <button class="btn-outline hidden" id="adminBtn" onclick="toggleAdmin()">👑 Admin Monitor</button>
        <button class="btn-outline hidden" id="previewBtn" onclick="togglePreview()">👁️ Preview Client View</button>
        <label class="btn-outline desk-only" style="margin:0; cursor:pointer;">🖼️ Upload Logo<input type="file" accept="image/*" style="display:none;" onchange="handleLogo(event)" /></label>
        <button class="btn-outline" onclick="logout()">Logout</button>
      </div>
    </header>

    <div id="adminPanel" class="card hidden">
      <h2><span>👑 A&amp;M Group — Registered Users &amp; Activity Monitor</span> <span id="dbStatusBadge" style="font-size:0.75rem; color:var(--green);"></span></h2>
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>WhatsApp</th><th>Calculations</th><th>Joined</th><th>Last Active</th></tr></thead>
        <tbody id="adminTableBody"></tbody>
      </table>
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.75rem; margin-bottom:1.25rem;">
      <div class="tabs" style="margin:0;">
        <button class="tab active" id="tabNFP" onclick="switchTab('NFP')">🇺🇸 NFP V2 Predictor</button>
        <button class="tab" id="tabCPI" onclick="switchTab('CPI')">🔥 CPI Predictor</button>
        <button class="tab" id="tabPPI" onclick="switchTab('PPI')">🏭 PPI V2 Predictor</button>
        <button class="tab" id="tabFOMC" onclick="switchTab('FOMC')">🏛️ FOMC &amp; Fed Chair</button>
      </div>
      <button class="btn desk-only" id="autoFetchBtn" onclick="autoFetch()">⚡ Auto-Fetch Latest Fed &amp; Oil Data</button>
    </div>
    <p id="fetchStatus" class="desk-only" style="font-size:0.8rem; color:var(--gold); margin-bottom:1rem;"></p>

    <div id="viewNFP" class="grid">
      <div class="card desk-only" id="nfpInputCard">
        <h2><span>1. NFP Survey-Week Proxy Inputs (V2)</span> <span style="font-size:0.75rem; color:var(--muted);">Week of 12th</span></h2>
        <div class="form-grid">
          <div><label>NFP Consensus Forecast (K)</label><input type="number" id="nfp_cons" value="110" /></div>
          <div><label>Strike / Weather Adj (K)</label><input type="number" id="nfp_strike" value="0" /></div>
          <div><label>ISM Services Emp Actual [22%]</label><input type="number" id="nfp_isms" value="51.8" step="0.1" /></div>
          <div><label>ISM Services Emp Prev</label><input type="number" id="nfp_isms_p" value="50.2" step="0.1" /></div>
          <div><label>Initial Claims 12th-Wk Δ (K) [16%]</label><input type="number" id="nfp_icsa" value="-8" step="0.1" /></div>
          <div><label>Continuing Claims 12th-Wk Δ (K) [12%]</label><input type="number" id="nfp_ccsa" value="-25" step="0.1" /></div>
          <div><label>ADP Actual (K) [14%]</label><input type="number" id="nfp_adp" value="135" /></div>
          <div><label>ADP Consensus (K)</label><input type="number" id="nfp_adp_c" value="105" /></div>
          <div><label>Homebase Hours % Δ [12%]</label><input type="number" id="nfp_hb" value="1.1" step="0.1" /></div>
          <div><label>Conf. Board Labor Diff Δ [8%]</label><input type="number" id="nfp_labor" value="1.5" step="0.1" /></div>
          <div><label>ISM Mfg Emp Actual [8%]</label><input type="number" id="nfp_ismm" value="49.5" step="0.1" /></div>
          <div><label>ISM Mfg Emp Prev</label><input type="number" id="nfp_ismm_p" value="48.8" step="0.1" /></div>
          <div><label>NFIB Hiring Plans Actual (%) [8%]</label><input type="number" id="nfp_nfib" value="18.0" step="0.5" /></div>
          <div><label>NFIB Hiring Plans Prev (%)</label><input type="number" id="nfp_nfib_p" value="17.0" step="0.5" /></div>
          <div style="grid-column: span 2;"><label>Prior-Month Govt Education Swing (K) [50% Reversion ≥ ±35K]</label><input type="number" id="nfp_edu" value="0.0" step="1" /></div>
          <div class="check-row">
            <input type="checkbox" id="nfp_summer" />
            <label for="nfp_summer" style="margin:0; color:var(--text); cursor:pointer;">Jul–Sep Back-to-School Window? (Widens No-Trade Buffer to ±40K)</label>
          </div>
        </div>
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcNFP()">Calculate V2 NFP Outcome &amp; Gold/FX Spikes</button>

        <details class="source-guide" open>
          <summary>📖 Where to Find Manual NFP Numbers (Free Official Links)</summary>
          <ul>
            <li><strong>Consensus, ADP &amp; ISM Employment:</strong> <a href="https://www.forexfactory.com/calendar" target="_blank">Forex Factory Calendar</a> (Filter USD red/orange events during NFP week).</li>
            <li><strong>NFIB Small Business Hiring Plans (%):</strong> <a href="https://www.nfib.com/news/press-release/" target="_blank">NFIB Jobs Report</a> (Released Tuesday morning of NFP week).</li>
            <li><strong>Homebase Hours % Δ:</strong> <a href="https://www.joinhomebase.com/data" target="_blank">Homebase Main Street Health</a> (Small business hours worked for the week of the 12th).</li>
            <li><strong>Conf. Board Labor Differential Δ:</strong> <a href="https://www.conference-board.org/topics/consumer-confidence" target="_blank">Conference Board Survey</a> (Subtract "Jobs Hard to Get %" from "Jobs Plentiful %").</li>
            <li><strong>Prior Govt Education Swing &amp; Strikes:</strong> <a href="https://www.bls.gov/news.release/empsit.nr0.htm" target="_blank">BLS Employment Summary</a> &amp; <a href="https://www.bls.gov/wsp/" target="_blank">BLS Strike Report</a>.</li>
          </ul>
        </details>
      </div>

      <div>
        <div class="card client-only" id="nfpClientPanel">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.6rem; margin-bottom:0.9rem;">
            <div class="desk-badge" id="nfpBadge">🏛️ A&amp;M Group Research Desk — Official Pre-Release Signal</div>
            <button class="btn-outline" onclick="loadSignals()">🔄 Refresh Latest Desk Signal</button>
          </div>
          <h2><span>🇺🇸 NFP — Forecast &amp; XAU/USD + FX Spike Matrix</span> <span id="nfpCTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="nfpCBias" class="big-score neut">Loading...</span>
              <span id="nfpCScore" style="font-weight:700;"></span>
            </div>
            <p id="nfpCSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="nfpCPairs"></tbody>
          </table>
        </div>

        <div class="card desk-only" id="nfpDeskCard">
          <h2><span>2. V2 NFP Forecast &amp; XAU/USD + FX Spike Matrix</span> <span id="nfpTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="nfpBox">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="nfpBias" class="big-score bull">READY</span>
              <span id="nfpScore" style="font-weight:700;"></span>
            </div>
            <p id="nfpSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="nfpPairs"></tbody>
          </table>
          <button class="btn" style="width:100%; margin-top:0.25rem;" onclick="publishSignal('NFP')">📡 Publish Official Desk Forecast to Clients</button>
          <p id="nfpPubStatus" style="font-size:0.8rem; margin-top:0.5rem; color:var(--gold);"></p>
        </div>

        <div class="card">
          <h2>⚡ 3. Post-Release NFP &amp; XAU/USD Action Decoder (After 8:30 AM Print)</h2>
          <div class="form-grid">
            <div><label>Actual NFP Print (K)</label><input type="number" id="dec_nfp_act" value="165" /></div>
            <div><label>2-Month Net Revisions (K)</label><input type="number" id="dec_nfp_rev" value="20" /></div>
            <div><label>Unemployment Forecast (%)</label><input type="number" id="dec_un_f" value="4.1" step="0.1" /></div>
            <div><label>Unemployment Actual (%)</label><input type="number" id="dec_un_a" value="4.0" step="0.1" /></div>
            <div><label>Avg Hourly Earnings Forecast (%)</label><input type="number" id="dec_ahe_f" value="0.3" step="0.1" /></div>
            <div><label>Avg Hourly Earnings Actual (%)</label><input type="number" id="dec_ahe_a" value="0.4" step="0.1" /></div>
          </div>
          <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="decodeNFP()">Decode Actual NFP &amp; Get Gold/FX Trade Plan</button>
          <div id="nfpDecodeOut" class="decoder-box hidden"></div>
        </div>
      </div>
    </div>

    <div id="viewCPI" class="grid hidden">
      <div class="card desk-only" id="cpiInputCard">
        <h2><span>1. CPI Leading Inflation Proxies</span> <span style="font-size:0.75rem; color:var(--muted);">8-Factor Model</span></h2>
        <div class="form-grid">
          <div><label>CPI MoM Consensus (%) [Target]</label><input type="number" id="cpi_cons" value="0.3" step="0.05" /></div>
          <div><label>Cleveland Fed Nowcast MoM (%) [25%]</label><input type="number" id="cpi_clev" value="0.38" step="0.01" /></div>
          <div><label>WTI Oil / Gas Monthly % Δ [18%]</label><input type="number" id="cpi_gas" value="4.2" step="0.1" /></div>
          <div><label>Core PPI MoM Surprise (%) [10%]</label><input type="number" id="cpi_ppi" value="0.1" step="0.05" /></div>
          <div><label>ISM Services Prices Paid [15%]</label><input type="number" id="cpi_srvp" value="58.5" step="0.1" /></div>
          <div><label>ISM Services Prices Prev</label><input type="number" id="cpi_srvp_p" value="56.2" step="0.1" /></div>
          <div><label>ISM Mfg Prices Paid [12%]</label><input type="number" id="cpi_mfgp" value="54.0" step="0.1" /></div>
          <div><label>ISM Mfg Prices Prev</label><input type="number" id="cpi_mfgp_p" value="52.1" step="0.1" /></div>
          <div><label>Manheim Used Cars % Δ [8%]</label><input type="number" id="cpi_manheim" value="1.2" step="0.1" /></div>
          <div><label>Market Rent Index MoM % [7%]</label><input type="number" id="cpi_rent" value="0.4" step="0.05" /></div>
          <div><label>NFIB Small Biz Price Plans % [5%]</label><input type="number" id="cpi_nfib" value="26" /></div>
        </div>
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcCPI()">Calculate CPI Outcome &amp; Gold/FX Spikes</button>

        <details class="source-guide" open>
          <summary>📖 Where to Find Manual CPI Numbers (Free Official Links)</summary>
          <ul>
            <li><strong>Cleveland Fed Nowcast MoM (%):</strong> <a href="https://www.clevelandfed.org/indicators-and-data/inflation-nowcasting" target="_blank">Cleveland Fed Inflation Nowcasting</a> (Updated daily).</li>
            <li><strong>CPI Consensus &amp; Core PPI Surprise:</strong> <a href="https://www.forexfactory.com/calendar" target="_blank">Forex Factory Calendar</a>.</li>
            <li><strong>ISM Services &amp; Mfg Prices Paid:</strong> <a href="https://www.ismworld.org/supply-management-news-and-reports/reports/ism-pmi-reports/" target="_blank">ISM PMI Reports</a> (Check "Prices" sub-index).</li>
            <li><strong>Manheim Used Cars % Δ:</strong> <a href="https://site.manheim.com/en/services/consulting/used-vehicle-value-index.html" target="_blank">Manheim Used Vehicle Value Index</a>.</li>
            <li><strong>Market Rent Index &amp; NFIB Price Plans:</strong> <a href="https://www.apartmentlist.com/research/category/data-rent-estimates" target="_blank">Apartment List Rent Report</a> &amp; <a href="https://www.nfib.com/surveys/small-business-economic-trends/" target="_blank">NFIB Economic Trends</a>.</li>
          </ul>
        </details>
      </div>

      <div>
        <div class="card client-only" id="cpiClientPanel">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.6rem; margin-bottom:0.9rem;">
            <div class="desk-badge" id="cpiBadge">🏛️ A&amp;M Group Research Desk — Official Pre-Release Signal</div>
            <button class="btn-outline" onclick="loadSignals()">🔄 Refresh Latest Desk Signal</button>
          </div>
          <h2><span>🔥 CPI — Forecast &amp; XAU/USD + FX Spike Matrix</span> <span id="cpiCTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="cpiCBias" class="big-score neut">Loading...</span>
              <span id="cpiCScore" style="font-weight:700;"></span>
            </div>
            <p id="cpiCSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="cpiCPairs"></tbody>
          </table>
        </div>

        <div class="card desk-only" id="cpiDeskCard">
          <h2><span>2. CPI Forecast &amp; XAU/USD + FX Spike Matrix</span> <span id="cpiTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="cpiBox">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="cpiBias" class="big-score bull">READY</span>
              <span id="cpiScore" style="font-weight:700;"></span>
            </div>
            <p id="cpiSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="cpiPairs"></tbody>
          </table>
          <button class="btn" style="width:100%; margin-top:0.25rem;" onclick="publishSignal('CPI')">📡 Publish Official Desk Forecast to Clients</button>
          <p id="cpiPubStatus" style="font-size:0.8rem; margin-top:0.5rem; color:var(--gold);"></p>
        </div>

        <div class="card">
          <h2>⚡ 3. Post-Release CPI &amp; XAU/USD Action Decoder (After 8:30 AM Print)</h2>
          <div class="form-grid">
            <div><label>Headline CPI MoM Forecast (%)</label><input type="number" id="dec_cpi_hf" value="0.3" step="0.1" /></div>
            <div><label>Headline CPI MoM Actual (%)</label><input type="number" id="dec_cpi_ha" value="0.4" step="0.1" /></div>
            <div><label>Core CPI MoM Forecast (%)</label><input type="number" id="dec_cpi_cf" value="0.3" step="0.1" /></div>
            <div><label>Core CPI MoM Actual (%)</label><input type="number" id="dec_cpi_ca" value="0.4" step="0.1" /></div>
          </div>
          <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="decodeCPI()">Decode Actual CPI &amp; Get Gold/FX Trade Plan</button>
          <div id="cpiDecodeOut" class="decoder-box hidden"></div>
        </div>
      </div>
    </div>

    <div id="viewPPI" class="grid hidden">
      <div class="card desk-only" id="ppiInputCard">
        <h2><span>1. PPI V2 Leading Producer-Price Proxies</span> <span style="font-size:0.75rem; color:var(--muted);">8-Factor Model + V2 Safeguards</span></h2>
        <div class="form-grid">
          <div><label>PPI MoM Consensus (%) [Reference]</label><input type="number" id="ppi_cons" value="0.3" step="0.05" /></div>
          <div><label>WTI Oil / Gas Monthly % Δ [18%]</label><input type="number" id="ppi_gas" value="-10.3" step="0.1" /></div>
          <div><label>ISM Services Prices Paid [22%]</label><input type="number" id="ppi_srvp" value="73.0" step="0.1" /></div>
          <div><label>ISM Services Prices Prev</label><input type="number" id="ppi_srvp_p" value="74.0" step="0.1" /></div>
          <div><label>ISM Mfg Prices Paid [18%]</label><input type="number" id="ppi_mfgp" value="75.2" step="0.1" /></div>
          <div><label>ISM Mfg Prices Prev</label><input type="number" id="ppi_mfgp_p" value="77.9" step="0.1" /></div>
          <div><label>Regional Fed Prices Paid (Empire/Philly) [14%]</label><input type="number" id="ppi_fed" value="28.0" step="0.1" /></div>
          <div><label>Regional Fed Prices Paid Prev</label><input type="number" id="ppi_fed_p" value="24.0" step="0.1" /></div>
          <div><label>Freight Rate % Δ [8%]</label><input type="number" id="ppi_frt" value="2.0" step="0.1" /></div>
          <div><label>Agri &amp; Metals % Δ [8%]</label><input type="number" id="ppi_met" value="1.5" step="0.1" /></div>
          <div><label>NFIB Small Biz Price Plans % [7%]</label><input type="number" id="ppi_nfib" value="37.0" step="0.5" /></div>
          <div><label>Import Price Surprise (%) [5%]</label><input type="number" id="ppi_imp" value="0.0" step="0.1" /></div>
          <div class="check-row">
            <input type="checkbox" id="ppi_jj" />
            <label for="ppi_jj" style="margin:0; color:var(--text); cursor:pointer;">Jan / Jul Seasonal-Reset Window? (Widens No-Trade Gate to ±35)</label>
          </div>
        </div>
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcPPI()">Calculate PPI V2 Outcome &amp; Gold/FX Spikes</button>

        <details class="source-guide" open>
          <summary>📖 Where to Find Manual PPI Numbers (Free Official Links)</summary>
          <ul>
            <li><strong>PPI Consensus &amp; Import Price Surprise:</strong> <a href="https://www.forexfactory.com/calendar" target="_blank">Forex Factory Calendar</a> (USD events: PPI and Import Prices actual vs forecast).</li>
            <li><strong>ISM Services &amp; Mfg Prices Paid:</strong> <a href="https://www.ismworld.org/supply-management-news-and-reports/reports/ism-pmi-reports/" target="_blank">ISM PMI Reports</a> (Check the "Prices" sub-index in each report).</li>
            <li><strong>Regional Fed Prices Paid:</strong> <a href="https://www.newyorkfed.org/survey/empire/empiresurvey_overview" target="_blank">NY Empire State Survey</a> &amp; <a href="https://www.philadelphiafed.org/manufacturing-bos" target="_blank">Philadelphia Fed Manufacturing Survey</a> (Enter the average of the two Prices Paid readings, and last month's average).</li>
            <li><strong>Oil, Metals, Agriculture &amp; Freight % Δ:</strong> <a href="https://tradingeconomics.com/commodities" target="_blank">Trading Economics Commodities</a> (Energy, metals, agriculture and freight indexes).</li>
            <li><strong>NFIB Price Plans (%):</strong> <a href="https://www.nfib.com/surveys/small-business-economic-trends/" target="_blank">NFIB Economic Trends</a>.</li>
          </ul>
        </details>
      </div>

      <div>
        <div class="card client-only" id="ppiClientPanel">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.6rem; margin-bottom:0.9rem;">
            <div class="desk-badge" id="ppiBadge">🏛️ A&amp;M Group Research Desk — Official Pre-Release Signal</div>
            <button class="btn-outline" onclick="loadSignals()">🔄 Refresh Latest Desk Signal</button>
          </div>
          <h2><span>🏭 PPI — Forecast &amp; XAU/USD + FX Spike Matrix</span> <span id="ppiCTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="ppiCBias" class="big-score neut">Loading...</span>
              <span id="ppiCScore" style="font-weight:700;"></span>
            </div>
            <p id="ppiCSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="ppiCPairs"></tbody>
          </table>
        </div>

        <div class="card desk-only" id="ppiDeskCard">
          <h2><span>2. PPI V2 Forecast &amp; XAU/USD + FX Spike Matrix</span> <span id="ppiTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="ppiBox">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="ppiBias" class="big-score bull">READY</span>
              <span id="ppiScore" style="font-weight:700;"></span>
            </div>
            <p id="ppiSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="ppiPairs"></tbody>
          </table>
          <button class="btn" style="width:100%; margin-top:0.25rem;" onclick="publishSignal('PPI')">📡 Publish Official Desk Forecast to Clients</button>
          <p id="ppiPubStatus" style="font-size:0.8rem; margin-top:0.5rem; color:var(--gold);"></p>
        </div>

        <div class="card">
          <h2>⚡ 3. Post-Release PPI &amp; XAU/USD Action Decoder (After 8:30 AM Print)</h2>
          <div class="form-grid">
            <div><label>Headline PPI MoM Forecast (%)</label><input type="number" id="dec_ppi_hf" value="0.3" step="0.1" /></div>
            <div><label>Headline PPI MoM Actual (%)</label><input type="number" id="dec_ppi_ha" value="0.5" step="0.1" /></div>
            <div><label>Core PPI MoM Forecast (%)</label><input type="number" id="dec_ppi_cf" value="0.3" step="0.1" /></div>
            <div><label>Core PPI MoM Actual (%)</label><input type="number" id="dec_ppi_ca" value="0.2" step="0.1" /></div>
          </div>
          <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="decodePPI()">Decode Actual PPI &amp; Get Gold/FX Trade Plan</button>
          <div id="ppiDecodeOut" class="decoder-box hidden"></div>
        </div>
      </div>
    </div>

    <div id="viewFOMC" class="grid hidden">
      <div class="card desk-only" id="fomcInputCard">
        <h2><span>1. FOMC Pre-Meeting Pricing &amp; Reversal Risk Gauge</span> <span style="font-size:0.75rem; color:var(--muted);">Before 2:00 PM ET</span></h2>
        <div class="form-grid">
          <div><label>CME FedWatch Probability of Expected Move (%)</label><input type="number" id="fomc_prob" value="82" step="1" /></div>
          <div><label>Expected Move (Priced In)</label>
            <select id="fomc_move">
              <option value="CUT_25">Cut 25 bp</option>
              <option value="HOLD" selected>Hold</option>
              <option value="HIKE_25">Hike 25 bp</option>
            </select>
          </div>
          <div><label>US 2-Year Yield 5-Day Change (bps)</label><input type="number" id="fomc_us2y" value="8" step="0.5" /></div>
          <div><label>Recent Core CPI Surprise (%)</label><input type="number" id="fomc_cpi" value="0.1" step="0.05" /></div>
          <div style="grid-column: span 2;"><label>Recent NFP Edge</label>
            <select id="fomc_nfp">
              <option value="STRONG" selected>Strong (beat)</option>
              <option value="INLINE">In line</option>
              <option value="WEAK">Weak (miss)</option>
            </select>
          </div>
        </div>
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcFOMC()">Gauge FOMC Pricing &amp; Reversal Risk</button>

        <details class="source-guide" open>
          <summary>📖 Where to Find Manual FOMC Numbers (Free Official Links)</summary>
          <ul>
            <li><strong>Probability of the Expected Move:</strong> <a href="https://www.cmegroup.com/markets/interest-rates/cme-fedwatch-tool.html" target="_blank">CME FedWatch Tool</a> (Use the probability of the most likely outcome for the next meeting).</li>
            <li><strong>Meeting Dates, Statements &amp; Press Conferences:</strong> <a href="https://www.federalreserve.gov/monetarypolicy/fomccalendars.htm" target="_blank">Federal Reserve FOMC Calendar &amp; Statements</a> (Statement 2:00 PM ET, press conference 2:30 PM ET).</li>
            <li><strong>US 2-Year Treasury Yield (5-day change):</strong> <a href="https://fred.stlouisfed.org/series/DGS2" target="_blank">US 2-Year Treasury Yield (FRED)</a> (Subtract the yield 5 trading days ago, in basis points).</li>
          </ul>
        </details>
      </div>

      <div>
        <div class="card client-only" id="fomcClientPanel">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.6rem; margin-bottom:0.9rem;">
            <div class="desk-badge" id="fomcBadge">🏛️ A&amp;M Group Research Desk — Official Pre-Release Signal</div>
            <button class="btn-outline" onclick="loadSignals()">🔄 Refresh Latest Desk Signal</button>
          </div>
          <h2><span>🏛️ FOMC — Lean &amp; XAU/USD + FX Spike Matrix</span> <span id="fomcCTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="fomcCBias" class="big-score neut">Loading...</span>
              <span id="fomcCScore" style="font-weight:700;"></span>
            </div>
            <p id="fomcCSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="fomcCPairs"></tbody>
          </table>
        </div>

        <div class="card desk-only" id="fomcDeskCard">
          <h2><span>2. FOMC Lean &amp; XAU/USD + FX Spike Matrix</span> <span id="fomcTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="fomcBox">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="fomcBias" class="big-score bull">READY</span>
              <span id="fomcScore" style="font-weight:700;"></span>
            </div>
            <p id="fomcSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="fomcPairs"></tbody>
          </table>
          <button class="btn" style="width:100%; margin-top:0.25rem;" onclick="publishSignal('FOMC')">📡 Publish Official Desk Forecast to Clients</button>
          <p id="fomcPubStatus" style="font-size:0.8rem; margin-top:0.5rem; color:var(--gold);"></p>
        </div>

        <div class="card">
          <h2>⚡ 3. Instant Statement &amp; Chair Warsh Presser Decoder (After 2:00 PM ET)</h2>
          <div class="form-grid">
            <div><label>Rate Decision vs Pricing</label>
              <select id="dec_fomc_rate">
                <option value="MORE_HAWKISH">More hawkish than priced</option>
                <option value="INLINE" selected>In line with pricing</option>
                <option value="MORE_DOVISH">More dovish than priced</option>
              </select>
            </div>
            <div><label>Dot Plot / Statement Tone</label>
              <select id="dec_fomc_dots">
                <option value="HAWKISH_SHIFT">Hawkish shift</option>
                <option value="UNCHANGED" selected>Unchanged</option>
                <option value="DOVISH_SHIFT">Dovish shift</option>
              </select>
            </div>
            <div><label>Vote Split</label>
              <select id="dec_fomc_vote">
                <option value="UNANIMOUS" selected>Unanimous</option>
                <option value="HAWKISH_DISSENT">Hawkish dissent</option>
                <option value="DOVISH_DISSENT">Dovish dissent</option>
              </select>
            </div>
            <div><label>Chair Presser Cue (2:30 PM ET)</label>
              <select id="dec_fomc_chair">
                <option value="PENDING" selected>Pending (presser not started)</option>
                <option value="PUSHBACK_ON_CUTS">Pushback on cuts</option>
                <option value="DATA_DEPENDENT">Data dependent</option>
                <option value="OPEN_TO_EASING">Open to easing</option>
              </select>
            </div>
          </div>
          <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="decodeFOMC()">Decode Statement &amp; Get Gold/FX Trade Plan</button>
          <div id="fomcDecodeOut" class="decoder-box hidden"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
  let isRegister = false;
  let currentUser = JSON.parse(localStorage.getItem("am_user") || "null");

  function renderLogo(src) {
    if (!src) return;
    document.getElementById("headerLogoSlot").innerHTML = `<img src="${src}" alt="A&M Logo" />`;
    document.getElementById("authLogoSlot").innerHTML = `<img src="${src}" alt="A&M Logo" />`;
  }

  function applySavedLogo() {
    const cached = localStorage.getItem("am_logo");
    if (cached) renderLogo(cached);
    fetch("/api/logo")
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.logo) {
          localStorage.setItem("am_logo", data.logo);
          renderLogo(data.logo);
        }
      })
      .catch(() => {});
  }
  applySavedLogo();

  function handleLogo(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const res = await fetch("/api/logo", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: currentUser ? currentUser.email : "", logo: reader.result })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { alert(data.detail || "The logo could not be saved to the database."); return; }
        if (data.storage && !data.storage.includes("Permanent")) {
          alert("Logo saved only to temporary storage. Database status: " + data.storage);
        }
      } catch (err) {
        alert("The logo could not be saved to the database.");
        return;
      }
      localStorage.setItem("am_logo", reader.result);
      renderLogo(reader.result);
    };
    reader.readAsDataURL(file);
  }

  function showReset() {
    document.getElementById("authMain").classList.add("hidden");
    document.getElementById("resetView").classList.remove("hidden");
    document.getElementById("resetEmail").value = document.getElementById("authEmail").value.trim();
    document.getElementById("resetErr").innerText = "";
    document.getElementById("resetOk").innerText = "";
  }

  function hideReset() {
    document.getElementById("resetView").classList.add("hidden");
    document.getElementById("authMain").classList.remove("hidden");
    document.getElementById("authErr").innerText = "";
  }

  async function submitReset() {
    const err = document.getElementById("resetErr");
    const ok = document.getElementById("resetOk");
    const btn = document.getElementById("resetBtn");
    err.innerText = "";
    ok.innerText = "";
    const email = document.getElementById("resetEmail").value.trim();
    const whatsapp = document.getElementById("resetPhone").value.trim();
    const new_password = document.getElementById("resetPass").value.trim();
    if (!email || !whatsapp || !new_password) { err.innerText = "Please fill in all three fields."; return; }
    if (new_password.length < 8) { err.innerText = "New password must be at least 8 characters."; return; }
    btn.disabled = true;
    try {
      const res = await fetch("/api/reset-password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, whatsapp, new_password }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { err.innerText = (typeof data.detail === "string") ? data.detail : "Password reset failed."; return; }
      document.getElementById("authEmail").value = email;
      document.getElementById("authPass").value = "";
      document.getElementById("resetPass").value = "";
      ok.innerText = "Password updated. Click Back to Sign In and log in with your new password.";
    } catch (e) {
      err.innerText = "Could not reach the server. Please try again.";
    } finally {
      btn.disabled = false;
    }
  }

  function toggleAuthMode() {
    isRegister = !isRegister;
    document.getElementById("regFields").classList.toggle("hidden", !isRegister);
    document.getElementById("authSubmitBtn").innerText = isRegister ? "Create A&M Account" : "Sign In to Terminal";
    document.getElementById("togglePrompt").innerText = isRegister ? "Already have an account?" : "New to A&M Group?";
    document.getElementById("toggleLink").innerText = isRegister ? "Sign In" : "Create Account";
    document.getElementById("authErr").innerText = "";
    document.getElementById("forgotRow").classList.toggle("hidden", isRegister);
  }

  async function submitAuth() {
    const email = document.getElementById("authEmail").value.trim();
    const password = document.getElementById("authPass").value.trim();
    if (!email || !password) { document.getElementById("authErr").innerText = "Please enter email and password."; return; }

    const url = isRegister ? "/api/register" : "/api/login";
    const body = isRegister
      ? { full_name: document.getElementById("regName").value.trim(), whatsapp: document.getElementById("regPhone").value.trim(), email, password }
      : { email, password };

    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok) { document.getElementById("authErr").innerText = data.detail || "Authentication failed."; return; }

    currentUser = data;
    localStorage.setItem("am_user", JSON.stringify(data));
    enterTerminal();
  }

  function enterTerminal() {
    if (!currentUser) return;
    document.getElementById("authSection").classList.add("hidden");
    document.getElementById("appSection").classList.remove("hidden");
    document.getElementById("userWelcome").innerText = `Welcome, ${currentUser.full_name}`;
    if (currentUser.is_admin) {
      document.getElementById("adminBtn").classList.remove("hidden");
      document.getElementById("previewBtn").classList.remove("hidden");
      setMode("desk");
      calcNFP();
      calcCPI();
    } else {
      setMode("client");
    }
  }

  async function logout() {
    try { await fetch("/api/logout", { method: "POST" }); } catch (e) {}
    localStorage.removeItem("am_user");
    location.reload();
  }

  function esc(v) {
    return String(v === null || v === undefined ? "" : v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c]));
  }

  async function toggleAdmin() {
    const panel = document.getElementById("adminPanel");
    panel.classList.toggle("hidden");
    if (!panel.classList.contains("hidden")) {
      const res = await fetch(`/api/admin/users?email=${encodeURIComponent(currentUser.email)}`);
      if (!res.ok) { document.getElementById("dbStatusBadge").innerText = "Admin access denied or session expired. Please log in again."; return; }
      const data = await res.json();
      document.getElementById("dbStatusBadge").innerText = data.db_mode;
      document.getElementById("adminTableBody").innerHTML = data.users.map(u =>
        `<tr><td><strong>${esc(u.full_name)}</strong></td><td>${esc(u.email)}</td><td>${esc(u.whatsapp)}</td><td>${esc(u.calc_count)}</td><td>${esc(u.created_at)}</td><td>${esc(u.last_login)}</td></tr>`
      ).join("");
    }
  }

  let ppiLoaded = false;
  let fomcLoaded = false;

  function switchTab(tab) {
    ["NFP", "CPI", "PPI", "FOMC"].forEach(t => {
      document.getElementById("tab" + t).classList.toggle("active", t === tab);
      document.getElementById("view" + t).classList.toggle("hidden", t !== tab);
    });
    if (tab === "PPI" && !ppiLoaded && viewMode === "desk") { ppiLoaded = true; calcPPI(); }
    if (tab === "FOMC" && !fomcLoaded && viewMode === "desk") { fomcLoaded = true; calcFOMC(); }
  }

  async function autoFetch() {
    const btn = document.getElementById("autoFetchBtn");
    const status = document.getElementById("fetchStatus");
    btn.disabled = true;
    btn.innerText = "⏳ Fetching...";
    status.innerText = "Fetching live Federal Reserve & WTI Crude Oil data...";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      const res = await fetch("/api/autofetch", { signal: controller.signal });
      if (!res.ok) throw new Error("Server error");
      const data = await res.json();
      document.getElementById("nfp_icsa").value = data.nfp.icsa_change_k;
      document.getElementById("nfp_ccsa").value = data.nfp.ccsa_change_k;
      document.getElementById("cpi_gas").value = data.cpi.gas_oil_pct_change;
      document.getElementById("ppi_gas").value = data.cpi.gas_oil_pct_change;
      status.innerText = `✅ Updated from: ${data.source}`;
      await calcNFP();
      await calcCPI();
      ppiLoaded = true;
      await calcPPI();
    } catch (err) {
      status.innerText = "⚠️ Live feed timed out — existing values kept. You can calculate normally.";
    } finally {
      clearTimeout(timer);
      btn.disabled = false;
      btn.innerText = "⚡ Auto-Fetch Latest Fed & Oil Data";
    }
  }

  async function calcNFP() {
    const payload = {
      user_email: currentUser ? currentUser.email : "",
      consensus_nfp: Number(document.getElementById("nfp_cons").value),
      net_strike_weather_adj: Number(document.getElementById("nfp_strike").value),
      icsa_change_k: Number(document.getElementById("nfp_icsa").value),
      ccsa_change_k: Number(document.getElementById("nfp_ccsa").value),
      ism_services_emp: Number(document.getElementById("nfp_isms").value),
      ism_services_prev: Number(document.getElementById("nfp_isms_p").value),
      adp_actual: Number(document.getElementById("nfp_adp").value),
      adp_consensus: Number(document.getElementById("nfp_adp_c").value),
      homebase_hours_pct: Number(document.getElementById("nfp_hb").value),
      labor_diff_change: Number(document.getElementById("nfp_labor").value),
      ism_mfg_emp: Number(document.getElementById("nfp_ismm").value),
      ism_mfg_prev: Number(document.getElementById("nfp_ismm_p").value),
      nfib_hiring_actual: Number(document.getElementById("nfp_nfib").value),
      nfib_hiring_prev: Number(document.getElementById("nfp_nfib_p").value),
      prev_govt_edu_swing: Number(document.getElementById("nfp_edu").value),
      is_summer_school_month: document.getElementById("nfp_summer").checked
    };
    const res = await fetch("/api/predict-nfp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    renderForecast("nfp", await res.json(), true);
  }

  async function calcCPI() {
    const payload = {
      user_email: currentUser ? currentUser.email : "",
      cpi_mom_consensus: Number(document.getElementById("cpi_cons").value),
      cleveland_nowcast_mom: Number(document.getElementById("cpi_clev").value),
      gas_oil_pct_change: Number(document.getElementById("cpi_gas").value),
      ppi_surprise_mom: Number(document.getElementById("cpi_ppi").value),
      ism_srv_prices: Number(document.getElementById("cpi_srvp").value),
      ism_srv_prices_prev: Number(document.getElementById("cpi_srvp_p").value),
      ism_mfg_prices: Number(document.getElementById("cpi_mfgp").value),
      ism_mfg_prices_prev: Number(document.getElementById("cpi_mfgp_p").value),
      manheim_used_car_pct: Number(document.getElementById("cpi_manheim").value),
      rent_index_pct: Number(document.getElementById("cpi_rent").value),
      nfib_price_plans: Number(document.getElementById("cpi_nfib").value)
    };
    const res = await fetch("/api/predict-cpi", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    renderForecast("cpi", await res.json(), false);
  }

  function renderForecast(prefix, d, isEdge) {
    const biasEl = document.getElementById(`${prefix}Bias`);
    if (d.bias === "HOTTER") {
      biasEl.innerText = "USD BULLISH (BEAT / HOTTER)";
      biasEl.className = "big-score bull";
    } else if (d.bias === "COOLER") {
      biasEl.innerText = "USD BEARISH (MISS / COOLER)";
      biasEl.className = "big-score bear";
    } else {
      biasEl.innerText = "NO-TRADE / LOW EDGE";
      biasEl.className = "big-score neut";
    }
    document.getElementById(`${prefix}Tier`).innerText = d.tier;
    const metricLabel = isEdge ? `Edge: ${d.score > 0 ? "+" : ""}${d.score}K` : `Score: ${d.score > 0 ? "+" : ""}${d.score}`;
    document.getElementById(`${prefix}Score`).innerText = `${metricLabel} | Conf: ${d.confidence}%`;
    document.getElementById(`${prefix}Summary`).innerText = d.summary;
    document.getElementById(`${prefix}Pairs`).innerHTML = d.pairs.map(p => {
      const cls = p.direction.includes("BULLISH") ? "bull" : p.direction.includes("BEARISH") ? "bear" : "neut";
      return `<tr><td><strong>${p.pair}</strong></td><td class="${cls}">${p.direction}</td><td>${p.range}</td><td style="color:var(--muted)">${p.note}</td></tr>`;
    }).join("");
  }

  async function decodeNFP() {
    const payload = {
      consensus_nfp: Number(document.getElementById("nfp_cons").value),
      actual_nfp: Number(document.getElementById("dec_nfp_act").value),
      revisions_k: Number(document.getElementById("dec_nfp_rev").value),
      unemp_forecast: Number(document.getElementById("dec_un_f").value),
      unemp_actual: Number(document.getElementById("dec_un_a").value),
      ahe_forecast: Number(document.getElementById("dec_ahe_f").value),
      ahe_actual: Number(document.getElementById("dec_ahe_a").value)
    };
    const res = await fetch("/api/decode-nfp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const d = await res.json();
    const out = document.getElementById("nfpDecodeOut");
    out.classList.remove("hidden");
    out.innerHTML = `<div style="color:var(--gold-bright); font-weight:800; margin-bottom:0.3rem;">${d.verdict}</div><p style="font-size:0.86rem;">${d.plan}</p>`;
  }

  async function decodeCPI() {
    const payload = {
      headline_forecast: Number(document.getElementById("dec_cpi_hf").value),
      headline_actual: Number(document.getElementById("dec_cpi_ha").value),
      core_forecast: Number(document.getElementById("dec_cpi_cf").value),
      core_actual: Number(document.getElementById("dec_cpi_ca").value)
    };
    const res = await fetch("/api/decode-cpi", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const d = await res.json();
    const out = document.getElementById("cpiDecodeOut");
    out.classList.remove("hidden");
    out.innerHTML = `<div style="color:var(--gold-bright); font-weight:800; margin-bottom:0.3rem;">${d.verdict}</div><p style="font-size:0.86rem;">${d.plan}</p>`;
  }

  async function apiPost(url, payload) {
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, data };
  }

  function errText(data) {
    return (data && typeof data.detail === "string") ? data.detail : "Please check the inputs and try again.";
  }

  function pairRows(pairs) {
    return pairs.map(p => {
      const cls = p.direction.includes("BULLISH") ? "bull" : p.direction.includes("BEARISH") ? "bear" : "neut";
      return `<tr><td><strong>${esc(p.pair)}</strong></td><td class="${cls}">${esc(p.direction)}</td><td>${esc(p.range)}</td><td style="color:var(--muted)">${esc(p.note)}</td></tr>`;
    }).join("");
  }

  function setVerdict(prefix, d, labels) {
    const el = document.getElementById(prefix + "Bias");
    const up = d.bias === "HOTTER" || d.bias === "HAWKISH";
    const down = d.bias === "COOLER" || d.bias === "DOVISH";
    el.innerText = up ? labels.up : down ? labels.down : labels.flat;
    el.className = "big-score " + (up ? "bull" : down ? "bear" : "neut");
  }

  function showDecode(id, d) {
    const out = document.getElementById(id);
    out.classList.remove("hidden");
    out.innerHTML = `<div style="color:var(--gold-bright); font-weight:800; margin-bottom:0.3rem;">${esc(d.verdict)}</div><p style="font-size:0.86rem;">${esc(d.plan)}</p>`;
  }

  function ppiPayload() {
    const val = id => Number(document.getElementById(id).value);
    return {
      ppi_mom_consensus: val("ppi_cons"),
      ism_srv_prices: val("ppi_srvp"),
      ism_srv_prices_prev: val("ppi_srvp_p"),
      ism_mfg_prices: val("ppi_mfgp"),
      ism_mfg_prices_prev: val("ppi_mfgp_p"),
      gas_oil_pct_change: val("ppi_gas"),
      regional_fed_prices: val("ppi_fed"),
      regional_fed_prices_prev: val("ppi_fed_p"),
      freight_rate_pct: val("ppi_frt"),
      agri_metals_pct: val("ppi_met"),
      nfib_price_plans: val("ppi_nfib"),
      import_price_surprise: val("ppi_imp"),
      is_jan_or_jul: document.getElementById("ppi_jj").checked
    };
  }

  function renderPPI(data) {
    setVerdict("ppi", data, { up: "HOTTER (USD BULLISH / GOLD BEARISH)", down: "COOLER (USD BEARISH / GOLD BULLISH)", flat: "NO-TRADE / LOW EDGE" });
    document.getElementById("ppiTier").innerText = data.tier;
    document.getElementById("ppiScore").innerText = `Score: ${data.score > 0 ? "+" : ""}${data.score} | Gate: ±${data.buffer}`;
    document.getElementById("ppiSummary").innerText = data.summary;
    document.getElementById("ppiPairs").innerHTML = pairRows(data.pairs);
  }

  async function calcPPI() {
    const { ok, data } = await apiPost("/api/predict-ppi", { user_email: currentUser ? currentUser.email : "", ...ppiPayload() });
    if (!ok) { document.getElementById("ppiSummary").innerText = errText(data); return; }
    renderPPI(data);
  }

  async function decodePPI() {
    const val = id => Number(document.getElementById(id).value);
    const { ok, data } = await apiPost("/api/decode-ppi", {
      headline_forecast: val("dec_ppi_hf"), headline_actual: val("dec_ppi_ha"),
      core_forecast: val("dec_ppi_cf"), core_actual: val("dec_ppi_ca")
    });
    showDecode("ppiDecodeOut", ok ? data : { verdict: "Could not decode", plan: errText(data) });
  }

  function fomcPayload() {
    const val = id => Number(document.getElementById(id).value);
    return {
      fedwatch_prob_pct: val("fomc_prob"),
      expected_move: document.getElementById("fomc_move").value,
      us2y_yield_5d_bps: val("fomc_us2y"),
      recent_core_cpi_surprise: val("fomc_cpi"),
      nfp_recent_edge: document.getElementById("fomc_nfp").value
    };
  }

  function renderFOMC(data) {
    setVerdict("fomc", data, { up: "HAWKISH LEAN (USD BULLISH / GOLD BEARISH)", down: "DOVISH LEAN (USD BEARISH / GOLD BULLISH)", flat: "NO-TRADE / INLINE HOLD" });
    document.getElementById("fomcTier").innerText = data.crowded ? "CROWDED CONSENSUS (BUY RUMOR / SELL FACT RISK)" : "";
    document.getElementById("fomcScore").innerText = `Hawkish score: ${data.score > 0 ? "+" : ""}${data.score} | Gate: ±${data.gate} | Reversal risk: ${data.reversal_risk}`;
    document.getElementById("fomcSummary").innerText = data.summary;
    document.getElementById("fomcPairs").innerHTML = pairRows(data.pairs);
  }

  async function calcFOMC() {
    const { ok, data } = await apiPost("/api/predict-fomc", { user_email: currentUser ? currentUser.email : "", ...fomcPayload() });
    if (!ok) { document.getElementById("fomcSummary").innerText = errText(data); return; }
    renderFOMC(data);
  }

  async function decodeFOMC() {
    const { ok, data } = await apiPost("/api/decode-fomc", {
      rate_surprise: document.getElementById("dec_fomc_rate").value,
      dot_plot_tone: document.getElementById("dec_fomc_dots").value,
      vote_split: document.getElementById("dec_fomc_vote").value,
      chair_presser_cue: document.getElementById("dec_fomc_chair").value
    });
    showDecode("fomcDecodeOut", ok ? data : { verdict: "Could not decode", plan: errText(data) });
  }

  let viewMode = "desk";
  let signals = {};

  const MODULE_LABELS = {
    NFP:  { up: "USD BULLISH (BEAT / HOTTER)", down: "USD BEARISH (MISS / COOLER)", flat: "NO-TRADE / LOW EDGE" },
    CPI:  { up: "USD BULLISH (BEAT / HOTTER)", down: "USD BEARISH (MISS / COOLER)", flat: "NO-TRADE / LOW EDGE" },
    PPI:  { up: "HOTTER (USD BULLISH / GOLD BEARISH)", down: "COOLER (USD BEARISH / GOLD BULLISH)", flat: "NO-TRADE / LOW EDGE" },
    FOMC: { up: "HAWKISH LEAN (USD BULLISH / GOLD BEARISH)", down: "DOVISH LEAN (USD BEARISH / GOLD BULLISH)", flat: "NO-TRADE / INLINE HOLD" }
  };
  const MODULE_API = { NFP: "/api/predict-nfp", CPI: "/api/predict-cpi", PPI: "/api/predict-ppi", FOMC: "/api/predict-fomc" };

  function setMode(mode) {
    viewMode = mode;
    document.body.classList.toggle("client-mode", mode === "client");
    const btn = document.getElementById("previewBtn");
    if (btn) btn.innerText = mode === "client" ? "🛠️ Back to Desk Mode" : "👁️ Preview Client View";
    if (mode === "client") loadSignals();
  }

  function togglePreview() {
    setMode(viewMode === "client" ? "desk" : "client");
  }

  function fmtTime(iso) {
    const t = new Date(iso);
    return isNaN(t.getTime()) ? String(iso || "unknown") : t.toLocaleString();
  }

  function renderClientPanel(mod, failed) {
    const p = mod.toLowerCase();
    const badge = document.getElementById(p + "Badge");
    const bias = document.getElementById(p + "CBias");
    const sig = signals[mod];
    if (failed || !sig || !sig.result) {
      badge.innerText = "🏛️ A&M Group Research Desk — Official Pre-Release Signal";
      bias.innerText = failed ? "COULD NOT LOAD" : "AWAITING DESK SIGNAL";
      bias.className = "big-score neut";
      document.getElementById(p + "CTier").innerText = "";
      document.getElementById(p + "CScore").innerText = "";
      document.getElementById(p + "CSummary").innerText = failed
        ? "The latest desk signal could not be loaded. Tap Refresh Latest Desk Signal to try again."
        : "The research desk has not published a forecast for this release yet. Tap Refresh Latest Desk Signal to check again.";
      document.getElementById(p + "CPairs").innerHTML = "";
      return;
    }
    const d = sig.result;
    const sign = d.score > 0 ? "+" : "";
    let metric = `Score: ${sign}${d.score}`;
    if (mod === "NFP") metric = `Edge: ${sign}${d.score}K`;
    if (mod === "PPI" && d.buffer !== undefined) metric += ` | Gate: ±${d.buffer}`;
    if (mod === "FOMC") metric = `Hawkish score: ${sign}${d.score} | Gate: ±${d.gate} | Reversal risk: ${d.reversal_risk}`;
    const L = MODULE_LABELS[mod];
    const up = d.bias === "HOTTER" || d.bias === "HAWKISH";
    const down = d.bias === "COOLER" || d.bias === "DOVISH";
    badge.innerText = `🏛️ A&M Group Research Desk — Official Pre-Release Signal (Updated: ${fmtTime(sig.updated_at)})`;
    bias.innerText = up ? L.up : down ? L.down : L.flat;
    bias.className = "big-score " + (up ? "bull" : down ? "bear" : "neut");
    document.getElementById(p + "CTier").innerText = d.tier || "";
    document.getElementById(p + "CScore").innerText = metric;
    document.getElementById(p + "CSummary").innerText = d.summary || "";
    document.getElementById(p + "CPairs").innerHTML = Array.isArray(d.pairs) ? pairRows(d.pairs) : "";
  }

  async function loadSignals() {
    let failed = false;
    try {
      const res = await fetch("/api/signals");
      if (!res.ok) throw new Error("bad response");
      const data = await res.json();
      signals = data.signals || {};
    } catch (e) {
      failed = true;
    }
    ["NFP", "CPI", "PPI", "FOMC"].forEach(m => renderClientPanel(m, failed));
    // The post-release NFP decoder needs the official consensus that the hidden input card normally supplies.
    const nfp = signals.NFP;
    if (!failed && currentUser && !currentUser.is_admin && nfp && nfp.inputs && nfp.inputs.consensus_nfp !== undefined) {
      document.getElementById("nfp_cons").value = nfp.inputs.consensus_nfp;
    }
  }

  function nfpPayload() {
    const val = id => Number(document.getElementById(id).value);
    return {
      consensus_nfp: val("nfp_cons"),
      net_strike_weather_adj: val("nfp_strike"),
      icsa_change_k: val("nfp_icsa"),
      ccsa_change_k: val("nfp_ccsa"),
      ism_services_emp: val("nfp_isms"),
      ism_services_prev: val("nfp_isms_p"),
      adp_actual: val("nfp_adp"),
      adp_consensus: val("nfp_adp_c"),
      homebase_hours_pct: val("nfp_hb"),
      labor_diff_change: val("nfp_labor"),
      ism_mfg_emp: val("nfp_ismm"),
      ism_mfg_prev: val("nfp_ismm_p"),
      nfib_hiring_actual: val("nfp_nfib"),
      nfib_hiring_prev: val("nfp_nfib_p"),
      prev_govt_edu_swing: val("nfp_edu"),
      is_summer_school_month: document.getElementById("nfp_summer").checked
    };
  }

  function cpiPayload() {
    const val = id => Number(document.getElementById(id).value);
    return {
      cpi_mom_consensus: val("cpi_cons"),
      cleveland_nowcast_mom: val("cpi_clev"),
      gas_oil_pct_change: val("cpi_gas"),
      ppi_surprise_mom: val("cpi_ppi"),
      ism_srv_prices: val("cpi_srvp"),
      ism_srv_prices_prev: val("cpi_srvp_p"),
      ism_mfg_prices: val("cpi_mfgp"),
      ism_mfg_prices_prev: val("cpi_mfgp_p"),
      manheim_used_car_pct: val("cpi_manheim"),
      rent_index_pct: val("cpi_rent"),
      nfib_price_plans: val("cpi_nfib")
    };
  }

  function payloadFor(mod) {
    return { NFP: nfpPayload, CPI: cpiPayload, PPI: ppiPayload, FOMC: fomcPayload }[mod]();
  }

  async function publishSignal(mod) {
    const status = document.getElementById(mod.toLowerCase() + "PubStatus");
    if (!confirm(`Publish this ${mod} forecast to all clients? It replaces the current official ${mod} signal.`)) return;
    status.innerText = "Calculating and publishing...";
    try {
      const inputs = payloadFor(mod);
      const calc = await apiPost(MODULE_API[mod], { user_email: currentUser.email, ...inputs });
      if (!calc.ok) { status.innerText = "Could not calculate: " + errText(calc.data); return; }
      if (mod === "NFP") renderForecast("nfp", calc.data, true);
      if (mod === "CPI") renderForecast("cpi", calc.data, false);
      if (mod === "PPI") renderPPI(calc.data);
      if (mod === "FOMC") renderFOMC(calc.data);
      const pub = await apiPost("/api/admin/publish-signal", { module: mod, inputs, result: calc.data, updated_at: new Date().toISOString() });
      if (!pub.ok) { status.innerText = "Publish failed: " + errText(pub.data); return; }
      const where = pub.data.storage && !pub.data.storage.includes("Permanent") ? " WARNING: saved only to temporary storage (" + pub.data.storage + ")." : "";
      status.innerText = `✅ Published to clients (${fmtTime(pub.data.updated_at)}).${where}`;
    } catch (e) {
      status.innerText = "Publish failed. Check your connection and try again.";
    }
  }

  if (currentUser) {
    fetch("/api/me")
      .then(r => r.ok ? r.json() : null)
      .then(me => {
        if (me) { currentUser.is_admin = me.is_admin; enterTerminal(); }
        else { localStorage.removeItem("am_user"); currentUser = null; }
      })
      .catch(() => { enterTerminal(); });
  }
</script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
