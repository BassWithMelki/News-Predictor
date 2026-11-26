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
import csv
import io
import threading
from typing import Optional
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

    # GBP / EUR energy inputs: Brent crude (daily) and EU natural gas (monthly)
    brent = fetch_fred_obs("DCOILBRENTEU", 25)
    brent_pct = round(((brent[0] - brent[20]) / brent[20]) * 100.0, 2) if len(brent) >= 21 and brent[20] != 0 else 0.0
    eu_gas = fetch_fred_obs("PNGASEUUSDM", 3)
    eu_gas_pct = round(((eu_gas[0] - eu_gas[1]) / eu_gas[1]) * 100.0, 2) if len(eu_gas) >= 2 and eu_gas[1] != 0 else brent_pct
    eur_energy_pct = round((eu_gas_pct * 0.6) + (brent_pct * 0.4), 2)

    source_note = "Live Federal Reserve (FRED API) & WTI Crude Feed" if FRED_API_KEY else "Live Federal Reserve Public CSV & WTI Crude Feed"
    return {
        "source": source_note,
        "nfp": {"icsa_change_k": icsa_delta, "ccsa_change_k": ccsa_delta},
        "cpi": {"gas_oil_pct_change": oil_pct},
        "gbp": {"uk_gas_petrol_pct": brent_pct},
        "eur": {"ttf_gas_brent_pct": eur_energy_pct}
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

# ---------------------------------------------------------------------------
# GBP V2 + EUR V2 predictors and post-release decoders
# ---------------------------------------------------------------------------
def _clamp(v):
    return max(-1.0, min(1.0, v))

def _gate_verdict(score, buffer, reason, subject, bull_text, bear_text):
    """Shared V2 guardrail. Returns (bias, bias_dir, mult, verdict, tier, summary)."""
    if abs(score) < buffer:
        verdict = "NO-TRADE / LOW EDGE"
        return ("NEUTRAL", 0, 0.55, verdict,
                f"NO-TRADE / LOW EDGE (±{buffer:g} gate: {reason})",
                f"Score {score:+.1f} is inside the ±{buffer:g} gate ({reason}). Skip the {subject} spike and wait for the print.")
    strong = abs(score) >= buffer + 20
    mult = 1.2 if strong else 0.9
    prefix = "TIER 1 " if strong else "TIER 2 "
    if score > 0:
        verdict = bull_text
        return ("HOTTER", 1, mult, verdict, prefix + verdict,
                f"{subject} proxies lean above consensus (score {score:+.1f} vs ±{buffer:g} gate; {reason}). {bull_text}.")
    verdict = bear_text
    return ("COOLER", -1, mult, verdict, prefix + verdict,
            f"{subject} proxies lean below consensus (score {score:+.1f} vs ±{buffer:g} gate; {reason}). {bear_text}.")

def _v2_payload(score, buffer, reason, bias, verdict, tier, summary, assets, bias_dir, mult, extra=None):
    out = {"score": score, "bias": bias, "verdict": verdict, "tier": tier,
           "confidence": min(85, round(50 + abs(score) * 0.44)),
           "buffer": buffer, "buffer_reason": reason, "summary": summary,
           "pairs": _spike_rows(assets, bias_dir, mult, "NO-TRADE / LOW EDGE")}
    if extra:
        out.update(extra)
    return out

# ----- GBP -----
class GBP_CPIInput(BaseModel):
    user_email: str
    uk_cpi_consensus: float = 2.4
    uk_srv_pmi_prices: float = 57.5
    uk_srv_pmi_prices_prev: float = 56.0
    brc_shop_price_yoy: float = 1.8
    brc_shop_price_prev: float = 1.5
    uk_input_ppi_mom: float = 0.3
    kantar_grocery_yoy: float = 2.6
    kantar_grocery_prev: float = 2.3
    uk_gas_petrol_pct: float = 3.5
    rec_starting_salaries: float = 53.0
    is_ofgem_reset_month: bool = False

class GBP_JobsInput(BaseModel):
    user_email: str
    boe_dmp_wage_exp: float = 4.2
    rec_starting_salaries: float = 53.5
    rec_starting_salaries_prev: float = 52.0
    rec_placements_idx: float = 48.5
    rec_placements_prev: float = 47.0
    uk_pmi_emp: float = 50.8
    uk_pmi_emp_prev: float = 49.9
    hmrc_paye_change_k: float = 15.0
    adzuna_job_ads_pct: float = 1.2

class DecodeGBPReq(BaseModel):
    event_type: str
    headline_forecast: float
    headline_actual: float
    core_or_wages_forecast: float
    core_or_wages_actual: float

@app.post("/api/predict-gbp-cpi")
def predict_gbp_cpi(data: GBP_CPIInput, user: str = Depends(require_admin)):
    check_numbers(data)
    increment_usage(user)
    sig_srv = _clamp(((data.uk_srv_pmi_prices - data.uk_srv_pmi_prices_prev) + ((data.uk_srv_pmi_prices - 55.0) * 0.3)) / 4.0)
    sig_brc = _clamp(((data.brc_shop_price_yoy - data.brc_shop_price_prev) + ((data.brc_shop_price_yoy - 1.5) * 0.5)) / 1.5)
    sig_ppi = _clamp((data.uk_input_ppi_mom - 0.1) / 0.5)
    sig_kan = _clamp(((data.kantar_grocery_yoy - data.kantar_grocery_prev) + ((data.kantar_grocery_yoy - 2.5) * 0.5)) / 1.5)
    sig_gas = _clamp(data.uk_gas_petrol_pct / 8.0)
    sig_sal = _clamp((data.rec_starting_salaries - 50.0) / 5.0)

    score = round((sig_srv * 30) + (sig_brc * 25) + (sig_ppi * 20) + (sig_kan * 10) + (sig_gas * 8) + (sig_sal * 7), 1)
    buffer = 35.0 if data.is_ofgem_reset_month else 25.0
    reason = "Ofgem energy-cap reset month" if data.is_ofgem_reset_month else "standard gate"
    bias, bias_dir, mult, verdict, tier, summary = _gate_verdict(
        score, buffer, reason, "UK CPI",
        "HOTTER UK CPI (GBP BULLISH): lean GBP up on BoE services-inflation repricing",
        "COOLER UK CPI (GBP BEARISH): lean GBP down as BoE cut pricing builds")
    assets = [
        {"pair": "GBP/JPY", "base": 135, "inv": False, "note": "Highest-beta GBP cross; let the first 2 minutes of spread settle"},
        {"pair": "GBP/USD", "base": 95,  "inv": False, "note": "Cleanest read of BoE rate-path repricing; wait for the 5m candle"},
        {"pair": "EUR/GBP", "base": 55,  "inv": True,  "note": "Inverse leg: a hot UK print pushes EUR/GBP lower; thin liquidity, wide spreads"},
    ]
    return _v2_payload(score, buffer, reason, bias, verdict, tier, summary, assets, bias_dir, mult)

@app.post("/api/predict-gbp-jobs")
def predict_gbp_jobs(data: GBP_JobsInput, user: str = Depends(require_admin)):
    check_numbers(data)
    increment_usage(user)
    sig_dmp = _clamp((data.boe_dmp_wage_exp - 4.0) / 1.0)
    sig_sal = _clamp(((data.rec_starting_salaries - data.rec_starting_salaries_prev) + ((data.rec_starting_salaries - 50.0) * 0.5)) / 3.0)
    plc_delta = data.rec_placements_idx - data.rec_placements_prev
    sig_plc = _clamp((plc_delta + ((data.rec_placements_idx - 50.0) * 0.5)) / 3.0)
    sig_pmi = _clamp(((data.uk_pmi_emp - data.uk_pmi_emp_prev) + ((data.uk_pmi_emp - 50.0) * 0.5)) / 2.5)
    sig_paye = _clamp(data.hmrc_paye_change_k / 50.0)
    sig_adz = _clamp(data.adzuna_job_ads_pct / 3.0)

    score = round((sig_dmp * 20) + (sig_sal * 15) + (sig_plc * 25) + (sig_pmi * 20) + (sig_paye * 12) + (sig_adz * 8), 1)

    # V2 guardrail: LFS divergence filter (HMRC PAYE vs REC placements pointing opposite ways)
    lfs_divergence = (data.hmrc_paye_change_k * plc_delta) < 0
    buffer = 32.0 if lfs_divergence else 25.0
    reason = "LFS divergence: HMRC PAYE and REC placements disagree" if lfs_divergence else "standard gate"
    bias, bias_dir, mult, verdict, tier, summary = _gate_verdict(
        score, buffer, reason, "UK labour-market",
        "HAWKISH WAGE-LED JOBS (GBP BULLISH): lean GBP up",
        "SOFT WAGE-LED JOBS (GBP BEARISH): lean GBP down")
    assets = [
        {"pair": "GBP/JPY", "base": 110, "inv": False, "note": "Wage prints move BoE pricing; wait for the first 5m candle"},
        {"pair": "GBP/USD", "base": 75,  "inv": False, "note": "Follows UK 2Y gilt repricing after the print"},
        {"pair": "EUR/GBP", "base": 45,  "inv": True,  "note": "Inverse leg; low liquidity around the 7:00 UK release"},
    ]
    return _v2_payload(score, buffer, reason, bias, verdict, tier, summary, assets, bias_dir, mult,
                       {"lfs_divergence": lfs_divergence})

# ----- shared divergence classifier for the decoders -----
def _classify(h, c, thr):
    """h / c are signed so that positive = bullish for the currency. Headline = h, Core/Services/Wages = c."""
    if h <= -thr and c >= thr:
        return "TRAP_BULL"
    if h >= thr and c <= -thr:
        return "TRAP_BEAR"
    if c >= thr and h >= 0:
        return "CLEAN_BULL"
    if c <= -thr and h <= 0:
        return "CLEAN_BEAR"
    return "FLAT"

GBP_DECODER_TEXT = {
    "UK_CPI": {
        "TRAP_BULL": ("UK SERVICES CPI DIVERGENCE TRAP (HEADLINE MISS, SERVICES BEAT)",
            "Headline CPI missed but Services CPI, the BoE's focus, beat. The first dip is a trap. "
            "GBP/USD: fade the initial dip and BUY once a 5-minute candle closes back above the pre-news level. "
            "GBP/JPY: same plan, BUY the failed breakdown. EUR/GBP: SELL a failed push higher."),
        "TRAP_BEAR": ("UK FALSE SPIKE TRAP (HEADLINE HOT, SERVICES COOL)",
            "Headline beat but Services CPI missed, so the BoE is unlikely to turn hawkish. "
            "GBP/USD and GBP/JPY: fade the initial rally and SELL a failed 5-minute breakout. EUR/GBP: BUY the first dip."),
        "CLEAN_BULL": ("HOT SERVICES & HEADLINE CPI — GBP BULLISH",
            "Sticky services inflation cuts BoE easing hopes. BUY GBP/USD and GBP/JPY on the first 5-minute pullback; SELL EUR/GBP on bounces."),
        "CLEAN_BEAR": ("COOL SERVICES & HEADLINE CPI — GBP BEARISH",
            "Disinflation confirmed in services. SELL GBP/USD and GBP/JPY on the first 5-minute pullback; BUY EUR/GBP on dips."),
        "FLAT": ("INLINE / MIXED UK CPI — STAND ASIDE",
            "Headline and services offset or matched consensus. Expect two-way wicks in GBP/USD and GBP/JPY; skip it and keep capital for the next release."),
    },
    "UK_JOBS": {
        "TRAP_BULL": ("UK WAGE DIVERGENCE TRAP (JOBS MISS, WAGES BEAT)",
            "Headline labour data was weak but 3M YoY wage growth beat, which is what the BoE watches. "
            "GBP/USD: fade the initial dip and BUY after the 5-minute candle closes back above the pre-news level. "
            "GBP/JPY: same plan. EUR/GBP: SELL a failed push higher."),
        "TRAP_BEAR": ("UK STRONG-HEADLINE / WEAK-WAGE TRAP",
            "Headline labour data beat but wage growth missed, so BoE hawkishness is not supported. "
            "GBP/USD and GBP/JPY: fade the initial rally and SELL a failed 5-minute breakout. EUR/GBP: BUY the first dip."),
        "CLEAN_BULL": ("STRONG JOBS & WAGES — GBP BULLISH",
            "Labour market and wages both firm. BUY GBP/USD and GBP/JPY on the first 5-minute pullback; SELL EUR/GBP on bounces."),
        "CLEAN_BEAR": ("WEAK JOBS & WAGES — GBP BEARISH",
            "Labour market and wages both soft. SELL GBP/USD and GBP/JPY on the first 5-minute pullback; BUY EUR/GBP on dips."),
        "FLAT": ("INLINE / MIXED UK JOBS PRINT — STAND ASIDE",
            "Headline and wages offset or matched consensus. Skip GBP pairs and wait for the next release."),
    },
}

@app.post("/api/decode-gbp")
def decode_gbp(d: DecodeGBPReq, user: str = Depends(current_user)):
    check_numbers(d)
    ev = d.event_type.strip().upper()
    if ev not in GBP_DECODER_TEXT:
        raise HTTPException(status_code=422, detail="'event_type' must be UK_CPI or UK_JOBS.")
    head_diff = round(d.headline_actual - d.headline_forecast, 2)
    core_diff = round(d.core_or_wages_actual - d.core_or_wages_forecast, 2)
    # For UK_JOBS the headline is the unemployment rate, where a HIGHER number is weaker for GBP.
    h = -head_diff if ev == "UK_JOBS" else head_diff
    scenario = _classify(h, core_diff, 0.1)
    verdict, plan = GBP_DECODER_TEXT[ev][scenario]
    return {"verdict": verdict, "plan": plan}

# ----- EUR -----
class EUR_CPIInput(BaseModel):
    user_email: str
    eur_cpi_mode: str = "YoY"                 # "YoY" or "MoM"
    eur_cpi_consensus: float = 2.1
    germany_hicp: float = 2.3
    france_hicp: float = 2.1
    italy_hicp: float = 1.9
    spain_hicp: float = 2.5
    netherlands_hicp: Optional[float] = None  # optional, leave blank if not released
    belgium_hicp: Optional[float] = None      # optional, leave blank if not released
    hcob_srv_prices: float = 55.2             # HCOB flash services output prices index, this month
    hcob_srv_prices_prev: float = 54.0        # same index, previous month
    ttf_gas_brent_pct: float = 4.0            # TTF gas / Brent monthly % change (Auto-Fetch fills this)

class EUR_PMIInput(BaseModel):
    user_email: str
    eur_comp_pmi_consensus: float = 50.5
    german_flash_pmi: float = 51.4
    french_flash_pmi: float = 50.8
    zew_sentix_change: float = 3.5
    eur_new_orders_subidx: float = 51.0

class DecodeEURReq(BaseModel):
    event_type: str
    headline_forecast: float
    headline_actual: float
    core_or_services_forecast: float
    core_or_services_actual: float

def _half_up(x, digits):
    f = 10 ** digits
    return math.floor(x * f + 0.5) / f

@app.post("/api/predict-eur-cpi")
def predict_eur_cpi(data: EUR_CPIInput, user: str = Depends(require_admin)):
    """Eurozone Flash CPI Proxy v3: dynamic-weight nowcast from national HICP flashes with a strict DO NOT TRADE gate."""
    check_numbers(data)
    mode = data.eur_cpi_mode.strip().upper().replace("-", "")
    if mode not in ("YOY", "MOM"):
        raise HTTPException(status_code=422, detail="'eur_cpi_mode' must be YoY or MoM.")
    increment_usage(user)
    # lead indicator is derived: services output prices and gas both up = +0.05, both down = -0.05, otherwise 0
    srv_change = data.hcob_srv_prices - data.hcob_srv_prices_prev
    gas_change = data.ttf_gas_brent_pct
    if srv_change > 0 and gas_change > 0:
        lead, lead_label = 0.05, "BULLISH (+0.05%)"
    elif srv_change < 0 and gas_change < 0:
        lead, lead_label = -0.05, "BEARISH (-0.05%)"
    else:
        lead, lead_label = 0.0, "NEUTRAL (0.00%)"

    de, fr, it, es = data.germany_hicp, data.france_hicp, data.italy_hicp, data.spain_hicp
    nl, be = data.netherlands_hicp, data.belgium_hicp
    consensus = data.eur_cpi_consensus

    weighted_sum = (0.278 * de) + (0.203 * fr) + (0.168 * it) + (0.111 * es)
    total_weight = 0.760
    if nl is not None:
        weighted_sum += 0.057 * nl
        total_weight += 0.057
    if be is not None:
        weighted_sum += 0.038 * be
        total_weight += 0.038

    scaled = weighted_sum / total_weight
    spread = 0.08 if mode == "YOY" else 0.015
    predicted = scaled + spread + lead
    rounded = _half_up(predicted, 1)
    delta = predicted - consensus
    coverage = _half_up(total_weight * 100, 1)

    # --- safety gate (a tiny epsilon keeps float noise from flipping a threshold) ---
    EPS = 1e-9
    flag_a = abs(delta) < 0.12 - EPS
    # normalised so negative MoM prints land in the same 0-9 bucket as positive ones
    hundredths = int(_half_up(((predicted * 100) % 10 + 10) % 10, 0))
    flag_b = total_weight < 0.85 - EPS and hundredths in (4, 5, 6) and abs(delta) < 0.15 - EPS
    de_gap, fr_gap = de - consensus, fr - consensus
    flag_c = ((de_gap >= 0.10 - EPS and fr_gap <= -0.10 + EPS) or (de_gap <= -0.10 + EPS and fr_gap >= 0.10 - EPS))

    reasons = []
    if flag_a:
        reasons.append("Spread < 0.12% noise threshold")
    if flag_b:
        reasons.append("Rounding cliff danger zone")
    if flag_c:
        reasons.append("DE/FR core divergence")

    edge_txt = f"{delta:+.2f}%"
    if reasons:
        signal, bias, bias_dir, mult = "DO NOT TRADE (UNSURE)", "NEUTRAL", 0, 0.55
        note = f"Trade blocked to protect capital: {'; '.join(reasons)}."
    elif delta >= 0.12 - EPS:
        signal, bias, bias_dir, mult = "STRONG BUY EUR", "HOTTER", 1, (1.2 if abs(delta) >= 0.25 else 0.9)
        note = f"Proxy is {edge_txt} above consensus with no safety flags, so the confirmed bias is bullish EUR."
    else:
        signal, bias, bias_dir, mult = "STRONG SELL EUR", "COOLER", -1, (1.2 if abs(delta) >= 0.25 else 0.9)
        note = f"Proxy is {edge_txt} below consensus with no safety flags, so the confirmed bias is bearish EUR."

    assets = [
        {"pair": "EUR/JPY", "base": 105, "inv": False, "note": "High-beta EUR cross; wait 2 minutes for spreads to normalise"},
        {"pair": "EUR/USD", "base": 78,  "inv": False, "note": "Cleanest follow-through after the 5m candle closes"},
        {"pair": "EUR/GBP", "base": 50,  "inv": False, "note": "Slower mover; confirm the direction on EUR/USD first"},
    ]
    return {
        "signal": signal, "bias": bias, "verdict": signal, "tier": f"Coverage: {coverage:.1f}% HICP",
        "score": round(delta, 2), "summary": note, "note": note, "reasons": reasons,
        "mode": "YoY" if mode == "YOY" else "MoM", "lead_adjustment": lead, "lead_label": lead_label,
        "proxy_rounded": rounded, "predicted_cpi": round(predicted, 4), "consensus": consensus,
        "surprise_delta": round(delta, 4), "coverage_pct": coverage,
        "inputs": {"DE": de, "FR": fr, "IT": it, "ES": es, "NL": nl, "BE": be},
        "flags": {"insufficient_edge": flag_a, "rounding_cliff": flag_b, "core_divergence": flag_c},
        "pairs": _spike_rows(assets, bias_dir, mult, "DO NOT TRADE"),
    }

@app.post("/api/predict-eur-pmi")
def predict_eur_pmi(data: EUR_PMIInput, user: str = Depends(require_admin)):
    check_numbers(data)
    increment_usage(user)
    cons = data.eur_comp_pmi_consensus
    sig_ger = _clamp((data.german_flash_pmi - cons) / 1.5)
    sig_fr = _clamp((data.french_flash_pmi - cons) / 1.5)
    sig_zew = _clamp(data.zew_sentix_change / 10.0)
    sig_no = _clamp((data.eur_new_orders_subidx - 50.0) / 3.0)

    score = round((sig_ger * 40) + (sig_fr * 25) + (sig_zew * 20) + (sig_no * 15), 1)

    # V2 guardrail: Franco-German divergence gate
    divergence = (abs(data.german_flash_pmi - data.french_flash_pmi) >= 2.5
                  and (data.german_flash_pmi - 50.0) * (data.french_flash_pmi - 50.0) < 0)
    buffer = 36.0 if divergence else 25.0
    reason = "Franco-German PMIs sit on opposite sides of 50" if divergence else "standard gate"
    bias, bias_dir, mult, verdict, tier, summary = _gate_verdict(
        score, buffer, reason, "Eurozone flash PMI",
        "STRONGER EZ PMI (EUR BULLISH): lean EUR up",
        "WEAKER EZ PMI (EUR BEARISH): lean EUR down")
    assets = [
        {"pair": "EUR/JPY", "base": 80, "inv": False, "note": "Risk-sensitive; moves with the equity reaction to the PMI"},
        {"pair": "EUR/USD", "base": 60, "inv": False, "note": "Wait for the first 5m candle; PMI spikes often fade"},
        {"pair": "EUR/GBP", "base": 40, "inv": False, "note": "Low volatility; trade only if EUR/USD confirms"},
    ]
    return _v2_payload(score, buffer, reason, bias, verdict, tier, summary, assets, bias_dir, mult,
                       {"franco_german_divergence": divergence})

EUR_DECODER_TEXT = {
    "EUR_CPI": {
        "TRAP_BULL": ("CORE CPI DIVERGENCE TRAP (HEADLINE MISS, CORE BEAT)",
            "Headline flash CPI missed but Core beat, and the ECB watches Core. The first dip is a trap. "
            "EUR/USD: fade the dip and BUY after a 5-minute close back above the pre-news level. "
            "EUR/JPY: BUY the failed breakdown. EUR/GBP: BUY the first 5-minute pullback, but only if EUR/USD has already recovered."),
        "TRAP_BEAR": ("FALSE SPIKE TRAP (HEADLINE HOT, CORE COOL)",
            "Headline beat but Core missed, so the ECB is unlikely to turn hawkish. "
            "EUR/USD: fade the initial rally and SELL a failed 5-minute breakout. EUR/JPY: same plan. EUR/GBP: SELL the first failed push higher."),
        "CLEAN_BULL": ("HOT CORE & HEADLINE CPI — EUR BULLISH",
            "Sticky core inflation trims ECB easing bets. BUY EUR/USD, EUR/JPY and EUR/GBP on the first 5-minute pullback."),
        "CLEAN_BEAR": ("COOL CORE & HEADLINE CPI — EUR BEARISH",
            "Disinflation confirmed in Core. SELL EUR/USD, EUR/JPY and EUR/GBP on the first 5-minute pullback."),
        "FLAT": ("INLINE / MIXED EZ CPI — STAND ASIDE",
            "Headline and core offset or matched consensus. Expect two-way wicks on EUR/USD, EUR/JPY and EUR/GBP; preserve capital."),
    },
    "EUR_PMI": {
        "TRAP_BULL": ("SERVICES PMI DIVERGENCE TRAP (COMPOSITE MISS, SERVICES BEAT)",
            "Composite flash PMI missed but Services PMI beat; services drive Eurozone growth and inflation. "
            "EUR/USD: fade the dip and BUY after the 5-minute candle closes back above the pre-news level. "
            "EUR/JPY: BUY the failed breakdown. EUR/GBP: BUY only after EUR/USD confirms."),
        "TRAP_BEAR": ("MANUFACTURING-LED FALSE SPIKE (COMPOSITE BEAT, SERVICES MISS)",
            "Composite beat but Services PMI missed, so the strength is narrow. "
            "EUR/USD and EUR/JPY: fade the initial rally and SELL a failed 5-minute breakout. EUR/GBP: SELL the first failed push higher."),
        "CLEAN_BULL": ("STRONG COMPOSITE & SERVICES PMI — EUR BULLISH",
            "Broad-based strength. BUY EUR/USD, EUR/JPY and EUR/GBP on the first 5-minute pullback; PMI reactions fade quickly, so keep size modest."),
        "CLEAN_BEAR": ("WEAK COMPOSITE & SERVICES PMI — EUR BEARISH",
            "Broad-based weakness. SELL EUR/USD, EUR/JPY and EUR/GBP on the first 5-minute pullback; keep size modest."),
        "FLAT": ("INLINE / MIXED EZ PMI — STAND ASIDE",
            "Composite and services offset or matched consensus. Skip EUR pairs and wait for the next release."),
    },
}

@app.post("/api/decode-eur")
def decode_eur(d: DecodeEURReq, user: str = Depends(current_user)):
    check_numbers(d)
    ev = d.event_type.strip().upper()
    if ev not in EUR_DECODER_TEXT:
        raise HTTPException(status_code=422, detail="'event_type' must be EUR_CPI or EUR_PMI.")
    head_diff = round(d.headline_actual - d.headline_forecast, 2)
    core_diff = round(d.core_or_services_actual - d.core_or_services_forecast, 2)
    thr = 0.5 if ev == "EUR_PMI" else 0.1  # PMI points vs CPI percentage points
    verdict, plan = EUR_DECODER_TEXT[ev][_classify(head_diff, core_diff, thr)]
    return {"verdict": verdict, "plan": plan}

# ---------------------------------------------------------------------------
# Next-event queue: the admin schedules signals, clients only see what is next
# (stored in site_settings under setting_key = "active_calendar_events")
# ---------------------------------------------------------------------------
EVENTS_KEY = "active_calendar_events"
EVENT_MODULES = {"USD": ("NFP", "CPI", "PPI", "FOMC"), "GBP": ("CPI", "JOBS"), "EUR": ("CPI", "PMI")}
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
EVENT_WINDOW_SECONDS = 2 * 3600       # keep an event visible this long after its release
EVENT_ARCHIVE_SECONDS = 7 * 86400     # events older than this are dropped when the admin next publishes
MAX_EVENTS = 40
MAX_EVENTS_CHARS = 400_000
# Clients only receive the inputs the post-release decoder needs (the consensus), never the proxy inputs.
PUBLIC_EVENT_INPUT_KEYS = {
    "USD_NFP": ("consensus_nfp",), "USD_CPI": ("cpi_mom_consensus",), "USD_PPI": ("ppi_mom_consensus",),
    "GBP_CPI": ("uk_cpi_consensus",), "EUR_CPI": ("eur_cpi_consensus",), "EUR_PMI": ("eur_comp_pmi_consensus",),
}
_EVENTS_LOCK = threading.Lock()

class PublishEventReq(BaseModel):
    event_id: str
    currency: str
    title: str
    release_utc: str
    inputs: dict = {}
    result: dict = {}
    active: bool = True
    released: bool = False  # False = countdown only; True = projection visible to clients

def _parse_release(text: str) -> datetime:
    try:
        return datetime.strptime(str(text).strip(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=422, detail="'release_utc' must look like 2026-12-04T13:30:00Z.")

def _event_module(event_id: str, currency: str) -> str:
    parts = event_id.split("_")
    if len(parts) < 2 or parts[0].upper() != currency or parts[1].upper() not in EVENT_MODULES[currency]:
        raise HTTPException(status_code=422, detail=f"'event_id' must start with {currency}_ followed by one of: {', '.join(EVENT_MODULES[currency])} (e.g. {currency}_{EVENT_MODULES[currency][0]}).")
    return parts[1].upper()

def _read_events(cur, ph) -> dict:
    cur.execute(f"SELECT setting_value FROM site_settings WHERE setting_key = {ph}", (EVENTS_KEY,))
    row = cur.fetchone()
    if not row:
        return {}
    try:
        data = json.loads(row["setting_value"])
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}

def _write_events(conn, cur, events: dict):
    text = json.dumps(events, separators=(",", ":"))
    if len(text) > MAX_EVENTS_CHARS:
        raise HTTPException(status_code=413, detail="The event queue is too large. Remove some events first.")
    if is_pg(conn):
        cur.execute(
            "INSERT INTO site_settings (setting_key, setting_value) VALUES (%s, %s) "
            "ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
            (EVENTS_KEY, text)
        )
    else:
        cur.execute("INSERT OR REPLACE INTO site_settings (setting_key, setting_value) VALUES (?, ?)", (EVENTS_KEY, text))

@app.post("/api/admin/publish-event")
def publish_event(req: PublishEventReq, admin: str = Depends(require_admin)):
    currency = req.currency.strip().upper()
    if currency not in EVENT_MODULES:
        raise HTTPException(status_code=422, detail="'currency' must be USD, GBP or EUR.")
    event_id = req.event_id.strip()
    if not EVENT_ID_RE.match(event_id):
        raise HTTPException(status_code=422, detail="'event_id' may only use letters, numbers, _ and - (3 to 64 characters).")
    module = _event_module(event_id, currency)
    title = req.title.strip()
    if not 1 <= len(title) <= 120:
        raise HTTPException(status_code=422, detail="'title' must be 1 to 120 characters.")
    release = _parse_release(req.release_utc)
    result = req.result
    if req.released:
        pairs = result.get("pairs")
        if not ({"bias", "score", "summary"} <= set(result) and isinstance(pairs, list)
                and all(isinstance(p, dict) for p in pairs)):
            raise HTTPException(status_code=422, detail="'result' is not a valid forecast. Calculate it first, then release.")
    else:
        result = {}  # countdown-only events never store a projection
    record = {
        "event_id": event_id, "currency": currency, "module": module, "title": title,
        "release_utc": release.strftime("%Y-%m-%dT%H:%M:%SZ"), "active": bool(req.active), "released": bool(req.released),
        "inputs": {k: v for k, v in req.inputs.items() if k != "user_email"},
        "result": result, "updated_at": _utc_iso(),  # server-stamped so it cannot be back-dated
    }
    now = datetime.now(timezone.utc)
    with _EVENTS_LOCK:
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            events = _read_events(cur, ph_for(conn))
            for key in list(events):
                try:
                    old = _parse_release(events[key].get("release_utc", ""))
                except Exception:
                    del events[key]
                    continue
                if (now - old).total_seconds() > EVENT_ARCHIVE_SECONDS:
                    del events[key]
            if event_id not in events and len(events) >= MAX_EVENTS:
                raise HTTPException(status_code=409, detail="The queue already holds the maximum number of events. Remove one first.")
            events[event_id] = record
            _write_events(conn, cur, events)
            if record["released"]:
                with _CPI_LOCK:
                    _release_touch(conn, cur, record)
            conn.commit()
        except HTTPException:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            log.exception("Publishing event failed")
            raise HTTPException(status_code=500, detail=f"Could not publish the event: {_first_line(e)}")
        finally:
            cur.close()
            conn.close()
    log.info("Calendar event published: %s at %s", event_id, record["release_utc"])
    return {"status": "ok", "event_id": event_id, "release_utc": record["release_utc"],
            "updated_at": record["updated_at"], "storage": DB_STATUS_MSG}

class PublishDecodeReq(BaseModel):
    event_id: str
    verdict: str
    plan: str

@app.post("/api/admin/publish-decode")
def publish_decode(req: PublishDecodeReq, admin: str = Depends(require_admin)):
    """The admin decodes the actual print and sends the verdict + trade plan to the event's client card."""
    verdict, plan = req.verdict.strip(), req.plan.strip()
    if not 1 <= len(verdict) <= 300 or not 1 <= len(plan) <= 3000:
        raise HTTPException(status_code=422, detail="Run the decoder first, then publish its result.")
    with _EVENTS_LOCK:
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            events = _read_events(cur, ph_for(conn))
            if req.event_id not in events:
                raise HTTPException(status_code=404, detail="Schedule or release this event first, then publish the decoded result.")
            ts = _utc_iso()
            events[req.event_id]["decoded"] = {"verdict": verdict, "plan": plan, "updated_at": ts}
            with _CPI_LOCK:
                _release_touch(conn, cur, events[req.event_id], verdict, ts)
            _write_events(conn, cur, events)
            conn.commit()
        except HTTPException:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            log.exception("Publishing decode failed")
            raise HTTPException(status_code=500, detail=f"Could not publish the decoded result: {_first_line(e)}")
        finally:
            cur.close()
            conn.close()
    log.info("Decoded result published: %s", req.event_id)
    return {"status": "ok", "event_id": req.event_id}

@app.delete("/api/admin/publish-event/{event_id}")
def remove_event(event_id: str, admin: str = Depends(require_admin)):
    with _EVENTS_LOCK:
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            events = _read_events(cur, ph_for(conn))
            if event_id not in events:
                raise HTTPException(status_code=404, detail="That event is not in the queue.")
            del events[event_id]
            _write_events(conn, cur, events)
            conn.commit()
        except HTTPException:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            log.exception("Removing event failed")
            raise HTTPException(status_code=500, detail=f"Could not remove the event: {_first_line(e)}")
        finally:
            cur.close()
            conn.close()
    log.info("Calendar event removed: %s", event_id)
    return {"status": "ok", "event_id": event_id}

@app.get("/api/next-events")
def next_events(request: Request, response: Response, user: str = Depends(current_user)):
    """Clients get only the earliest upcoming date's events. The admin can add ?all=1 for the full queue manager."""
    response.headers["Cache-Control"] = "no-store"
    is_admin = user == ADMIN_EMAIL
    want_all = is_admin and request.query_params.get("all") == "1"
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        events = _read_events(cur, ph_for(conn))
    finally:
        cur.close()
        conn.close()
    now = datetime.now(timezone.utc)
    rows = []
    for ev in events.values():
        try:
            release = _parse_release(ev.get("release_utc", ""))
        except Exception:
            continue
        rows.append((release, ev))
    rows.sort(key=lambda r: (r[0], r[1].get("event_id", "")))

    def shape(ev):
        inputs = ev.get("inputs") or {}
        released = bool(ev.get("released", False))
        result = ev.get("result")
        if not want_all:
            keep = PUBLIC_EVENT_INPUT_KEYS.get(f"{ev.get('currency')}_{ev.get('module')}", ())
            inputs = {k: inputs[k] for k in keep if k in inputs}
            if not released:  # before the release clients get the countdown only, never the projection
                inputs, result = {}, None
        return {"released": released, "decoded": ev.get("decoded"), "event_id": ev.get("event_id"), "currency": ev.get("currency"), "module": ev.get("module"),
                "title": ev.get("title"), "release_utc": ev.get("release_utc"), "active": ev.get("active", True),
                "updated_at": ev.get("updated_at"), "result": result, "inputs": inputs}

    server_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if want_all:
        return {"server_time": server_time, "events": [shape(ev) for _, ev in rows]}
    live = [(r, ev) for r, ev in rows
            if ev.get("active") and (now - r).total_seconds() <= EVENT_WINDOW_SECONDS]
    if not live:
        return {"server_time": server_time, "next_date": None, "events": []}
    next_date = live[0][0].strftime("%Y-%m-%d")
    todays = [shape(ev) for r, ev in live if r.strftime("%Y-%m-%d") == next_date]
    return {"server_time": server_time, "next_date": next_date, "events": todays}

# ---------------------------------------------------------------------------
# Eurozone CPI Post-Release Decoder v2 + admin ledger / calibration
# Config, ledger rows and everything admin-only live in site_settings (no schema change).
# ---------------------------------------------------------------------------
DECODER_CONFIG_DEFAULTS = {
    "weights": {"services": 0.40, "core": 0.40, "headline": 0.20},
    "deadzoneThreshold": 0.08,
    "standardThreshold": 0.10,
    "coldEntryThreshold": 0.15,   # higher bar when Proxy v3 said DO NOT TRADE
    "riskPerTradePct": 0.5,       # half-risk on post-release spikes
    "timeStopMinutes": 20,        # exit by 11:20 CET if the target is not hit
    "releaseTimeCET": "11:00",
    "trapThreshold": 0.10,        # headline vs core/services divergence size
    "trapSpikePips": 8,           # EUR/USD 1-minute spike needed for a trap
    "killSwitchScore": 0.05,      # proxy contradiction level
    "conflictThreshold": 0.10,
    "maxSpikePips": 30,           # skip EUR/USD if the first spike was already this big
    "pairs": {
        "EURUSD": {"stopPips": 12, "targetR": 1.8, "pipValuePerLot": 10},
        "EURGBP": {"stopPips": 10, "targetR": 1.8, "pipValuePerLot": 12.7},
        "EURJPY": {"stopPips": 20, "targetR": 1.8, "pipValuePerLot": 6.5},
    },
}
CPI_CONFIG_KEY = "cpi_decoder_config"
CPI_LEDGER_KEY = "cpi_decoder_ledger"
CPI_LEDGER_MAX_ROWS = 3000
CPI_LEDGER_MAX_CHARS = 3_000_000
PAIR_CODES = {"EUR/USD": "EURUSD", "EUR/GBP": "EURGBP", "EUR/JPY": "EURJPY"}
CPI_OUTCOMES = ("WIN", "LOSS", "TIME_EXIT", "SKIPPED")
PROXY_SIGNALS = ("STRONG BUY EUR", "STRONG SELL EUR", "DO NOT TRADE")
_CPI_LOCK = threading.Lock()

def _clone(obj):
    return json.loads(json.dumps(obj))

def _setting_get(cur, ph, key):
    cur.execute(f"SELECT setting_value FROM site_settings WHERE setting_key = {ph}", (key,))
    row = cur.fetchone()
    if not row:
        return None
    try:
        return json.loads(row["setting_value"])
    except Exception:
        return None

def _setting_set(conn, cur, key, obj, max_chars):
    text = json.dumps(obj, separators=(",", ":"))
    if len(text) > max_chars:
        raise HTTPException(status_code=413, detail="Stored data is too large. Export the ledger and contact support.")
    if is_pg(conn):
        cur.execute(
            "INSERT INTO site_settings (setting_key, setting_value) VALUES (%s, %s) "
            "ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value",
            (key, text)
        )
    else:
        cur.execute("INSERT OR REPLACE INTO site_settings (setting_key, setting_value) VALUES (?, ?)", (key, text))

def _num(v, lo, hi, name):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < lo or v > hi:
        raise HTTPException(status_code=422, detail=f"'{name}' must be a number between {lo} and {hi}.")
    return float(v)

def _validate_cfg(inc, base):
    cfg = _clone(base)
    w = inc.get("weights")
    if isinstance(w, dict):
        for k in ("services", "core", "headline"):
            if k in w:
                cfg["weights"][k] = _num(w[k], 0, 1, "weights." + k)
    if abs(sum(cfg["weights"].values()) - 1.0) > 0.001:
        raise HTTPException(status_code=422, detail="The three weights must add up to 1.00.")
    scalars = {"deadzoneThreshold": (0, 1), "standardThreshold": (0, 1), "coldEntryThreshold": (0, 1),
               "riskPerTradePct": (0.01, 5), "timeStopMinutes": (1, 120), "trapThreshold": (0, 1),
               "trapSpikePips": (0, 100), "killSwitchScore": (0, 1), "conflictThreshold": (0, 1),
               "maxSpikePips": (1, 500)}
    for k, (lo, hi) in scalars.items():
        if k in inc:
            cfg[k] = _num(inc[k], lo, hi, k)
    if not (cfg["deadzoneThreshold"] <= cfg["standardThreshold"] <= cfg["coldEntryThreshold"]):
        raise HTTPException(status_code=422, detail="Thresholds must satisfy: deadzone <= standard <= cold-entry.")
    pairs = inc.get("pairs")
    if isinstance(pairs, dict):
        limits = {"stopPips": (1, 500), "targetR": (0.5, 10), "pipValuePerLot": (0.01, 1000)}
        for code in cfg["pairs"]:
            p = pairs.get(code)
            if isinstance(p, dict):
                for k, (lo, hi) in limits.items():
                    if k in p:
                        cfg["pairs"][code][k] = _num(p[k], lo, hi, f"pairs.{code}.{k}")
    return cfg

def _load_cfg(cur, ph):
    saved = _setting_get(cur, ph, CPI_CONFIG_KEY)
    cfg = _clone(DECODER_CONFIG_DEFAULTS)
    if isinstance(saved, dict):
        try:
            cfg = _validate_cfg(saved, cfg)
        except HTTPException:
            pass
    return cfg

def _exit_time(cfg):
    hh, mm = (int(x) for x in cfg["releaseTimeCET"].split(":"))
    t = hh * 60 + mm + int(cfg["timeStopMinutes"])
    return f"{t // 60:02d}:{t % 60:02d} CET"

class CPIDecodeV2Req(BaseModel):
    proxy_signal: Optional[str] = None
    account_balance: float = 0.0
    headline_actual: float
    headline_forecast: float
    core_actual: float
    core_forecast: float
    services_actual: float = 0.0
    services_benchmark: float = 0.0
    services_basis: str = "NONE"      # FORECAST, PRIOR or NONE
    spike_1m_pips: float = 0.0        # EUR/USD, 11:01 close minus 10:59 close, in pips
    reclaimed: bool = False           # 11:01 candle reclaimed (or broke back through) the 10:59 price
    uk_news: bool = False
    risk_off: bool = False

def _norm_proxy(p):
    p = (p or "DO NOT TRADE").strip().upper()
    if p.startswith("DO NOT TRADE"):
        return "DO NOT TRADE"
    if p in PROXY_SIGNALS:
        return p
    raise HTTPException(status_code=422, detail="'proxy_signal' must be STRONG BUY EUR, STRONG SELL EUR or DO NOT TRADE.")

def _norm_basis(b):
    b = (b or "NONE").strip().upper()
    if b not in ("FORECAST", "PRIOR", "NONE"):
        raise HTTPException(status_code=422, detail="'services_basis' must be FORECAST, PRIOR or NONE.")
    return b

def _pair_plans(direction, classification, r, cfg):
    side = "BUY" if direction == "BUY" else "SELL"
    trap = classification == "CONFIRMED TRAP"
    exit_txt = _exit_time(cfg)
    plans = {}
    balance = r.account_balance
    for pair, code in PAIR_CODES.items():
        pc = cfg["pairs"][code]
        stop = pc["stopPips"]
        target = round(stop * pc["targetR"], 1)
        status, text = "TRADE", ""
        entry = (f"enter once the 1-minute candle closes back through the 10:59 CET price" if trap
                 else "enter on a 38.2%–50% pullback of the 11:01 CET 1-minute bar")
        if code == "EURUSD":
            if abs(r.spike_1m_pips) > cfg["maxSpikePips"]:
                status = "SKIP"
                text = f"SKIP EUR/USD — the first 1-minute spike ({abs(r.spike_1m_pips):g} pips) is over the {cfg['maxSpikePips']:g} pip limit, so the move is already done."
            else:
                text = (f"{side} EUR/USD (primary rate play): {entry}. Stop: {stop:g} pips beyond the "
                        f"{'spike extreme' if trap else '10:59 CET anchor'}. Target: {target:g} pips ({pc['targetR']:g}R). Hard exit at {exit_txt}.")
        elif code == "EURGBP":
            if r.uk_news:
                status = "SKIP"
                text = "SKIP EUR/GBP — UK high-impact news today, so the UK catalyst overrides the Euro print."
            else:
                text = (f"{side} EUR/GBP (policy divergence filter): {entry}. Tight {stop:g} pip stop, "
                        f"{target:g} pip target, time stop at {exit_txt}.")
        else:
            if side == "BUY" and r.risk_off:
                status = "SKIP"
                text = "SKIP EUR/JPY — a hot print is tanking equities (DAX down more than 0.5%), so JPY safe-haven buying will fight EUR strength."
            else:
                extra = " Risk-off supports this sell, but spreads are wide, so keep size small." if (side == "SELL" and r.risk_off) else ""
                text = (f"{side} EUR/JPY (risk-sentiment filter): {entry}. {stop:g} pip stop, "
                        f"{target:g} pip target, time stop at {exit_txt}.{extra}")
        plan = {"status": status, "text": text, "stop": stop, "target": target,
                "target_r": pc["targetR"], "pip_value": pc["pipValuePerLot"]}
        if status == "TRADE" and balance > 0:
            risk_cash = balance * cfg["riskPerTradePct"] / 100.0
            plan["lot"] = math.floor((risk_cash / (stop * pc["pipValuePerLot"])) * 100) / 100
        plans[pair] = plan
    return plans

def _cpi_decode_v2(r, proxy, cfg):
    EPS = 1e-9
    h = round(r.headline_actual - r.headline_forecast, 4)
    c = round(r.core_actual - r.core_forecast, 4)
    basis = _norm_basis(r.services_basis)
    s = None if basis == "NONE" else round(r.services_actual - r.services_benchmark, 4)
    w = cfg["weights"]
    if s is None:
        ecb = (w["core"] * c + w["headline"] * h) / (w["core"] + w["headline"])
    else:
        ecb = (w["services"] * s) + (w["core"] * c) + (w["headline"] * h)
    ecb = round(ecb, 4)
    min_th = cfg["coldEntryThreshold"] if proxy == "DO NOT TRADE" else cfg["standardThreshold"]
    T = cfg["trapThreshold"]
    ks = cfg["killSwitchScore"]
    contradicted = ((proxy == "STRONG BUY EUR" and ecb <= -ks + EPS) or (proxy == "STRONG SELL EUR" and ecb >= ks - EPS))
    s_bull = s is None or s >= T - EPS
    s_bear = s is None or s <= -T + EPS
    bull_pat = h <= -T + EPS and c >= T - EPS and s_bull and r.spike_1m_pips <= -cfg["trapSpikePips"] + EPS
    bear_pat = h >= T - EPS and c <= -T + EPS and s_bear and r.spike_1m_pips >= cfg["trapSpikePips"] - EPS

    direction, label, classification, summary = None, "STAND ASIDE", "STAND ASIDE", ""
    if bull_pat or bear_pat:
        d_word = "bullish" if bull_pat else "bearish"
        if r.reclaimed:
            direction = "BUY" if bull_pat else "SELL"
            label = f"CONFIRMED TRAP ({d_word.upper()} REVERSAL)"
            classification = "CONFIRMED TRAP"
            summary = (f"Headline {'missed' if bull_pat else 'beat'} but core"
                       f"{' and services' if s is not None else ''} pointed the other way, and the 1-minute candle has "
                       f"{'reclaimed' if bull_pat else 'broken back through'} the 10:59 CET price. Bias: {d_word} reversal.")
        else:
            label = "STAND ASIDE (TRAP PENDING)"
            summary = ("The divergence pattern is there, but the 1-minute candle has not "
                       f"{'reclaimed' if bull_pat else 'broken back through'} the 10:59 CET price. Wait for it or skip.")
    elif contradicted:
        label = "STAND ASIDE (PROXY INVALIDATED)"
        summary = f"The proxy said {proxy} but the print contradicts it."
    elif abs(ecb) < cfg["deadzoneThreshold"] - EPS or abs(ecb) < min_th - EPS:
        summary = (f"The blended ECB score ({ecb:+.2f}) is inside the noise zone"
                   f"{' (higher bar because the proxy said DO NOT TRADE)' if proxy == 'DO NOT TRADE' else ''}.")
    elif ((h > 0) != (c > 0)) and abs(h) >= cfg["conflictThreshold"] - EPS and abs(c) >= cfg["conflictThreshold"] - EPS:
        label = "STAND ASIDE (CONFLICTING DATA)"
        summary = "Headline and core point in opposite directions and the trap conditions are not met."
    elif ecb >= min_th - EPS and c > 0 and (s is None or s >= 0):
        direction, label, classification = "BUY", "CLEAN BEAT (BULLISH EUR)", "CLEAN BEAT"
        summary = f"Core{' and services' if s is not None else ''} beat and the blended ECB score is {ecb:+.2f}. Bias: bullish EUR."
    elif ecb <= -min_th + EPS and c < 0 and (s is None or s <= 0):
        direction, label, classification = "SELL", "CLEAN MISS (BEARISH EUR)", "CLEAN MISS"
        summary = f"Core{' and services' if s is not None else ''} missed and the blended ECB score is {ecb:+.2f}. Bias: bearish EUR."
    else:
        summary = "The print does not meet the clean beat or clean miss conditions."

    close_note = ("The proxy contradicts this print: close any pre-release position immediately."
                  if contradicted else "")
    return {
        "label": label, "classification": classification, "direction": direction,
        "ecb_score": ecb, "min_threshold": min_th, "h_surp": h, "c_surp": c, "s_surp": s,
        "services_basis": basis, "summary": summary, "close_note": close_note,
        "proxy_signal": proxy, "spike_1m_pips": r.spike_1m_pips, "reclaimed": bool(r.reclaimed),
        "uk_news": bool(r.uk_news), "risk_off": bool(r.risk_off),
        "risk_pct": cfg["riskPerTradePct"], "exit_time": _exit_time(cfg),
        "pairs": _pair_plans(direction, classification, r, cfg) if direction else {},
    }

def _client_details(res):
    """Everything a member may see: the verdict and plain-language plans. No lots, balance, score or thresholds."""
    return {
        "label": res["label"], "classification": res["classification"], "direction": res["direction"],
        "h_surp": res["h_surp"], "c_surp": res["c_surp"], "s_surp": res["s_surp"],
        "services_basis": res["services_basis"], "summary": res["summary"], "close_note": res["close_note"],
        "risk_pct": res["risk_pct"], "exit_time": res["exit_time"],
        "pairs": {p: {k: v for k, v in plan.items() if k != "lot"} for p, plan in res["pairs"].items()},
    }

def _calc_r(row):
    out = row.get("outcome")
    if out not in ("WIN", "LOSS", "TIME_EXIT"):
        return None
    stop = row.get("stop_pips") or 0
    net = row.get("net_pips")
    if net is not None and stop:
        return round(net / stop, 2)
    if out == "WIN":
        return float(row.get("target_r") or 0)
    if out == "LOSS":
        return -1.0
    return 0.0

def _ledger_rows(res, release_utc, cfg, decode_ts):
    date = release_utc[:10]
    rows = {}
    for pair, code in PAIR_CODES.items():
        plan = res["pairs"].get(pair)
        if res["classification"] == "STAND ASIDE":
            outcome, plan_status = "NO_SIGNAL", "NONE"
        elif plan and plan["status"] == "SKIP":
            outcome, plan_status = "SKIPPED", "SKIP"
        else:
            outcome, plan_status = "PENDING", "TRADE"
        rows[f"{date}|{code}"] = {
            "id": f"{date}|{code}", "release_date": date, "release_utc": release_utc, "pair": pair,
            "proxy_signal": res["proxy_signal"], "classification": res["classification"], "label": res["label"],
            "ecb_score": res["ecb_score"], "h_surp": res["h_surp"], "c_surp": res["c_surp"], "s_surp": res["s_surp"],
            "services_basis": res["services_basis"], "spike_1m_pips": res["spike_1m_pips"],
            "reclaimed": res["reclaimed"], "uk_news": res["uk_news"], "risk_off": res["risk_off"],
            "plan_status": plan_status, "outcome": outcome, "net_pips": None, "r_multiple": None,
            "stop_pips": cfg["pairs"][code]["stopPips"], "target_r": cfg["pairs"][code]["targetR"],
            "manual": False, "decoded_at": decode_ts, "logged_at": None, "config": cfg,
        }
    return rows

def _merge_ledger(ledger, new_rows):
    for rid, row in new_rows.items():
        old = ledger.get(rid)
        if old and old.get("manual"):
            for k in ("outcome", "net_pips", "r_multiple", "logged_at", "manual"):
                row[k] = old.get(k)
        ledger[rid] = row
    if len(ledger) > CPI_LEDGER_MAX_ROWS:
        for rid in sorted(ledger, key=lambda k: ledger[k].get("release_date", ""))[: len(ledger) - CPI_LEDGER_MAX_ROWS]:
            del ledger[rid]

def _ledger_stats(rows):
    out = {}
    for cls in ("CLEAN BEAT", "CLEAN MISS", "CONFIRMED TRAP"):
        done = [r for r in rows if r.get("classification") == cls and r.get("outcome") in ("WIN", "LOSS", "TIME_EXIT")]
        n = len(done)
        wins = sum(1 for r in done if r["outcome"] == "WIN")
        rs = [r["r_multiple"] for r in done if r.get("r_multiple") is not None]
        out[cls] = {
            "n": n, "wins": wins, "win_rate": round(wins / n * 100, 1) if n else None,
            "net_pips": round(sum(r.get("net_pips") or 0 for r in done), 1),
            "avg_r": round(sum(rs) / len(rs), 2) if rs else None, "warning": False,
        }
    trap = out["CONFIRMED TRAP"]
    trap["warning"] = trap["n"] >= 5 and trap["win_rate"] is not None and trap["win_rate"] < 45
    return {
        "by_class": out,
        "pending": sum(1 for r in rows if r.get("outcome") == "PENDING"),
        "skipped": sum(1 for r in rows if r.get("outcome") == "SKIPPED"),
        "no_signal": sum(1 for r in rows if r.get("outcome") == "NO_SIGNAL"),
        "releases": len({r.get("release_date") for r in rows}),
    }

def _release_for(events, event_id, supplied):
    if supplied:
        return _parse_release(supplied).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = events.get(event_id) or events.get("EUR_CPI")
    if ev and ev.get("release_utc"):
        return ev["release_utc"]
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

@app.get("/api/admin/cpi-config")
def get_cpi_config(admin: str = Depends(require_admin)):
    conn = get_db_conn(); cur = conn.cursor()
    try:
        return {"config": _load_cfg(cur, ph_for(conn)), "defaults": DECODER_CONFIG_DEFAULTS}
    finally:
        cur.close(); conn.close()

class CPIConfigReq(BaseModel):
    config: dict

@app.post("/api/admin/cpi-config")
def save_cpi_config(req: CPIConfigReq, admin: str = Depends(require_admin)):
    with _CPI_LOCK:
        conn = get_db_conn(); cur = conn.cursor()
        try:
            ph = ph_for(conn)
            cfg = _validate_cfg(req.config, _load_cfg(cur, ph))
            _setting_set(conn, cur, CPI_CONFIG_KEY, cfg, 20_000)
            conn.commit()
        except HTTPException:
            conn.rollback(); raise
        except Exception as e:
            conn.rollback(); log.exception("Saving decoder config failed")
            raise HTTPException(status_code=500, detail=f"Could not save the config: {_first_line(e)}")
        finally:
            cur.close(); conn.close()
    log.info("CPI decoder config updated by admin")
    return {"status": "ok", "config": cfg}

@app.post("/api/admin/cpi-decode")
def cpi_decode(req: CPIDecodeV2Req, admin: str = Depends(require_admin)):
    check_numbers(req)
    proxy = _norm_proxy(req.proxy_signal)
    conn = get_db_conn(); cur = conn.cursor()
    try:
        cfg = _load_cfg(cur, ph_for(conn))
    finally:
        cur.close(); conn.close()
    res = _cpi_decode_v2(req, proxy, cfg)
    res["config_used"] = cfg   # admin only
    return res

class PublishCPIDecodeReq(BaseModel):
    event_id: str
    inputs: CPIDecodeV2Req

@app.post("/api/admin/publish-cpi-decode")
def publish_cpi_decode(req: PublishCPIDecodeReq, admin: str = Depends(require_admin)):
    """Decode on the server with the saved config, send the plain-language result to the client card
    and write the release into the ledger (so every released decode is accounted for)."""
    check_numbers(req.inputs)
    if _event_module(req.event_id, "EUR") != "CPI":
        raise HTTPException(status_code=422, detail="This decoder is for the EUR CPI event only.")
    with _EVENTS_LOCK, _CPI_LOCK:
        conn = get_db_conn(); cur = conn.cursor()
        try:
            ph = ph_for(conn)
            events = _read_events(cur, ph)
            ev = events.get(req.event_id)
            if not ev:
                raise HTTPException(status_code=404, detail="Schedule or release this event first, then publish the decoded result.")
            cfg = _load_cfg(cur, ph)
            proxy = _norm_proxy(req.inputs.proxy_signal or (ev.get("result") or {}).get("signal"))
            res = _cpi_decode_v2(req.inputs, proxy, cfg)
            ts = _utc_iso()
            plan_line = res["summary"] + ((" " + res["close_note"]) if res["close_note"] else "")
            ev["decoded"] = {"verdict": res["label"], "plan": plan_line, "updated_at": ts, "details": _client_details(res)}
            events[req.event_id] = ev
            _write_events(conn, cur, events)
            _release_touch(conn, cur, ev, res["label"], ts)
            ledger = _setting_get(cur, ph, CPI_LEDGER_KEY) or {}
            _merge_ledger(ledger, _ledger_rows(res, ev["release_utc"], cfg, ts))
            _setting_set(conn, cur, CPI_LEDGER_KEY, ledger, CPI_LEDGER_MAX_CHARS)
            conn.commit()
        except HTTPException:
            conn.rollback(); raise
        except Exception as e:
            conn.rollback(); log.exception("Publishing CPI decode failed")
            raise HTTPException(status_code=500, detail=f"Could not publish the decoded result: {_first_line(e)}")
        finally:
            cur.close(); conn.close()
    log.info("CPI decode published and ledgered: %s", req.event_id)
    return {"status": "ok", "label": res["label"]}

class CPILogReq(BaseModel):
    pair: str
    outcome: str
    net_pips: Optional[float] = None
    release_utc: Optional[str] = None
    release_date: Optional[str] = None
    inputs: Optional[CPIDecodeV2Req] = None

@app.post("/api/admin/cpi-ledger/log")
def cpi_ledger_log(req: CPILogReq, admin: str = Depends(require_admin)):
    pair = req.pair.strip().upper().replace("/", "")
    code_to_pair = {v: k for k, v in PAIR_CODES.items()}
    if pair not in code_to_pair:
        raise HTTPException(status_code=422, detail="'pair' must be EUR/USD, EUR/GBP or EUR/JPY.")
    outcome = req.outcome.strip().upper()
    if outcome not in CPI_OUTCOMES:
        raise HTTPException(status_code=422, detail="'outcome' must be WIN, LOSS, TIME_EXIT or SKIPPED.")
    net = req.net_pips
    if outcome == "SKIPPED":
        net = 0.0
    elif net is not None:
        net = _num(net, -1000, 1000, "net_pips")
    with _EVENTS_LOCK, _CPI_LOCK:
        conn = get_db_conn(); cur = conn.cursor()
        try:
            ph = ph_for(conn)
            ledger = _setting_get(cur, ph, CPI_LEDGER_KEY) or {}
            events = _read_events(cur, ph)
            if req.release_date:
                date = req.release_date.strip()
                if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
                    raise HTTPException(status_code=422, detail="'release_date' must look like 2026-12-01.")
                release_utc = date + "T00:00:00Z"
            else:
                release_utc = _release_for(events, "EUR_CPI", req.release_utc)
            if req.inputs is not None:
                check_numbers(req.inputs)
                cfg = _load_cfg(cur, ph)
                proxy = _norm_proxy(req.inputs.proxy_signal or ((events.get("EUR_CPI") or {}).get("result") or {}).get("signal"))
                res = _cpi_decode_v2(req.inputs, proxy, cfg)
                _merge_ledger(ledger, _ledger_rows(res, release_utc, cfg, _utc_iso()))
            rid = f"{release_utc[:10]}|{pair}"
            row = ledger.get(rid)
            if not row:
                raise HTTPException(status_code=404, detail="No ledger row for that release and pair. Decode the release first.")
            if net is None:  # no pips typed: use the planned outcome so the pip totals stay meaningful
                stop = row.get("stop_pips") or 0
                net = {"WIN": round(stop * (row.get("target_r") or 0), 1), "LOSS": -float(stop)}.get(outcome, 0.0)
            row["outcome"], row["net_pips"] = outcome, net
            row["r_multiple"] = _calc_r(row)
            row["manual"], row["logged_at"] = True, _utc_iso()
            _setting_set(conn, cur, CPI_LEDGER_KEY, ledger, CPI_LEDGER_MAX_CHARS)
            conn.commit()
        except HTTPException:
            conn.rollback(); raise
        except Exception as e:
            conn.rollback(); log.exception("Ledger log failed")
            raise HTTPException(status_code=500, detail=f"Could not save the log: {_first_line(e)}")
        finally:
            cur.close(); conn.close()
    return {"status": "ok", "id": rid, "outcome": outcome, "net_pips": net, "r_multiple": row["r_multiple"]}

def _read_ledger_rows():
    conn = get_db_conn(); cur = conn.cursor()
    try:
        ledger = _setting_get(cur, ph_for(conn), CPI_LEDGER_KEY) or {}
    finally:
        cur.close(); conn.close()
    return sorted(ledger.values(), key=lambda r: (r.get("release_date", ""), r.get("pair", "")), reverse=True)

@app.get("/api/admin/cpi-ledger")
def cpi_ledger(response: Response, admin: str = Depends(require_admin)):
    response.headers["Cache-Control"] = "no-store"
    rows = _read_ledger_rows()
    return {"rows": rows[:200], "total_rows": len(rows), "stats": _ledger_stats(rows)}

CSV_COLUMNS = ["release_date", "release_utc", "pair", "proxy_signal", "classification", "label", "ecb_score",
               "h_surp", "c_surp", "s_surp", "services_basis", "spike_1m_pips", "reclaimed", "uk_news", "risk_off",
               "plan_status", "outcome", "net_pips", "r_multiple", "stop_pips", "target_r", "decoded_at", "logged_at", "config_json"]

def _csv_cell(v):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
        return "'" + v   # stops spreadsheet formula injection in text cells
    return "" if v is None else v

@app.get("/api/admin/cpi-ledger.csv")
def cpi_ledger_csv(admin: str = Depends(require_admin)):
    rows = list(reversed(_read_ledger_rows()))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for r in rows:
        line = []
        for col in CSV_COLUMNS:
            line.append(json.dumps(r.get("config"), separators=(",", ":")) if col == "config_json" else _csv_cell(r.get(col)))
        w.writerow(line)
    return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="cpi_decoder_ledger.csv"', "Cache-Control": "no-store"})

# ---------------------------------------------------------------------------
# Release Ledger (all news): was each release a HIT, MISS or TRAP versus our projection?
# One row per release date + event, stored in site_settings. Rows are created when the projection
# is released and completed when the decoder result is sent to clients.
# ---------------------------------------------------------------------------
REL_LEDGER_KEY = "release_ledger"
REL_LEDGER_MAX_ROWS = 3000
REL_LEDGER_MAX_CHARS = 3_000_000
REL_RESULTS = ("HIT", "MISS", "TRAP", "INLINE", "NO CALL")
BULL_WORDS = ("USD BULLISH", "USD SURGE", "HAWKISH BREAKOUT", "GBP BULLISH", "EUR BULLISH", "BULLISH EUR")
BEAR_WORDS = ("USD BEARISH", "USD DROP", "DOVISH RALLY", "GBP BEARISH", "EUR BEARISH", "BEARISH EUR")

def _projected_dir(result):
    bias = str((result or {}).get("bias", "")).upper()
    if bias in ("HOTTER", "HAWKISH", "BULLISH"):
        return "BULLISH"
    if bias in ("COOLER", "DOVISH", "BEARISH"):
        return "BEARISH"
    return "NONE"

def _actual_dir(verdict):
    v = str(verdict or "").upper()
    if v.startswith("STAND ASIDE"):
        return "NEUTRAL"
    if "TRAP" in v:
        return "TRAP"
    bull = any(w in v for w in BULL_WORDS)
    bear = any(w in v for w in BEAR_WORDS)
    if bull and not bear:
        return "BULLISH"
    if bear and not bull:
        return "BEARISH"
    return "NEUTRAL"

def _call_result(projected, actual):
    if actual is None:
        return "PENDING"
    if actual == "TRAP":
        return "TRAP"
    if projected == "NONE":
        return "NO CALL"
    if actual == "NEUTRAL":
        return "INLINE"
    return "HIT" if projected == actual else "MISS"

def _release_touch(conn, cur, ev, verdict=None, ts=None):
    """Create or update the ledger row for this release. The caller holds the locks and commits."""
    ph = ph_for(conn)
    ledger = _setting_get(cur, ph, REL_LEDGER_KEY) or {}
    date = str(ev.get("release_utc", ""))[:10]
    rid = f"{date}|{ev.get('event_id')}"
    res = ev.get("result") or {}
    row = ledger.get(rid)
    if row is None:
        row = {"id": rid, "release_date": date, "release_utc": ev.get("release_utc"), "event_id": ev.get("event_id"),
               "currency": ev.get("currency"), "module": ev.get("module"), "title": ev.get("title"),
               "decoder_verdict": None, "actual": None, "result": "PENDING", "manual": False,
               "projected_at": None, "decoded_at": None}
    if ev.get("released") or row.get("projected") is None:
        row["projected"] = _projected_dir(res)
        row["projection_label"] = str(res.get("signal") or res.get("verdict") or res.get("bias") or "")[:120]
        row["projection_score"] = res.get("score")
        row["projection_summary"] = str(res.get("summary") or "")[:300]
        row["projected_at"] = ev.get("updated_at") or _utc_iso()
    if verdict is not None:
        row["decoder_verdict"] = str(verdict)[:300]
        row["actual"] = _actual_dir(verdict)
        row["decoded_at"] = ts or _utc_iso()
    if not row.get("manual"):
        row["result"] = _call_result(row.get("projected", "NONE"), row.get("actual"))
    ledger[rid] = row
    if len(ledger) > REL_LEDGER_MAX_ROWS:
        for k in sorted(ledger, key=lambda x: ledger[x].get("release_date", ""))[: len(ledger) - REL_LEDGER_MAX_ROWS]:
            del ledger[k]
    _setting_set(conn, cur, REL_LEDGER_KEY, ledger, REL_LEDGER_MAX_CHARS)

def _release_stats(rows):
    def blank():
        return {"releases": 0, "HIT": 0, "MISS": 0, "TRAP": 0, "INLINE": 0, "NO CALL": 0, "PENDING": 0, "hit_rate": None}
    out = {"ALL": blank()}
    for r in rows:
        key = f"{r.get('currency')}_{r.get('module')}"
        for k in (key, "ALL"):
            b = out.setdefault(k, blank())
            b["releases"] += 1
            b[r.get("result", "PENDING")] = b.get(r.get("result", "PENDING"), 0) + 1
    for b in out.values():
        scored = b["HIT"] + b["MISS"]
        b["hit_rate"] = round(b["HIT"] / scored * 100, 1) if scored else None
    return out

def _read_release_rows():
    conn = get_db_conn(); cur = conn.cursor()
    try:
        ledger = _setting_get(cur, ph_for(conn), REL_LEDGER_KEY) or {}
    finally:
        cur.close(); conn.close()
    return sorted(ledger.values(), key=lambda r: (r.get("release_date", ""), r.get("event_id", "")), reverse=True)

@app.get("/api/admin/release-ledger")
def release_ledger(response: Response, admin: str = Depends(require_admin)):
    response.headers["Cache-Control"] = "no-store"
    rows = _read_release_rows()
    return {"rows": rows[:300], "total_rows": len(rows), "stats": _release_stats(rows)}

class ReleaseOverrideReq(BaseModel):
    id: str
    result: str

@app.post("/api/admin/release-ledger/override")
def release_ledger_override(req: ReleaseOverrideReq, admin: str = Depends(require_admin)):
    result = req.result.strip().upper()
    if result not in REL_RESULTS:
        raise HTTPException(status_code=422, detail="'result' must be HIT, MISS, TRAP, INLINE or NO CALL.")
    with _CPI_LOCK:
        conn = get_db_conn(); cur = conn.cursor()
        try:
            ph = ph_for(conn)
            ledger = _setting_get(cur, ph, REL_LEDGER_KEY) or {}
            row = ledger.get(req.id)
            if not row:
                raise HTTPException(status_code=404, detail="That release is not in the ledger.")
            row["result"], row["manual"] = result, True
            _setting_set(conn, cur, REL_LEDGER_KEY, ledger, REL_LEDGER_MAX_CHARS)
            conn.commit()
        except HTTPException:
            conn.rollback(); raise
        except Exception as e:
            conn.rollback(); log.exception("Ledger override failed")
            raise HTTPException(status_code=500, detail=f"Could not save the change: {_first_line(e)}")
        finally:
            cur.close(); conn.close()
    return {"status": "ok", "id": req.id, "result": result}

REL_CSV_COLUMNS = ["release_date", "release_utc", "event_id", "currency", "module", "title", "projected",
                   "projection_label", "projection_score", "decoder_verdict", "actual", "result", "manual",
                   "projected_at", "decoded_at"]

@app.get("/api/admin/release-ledger.csv")
def release_ledger_csv(admin: str = Depends(require_admin)):
    rows = list(reversed(_read_release_rows()))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(REL_CSV_COLUMNS)
    for r in rows:
        w.writerow([_csv_cell(r.get(c)) for c in REL_CSV_COLUMNS])
    return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="release_ledger.csv"', "Cache-Control": "no-store"})

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
  .countdown { font-size: 1.15rem; font-weight: 800; color: var(--gold-bright); background: #04140f; border: 1px solid var(--gold); border-radius: 8px; padding: 0.7rem 0.9rem; margin-bottom: 0.9rem; text-align: center; letter-spacing: 0.5px; font-variant-numeric: tabular-nums; }
  .countdown.live { color: #fff; background: #7f1d1d; border-color: var(--red); animation: pulse 1.4s infinite; }
  @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.7; } 100% { opacity: 1; } }
  .btn-publish { width: 100%; padding: 0.85rem 1rem; font-size: 1rem; background: linear-gradient(135deg, #f3cf65, #d4af37 55%, #b58e22); box-shadow: 0 0 0 2px rgba(243,207,101,0.35), 0 6px 18px rgba(212,175,55,0.25); }
  .cur-filter { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.9rem; }
  .cur-chip { padding: 0.5rem 1rem; border-radius: 999px; border: 1px solid var(--border); background: var(--card); color: var(--muted); font-weight: 800; cursor: pointer; font-size: 0.85rem; }
  .cur-chip.active { border-color: var(--gold); color: var(--gold-bright); background: #04140f; }
  .pill { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.72rem; font-weight: 800; border: 1px solid var(--border); }
  .pill.up { color: var(--gold-bright); border-color: var(--gold); }
  .pill.live { color: #fff; background: #7f1d1d; border-color: var(--red); }
  .pill.done { color: var(--muted); }
  .pill.hit { color: #34d399; border-color: #34d399; }
  .pill.miss { color: #fff; background: #7f1d1d; border-color: var(--red); }
  .pill.trap { color: #fbbf24; border-color: #fbbf24; }
  .sched-box { border-color: var(--gold); }
  .sched-box input[type="datetime-local"] { width: 100%; background: #04140f; border: 1px solid var(--border); color: #fff; padding: 0.5rem; border-radius: 6px; font-size: 0.9rem; color-scheme: dark; }
  #clientQueue { display: none; }
  .client-mode #clientQueue { display: block; }
  .client-mode .grid, .client-mode #tabsRow, .client-mode #curFilter, .client-mode #fetchStatus { display: none !important; }
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

    <div class="card desk-only" id="queueCard">
      <h2><span>📡 Active Next-Event Client Queue</span> <button class="btn-outline" onclick="loadQueue()">🔄 Refresh</button></h2>
      <p style="font-size:0.8rem; color:var(--muted); margin-bottom:0.75rem;">Clients only ever see the earliest scheduled date. An event stays visible for 2 hours after its release (the decoder window), then drops off automatically.</p>
      <div style="overflow-x:auto;"><table>
        <thead><tr><th>Event</th><th>Release (local)</th><th>Release (UTC)</th><th>Status</th><th></th></tr></thead>
        <tbody id="queueBody"></tbody>
      </table></div>
    </div>

    <div id="curFilter" class="cur-filter desk-only"></div>

    <div id="tabsRow" class="desk-only" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.75rem; margin-bottom:1.25rem;">
      <div class="tabs" id="tabsBox" style="margin:0;">
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

    <div id="newViews"></div>

    <div id="clientQueue" class="client-only">
      <h2 style="margin-bottom:0.75rem;"><span>⏳ Next Scheduled Release</span></h2>
      <div id="clientQueueBody"><div class="card"><p style="color:var(--muted);">Loading the next event...</p></div></div>
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
      setupV2Desk();
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

  async function autoFetch() {
    const btn = document.getElementById("autoFetchBtn");
    const status = document.getElementById("fetchStatus");
    btn.disabled = true;
    btn.innerText = "⏳ Fetching...";
    status.innerText = "Fetching live Federal Reserve, WTI, Brent & EU gas data...";

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
      if (data.gbp) {
        const g = document.getElementById("gbpcpi_uk_gas_petrol_pct");
        if (g) g.value = data.gbp.uk_gas_petrol_pct;
      }
      if (data.eur) {
        const e = document.getElementById("eurcpi_ttf_gas_brent_pct");
        if (e) e.value = data.eur.ttf_gas_brent_pct;
      }
      if (loadedTab.GBP_CPI) calcGeneric("GBP_CPI");
      if (loadedTab.EUR_CPI) calcGeneric("EUR_CPI");
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


  // ==========================================================================
  // V2: GBP + EUR modules, release scheduling, admin queue, next-event client view
  // ==========================================================================
  const FLAG = { USD: "🇺🇸", GBP: "🇬🇧", EUR: "🇪🇺" };
  const FILTER_LABEL = { ALL: "All", USD: "🇺🇸 USD", GBP: "🇬🇧 GBP", EUR: "🇪🇺 EUR" };

  // prefix = element-id prefix, api = predictor endpoint
  const MODS = {
    USD_NFP:  { cur: "USD", prefix: "nfp",  api: "/api/predict-nfp",  title: "NFP — US Non-Farm Payrolls" },
    USD_CPI:  { cur: "USD", prefix: "cpi",  api: "/api/predict-cpi",  title: "CPI — US Consumer Prices" },
    USD_PPI:  { cur: "USD", prefix: "ppi",  api: "/api/predict-ppi",  title: "PPI — US Producer Prices" },
    USD_FOMC: { cur: "USD", prefix: "fomc", api: "/api/predict-fomc", title: "FOMC — Rate Decision & Chair Presser" },
    GBP_CPI: {
      cur: "GBP", prefix: "gbpcpi", api: "/api/predict-gbp-cpi", title: "UK CPI — BoE Services Focus",
      heading: "UK CPI V2 Leading Proxies", tabLabel: "🇬🇧 UK CPI V2",
      fields: [
        ["uk_cpi_consensus", "UK CPI YoY Consensus (%) [Reference]", 2.4, 0.1],
        ["uk_srv_pmi_prices", "UK Services PMI Prices Charged [30%]", 57.5, 0.1],
        ["uk_srv_pmi_prices_prev", "UK Services PMI Prices Prev", 56.0, 0.1],
        ["brc_shop_price_yoy", "BRC Shop Price Index YoY (%) [25%]", 1.8, 0.1],
        ["brc_shop_price_prev", "BRC Shop Price Index Prev (%)", 1.5, 0.1],
        ["uk_input_ppi_mom", "UK Input PPI MoM (%) [20%]", 0.3, 0.1],
        ["kantar_grocery_yoy", "Kantar Grocery Inflation YoY (%) [10%]", 2.6, 0.1],
        ["kantar_grocery_prev", "Kantar Grocery Inflation Prev (%)", 2.3, 0.1],
        ["uk_gas_petrol_pct", "UK Gas / Petrol Monthly % Δ [8%]", 3.5, 0.1],
        ["rec_starting_salaries", "REC Starting Salaries Index [7%]", 53.0, 0.1]
      ],
      checks: [["is_ofgem_reset_month", "Ofgem Energy-Cap Reset Month? April / October (Widens No-Trade Gate to ±35)"]],
      labels: { up: "HOTTER UK CPI (GBP BULLISH)", down: "COOLER UK CPI (GBP BEARISH)", flat: "NO-TRADE / LOW EDGE" }
    },
    GBP_JOBS: {
      cur: "GBP", prefix: "gbpjobs", api: "/api/predict-gbp-jobs", title: "UK Jobs & Wages — BoE Wage-First",
      heading: "UK Jobs V2 Leading Proxies", tabLabel: "🇬🇧 UK Jobs V2",
      fields: [
        ["boe_dmp_wage_exp", "BoE DMP Wage Expectations (%) [20%]", 4.2, 0.1],
        ["rec_starting_salaries", "REC Starting Salaries Index [15%]", 53.5, 0.1],
        ["rec_starting_salaries_prev", "REC Starting Salaries Prev", 52.0, 0.1],
        ["rec_placements_idx", "REC Permanent Placements Index [25%]", 48.5, 0.1],
        ["rec_placements_prev", "REC Permanent Placements Prev", 47.0, 0.1],
        ["uk_pmi_emp", "UK PMI Employment Index [20%]", 50.8, 0.1],
        ["uk_pmi_emp_prev", "UK PMI Employment Prev", 49.9, 0.1],
        ["hmrc_paye_change_k", "HMRC PAYE Payrolls Change (K) [12%]", 15.0, 1],
        ["adzuna_job_ads_pct", "Adzuna Job Ads % Δ [8%]", 1.2, 0.1]
      ],
      checks: [],
      note: "LFS divergence filter is automatic: if HMRC PAYE and REC placements point in opposite directions, the gate widens from ±25 to ±32.",
      labels: { up: "HAWKISH WAGE-LED JOBS (GBP BULLISH)", down: "SOFT WAGE-LED JOBS (GBP BEARISH)", flat: "NO-TRADE / LOW EDGE" }
    },
    EUR_CPI: {
      cur: "EUR", prefix: "eurcpi", api: "/api/predict-eur-cpi", title: "EUROZONE FLASH CPI PROXY v3",
      heading: "Eurozone Flash CPI Proxy v3 Inputs", tabLabel: "🇪🇺 EUR Flash CPI v3",
      selects: [["eur_cpi_mode", "Mode", [["YoY", "YoY (Year-over-Year)"], ["MoM", "MoM (Month-over-Month)"]], "YoY"]],
      fields: [
        ["eur_cpi_consensus", "Market Consensus Forecast (%) *", 2.1, 0.01],
        ["germany_hicp", "Germany HICP (%) * [27.8%]", 2.3, 0.01],
        ["france_hicp", "France HICP (%) * [20.3%]", 2.1, 0.01],
        ["italy_hicp", "Italy HICP (%) * [16.8%]", 1.9, 0.01],
        ["spain_hicp", "Spain HICP (%) * [11.1%]", 2.5, 0.01],
        ["netherlands_hicp", "Netherlands HICP (%) [5.7%] — optional, leave blank if not released", "", 0.01, true],
        ["belgium_hicp", "Belgium HICP (%) [3.8%] — optional, leave blank if not released", "", 0.01, true],
        ["hcob_srv_prices", "Lead: HCOB Flash Services Output Prices (this month)", 55.2, 0.1],
        ["hcob_srv_prices_prev", "Lead: HCOB Services Output Prices (previous month)", 54.0, 0.1],
        ["ttf_gas_brent_pct", "Lead: TTF Gas / Brent Monthly % Δ (⚡ Auto-Fetch fills this)", 4.0, 0.1]
      ],
      note: "Lead adjustment is automatic: services prices and gas both up = +0.05%, both down = -0.05%, mixed = 0.00%.",
      checks: [],
      extraHtml: `<div style="margin-top:0.9rem; padding:0.75rem; border:1px solid var(--border); border-radius:8px; background:#04140f;">
        <label style="color:var(--gold-bright);">Germany HICP — 4-State Calculator</label>
        <div class="form-grid">
          <div><label>NRW (41%)</label><input type="number" id="eurcpi_st_nrw" step="0.01" /></div>
          <div><label>Bavaria (28%)</label><input type="number" id="eurcpi_st_bay" step="0.01" /></div>
          <div><label>Baden-Württemberg (21%)</label><input type="number" id="eurcpi_st_bw" step="0.01" /></div>
          <div><label>Hesse (10%)</label><input type="number" id="eurcpi_st_hes" step="0.01" /></div>
        </div>
        <button class="btn-outline" style="width:100%; margin-top:0.6rem;" onclick="calcGermany()">Calculate Germany HICP &amp; fill the box above</button>
        <p id="eurcpi_st_msg" style="font-size:0.78rem; color:var(--muted); margin-top:0.4rem;">(0.41 × NRW) + (0.28 × Bavaria) + (0.21 × Baden-Württemberg) + (0.10 × Hesse)</p>
      </div>`,
      labels: { up: "STRONG BUY EUR", down: "STRONG SELL EUR", flat: "DO NOT TRADE (UNSURE)" }
    },
    EUR_PMI: {
      cur: "EUR", prefix: "eurpmi", api: "/api/predict-eur-pmi", title: "Eurozone Flash PMI",
      heading: "Eurozone Flash PMI V2 Leading Proxies", tabLabel: "🇪🇺 EUR Flash PMI V2",
      fields: [
        ["eur_comp_pmi_consensus", "Eurozone Composite PMI Consensus [Reference]", 50.5, 0.1],
        ["german_flash_pmi", "German Flash PMI [40%]", 51.4, 0.1],
        ["french_flash_pmi", "French Flash PMI [25%]", 50.8, 0.1],
        ["zew_sentix_change", "ZEW / Sentix Change [20%]", 3.5, 0.1],
        ["eur_new_orders_subidx", "Eurozone New Orders Sub-Index [15%]", 51.0, 0.1]
      ],
      checks: [],
      note: "Franco-German divergence gate is automatic: if the two PMIs are 2.5+ points apart and on opposite sides of 50, the gate widens from ±25 to ±36.",
      labels: { up: "STRONGER EZ PMI (EUR BULLISH)", down: "WEAKER EZ PMI (EUR BEARISH)", flat: "NO-TRADE / LOW EDGE" }
    }
  };
  MODS.USD_NFP.labels  = MODULE_LABELS.NFP;
  MODS.USD_CPI.labels  = MODULE_LABELS.CPI;
  MODS.USD_PPI.labels  = MODULE_LABELS.PPI;
  MODS.USD_FOMC.labels = MODULE_LABELS.FOMC;
  const USD_PAYLOAD = { USD_NFP: nfpPayload, USD_CPI: cpiPayload, USD_PPI: ppiPayload, USD_FOMC: fomcPayload };
  const TAB_ORDER = ["USD_NFP", "USD_CPI", "USD_PPI", "USD_FOMC", "GBP_CPI", "GBP_JOBS", "EUR_CPI", "EUR_PMI"];
  const MOD_NAME = { USD_NFP: "NFP", USD_CPI: "CPI", USD_PPI: "PPI", USD_FOMC: "FOMC" };
  const TAB_ID = { USD_NFP: "NFP", USD_CPI: "CPI", USD_PPI: "PPI", USD_FOMC: "FOMC" };
  const tabIdFor = key => TAB_ID[key] || key.replace("_", "");

  // ---- post-release decoder definitions (shared by the desk tabs and the client cards) ----
  const SEL_RATE = [["MORE_HAWKISH", "More hawkish than priced"], ["INLINE", "In line with pricing"], ["MORE_DOVISH", "More dovish than priced"]];
  const SEL_DOTS = [["HAWKISH_SHIFT", "Hawkish shift"], ["UNCHANGED", "Unchanged"], ["DOVISH_SHIFT", "Dovish shift"]];
  const SEL_VOTE = [["UNANIMOUS", "Unanimous"], ["HAWKISH_DISSENT", "Hawkish dissent"], ["DOVISH_DISSENT", "Dovish dissent"]];
  const SEL_CHAIR = [["PENDING", "Pending (presser not started)"], ["PUSHBACK_ON_CUTS", "Pushback on cuts"], ["DATA_DEPENDENT", "Data dependent"], ["OPEN_TO_EASING", "Open to easing"]];
  const DEC = {
    USD_NFP: { url: "/api/decode-nfp", fields: [
      ["consensus_nfp", "NFP Consensus (K)", 110, 1, "consensus_nfp"], ["actual_nfp", "Actual NFP Print (K)", 165, 1],
      ["revisions_k", "2-Month Net Revisions (K)", 20, 1], ["unemp_forecast", "Unemployment Forecast (%)", 4.1, 0.1],
      ["unemp_actual", "Unemployment Actual (%)", 4.0, 0.1], ["ahe_forecast", "Avg Hourly Earnings Forecast (%)", 0.3, 0.1],
      ["ahe_actual", "Avg Hourly Earnings Actual (%)", 0.4, 0.1]] },
    USD_CPI: { url: "/api/decode-cpi", fields: [
      ["headline_forecast", "Headline CPI MoM Forecast (%)", 0.3, 0.1, "cpi_mom_consensus"], ["headline_actual", "Headline CPI MoM Actual (%)", 0.4, 0.1],
      ["core_forecast", "Core CPI MoM Forecast (%)", 0.3, 0.1], ["core_actual", "Core CPI MoM Actual (%)", 0.4, 0.1]] },
    USD_PPI: { url: "/api/decode-ppi", fields: [
      ["headline_forecast", "Headline PPI MoM Forecast (%)", 0.3, 0.1, "ppi_mom_consensus"], ["headline_actual", "Headline PPI MoM Actual (%)", 0.5, 0.1],
      ["core_forecast", "Core PPI MoM Forecast (%)", 0.3, 0.1], ["core_actual", "Core PPI MoM Actual (%)", 0.2, 0.1]] },
    USD_FOMC: { url: "/api/decode-fomc", fields: [], selects: [
      ["rate_surprise", "Rate Decision vs Pricing", SEL_RATE, "INLINE"], ["dot_plot_tone", "Dot Plot / Statement Tone", SEL_DOTS, "UNCHANGED"],
      ["vote_split", "Vote Split", SEL_VOTE, "UNANIMOUS"], ["chair_presser_cue", "Chair Presser Cue (2:30 PM ET)", SEL_CHAIR, "PENDING"]] },
    GBP_CPI: { url: "/api/decode-gbp", extra: { event_type: "UK_CPI" }, fields: [
      ["headline_forecast", "Headline CPI YoY Forecast (%)", 2.4, 0.1, "uk_cpi_consensus"], ["headline_actual", "Headline CPI YoY Actual (%)", 2.3, 0.1],
      ["core_or_wages_forecast", "Services CPI YoY Forecast (%)", 4.8, 0.1], ["core_or_wages_actual", "Services CPI YoY Actual (%)", 5.0, 0.1]] },
    GBP_JOBS: { url: "/api/decode-gbp", extra: { event_type: "UK_JOBS" }, fields: [
      ["headline_forecast", "Unemployment Rate (3M) Forecast (%)", 4.4, 0.1], ["headline_actual", "Unemployment Rate (3M) Actual (%)", 4.5, 0.1],
      ["core_or_wages_forecast", "Avg Weekly Earnings 3M YoY Forecast (%)", 4.6, 0.1], ["core_or_wages_actual", "Avg Weekly Earnings 3M YoY Actual (%)", 4.8, 0.1]] },
    EUR_CPI: { url: "/api/decode-eur", extra: { event_type: "EUR_CPI" }, fields: [
      ["headline_forecast", "Flash CPI YoY Forecast (%)", 2.1, 0.1, "eur_cpi_consensus"], ["headline_actual", "Flash CPI YoY Actual (%)", 2.0, 0.1],
      ["core_or_services_forecast", "Core CPI YoY Forecast (%)", 2.3, 0.1], ["core_or_services_actual", "Core CPI YoY Actual (%)", 2.5, 0.1]] },
    EUR_PMI: { url: "/api/decode-eur", extra: { event_type: "EUR_PMI" }, fields: [
      ["headline_forecast", "Composite Flash PMI Forecast", 50.5, 0.1, "eur_comp_pmi_consensus"], ["headline_actual", "Composite Flash PMI Actual", 50.1, 0.1],
      ["core_or_services_forecast", "Services Flash PMI Forecast", 51.0, 0.1], ["core_or_services_actual", "Services Flash PMI Actual", 51.8, 0.1]] }
  };

  function decoderFormHtml(key, idp, inputs) {
    const cfg = DEC[key];
    const inp = inputs || {};
    const nums = cfg.fields.map(f => {
      const v = (f[4] && inp[f[4]] !== undefined) ? inp[f[4]] : f[2];
      return `<div><label>${esc(f[1])}</label><input type="number" id="${idp}_${f[0]}" value="${esc(v)}" step="${f[3]}" /></div>`;
    }).join("");
    const sels = (cfg.selects || []).map(s =>
      `<div><label>${esc(s[1])}</label><select id="${idp}_${s[0]}">${s[2].map(o => `<option value="${o[0]}"${o[0] === s[3] ? " selected" : ""}>${esc(o[1])}</option>`).join("")}</select></div>`
    ).join("");
    return `<div class="form-grid">${nums}${sels}</div>
      <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="runDecoder('${key}', '${idp}')">Decode Actual Print &amp; Get Trade Plan</button>
      <div id="${idp}_out" class="decoder-box hidden"></div>`;
  }

  async function runDecoder(key, idp) {
    const cfg = DEC[key];
    const payload = { ...(cfg.extra || {}) };
    cfg.fields.forEach(f => { payload[f[0]] = Number(document.getElementById(`${idp}_${f[0]}`).value); });
    (cfg.selects || []).forEach(s => { payload[s[0]] = document.getElementById(`${idp}_${s[0]}`).value; });
    const { ok, data } = await apiPost(cfg.url, payload);
    showDecode(`${idp}_out`, ok ? data : { verdict: "Could not decode", plan: errText(data) });
  }

  // ---- desk views for the four new modules (built from the definitions above) ----
  function buildDeskView(key) {
    const m = MODS[key];
    const p = m.prefix;
    const fields = m.fields.map(f =>
      `<div><label>${esc(f[1])}</label><input type="number" id="${p}_${f[0]}" value="${f[2]}" step="${f[3]}" /></div>`).join("");
    const selHtml = list => (list || []).map(sl =>
      `<div><label>${esc(sl[1])}</label><select id="${p}_${sl[0]}">${sl[2].map(o => `<option value="${o[0]}"${o[0] === sl[3] ? " selected" : ""}>${esc(o[1])}</option>`).join("")}</select></div>`).join("");
    const checks = m.checks.map(c =>
      `<div class="check-row"><input type="checkbox" id="${p}_${c[0]}" /><label for="${p}_${c[0]}" style="margin:0; color:var(--text); cursor:pointer;">${esc(c[1])}</label></div>`).join("");
    const note = m.note ? `<p style="font-size:0.8rem; color:var(--muted); margin-top:0.75rem;">${esc(m.note)}</p>` : "";
    return `<div id="view${tabIdFor(key)}" class="grid hidden">
      <div class="card desk-only">
        <h2><span>1. ${esc(m.heading)}</span> <span style="font-size:0.75rem; color:var(--muted);">${FLAG[m.cur]} ${m.cur} V2</span></h2>
        <div class="form-grid">${selHtml(m.selects)}${fields}${selHtml(m.selectsAfter)}${checks}</div>${m.extraHtml || ""}${note}
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcGeneric('${key}')">Calculate ${esc(m.heading.replace(' Leading Proxies', ''))} Outcome &amp; FX Spikes</button>
      </div>
      <div>
        <div class="card desk-only" id="${p}DeskCard">
          <h2><span>2. ${esc(m.title)} — FX Spike Matrix</span> <span id="${p}Tier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="${p}Bias" class="big-score neut">READY</span>
              <span id="${p}Score" style="font-weight:700;"></span>
            </div>
            <p id="${p}Summary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="${p}Pairs"></tbody>
          </table>
        </div>
        <div class="card">
          <h2>⚡ 3. Post-Release Action Decoder</h2>
          ${key === "EUR_CPI" ? cpiDecoderV2Html() : decoderFormHtml(key, "dec_" + p, null)}
        </div>
      </div>
    </div>`;
  }

  function genericPayload(key) {
    const m = MODS[key];
    const out = {};
    m.fields.forEach(f => {
      const raw = document.getElementById(`${m.prefix}_${f[0]}`).value;
      out[f[0]] = (f[4] && String(raw).trim() === "") ? null : Number(raw);
    });
    (m.selects || []).concat(m.selectsAfter || []).forEach(sl => { out[sl[0]] = document.getElementById(`${m.prefix}_${sl[0]}`).value; });
    m.checks.forEach(c => { out[c[0]] = document.getElementById(`${m.prefix}_${c[0]}`).checked; });
    return out;
  }

  function calcGermany() {
    const ids = ["nrw", "bay", "bw", "hes"];
    const w = [0.41, 0.28, 0.21, 0.10];
    const vals = ids.map(i => document.getElementById("eurcpi_st_" + i).value);
    const msg = document.getElementById("eurcpi_st_msg");
    if (vals.some(v => String(v).trim() === "" || isNaN(Number(v)))) { msg.innerText = "Enter all four state prints first."; return; }
    const de = vals.reduce((a, v, i) => a + Number(v) * w[i], 0);
    document.getElementById("eurcpi_germany_hicp").value = (Math.round(de * 100) / 100).toFixed(2);
    msg.innerText = "Germany HICP set to " + (Math.round(de * 100) / 100).toFixed(2) + "%.";
  }

  function eurCpiLines(d) {
    if (d.proxy_rounded === undefined || !d.inputs) return `<p style="font-size:0.88rem; color:#d1d5db;">${esc(d.summary || "")}</p>`;
    const sgn = d.surprise_delta >= 0 ? "+" : "";
    let inp = `DE: ${d.inputs.DE}% | FR: ${d.inputs.FR}% | IT: ${d.inputs.IT}% | ES: ${d.inputs.ES}%`;
    if (d.inputs.NL !== null && d.inputs.NL !== undefined) inp += ` | NL: ${d.inputs.NL}%`;
    if (d.inputs.BE !== null && d.inputs.BE !== undefined) inp += ` | BE: ${d.inputs.BE}%`;
    const tags = (d.reasons || []).map(r => `<span class="pill up" style="margin-right:0.35rem;">${esc(r)}</span>`).join("");
    return `<div style="font-weight:700; margin-bottom:0.35rem;">Proxy: ${d.proxy_rounded.toFixed(1)}% (${d.predicted_cpi.toFixed(2)}%) vs. Consensus: ${esc(d.consensus)}% | Edge: ${sgn}${d.surprise_delta.toFixed(2)}%</div>
      <div style="font-size:0.85rem; color:#d1d5db; margin-bottom:0.35rem;">${esc(inp)}${d.lead_label ? esc("  |  Lead: " + d.lead_label) : ""}</div>
      ${tags ? `<div style="margin-bottom:0.35rem;">${tags}</div>` : ""}
      <div style="font-size:0.88rem; color:#d1d5db;">${esc(d.note || d.summary || "")}</div>`;
  }

  function renderGeneric(key, d) {
    const m = MODS[key];
    const p = m.prefix;
    if (key === "EUR_CPI" && d.proxy_rounded !== undefined) {
      const up = d.bias === "HOTTER", down = d.bias === "COOLER";
      const el = document.getElementById(p + "Bias");
      el.innerText = d.signal;
      el.className = "big-score " + (up ? "bull" : down ? "bear" : "neut");
      document.getElementById(p + "Tier").innerText = d.tier || "";
      document.getElementById(p + "Score").innerText = `Edge: ${d.surprise_delta >= 0 ? "+" : ""}${d.surprise_delta.toFixed(2)}%`;
      document.getElementById(p + "Summary").innerHTML = eurCpiLines(d);
      document.getElementById(p + "Pairs").innerHTML = pairRows(d.pairs);
      const px = document.getElementById("cd2_proxy");
      if (px) px.value = d.signal.indexOf("DO NOT TRADE") === 0 ? "DO NOT TRADE" : d.signal;
      return;
    }
    const up = d.bias === "HOTTER", down = d.bias === "COOLER";
    const el = document.getElementById(p + "Bias");
    el.innerText = up ? m.labels.up : down ? m.labels.down : m.labels.flat;
    el.className = "big-score " + (up ? "bull" : down ? "bear" : "neut");
    document.getElementById(p + "Tier").innerText = d.tier || "";
    document.getElementById(p + "Score").innerText = `Score: ${d.score > 0 ? "+" : ""}${d.score} | Gate: ±${d.buffer} | Conf: ${d.confidence}%`;
    document.getElementById(p + "Summary").innerText = d.summary;
    document.getElementById(p + "Pairs").innerHTML = pairRows(d.pairs);
  }

  async function calcGeneric(key) {
    const m = MODS[key];
    const { ok, data } = await apiPost(m.api, { user_email: currentUser ? currentUser.email : "", ...genericPayload(key) });
    if (!ok) { document.getElementById(m.prefix + "Summary").innerText = errText(data); return; }
    renderGeneric(key, data);
  }

  // ---- tabs + currency filter (admin) ----
  const loadedTab = { USD_NFP: true, USD_CPI: true };
  let curFilter = "ALL";

  function switchTab(tab) {
    TAB_ORDER.forEach(k => {
      const id = tabIdFor(k);
      const active = (k === tab) || (id === tab);
      document.getElementById("tab" + id).classList.toggle("active", active);
      document.getElementById("view" + id).classList.toggle("hidden", !active);
      if (active && viewMode === "desk" && !loadedTab[k]) {
        loadedTab[k] = true;
        if (k === "USD_PPI") { ppiLoaded = true; calcPPI(); }
        else if (k === "USD_FOMC") { fomcLoaded = true; calcFOMC(); }
        else if (MODS[k].fields) { calcGeneric(k); }
      }
    });
  }

  function setCurFilter(cur) {
    curFilter = cur;
    document.querySelectorAll(".cur-chip").forEach(c => c.classList.toggle("active", c.dataset.cur === cur));
    let first = null;
    TAB_ORDER.forEach(k => {
      const show = cur === "ALL" || MODS[k].cur === cur;
      document.getElementById("tab" + tabIdFor(k)).classList.toggle("hidden", !show);
      if (show && !first) first = k;
    });
    const activeNow = TAB_ORDER.find(k => document.getElementById("tab" + tabIdFor(k)).classList.contains("active"));
    if (!activeNow || !(cur === "ALL" || MODS[activeNow].cur === cur)) switchTab(first);
  }

  // ---- scheduling + publishing (admin) ----
  function schedulePanelHtml(key) {
    const m = MODS[key];
    return `<div class="card desk-only sched-box" id="sched_${key}">
      <h2><span>📅 Schedule &amp; Publish — ${FLAG[m.cur]} ${esc(m.title)}</span></h2>
      <label>Release Date &amp; Time (your local time — saved as UTC)</label>
      <input type="datetime-local" id="rel_${key}" style="margin-bottom:0.85rem;" />
      <button class="btn-outline" style="width:100%; margin-bottom:0.6rem;" onclick="publishEvent('${key}', false)">⏳ Step 1: Schedule Countdown (no projection shown)</button>
      <button class="btn btn-publish" onclick="publishEvent('${key}', true)">📡 Step 2: Release Projection to Clients</button>
      <button class="btn-outline" style="width:100%; margin-top:0.6rem; border-color:var(--gold-bright); color:var(--gold-bright);" onclick="publishDecode('${key}')">📣 Step 3: Send Decoded Result to Clients (decode below first)</button>
      <button class="btn-outline" style="width:100%; margin-top:0.6rem;" onclick="togglePreview()">👁️ Preview Client View</button>
      <p id="pubst_${key}" style="font-size:0.8rem; margin-top:0.5rem; color:var(--gold);"></p>
    </div>`;
  }

  function payloadForKey(key) {
    return USD_PAYLOAD[key] ? USD_PAYLOAD[key]() : genericPayload(key);
  }

  async function publishEvent(key, released) {
    const m = MODS[key];
    const status = document.getElementById("pubst_" + key);
    const local = document.getElementById("rel_" + key).value;
    if (!local) { status.innerText = "Pick a release date & time first."; return; }
    const when = new Date(local);
    if (isNaN(when.getTime())) { status.innerText = "That release date & time is not valid."; return; }
    const releaseUtc = when.toISOString().slice(0, 19) + "Z";
    if (!confirm(released ? `Release the ${m.title} projection to clients now? Release time: ${when.toLocaleString()}.` : `Schedule the ${m.title} countdown for ${when.toLocaleString()}? Clients will see the countdown only, no projection.`)) return;
    status.innerText = "Calculating and publishing...";
    try {
      let inputs = {};
      let result = {};
      if (released) {
        inputs = payloadForKey(key);
        const calc = await apiPost(m.api, { user_email: currentUser.email, ...inputs });
        if (!calc.ok) { status.innerText = "Could not calculate: " + errText(calc.data); return; }
        result = calc.data;
        if (key === "USD_NFP") renderForecast("nfp", calc.data, true);
        else if (key === "USD_CPI") renderForecast("cpi", calc.data, false);
        else if (key === "USD_PPI") renderPPI(calc.data);
        else if (key === "USD_FOMC") renderFOMC(calc.data);
        else renderGeneric(key, calc.data);
      }
      const pub = await apiPost("/api/admin/publish-event", {
        event_id: key, currency: m.cur, title: m.title, release_utc: releaseUtc,
        inputs: inputs, result: result, active: true, released: !!released
      });
      if (!pub.ok) { status.innerText = "Publish failed: " + errText(pub.data); return; }
      const warn = pub.data.storage && !pub.data.storage.includes("Permanent") ? " WARNING: saved only to temporary storage (" + pub.data.storage + ")." : "";
      status.innerText = (released ? `✅ Projection released to clients and added to the release ledger.` : `✅ Countdown scheduled for ${when.toLocaleString()}.`) + warn;
      loadRelLedger();
      loadQueue();
    } catch (e) {
      status.innerText = "Publish failed. Check your connection and try again.";
    }
  }

  const DECODE_OUT_ID = { USD_NFP: "nfpDecodeOut", USD_CPI: "cpiDecodeOut", USD_PPI: "ppiDecodeOut", USD_FOMC: "fomcDecodeOut" };

  async function publishDecode(key) {
    if (key === "EUR_CPI") { publishCpiDecode(); return; }
    const status = document.getElementById("pubst_" + key);
    const out = document.getElementById(DECODE_OUT_ID[key] || ("dec_" + MODS[key].prefix + "_out"));
    const verdict = out && out.children[0] ? out.children[0].innerText.trim() : "";
    const plan = out && out.children[1] ? out.children[1].innerText.trim() : "";
    if (!verdict || out.classList.contains("hidden")) { status.innerText = "Run the decoder for this module first (Step 3 box below), then send it."; return; }
    if (!confirm(`Send this decoded result to clients?\n\n${verdict}`)) return;
    const pub = await apiPost("/api/admin/publish-decode", { event_id: key, verdict: verdict, plan: plan });
    status.innerText = pub.ok ? "✅ Decoded result sent to clients and the release ledger updated." : "Could not send: " + errText(pub.data);
    if (pub.ok) loadRelLedger();
  }

  // ---- admin queue manager ----
  function eventState(ev, nowMs) {
    const rel = Date.parse(ev.release_utc);
    if (!ev.active) return { cls: "done", label: "INACTIVE" };
    if (nowMs < rel) return { cls: "up", label: "UPCOMING" };
    if (nowMs <= rel + 2 * 3600 * 1000) return { cls: "live", label: "LIVE WINDOW" };
    return { cls: "done", label: "EXPIRED" };
  }

  async function loadQueue() {
    const body = document.getElementById("queueBody");
    if (!body) return;
    try {
      const res = await fetch("/api/next-events?all=1", { cache: "no-store" });
      if (!res.ok) throw new Error("bad response");
      const data = await res.json();
      serverOffset = Date.parse(data.server_time) - Date.now();
      const now = Date.now() + serverOffset;
      if (!data.events.length) {
        body.innerHTML = `<tr><td colspan="5" style="color:var(--muted);">Nothing queued. Clients will see "no upcoming event" until you publish one.</td></tr>`;
        return;
      }
      body.innerHTML = data.events.map(ev => {
        const st = eventState(ev, now);
        return `<tr><td><strong>${esc(FLAG[ev.currency] || "")} ${esc(ev.title)}</strong><br><span style="color:var(--muted); font-size:0.75rem;">${esc(ev.event_id)}</span></td>
          <td>${esc(fmtTime(ev.release_utc))}</td><td>${esc(ev.release_utc)}</td>
          <td><span class="pill ${st.cls}">${st.label}</span> <span class="pill ${ev.released ? "live" : "up"}">${ev.released ? "PROJECTION LIVE" : "COUNTDOWN ONLY"}</span></td>
          <td><button class="btn-outline" onclick="removeEvent('${esc(ev.event_id)}')">Remove</button></td></tr>`;
      }).join("");
    } catch (e) {
      body.innerHTML = `<tr><td colspan="5" style="color:var(--red);">Could not load the queue. Tap Refresh to try again.</td></tr>`;
    }
  }

  async function removeEvent(id) {
    if (!confirm(`Remove ${id} from the client queue?`)) return;
    try {
      const res = await fetch("/api/admin/publish-event/" + encodeURIComponent(id), { method: "DELETE" });
      if (!res.ok) { const d = await res.json().catch(() => ({})); alert(errText(d)); return; }
    } catch (e) { alert("Could not remove the event. Check your connection."); return; }
    loadQueue();
  }

  // ---- client view: next upcoming event(s) only ----
  let serverOffset = 0;
  let lastQueueSig = "";
  let clientTimer = null;
  let tickTimer = null;
  let refetching = false;
  let lastRefetch = 0;

  function fmtCountdown(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const p = n => String(n).padStart(2, "0");
    return `${p(Math.floor(s / 86400))}d ${p(Math.floor((s % 86400) / 3600))}h ${p(Math.floor((s % 3600) / 60))}m ${p(s % 60)}s`;
  }

  function tickCountdowns() {
    const now = Date.now() + serverOffset;
    document.querySelectorAll(".countdown").forEach(el => {
      const rel = Date.parse(el.dataset.release);
      if (isNaN(rel)) return;
      if (now < rel) {
        el.innerText = "⏳ Releases in: " + fmtCountdown(rel - now);
        el.classList.remove("live");
      } else if (now <= rel + 2 * 3600 * 1000) {
        el.innerText = "🔴 LIVE RELEASE WINDOW — USE DECODER BELOW";
        el.classList.add("live");
      } else if (!refetching && Date.now() - lastRefetch > 15000) {
        refetching = true;
        lastRefetch = Date.now();
        loadClientQueue(true).finally(() => { refetching = false; });
      }
    });
  }

  function metricFor(key, d) {
    const sign = d.score > 0 ? "+" : "";
    if (key === "USD_NFP") return `Edge: ${sign}${d.score}K`;
    if (key === "EUR_CPI" && d.surprise_delta !== undefined) return `Edge: ${d.surprise_delta >= 0 ? "+" : ""}${d.surprise_delta.toFixed(2)}%`;
    if (key === "USD_FOMC") return `Hawkish score: ${sign}${d.score} | Gate: ±${d.gate} | Reversal risk: ${d.reversal_risk}`;
    if (d.buffer !== undefined) return `Score: ${sign}${d.score} | Gate: ±${d.buffer}`;
    return `Score: ${sign}${d.score}`;
  }

  function decodedHtml(ev) {
    const d = ev.decoded;
    if (!d) return "";
    if (d.details) {
      return `<div class="decoder-box" style="margin-top:1.1rem; border-width:2px; text-align:left;">
        <div class="desk-badge" style="margin-bottom:0.2rem;">⚡ A&amp;M Research Desk — Post-Release Decode (Updated: ${esc(fmtTime(d.updated_at))})</div>
        ${cpiPlanHtml(d.details, false, ev.event_id)}</div>`;
    }
    return `<div class="decoder-box" style="margin-top:1.1rem; border-width:2px; text-align:left;">
      <div class="desk-badge" style="margin-bottom:0.6rem;">⚡ A&amp;M Research Desk — Post-Release Decode (Updated: ${esc(fmtTime(d.updated_at))})</div>
      <div style="color:var(--gold-bright); font-weight:800; margin-bottom:0.3rem;">${esc(d.verdict)}</div>
      <p style="font-size:0.88rem;">${esc(d.plan)}</p></div>`;
  }

  function teaserCardHtml(ev) {
    return `<div class="card" style="border-color:var(--gold); text-align:center;">
      <div class="dept-tag" style="margin-bottom:0.4rem;">Next Event</div>
      <h2 style="justify-content:center; font-size:1.25rem;">${esc(FLAG[ev.currency] || "")} ${esc(ev.title)} — Prediction</h2>
      <div class="countdown" data-release="${esc(ev.release_utc)}">⏳ Releases in: --d --h --m --s</div>
      <p style="font-size:0.88rem; color:var(--muted);">The A&amp;M Group Research Desk will publish its projection here before the release. This page updates automatically.</p>
      ${decodedHtml(ev)}
    </div>`;
  }

  function eventCardHtml(ev) {
    if (!ev.released || !ev.result) return teaserCardHtml(ev);
    const key = `${ev.currency}_${ev.module}`;
    const m = MODS[key];
    const d = ev.result || {};
    const L = m ? m.labels : { up: "BULLISH", down: "BEARISH", flat: "NO-TRADE / LOW EDGE" };
    const up = d.bias === "HOTTER" || d.bias === "HAWKISH";
    const down = d.bias === "COOLER" || d.bias === "DOVISH";
    const tier = d.tier || (d.crowded ? "CROWDED CONSENSUS (BUY RUMOR / SELL FACT RISK)" : "");
    const idp = "cdec_" + ev.event_id;
    const decoder = decodedHtml(ev);
    const isV3 = key === "EUR_CPI" && d.proxy_rounded !== undefined;
    const bodyHtml = isV3 ? eurCpiLines(d) : `<p style="font-size:0.88rem; color:#d1d5db;">${esc(d.summary || "")}</p>`;
    return `<div class="card" style="border-color:var(--gold);">
      <div class="desk-badge" style="margin-bottom:0.9rem;">🏛️ A&amp;M Group Research Desk — Official Signal (Updated: ${esc(fmtTime(ev.updated_at))})</div>
      <h2><span>${esc(FLAG[ev.currency] || "")} ${esc(ev.title)} — Asset &amp; FX Spike Matrix</span> <span style="font-size:0.75rem; color:var(--gold);">${esc(tier)}</span></h2>
      <div class="verdict-box">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.4rem; margin-bottom:0.4rem;">
          <span class="big-score ${up ? "bull" : down ? "bear" : "neut"}">${esc(isV3 ? d.signal : (up ? L.up : down ? L.down : L.flat))}</span>
          <span style="font-weight:700;">${esc(metricFor(key, d))}</span>
        </div>
        ${bodyHtml}
      </div>
      <div style="overflow-x:auto;"><table>
        <thead><tr><th>Pair / Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
        <tbody>${Array.isArray(d.pairs) ? pairRows(d.pairs) : ""}</tbody>
      </table></div>
      ${decoder}
    </div>`;
  }

  async function loadClientQueue(force) {
    const box = document.getElementById("clientQueueBody");
    try {
      const res = await fetch("/api/next-events", { cache: "no-store" });
      if (!res.ok) throw new Error("bad response");
      const data = await res.json();
      serverOffset = Date.parse(data.server_time) - Date.now();
      const sig = (data.events || []).map(e => e.event_id + "|" + e.updated_at + "|" + e.release_utc + "|" + e.released + "|" + (e.decoded ? e.decoded.updated_at : "")).join(",");
      if (!force && sig === lastQueueSig) { tickCountdowns(); return; }
      lastQueueSig = sig;
      if (!data.events.length) {
        box.innerHTML = `<div class="card"><h2>No upcoming event scheduled</h2><p style="color:var(--muted); font-size:0.9rem;">The research desk has not scheduled the next release yet. This page checks again every minute.</p></div>`;
      } else {
        box.innerHTML = data.events.map(eventCardHtml).join("");
      }
      tickCountdowns();
    } catch (e) {
      lastQueueSig = "";
      box.innerHTML = `<div class="card"><h2>Could not load the next event</h2><p style="color:var(--muted); font-size:0.9rem; margin-bottom:0.75rem;">Check your connection and try again.</p><button class="btn-outline" onclick="loadClientQueue(true)">🔄 Retry</button></div>`;
    }
  }

  function setMode(mode) {
    viewMode = mode;
    document.body.classList.toggle("client-mode", mode === "client");
    const btn = document.getElementById("previewBtn");
    if (btn) btn.innerText = mode === "client" ? "🛠️ Back to Desk Mode" : "👁️ Preview Client View";
    clearInterval(clientTimer); clearInterval(tickTimer);
    if (mode === "client") {
      lastQueueSig = "";
      loadClientQueue(true);
      tickTimer = setInterval(tickCountdowns, 1000);
      clientTimer = setInterval(() => loadClientQueue(false), 60000);
    } else if (currentUser && currentUser.is_admin) {
      loadQueue();
    }
  }

  // ---- Admin cheat sheet: release & data-entry schedule (EAT). Built only for the admin; never rendered for clients ----
  const SHEET_LINKS = {
    FF: ["Forex Factory", "https://www.forexfactory.com/calendar"],
    CLEV: ["Cleveland Fed", "https://www.clevelandfed.org/indicators-and-data/inflation-nowcasting"],
    ISM: ["ISM", "https://www.ismworld.org/supply-management-news-and-reports/reports/ism-report-on-business/"],
    NFIB: ["NFIB", "https://www.nfib.com/surveys/small-business-economic-trends/"],
    HB: ["Homebase", "https://joinhomebase.com/data/"],
    CME: ["CME FedWatch", "https://www.cmegroup.com/markets/interest-rates/cme-fedwatch-tool.html"],
    ONS: ["ONS", "https://www.ons.gov.uk/releasecalendar"],
    BRC: ["BRC", "https://brc.org.uk/"],
    REC: ["REC", "https://www.rec.uk.com/"],
    PMI: ["S&P Global PMI", "https://www.pmi.spglobal.com/"]
  };
  const SHEET = [
    { key: "USD_NFP", cur: "USD", main: "First Friday of the month, 16:30 EAT", rows: [
      ["ISM Services Employment [22%]", "3rd business day, 18:00", "ISM"],
      ["Initial Claims 12th-week Δ [16%]", "Every Thursday, 16:30", "FF"],
      ["Continuing Claims 12th-week Δ [12%]", "Every Thursday, 16:30", "FF"],
      ["ADP Employment [14%]", "Wednesday before NFP, 16:15", "FF"],
      ["Homebase Hours % Δ [12%]", "Live data page, check the day before NFP", "HB"],
      ["Conf. Board Labor Differential [8%]", "Last Tuesday of the month, 18:00", "FF"],
      ["ISM Manufacturing Employment [8%]", "1st business day, 18:00", "ISM"],
      ["NFIB Hiring Plans [8%]", "2nd Tuesday of the month, 14:00", "NFIB"],
      ["Prior-month Govt Education Swing", "From the previous NFP report", "FF"]
    ] },
    { key: "USD_CPI", cur: "USD", main: "Mid-month (~10th–15th), 16:30 EAT", rows: [
      ["Cleveland Fed Nowcast MoM [25%]", "Updated daily", "CLEV"],
      ["WTI Oil / Gas Monthly % Δ [18%]", "Daily, use ⚡ Auto-Fetch", null],
      ["ISM Services Prices Paid [15%]", "3rd business day, 18:00", "ISM"],
      ["ISM Manufacturing Prices Paid [12%]", "1st business day, 18:00", "ISM"],
      ["Core PPI MoM Surprise [10%]", "PPI day (around CPI), 16:30", "FF"],
      ["Manheim Used Cars % Δ [8%]", "Monthly, early and mid-month", "FF"],
      ["Market Rent Index MoM [7%]", "Monthly, first week", null],
      ["NFIB Small Biz Price Plans [5%]", "2nd Tuesday of the month, 14:00", "NFIB"]
    ] },
    { key: "USD_PPI", cur: "USD", main: "Around CPI week, 16:30 EAT", rows: [
      ["ISM Services Prices Paid [22%]", "3rd business day, 18:00", "ISM"],
      ["ISM Manufacturing Prices Paid [18%]", "1st business day, 18:00", "ISM"],
      ["WTI Oil / Gas Monthly % Δ [18%]", "Daily, use ⚡ Auto-Fetch", null],
      ["Regional Fed Prices Paid, Empire / Philly [14%]", "Empire ~15th, Philly 3rd Thursday, 16:30", "FF"],
      ["Freight Rate % Δ [8%]", "Weekly", null],
      ["Agri & Metals % Δ [8%]", "Daily market data", null],
      ["NFIB Small Biz Price Plans [7%]", "2nd Tuesday of the month, 14:00", "NFIB"],
      ["Import Price Surprise [5%]", "Around CPI week, 16:30", "FF"]
    ] },
    { key: "USD_FOMC", cur: "USD", main: "Decision 22:00 EAT, Chair presser 22:30 EAT", rows: [
      ["US 2-Year Yield 5-day change [40%]", "Live market data", null],
      ["Recent Core CPI Surprise [35%]", "CPI day, 16:30", "FF"],
      ["Recent NFP Edge [25%]", "First Friday, 16:30", "FF"],
      ["FedWatch probability of expected move (priced-in check)", "Live, check before the statement", "CME"]
    ] },
    { key: "GBP_CPI", cur: "GBP", main: "Wednesday, 10:00 EAT (ONS)", rows: [
      ["UK Services PMI Prices Charged [30%]", "Flash ~3rd/4th week 12:30; final 3rd business day 12:30", "PMI"],
      ["BRC Shop Price Index [25%]", "First Tuesday of the month, 03:01", "BRC"],
      ["UK Input PPI MoM [20%]", "ONS PPI release, around CPI day", "ONS"],
      ["Kantar Grocery Inflation [10%]", "Every ~4 weeks, Tuesday morning", null],
      ["UK Gas / Petrol % Δ [8%]", "Daily, use ⚡ Auto-Fetch", null],
      ["REC Starting Salaries [7%]", "~8th–10th of the month, 03:01", "REC"],
      ["Ofgem cap reset (April / October) checkbox", "Check the Ofgem date", "ONS"]
    ] },
    { key: "GBP_JOBS", cur: "GBP", main: "Tuesday, 10:00 EAT (ONS Labour Market)", rows: [
      ["BoE DMP Wage Expectations [20%]", "Early month (around the first Thursday)", "FF"],
      ["REC Permanent Placements [25%]", "~8th–10th of the month, 03:01", "REC"],
      ["UK PMI Employment [20%]", "Flash ~3rd/4th week 12:30; final 3rd business day 12:30", "PMI"],
      ["REC Starting Salaries [15%]", "~8th–10th of the month, 03:01", "REC"],
      ["HMRC PAYE Payrolls Change [12%]", "Released with ONS Labour Market, Tuesday 10:00", "ONS"],
      ["Adzuna Job Ads % Δ [8%]", "Monthly, first week", null]
    ] },
    { key: "EUR_CPI", cur: "EUR", main: "Eurostat flash, around month-end, 13:00 EAT", rows: [
      ["Germany HICP: NRW, Bavaria, Baden-Württemberg, Hesse [27.8%]", "Morning of the Eurostat flash (state offices, then Destatis)", "FF"],
      ["France HICP flash [20.3%]", "Same morning, about 10:45", "FF"],
      ["Italy HICP flash [16.8%]", "Same morning, check the calendar for the time", "FF"],
      ["Spain HICP flash [11.1%]", "Same morning, about 11:00", "FF"],
      ["Netherlands HICP [5.7%], optional", "Same morning if published, else leave blank", "FF"],
      ["Belgium HICP [3.8%], optional", "Same morning if published, else leave blank", "FF"],
      ["HCOB Flash Services Output Prices, this and previous month (lead ±0.05%)", "Flash PMI ~3rd/4th week 12:00", "PMI"],
      ["TTF Gas / Brent monthly % Δ (lead ±0.05%)", "Daily, use ⚡ Auto-Fetch", null]
    ] },
    { key: "EUR_PMI", cur: "EUR", main: "HCOB Flash, 12:00 EAT (Germany 11:30, France 11:15)", rows: [
      ["German Flash PMI [40%]", "Flash day ~3rd/4th week, 11:30", "PMI"],
      ["French Flash PMI [25%]", "Flash day, 11:15", "PMI"],
      ["ZEW Economic Sentiment / Sentix change [20%]", "ZEW 2nd/3rd Tuesday 13:00; Sentix first Monday 12:30", "FF"],
      ["Eurozone New Orders Sub-Index [15%]", "With the full HCOB release, 12:00", "PMI"]
    ] }
  ];

  function sheetFilter(cur) {
    document.querySelectorAll(".sheet-chip").forEach(c => c.classList.toggle("active", c.dataset.cur === cur));
    document.querySelectorAll(".sh-row").forEach(r => r.classList.toggle("hidden", cur !== "ALL" && r.dataset.cur !== cur));
  }

  function sheetHtml() {
    const link = k => k ? `<a href="${SHEET_LINKS[k][1]}" target="_blank" rel="noopener noreferrer" style="color:var(--gold-bright);">${esc(SHEET_LINKS[k][0])} ↗</a>` : `<span style="color:var(--muted);">—</span>`;
    const body = SHEET.map(s => {
      const head = `<tr class="sh-row" data-cur="${s.cur}"><td colspan="3" style="background:#04140f; color:var(--gold-bright); font-weight:800;">${FLAG[s.cur]} ${s.key} <span style="color:var(--muted); font-weight:600;">— ${esc(s.main)}</span></td></tr>`;
      const rows = s.rows.map(r => `<tr class="sh-row" data-cur="${s.cur}"><td>${esc(r[0])}</td><td>${esc(r[1])}</td><td>${link(r[2])}</td></tr>`).join("");
      return head + rows;
    }).join("");
    const chips = ["ALL", "USD", "GBP", "EUR"].map(c =>
      `<button class="cur-chip sheet-chip${c === "ALL" ? " active" : ""}" data-cur="${c}" onclick="sheetFilter('${c}')">${FILTER_LABEL[c]}</button>`).join("");
    return `<details class="card desk-only" id="sheetCard" style="border-color: var(--gold);">
      <summary style="cursor:pointer; font-weight:800; color:var(--gold-bright);">📅 Master Red-Folder Release &amp; Data-Entry Schedule (EAT)</summary>
      <div class="cur-filter" style="margin-top:0.9rem;">${chips}</div>
      <div style="overflow-x:auto;"><table>
        <thead><tr><th>Proxy Input [weight]</th><th>Release (EAT)</th><th>Link</th></tr></thead>
        <tbody>${body}</tbody>
      </table></div>
      <p style="font-size:0.78rem; color:var(--muted); margin-top:0.75rem;">Typical timings, shown on winter clocks (US EST, UK GMT, EU CET). Subtract 1 hour while that region is on daylight time. Always confirm exact dates on Forex Factory.</p>
    </details>`;
  }


  // ==========================================================================
  // EUR CPI Post-Release Decoder v2 (admin form + client plan card) and the admin ledger / calibration panel
  // ==========================================================================
  const UNVERIFIED_BADGE = "⚠️ Unverified Edge — Log live trades to validate thresholds before scaling size.";
  const PAIR_LIST = ["EUR/USD", "EUR/GBP", "EUR/JPY"];
  const PAIR_CODE = { "EUR/USD": "EURUSD", "EUR/GBP": "EURGBP", "EUR/JPY": "EURJPY" };
  const fmtS = v => (v === null || v === undefined) ? "n/a" : ((v >= 0 ? "+" : "") + Number(v).toFixed(2));

  function cpiDecoderV2Html() {
    const chk = (id, label) => `<div class="check-row"><input type="checkbox" id="cd2_${id}" /><label for="cd2_${id}" style="margin:0; color:var(--text); cursor:pointer;">${label}</label></div>`;
    const num = (id, label, val, step) => `<div><label>${label}</label><input type="number" id="cd2_${id}" value="${val}" step="${step}" /></div>`;
    return `<div class="form-grid">
        <div><label>Pre-Release Proxy v3 Signal (auto-filled from the calculator above)</label>
          <select id="cd2_proxy"><option value="STRONG BUY EUR">STRONG BUY EUR</option><option value="STRONG SELL EUR">STRONG SELL EUR</option><option value="DO NOT TRADE" selected>DO NOT TRADE</option></select></div>
        ${num("balance", "Account Balance ($) — for your lot sizes only, never shown to clients", 10000, 100)}
        ${num("hf", "Headline Forecast (%)", 2.1, 0.1)}${num("ha", "Headline Actual (%)", 2.2, 0.1)}
        ${num("cf", "Core Forecast (%)", 2.3, 0.1)}${num("ca", "Core Actual (%)", 2.5, 0.1)}
        <div><label>Services HICP Benchmark Type</label>
          <select id="cd2_sbasis"><option value="FORECAST">Actual vs Forecast</option><option value="PRIOR">Actual vs Prior</option><option value="NONE">Not available (ignore services)</option></select></div>
        ${num("sb", "Services Benchmark (%)", 3.9, 0.1)}${num("sa", "Services Actual (%)", 4.1, 0.1)}
        ${num("spike", "EUR/USD 1-min check: 11:01 close minus 10:59 close (pips)", 0, 0.1)}
        ${chk("reclaim", "11:01 candle has reclaimed (or broken back through) the 10:59 CET price")}
        ${chk("uk", "UK High-Impact News Today (skips EUR/GBP)")}
        ${chk("risk", "Risk-Off Equity Drop (DAX below -0.5%) (skips EUR/JPY buys)")}
      </div>
      <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="runCpiDecode()">Decode Actual Print &amp; Get Trade Plan (Decoder v2)</button>
      <div id="cd2_out" class="hidden"></div>`;
  }

  function gatherCpiInputs() {
    const v = id => Number(document.getElementById("cd2_" + id).value);
    return {
      proxy_signal: document.getElementById("cd2_proxy").value,
      account_balance: v("balance"),
      headline_forecast: v("hf"), headline_actual: v("ha"),
      core_forecast: v("cf"), core_actual: v("ca"),
      services_basis: document.getElementById("cd2_sbasis").value,
      services_benchmark: v("sb"), services_actual: v("sa"),
      spike_1m_pips: v("spike"),
      reclaimed: document.getElementById("cd2_reclaim").checked,
      uk_news: document.getElementById("cd2_uk").checked,
      risk_off: document.getElementById("cd2_risk").checked
    };
  }

  function cpiPlanHtml(d, admin, eid) {
    const cls = d.direction === "BUY" ? "bull" : d.direction === "SELL" ? "bear" : "neut";
    const surp = `Surprises: Headline ${fmtS(d.h_surp)}% | Core ${fmtS(d.c_surp)}% | Services ${fmtS(d.s_surp)}%`;
    const tradable = PAIR_LIST.filter(p => d.pairs && d.pairs[p] && d.pairs[p].status === "TRADE");
    const calc = (!admin && tradable.length) ? `<div style="margin:0.7rem 0;"><label>Your account balance ($) — lot sizes at ${esc(d.risk_pct)}% risk (calculated on your device, never stored)</label>
        <input type="number" id="cc_bal_${eid}" placeholder="e.g. 5000" oninput="clientLots('${eid}')" /></div>` : "";
    const rows = PAIR_LIST.filter(p => d.pairs && d.pairs[p]).map(p => {
      const pl = d.pairs[p];
      const lot = admin ? (pl.lot !== undefined ? `<div style="color:var(--gold-bright); font-weight:700; margin-top:0.25rem;">Your lot size at ${esc(d.risk_pct)}% risk: ${Number(pl.lot).toFixed(2)}</div>` : "")
        : (pl.status === "TRADE" ? `<div class="cpi-lot" id="lot_${eid}_${PAIR_CODE[p]}" data-stop="${pl.stop}" data-pip="${pl.pip_value}" style="color:var(--gold-bright); font-weight:700; margin-top:0.25rem;"></div>` : "");
      return `<div style="border-top:1px solid var(--border); padding:0.6rem 0;"><span class="pill ${pl.status === "TRADE" ? "up" : "done"}">${pl.status}</span> <span style="font-size:0.88rem;">${esc(pl.text)}</span>${lot}</div>`;
    }).join("");
    return `<div data-risk="${esc(d.risk_pct)}" id="cpiplan_${eid}">
      <div class="verdict-box" style="margin-top:0.9rem;">
        <span class="big-score ${cls}">${esc(d.label)}</span>
        <p style="font-size:0.88rem; color:#d1d5db; margin-top:0.5rem;">${esc(d.summary)}</p>
        ${d.close_note ? `<p style="font-size:0.88rem; color:var(--red); font-weight:700; margin-top:0.4rem;">${esc(d.close_note)}</p>` : ""}
        <p style="font-size:0.78rem; color:var(--muted); margin-top:0.4rem;">${esc(surp)}${admin ? esc(` | ECB score: ${fmtS(d.ecb_score)} (min ${d.min_threshold})`) : ""}</p>
      </div>
      ${calc}${rows}
      <p style="font-size:0.75rem; color:var(--muted); margin-top:0.6rem;">${UNVERIFIED_BADGE}</p>
    </div>`;
  }

  function clientLots(eid) {
    const bal = Number(document.getElementById("cc_bal_" + eid).value);
    const risk = Number(document.getElementById("cpiplan_" + eid).dataset.risk);
    document.querySelectorAll("#cpiplan_" + eid + " .cpi-lot").forEach(el => {
      if (!(bal > 0)) { el.innerText = ""; return; }
      const lot = Math.floor(((bal * risk / 100) / (Number(el.dataset.stop) * Number(el.dataset.pip))) * 100) / 100;
      el.innerText = `Lot size at ${risk}% risk: ${lot.toFixed(2)}`;
    });
  }

  let cpiOutcome = null;
  async function runCpiDecode() {
    if (!(currentUser && currentUser.is_admin)) return;
    const out = document.getElementById("cd2_out");
    out.classList.remove("hidden");
    out.innerHTML = `<p style="color:var(--muted); margin-top:0.8rem;">Decoding...</p>`;
    const { ok, data } = await apiPost("/api/admin/cpi-decode", gatherCpiInputs());
    if (!ok) { out.innerHTML = `<p style="color:var(--red); margin-top:0.8rem;">${esc(errText(data))}</p>`; return; }
    cpiOutcome = null;
    out.innerHTML = cpiPlanHtml(data, true, "admin") + cpiLogBarHtml(data);
  }

  // ---- admin-only quick-log bar (only ever built inside the admin decoder) ----
  function cpiLogBarHtml(d) {
    if (!(currentUser && currentUser.is_admin)) return "";
    const btn = (o, label) => `<button class="btn-outline cpi-out-btn" data-out="${o}" onclick="pickCpiOutcome('${o}')">${label}</button>`;
    return `<div class="desk-only" id="cd2_log" style="margin-top:1rem; padding:0.8rem; border:1px dashed var(--gold); border-radius:8px;">
      <label style="color:var(--gold-bright);">📒 Admin Quick-Log (saved to the ledger)</label>
      <div class="form-grid" style="margin-bottom:0.6rem;">
        <div><label>Pair</label><select id="cd2_lpair">${PAIR_LIST.map(p => `<option>${p}</option>`).join("")}</select></div>
        <div><label>Actual Net Pips (e.g. +21.6 or -12.0; leave blank to use the planned result)</label><input type="number" id="cd2_lpips" step="0.1" /></div>
      </div>
      <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.6rem;">
        ${btn("WIN", "✅ WIN (+1.8R)")}${btn("LOSS", "❌ LOSS (-1.0R)")}${btn("TIME_EXIT", "⏱️ TIME EXIT (Flat/Partial)")}${btn("SKIPPED", "⏭️ SKIPPED")}
      </div>
      <button class="btn" style="width:100%;" onclick="saveCpiLog()">💾 Save to Database</button>
      <p id="cd2_logmsg" style="font-size:0.8rem; margin-top:0.4rem; color:var(--gold);"></p>
    </div>`;
  }

  function pickCpiOutcome(o) {
    cpiOutcome = o;
    document.querySelectorAll(".cpi-out-btn").forEach(b => { b.style.borderColor = b.dataset.out === o ? "var(--gold-bright)" : ""; b.style.color = b.dataset.out === o ? "var(--gold-bright)" : ""; });
  }

  async function saveCpiLog() {
    if (!(currentUser && currentUser.is_admin)) return;
    const msg = document.getElementById("cd2_logmsg");
    if (!cpiOutcome) { msg.innerText = "Pick an outcome first."; return; }
    const pipsRaw = document.getElementById("cd2_lpips").value;
    const rel = document.getElementById("rel_EUR_CPI") ? document.getElementById("rel_EUR_CPI").value : "";
    const body = { pair: document.getElementById("cd2_lpair").value, outcome: cpiOutcome, inputs: gatherCpiInputs() };
    if (String(pipsRaw).trim() !== "") body.net_pips = Number(pipsRaw);
    if (rel && !isNaN(new Date(rel).getTime())) body.release_utc = new Date(rel).toISOString().slice(0, 19) + "Z";
    const { ok, data } = await apiPost("/api/admin/cpi-ledger/log", body);
    msg.innerText = ok ? `✅ Saved ${body.pair}: ${data.outcome}${data.r_multiple !== null ? " (" + data.r_multiple + "R)" : ""}` : "Could not save: " + errText(data);
    if (ok) loadCalibration();
  }

  async function publishCpiDecode() {
    const status = document.getElementById("pubst_EUR_CPI");
    if (!confirm("Send the Decoder v2 result to clients and add this release to the ledger?")) return;
    const { ok, data } = await apiPost("/api/admin/publish-cpi-decode", { event_id: "EUR_CPI", inputs: gatherCpiInputs() });
    status.innerText = ok ? `✅ Sent to clients: ${data.label}. Release added to the ledgers.` : "Could not send: " + errText(data);
    if (ok) { loadCalibration(); loadRelLedger(); }
  }

  // ---- admin calibration & reality-check dashboard ----
  function calibrationHtml() {
    const cfgIn = (id, label, step) => `<div><label>${label}</label><input type="number" id="cfg_${id}" step="${step}" /></div>`;
    return `<details class="card desk-only" id="calCard" style="border-color: var(--gold);" ontoggle="if (this.open) loadCalibration()">
      <summary style="cursor:pointer; font-weight:800; color:var(--gold-bright);">📊 CPI Decoder Empirical Validation (Admin Only)</summary>
      <div style="overflow-x:auto; margin-top:0.9rem;"><table>
        <thead><tr><th>Signal Type</th><th>Sample (N)</th><th>Win Rate</th><th>Net Pips</th><th>Avg R</th></tr></thead>
        <tbody id="calStats"><tr><td colspan="5" style="color:var(--muted);">Loading...</td></tr></tbody>
      </table></div>
      <div id="calWarn"></div>
      <p id="calTotals" style="font-size:0.8rem; color:var(--muted); margin:0.6rem 0;"></p>
      <h2 style="margin-top:1rem;"><span>🎚️ Live Threshold Sandbox</span></h2>
      <div class="form-grid">
        ${cfgIn("deadzoneThreshold", "Deadzone Threshold", 0.01)}${cfgIn("standardThreshold", "Standard Threshold", 0.01)}${cfgIn("coldEntryThreshold", "Cold-Entry Threshold", 0.01)}
        ${cfgIn("w_services", "Weight: Services", 0.05)}${cfgIn("w_core", "Weight: Core", 0.05)}${cfgIn("w_headline", "Weight: Headline", 0.05)}
        ${cfgIn("pip_EURUSD", "Pip value per lot: EUR/USD ($)", 0.1)}${cfgIn("pip_EURGBP", "Pip value per lot: EUR/GBP ($)", 0.1)}${cfgIn("pip_EURJPY", "Pip value per lot: EUR/JPY ($)", 0.1)}
      </div>
      <p style="font-size:0.78rem; color:var(--muted); margin-top:0.5rem;">Weights must add up to 1.00. Saved values apply to every future decode and are stamped on each ledger row. Pip values only hold near current exchange rates.</p>
      <div style="display:flex; gap:0.6rem; flex-wrap:wrap; margin-top:0.6rem;">
        <button class="btn" onclick="saveCpiConfig()">💾 Save Calibration</button>
        <a class="btn-outline" href="/api/admin/cpi-ledger.csv" style="text-decoration:none; display:inline-block; padding:0.55rem 1rem; border-radius:6px;">⬇️ Export CSV</a>
        <button class="btn-outline" onclick="loadCalibration()">🔄 Refresh</button>
      </div>
      <p id="cfgMsg" style="font-size:0.8rem; margin-top:0.4rem; color:var(--gold);"></p>
      <h2 style="margin-top:1rem;"><span>📒 Release Ledger (every decoded release)</span></h2>
      <div style="overflow-x:auto;"><table>
        <thead><tr><th>Date</th><th>Pair</th><th>Signal</th><th>Outcome</th><th>Net Pips</th><th>R</th><th>Update</th></tr></thead>
        <tbody id="calLedger"></tbody>
      </table></div>
    </details>`;
  }

  async function loadCalibration() {
    const statsBody = document.getElementById("calStats");
    if (!statsBody) return;
    try {
      const [lres, cres] = await Promise.all([fetch("/api/admin/cpi-ledger", { cache: "no-store" }), fetch("/api/admin/cpi-config", { cache: "no-store" })]);
      if (!lres.ok || !cres.ok) throw new Error("bad response");
      const led = await lres.json();
      const cfg = (await cres.json()).config;
      const bc = led.stats.by_class;
      statsBody.innerHTML = ["CLEAN BEAT", "CLEAN MISS", "CONFIRMED TRAP"].map(k => {
        const r = bc[k];
        return `<tr style="${r.warning ? "background:#3b0d0d;" : ""}"><td><strong>${k}</strong></td><td>${r.n}</td><td>${r.win_rate === null ? "—" : r.win_rate + "%"}</td><td>${r.net_pips}</td><td>${r.avg_r === null ? "—" : r.avg_r}</td></tr>`;
      }).join("");
      document.getElementById("calWarn").innerHTML = bc["CONFIRMED TRAP"].warning
        ? `<p style="color:#fff; background:#7f1d1d; border:1px solid var(--red); border-radius:6px; padding:0.6rem; margin-top:0.6rem; font-weight:700;">⚠️ Trap assumption failing — consider switching divergence rule to STAND ASIDE.</p>` : "";
      const st = led.stats;
      document.getElementById("calTotals").innerText = `Releases decoded: ${st.releases} | Awaiting your outcome: ${st.pending} | Skipped: ${st.skipped} | No signal: ${st.no_signal} | Rows stored: ${led.total_rows}`;
      document.getElementById("cfg_deadzoneThreshold").value = cfg.deadzoneThreshold;
      document.getElementById("cfg_standardThreshold").value = cfg.standardThreshold;
      document.getElementById("cfg_coldEntryThreshold").value = cfg.coldEntryThreshold;
      document.getElementById("cfg_w_services").value = cfg.weights.services;
      document.getElementById("cfg_w_core").value = cfg.weights.core;
      document.getElementById("cfg_w_headline").value = cfg.weights.headline;
      Object.keys(cfg.pairs).forEach(c => { document.getElementById("cfg_pip_" + c).value = cfg.pairs[c].pipValuePerLot; });
      document.getElementById("calLedger").innerHTML = led.rows.length ? led.rows.map(r => {
        const rid = r.release_date + "_" + PAIR_CODE[r.pair];
        const sel = ["WIN", "LOSS", "TIME_EXIT", "SKIPPED"].map(o => `<option value="${o}"${r.outcome === o ? " selected" : ""}>${o}</option>`).join("");
        const editable = r.classification !== "STAND ASIDE";
        return `<tr><td>${esc(r.release_date)}</td><td>${esc(r.pair)}</td><td>${esc(r.classification)}</td><td><span class="pill ${r.outcome === "PENDING" ? "up" : "done"}">${esc(r.outcome)}</span></td>
          <td>${r.net_pips === null ? "—" : r.net_pips}</td><td>${r.r_multiple === null ? "—" : r.r_multiple}</td>
          <td>${editable ? `<select id="lr_o_${rid}">${sel}</select> <input type="number" id="lr_p_${rid}" step="0.1" placeholder="pips" style="width:5rem;" /> <button class="btn-outline" onclick="logRow('${r.release_date}', '${PAIR_CODE[r.pair]}')">Save</button>` : "—"}</td></tr>`;
      }).join("") : `<tr><td colspan="7" style="color:var(--muted);">No releases decoded yet. Press "Send Decoded Result to Clients" on the EUR CPI tab and each release is added here automatically.</td></tr>`;
    } catch (e) {
      statsBody.innerHTML = `<tr><td colspan="5" style="color:var(--red);">Could not load the ledger. Tap Refresh to try again.</td></tr>`;
    }
  }

  async function logRow(date, code) {
    const pair = Object.keys(PAIR_CODE).find(p => PAIR_CODE[p] === code);
    const rid = date + "_" + code;
    const body = { pair: pair, outcome: document.getElementById("lr_o_" + rid).value, release_date: date };
    const pips = document.getElementById("lr_p_" + rid).value;
    if (String(pips).trim() !== "") body.net_pips = Number(pips);
    const { ok, data } = await apiPost("/api/admin/cpi-ledger/log", body);
    if (!ok) { alert(errText(data)); return; }
    loadCalibration();
  }

  async function saveCpiConfig() {
    const v = id => Number(document.getElementById("cfg_" + id).value);
    const cfg = {
      deadzoneThreshold: v("deadzoneThreshold"), standardThreshold: v("standardThreshold"), coldEntryThreshold: v("coldEntryThreshold"),
      weights: { services: v("w_services"), core: v("w_core"), headline: v("w_headline") },
      pairs: { EURUSD: { pipValuePerLot: v("pip_EURUSD") }, EURGBP: { pipValuePerLot: v("pip_EURGBP") }, EURJPY: { pipValuePerLot: v("pip_EURJPY") } }
    };
    const { ok, data } = await apiPost("/api/admin/cpi-config", { config: cfg });
    document.getElementById("cfgMsg").innerText = ok ? "✅ Saved. Future decodes use these values." : "Could not save: " + errText(data);
  }


  // ---- admin Release Ledger: hit / miss / trap for every release ----
  let relRows = [];
  let relStats = {};
  let relFilter = "ALL";
  const REL_PILL = { HIT: "hit", MISS: "miss", TRAP: "trap", INLINE: "done", "NO CALL": "done", PENDING: "up" };

  function relLedgerHtml() {
    const chips = ["ALL", "USD", "GBP", "EUR"].map(c =>
      `<button class="cur-chip rel-chip${c === "ALL" ? " active" : ""}" data-cur="${c}" onclick="relSetFilter('${c}')">${FILTER_LABEL[c]}</button>`).join("");
    return `<details class="card desk-only" id="relCard" style="border-color: var(--gold);" ontoggle="if (this.open) loadRelLedger()">
      <summary style="cursor:pointer; font-weight:800; color:var(--gold-bright);">📒 Release Ledger — Hit / Miss / Trap for Every News Release (Admin Only)</summary>
      <p style="font-size:0.8rem; color:var(--muted); margin:0.7rem 0;">A release is added when you publish its projection and completed when you send its decoder result. HIT = projection matched the print. MISS = print went the other way. TRAP = the decoder flagged a divergence trap. INLINE = print was flat. NO CALL = no directional projection.</p>
      <div class="cur-filter">${chips}</div>
      <div style="overflow-x:auto;"><table>
        <thead><tr><th>Release</th><th>Releases</th><th>Hit</th><th>Miss</th><th>Trap</th><th>Inline</th><th>No Call</th><th>Pending</th><th>Hit Rate</th></tr></thead>
        <tbody id="relStats"><tr><td colspan="9" style="color:var(--muted);">Loading...</td></tr></tbody>
      </table></div>
      <div style="display:flex; gap:0.6rem; flex-wrap:wrap; margin:0.8rem 0;">
        <a class="btn-outline" href="/api/admin/release-ledger.csv" style="text-decoration:none; display:inline-block; padding:0.55rem 1rem; border-radius:6px;">⬇️ Export CSV</a>
        <button class="btn-outline" onclick="loadRelLedger()">🔄 Refresh</button>
      </div>
      <div style="overflow-x:auto;"><table>
        <thead><tr><th>Date</th><th>Release</th><th>Our Call</th><th>Decoder Verdict</th><th>Result</th><th>Correct it</th></tr></thead>
        <tbody id="relRows"></tbody>
      </table></div>
    </details>`;
  }

  function relSetFilter(cur) {
    relFilter = cur;
    document.querySelectorAll(".rel-chip").forEach(c => c.classList.toggle("active", c.dataset.cur === cur));
    relRender();
  }

  function relRender() {
    const stBody = document.getElementById("relStats");
    if (!stBody) return;
    const keys = Object.keys(relStats).filter(k => k !== "ALL" && (relFilter === "ALL" || k.indexOf(relFilter + "_") === 0)).sort();
    const line = (name, b) => `<tr><td><strong>${esc(name)}</strong></td><td>${b.releases}</td><td>${b.HIT}</td><td>${b.MISS}</td><td>${b.TRAP}</td><td>${b.INLINE}</td><td>${b["NO CALL"]}</td><td>${b.PENDING}</td><td>${b.hit_rate === null ? "—" : b.hit_rate + "%"}</td></tr>`;
    const total = { releases: 0, HIT: 0, MISS: 0, TRAP: 0, INLINE: 0, "NO CALL": 0, PENDING: 0, hit_rate: null };
    keys.forEach(k => { ["releases", "HIT", "MISS", "TRAP", "INLINE", "NO CALL", "PENDING"].forEach(f => { total[f] += relStats[k][f]; }); });
    total.hit_rate = (total.HIT + total.MISS) ? Math.round(total.HIT / (total.HIT + total.MISS) * 1000) / 10 : null;
    stBody.innerHTML = keys.length ? keys.map(k => line(FLAG[k.slice(0, 3)] + " " + k.replace("_", " "), relStats[k])).join("") + line("Total", total)
      : `<tr><td colspan="9" style="color:var(--muted);">No releases logged yet. Publish a projection and each release appears here automatically.</td></tr>`;
    const rows = relRows.map((r, i) => ({ r: r, i: i })).filter(x => relFilter === "ALL" || x.r.currency === relFilter);
    document.getElementById("relRows").innerHTML = rows.length ? rows.map(x => {
      const r = x.r;
      const sel = ["HIT", "MISS", "TRAP", "INLINE", "NO CALL"].map(o => `<option value="${o}"${r.result === o ? " selected" : ""}>${o}</option>`).join("");
      return `<tr><td>${esc(r.release_date)}</td><td><strong>${esc(FLAG[r.currency] || "")} ${esc(r.currency)} ${esc(r.module)}</strong></td>
        <td>${esc(r.projection_label || "—")}</td><td style="font-size:0.8rem;">${esc(r.decoder_verdict || "Awaiting decode")}</td>
        <td><span class="pill ${REL_PILL[r.result] || "done"}">${esc(r.result)}</span>${r.manual ? " ✎" : ""}</td>
        <td><select id="rl_o_${x.i}">${sel}</select> <button class="btn-outline" onclick="relOverride(${x.i})">Save</button></td></tr>`;
    }).join("") : `<tr><td colspan="6" style="color:var(--muted);">Nothing to show for this filter.</td></tr>`;
  }

  async function loadRelLedger() {
    if (!document.getElementById("relStats")) return;
    try {
      const res = await fetch("/api/admin/release-ledger", { cache: "no-store" });
      if (!res.ok) throw new Error("bad response");
      const data = await res.json();
      relRows = data.rows; relStats = data.stats;
      relRender();
    } catch (e) {
      document.getElementById("relStats").innerHTML = `<tr><td colspan="9" style="color:var(--red);">Could not load the ledger. Tap Refresh to try again.</td></tr>`;
    }
  }

  async function relOverride(i) {
    const r = relRows[i];
    const { ok, data } = await apiPost("/api/admin/release-ledger/override", { id: r.id, result: document.getElementById("rl_o_" + i).value });
    if (!ok) { alert(errText(data)); return; }
    loadRelLedger();
  }

  // ---- one-time admin setup: new tabs, desk views, schedule panels, queue manager ----
  let v2Ready = false;
  function setupV2Desk() {
    if (v2Ready) return;
    v2Ready = true;
    const tabsBox = document.getElementById("tabsBox");
    ["GBP_CPI", "GBP_JOBS", "EUR_CPI", "EUR_PMI"].forEach(k => {
      tabsBox.insertAdjacentHTML("beforeend", `<button class="tab" id="tab${tabIdFor(k)}" onclick="switchTab('${k}')">${MODS[k].tabLabel}</button>`);
      document.getElementById("newViews").insertAdjacentHTML("beforeend", buildDeskView(k));
    });
    TAB_ORDER.forEach(k => {
      const host = document.getElementById(MODS[k].prefix + "DeskCard");
      if (host) host.insertAdjacentHTML("afterend", schedulePanelHtml(k));
    });
    document.getElementById("queueCard").insertAdjacentHTML("beforebegin", sheetHtml());
    document.getElementById("queueCard").insertAdjacentHTML("beforebegin", relLedgerHtml());
    document.getElementById("queueCard").insertAdjacentHTML("beforebegin", calibrationHtml());
    document.getElementById("curFilter").innerHTML = ["ALL", "USD", "GBP", "EUR"].map(c =>
      `<button class="cur-chip${c === "ALL" ? " active" : ""}" data-cur="${c}" onclick="setCurFilter('${c}')">${FILTER_LABEL[c]}</button>`).join("");
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
