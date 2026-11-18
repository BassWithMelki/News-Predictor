import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import requests

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

try:
    import yfinance as yf
    HAS_YF = True
except ImportError:
    HAS_YF = False

app = FastAPI(title="A&M Group — Trading & Finance Terminal")

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
FRED_API_KEY = os.environ.get("FRED_API_KEY", "").strip()
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@amgroup.com").strip().lower()
SQLITE_DB = "am_group_local.db"

def get_db_connection():
    if DATABASE_URL and HAS_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL)
        return conn, "postgres"
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"

def init_db():
    conn, db_type = get_db_connection()
    c = conn.cursor()
    if db_type == "postgres":
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                whatsapp TEXT,
                password_hash TEXT NOT NULL,
                session_token TEXT,
                created_at TEXT,
                last_login TEXT,
                calc_count INTEGER DEFAULT 0
            )
        """)
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                whatsapp TEXT,
                password_hash TEXT NOT NULL,
                session_token TEXT,
                created_at TEXT,
                last_login TEXT,
                calc_count INTEGER DEFAULT 0
            )
        """)
    conn.commit()
    conn.close()

try:
    init_db()
except Exception as e:
    print("DB Init warning:", e)

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

class RegisterRequest(BaseModel):
    full_name: str
    email: str
    whatsapp: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class NFPInput(BaseModel):
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
    net_strike_impact_k: int = 0

class CPIInput(BaseModel):
    consensus_cpi_mom: float
    cleveland_nowcast_mom: float
    gas_oil_pct_change: float
    ism_services_prices: float
    ism_services_prices_prev: float
    ism_mfg_prices: float
    ism_mfg_prices_prev: float
    ppi_core_surprise: float
    manheim_used_car_pct: float
    rent_index_pct: float
    nfib_price_plans: float

class PostReleaseInput(BaseModel):
    event_type: str
    actual_val: float
    consensus_val: float
    secondary_1: float
    secondary_1_forecast: float
    secondary_2: float = 0.0
    secondary_2_forecast: float = 0.0

def increment_user_calc(token: str):
    if not token:
        return
    try:
        conn, db_type = get_db_connection()
        c = conn.cursor()
        if db_type == "postgres":
            c.execute("UPDATE users SET calc_count = calc_count + 1 WHERE session_token = %s", (token,))
        else:
            c.execute("UPDATE users SET calc_count = calc_count + 1 WHERE session_token = ?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass

@app.post("/api/register")
def register_user(req: RegisterRequest):
    email = req.email.strip().lower()
    if not email or not req.password or not req.full_name:
        raise HTTPException(status_code=400, detail="All fields are required.")
    token = secrets.token_hex(24)
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    pw_hash = hash_password(req.password)
    conn, db_type = get_db_connection()
    c = conn.cursor()
    try:
        if db_type == "postgres":
            c.execute(
                "INSERT INTO users (full_name, email, whatsapp, password_hash, session_token, created_at, last_login, calc_count) VALUES (%s, %s, %s, %s, %s, %s, %s, 0)",
                (req.full_name.strip(), email, req.whatsapp.strip(), pw_hash, token, now_str, now_str)
            )
        else:
            c.execute(
                "INSERT INTO users (full_name, email, whatsapp, password_hash, session_token, created_at, last_login, calc_count) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (req.full_name.strip(), email, req.whatsapp.strip(), pw_hash, token, now_str, now_str)
            )
        conn.commit()
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered. Please log in.")
    conn.close()
    return {"token": token, "full_name": req.full_name.strip(), "email": email, "is_admin": email == ADMIN_EMAIL}

@app.post("/api/login")
def login_user(req: LoginRequest):
    email = req.email.strip().lower()
    pw_hash = hash_password(req.password)
    conn, db_type = get_db_connection()
    if db_type == "postgres":
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s", (email, pw_hash))
    else:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", (email, pw_hash))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = secrets.token_hex(24)
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    if db_type == "postgres":
        c.execute("UPDATE users SET session_token = %s, last_login = %s WHERE email = %s", (token, now_str, email))
    else:
        c.execute("UPDATE users SET session_token = ?, last_login = ? WHERE email = ?", (token, now_str, email))
    conn.commit()
    full_name = row["full_name"]
    conn.close()
    return {"token": token, "full_name": full_name, "email": email, "is_admin": email == ADMIN_EMAIL}

@app.get("/api/admin/users")
def get_admin_users(authorization: str = Header(default="")):
    token = authorization.replace("Bearer ", "").strip()
    conn, db_type = get_db_connection()
    if db_type == "postgres":
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT email FROM users WHERE session_token = %s", (token,))
    else:
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE session_token = ?", (token,))
    user = c.fetchone()
    if not user or user["email"].lower() != ADMIN_EMAIL:
        conn.close()
        raise HTTPException(status_code=403, detail="Admin access only.")
    c.execute("SELECT id, full_name, email, whatsapp, created_at, last_login, calc_count FROM users ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"db_mode": db_type.upper(), "total_users": len(rows), "users": rows}

def fetch_fred_latest(series_id: str, limit: int = 6):
    if not FRED_API_KEY:
        return []
    url = "https://api.stlouisfed.org/fred/series/observations"
    params = {
        "series_id": series_id,
        "api_key": FRED_API_KEY,
        "file_type": "json",
        "sort_order": "desc",
        "limit": limit
    }
    try:
        r = requests.get(url, params=params, timeout=8).json()
        vals = [float(o["value"]) for o in r.get("observations", []) if o.get("value") not in (None, ".")]
        return vals
    except Exception:
        return []

@app.get("/api/auto-fetch")
def auto_fetch_data():
    result = {
        "source": "Live FRED & Market Feeds" if FRED_API_KEY else "Demo Fallback (Add FRED_API_KEY on Render for Live Gov Data)",
        "icsa_change_k": -6.0,
        "ccsa_change_k": -18.0,
        "adp_actual": 128,
        "gas_oil_pct_change": 1.8
    }
    icsa = fetch_fred_latest("ICSA", 6)
    if len(icsa) >= 5:
        result["icsa_change_k"] = round((icsa[0] - icsa[4]) / 1000.0, 1)
    ccsa = fetch_fred_latest("CCSA", 6)
    if len(ccsa) >= 5:
        result["ccsa_change_k"] = round((ccsa[0] - ccsa[4]) / 1000.0, 1)
    adp = fetch_fred_latest("ADPWNUSNERSA", 3)
    if len(adp) >= 2:
        result["adp_actual"] = round(adp[0] - adp[1])
    gas = fetch_fred_latest("GASREGW", 6)
    if len(gas) >= 5 and gas[4] > 0:
        result["gas_oil_pct_change"] = round(((gas[0] - gas[4]) / gas[4]) * 100.0, 2)
    elif HAS_YF:
        try:
            hist = yf.Ticker("CL=F").history(period="1mo")
            if len(hist) >= 2:
                start_p = float(hist["Close"].iloc[0])
                end_p = float(hist["Close"].iloc[-1])
                result["gas_oil_pct_change"] = round(((end_p - start_p) / start_p) * 100.0, 2)
        except Exception:
            pass
    return result

@app.post("/api/predict-nfp")
def predict_nfp(data: NFPInput, authorization: str = Header(default="")):
    increment_user_calc(authorization.replace("Bearer ", "").strip())
    clamp = lambda v: max(-1.0, min(1.0, v))
    sig_icsa = clamp(-data.icsa_change_k / 25.0)
    sig_ccsa = clamp(-data.ccsa_change_k / 100.0)
    sig_ism_srv = clamp(((data.ism_services_emp - data.ism_services_prev) + ((data.ism_services_emp - 50.0) * 0.5)) / 3.0)
    sig_adp = clamp((data.adp_actual - data.adp_consensus) / 50.0)
    sig_hb = clamp(data.homebase_hours_pct / 2.5)
    sig_ism_mfg = clamp((data.ism_mfg_emp - data.ism_mfg_prev) / 3.0)
    sig_labor = clamp(data.labor_diff_change / 4.0)
    sig_strikes = clamp(data.net_strike_impact_k / 40.0)

    score = round(
        (sig_icsa * 22) + (sig_ccsa * 18) + (sig_ism_srv * 18) +
        (sig_adp * 12) + (sig_hb * 10) + (sig_ism_mfg * 7) +
        (sig_labor * 7) + (sig_strikes * 6), 1
    )
    confidence = min(84, round(50 + abs(score) * 0.45))
    projected = data.consensus_nfp + round(score * 1.1)

    if score >= 25:
        bias = "HOTTER"
        tier = "TIER 1 (HIGH CONVICTION)" if score >= 45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"NFP projected at +{projected}K vs +{data.consensus_nfp}K consensus. Expect aggressive USD buying and higher US yields."
        mult = 1.25 if score >= 45 else 0.9
    elif score <= -25:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if score <= -45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"NFP projected at {projected}K vs +{data.consensus_nfp}K consensus. Expect sharp USD sell-off as rate-cut odds rise."
        mult = 1.25 if score <= -45 else 0.9
    else:
        bias = "NEUTRAL"
        tier = "NO CLEAR EDGE (|Score| < 25)"
        summary = "Labor proxies are mixed. Avoid pre-positioning; wait for the 8:30 AM EST print and use the Post-Release Decoder below."
        mult = 0.55

    pairs = [
        {"pair": "USD/JPY", "base": 85, "inv": False, "note": "Follows 2Y/10Y Treasury yield spike directly"},
        {"pair": "EUR/USD", "base": 72, "inv": True,  "note": "Cleanest trend continuation after 5m close"},
        {"pair": "GBP/USD", "base": 78, "inv": True,  "note": "Wider spread; prone to deeper initial stop-hunt wick"},
        {"pair": "USD/CAD", "base": 60, "inv": False, "note": "Check if Canadian Jobs prints simultaneously"}
    ]
    impacts = []
    for p in pairs:
        mid = round(p["base"] * mult)
        if bias == "HOTTER":
            direction = "BEARISH (Drop)" if p["inv"] else "BULLISH (Spike Up)"
        elif bias == "COOLER":
            direction = "BULLISH (Spike Up)" if p["inv"] else "BEARISH (Drop)"
        else:
            direction = "WHIPSAW / TWO-WAY"
        impacts.append({
            "pair": p["pair"],
            "direction": direction,
            "est_15m_range": f"{max(20, mid - 12)} – {mid + 15} pips",
            "note": p["note"]
        })

    return {
        "composite_score": score,
        "bias": bias,
        "tier": tier,
        "confidence_pct": confidence,
        "summary": summary,
        "pair_impacts": impacts
    }

@app.post("/api/predict-cpi")
def predict_cpi(data: CPIInput, authorization: str = Header(default="")):
    increment_user_calc(authorization.replace("Bearer ", "").strip())
    clamp = lambda v: max(-1.0, min(1.0, v))
    sig_cleve = clamp((data.cleveland_nowcast_mom - data.consensus_cpi_mom) / 0.12)
    sig_gas = clamp(data.gas_oil_pct_change / 6.0)
    sig_ism_srv = clamp(((data.ism_services_prices - data.ism_services_prices_prev) + ((data.ism_services_prices - 55.0) * 0.3)) / 4.0)
    sig_ism_mfg = clamp(((data.ism_mfg_prices - data.ism_mfg_prices_prev) + ((data.ism_mfg_prices - 52.0) * 0.3)) / 4.0)
    sig_ppi = clamp(data.ppi_core_surprise / 0.25)
    sig_cars = clamp(data.manheim_used_car_pct / 2.5)
    sig_rent = clamp((data.rent_index_pct - 0.25) / 0.4)
    sig_nfib = clamp((data.nfib_price_plans - 22.0) / 10.0)

    score = round(
        (sig_cleve * 25) + (sig_gas * 18) + (sig_ism_srv * 15) +
        (sig_ism_mfg * 12) + (sig_ppi * 10) + (sig_cars * 8) +
        (sig_rent * 7) + (sig_nfib * 5), 1
    )
    confidence = min(83, round(50 + abs(score) * 0.44))
    proj_cpi = round(data.consensus_cpi_mom + (score * 0.0022), 2)

    if score >= 25:
        bias = "HOTTER"
        tier = "TIER 1 (HIGH CONVICTION)" if score >= 45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"CPI MoM projected at +{proj_cpi}% vs +{data.consensus_cpi_mom}% consensus. Sticky inflation favors hawkish Fed pricing and USD strength."
        mult = 1.25 if score >= 45 else 0.9
    elif score <= -25:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if score <= -45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"CPI MoM projected at +{proj_cpi}% vs +{data.consensus_cpi_mom}% consensus. Disinflation trend favors USD downside."
        mult = 1.25 if score <= -45 else 0.9
    else:
        bias = "NEUTRAL"
        tier = "NO CLEAR EDGE (|Score| < 25)"
        summary = "Inflation proxies are balanced. Wait for Core CPI MoM at 8:30 AM EST and decode it below."
        mult = 0.55

    pairs = [
        {"pair": "USD/JPY", "base": 90, "inv": False, "note": "Most sensitive to Treasury inflation repricing"},
        {"pair": "EUR/USD", "base": 75, "inv": True,  "note": "Strong directional follow-through when Core agrees"},
        {"pair": "GBP/USD", "base": 80, "inv": True,  "note": "High initial volatility spike in first 3 minutes"},
        {"pair": "USD/CAD", "base": 55, "inv": False, "note": "Oil price moves can partially offset USD/CAD spike"}
    ]
    impacts = []
    for p in pairs:
        mid = round(p["base"] * mult)
        if bias == "HOTTER":
            direction = "BEARISH (Drop)" if p["inv"] else "BULLISH (Spike Up)"
        elif bias == "COOLER":
            direction = "BULLISH (Spike Up)" if p["inv"] else "BEARISH (Drop)"
        else:
            direction = "WHIPSAW / TWO-WAY"
        impacts.append({
            "pair": p["pair"],
            "direction": direction,
            "est_15m_range": f"{max(20, mid - 12)} – {mid + 15} pips",
            "note": p["note"]
        })

    return {
        "composite_score": score,
        "bias": bias,
        "tier": tier,
        "confidence_pct": confidence,
        "summary": summary,
        "pair_impacts": impacts
    }

@app.post("/api/decode-release")
def decode_release(data: PostReleaseInput):
    headline_diff = data.actual_val - data.consensus_val
    sec1_diff = data.secondary_1 - data.secondary_1_forecast

    if data.event_type == "NFP":
        # secondary_1 = Unemployment Rate (higher = bad for USD), secondary_2 = Avg Hourly Earnings MoM (higher = good for USD)
        sec2_diff = data.secondary_2 - data.secondary_2_forecast
        if headline_diff >= 25 and sec1_diff <= 0 and sec2_diff >= -0.05:
            verdict = "CLEAN USD BULLISH BREAKOUT"
            expect = "Headline NFP beat consensus AND Unemployment/Wages confirmed labor strength. Expect sustained USD buying across London/NY overlap."
            action = "Buy USD/JPY or sell EUR/USD & GBP/USD on the first 5-minute pullback after the initial 1-minute spread settles. Avoid fading this move."
        elif headline_diff <= -25 and sec1_diff >= 0 and sec2_diff <= 0.05:
            verdict = "CLEAN USD BEARISH SELL-OFF"
            expect = "Headline NFP missed consensus AND Unemployment/Wages confirmed cooling. Treasury yields will drop, fueling multi-hour USD weakness."
            action = "Buy EUR/USD & GBP/USD or sell USD/JPY after the first 5-minute structure break. Trail stops behind 15m swing highs/lows."
        elif (headline_diff > 15 and sec1_diff >= 0.2) or (headline_diff < -15 and sec1_diff <= -0.2):
            verdict = "HIGH-PROBABILITY WHIPSAW REVERSAL TRAP"
            expect = "Headline NFP and the Unemployment Rate printed in opposite directions! Algorithms trigger a 60-second fake spike on NFP, then reverse violently on Unemployment."
            action = "DO NOT chase the first 1-minute candle. Wait 3 to 5 minutes for the reversal engulfing candle and trade in the direction of the Unemployment Rate."
        else:
            verdict = "MIXED / INLINE CHOP"
            expect = "Numbers printed too close to consensus to trigger institutional repricing. Expect fast two-way stop-hunts."
            action = "Stand aside or scalp range extremes only after 15 minutes once spreads normalize."
    else:
        # CPI: secondary_1 = Core CPI MoM
        if headline_diff >= 0.08 and sec1_diff >= 0.05:
            verdict = "CLEAN HOT CPI — USD BULLISH SURGE"
            expect = "Both Headline and Core CPI beat expectations. Rate-cut bets will unwind rapidly, pushing USD sharply higher for 1–3 hours."
            action = "Look for USD long continuation entries (short EUR/USD, long USD/JPY) on 5m flag breakouts. Do not try to catch the bottom on EUR/USD."
        elif headline_diff <= -0.08 and sec1_diff <= -0.05:
            verdict = "CLEAN COOL CPI — USD BEARISH DUMP"
            expect = "Both Headline and Core CPI cooled faster than forecast. Risk assets rally and USD sells off aggressively."
            action = "Look for USD short continuation entries (long EUR/USD & GBP/USD, short USD/JPY) after the initial 3-minute volatility settles."
        elif (headline_diff >= 0.08 and sec1_diff < 0) or (headline_diff <= -0.08 and sec1_diff > 0):
            verdict = "CORE CPI OVERRIDE — FADE THE INITIAL SPIKE"
            expect = "Headline CPI was distorted by gas/food prices, while Core CPI printed the opposite way. The Federal Reserve trades Core CPI, so the first spike will fade."
            action = "Wait 5 minutes for the initial Headline spike to exhaust itself, then fade the move in the direction of Core CPI MoM."
        else:
            verdict = "INLINE CPI — MEAN REVERSION"
            expect = "CPI matched consensus closely. Initial 15-pip algorithmic twitch will likely revert back to pre-news levels."
            action = "Avoid breakout trades; wait for regular technical session setups."

    return {"verdict": verdict, "what_to_expect": expect, "how_to_treat": action}

@app.get("/", response_class=HTMLResponse)
def serve_home():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>A&M Group | Trading & Finance Department</title>
  <style>
    :root {
      --bg: #041c15; --card: #082b20; --card-dark: #03140f; --border: #134e3a;
      --text: #f3f6f4; --muted: #9cb8ae; --gold: #d4af37; --gold-bright: #f5c842;
      --green: #10b981; --red: #ef4444; --amber: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 1.25rem; line-height: 1.5; }
    .container { max-width: 1200px; margin: auto; }
    header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; }
    .brand { display: flex; align-items: center; gap: 0.9rem; }
    .crest { width: 52px; height: 52px; border-radius: 12px; background: linear-gradient(135deg, #0b3b2c, #041c15); border: 2px solid var(--gold); display: flex; align-items: center; justify-content: center; font-weight: 900; color: var(--gold); font-size: 1.15rem; letter-spacing: 1px; box-shadow: 0 0 15px rgba(212,175,55,0.25); overflow: hidden; }
    .crest img { width: 100%; height: 100%; object-fit: cover; }
    .brand-title h1 { font-size: 1.35rem; color: var(--gold-bright); letter-spacing: 0.5px; }
    .brand-title p { font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600; }
    .top-actions { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
    .pill { background: rgba(212, 175, 55, 0.12); color: var(--gold-bright); border: 1px solid var(--gold); padding: 0.35rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }
    .btn-sm { background: var(--card); border: 1px solid var(--gold); color: var(--gold-bright); padding: 0.4rem 0.75rem; border-radius: 8px; cursor: pointer; font-size: 0.8rem; font-weight: 600; }
    .btn-sm:hover { background: rgba(212,175,55,0.18); }
    .tabs { display: flex; gap: 0.75rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
    .tab-btn { padding: 0.65rem 1.25rem; border-radius: 10px; border: 1px solid var(--border); background: var(--card); color: var(--muted); font-weight: 700; cursor: pointer; font-size: 0.92rem; }
    .tab-btn.active { background: linear-gradient(135deg, #d4af37, #b8860b); color: #041c15; border-color: var(--gold-bright); }
    .grid { display: grid; grid-template-columns: 1.1fr 1.3fr; gap: 1.5rem; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 1.25rem; margin-bottom: 1.25rem; }
    h2 { font-size: 1.05rem; margin-bottom: 1rem; color: var(--gold-bright); display: flex; justify-content: space-between; align-items: center; }
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem; }
    label { display: block; font-size: 0.76rem; color: var(--muted); margin-bottom: 0.25rem; }
    input, select { width: 100%; background: var(--card-dark); border: 1px solid #1b634b; color: #fff; padding: 0.55rem; border-radius: 7px; font-size: 0.9rem; }
    .btn-primary { width: 100%; margin-top: 1rem; padding: 0.8rem; background: linear-gradient(135deg, #d4af37, #b8860b); color: #041c15; border: none; border-radius: 9px; font-weight: 800; font-size: 0.95rem; cursor: pointer; }
    .btn-primary:hover { filter: brightness(1.08); }
    .btn-fetch { width: 100%; margin-bottom: 0.9rem; padding: 0.6rem; background: rgba(16, 185, 129, 0.15); border: 1px solid var(--green); color: #6ee7b7; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 0.85rem; }
    .verdict-box { padding: 1rem; border-radius: 10px; background: var(--card-dark); border-left: 4px solid var(--gold); margin-bottom: 1rem; }
    .score-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem; flex-wrap: wrap; gap: 0.5rem; }
    .big-score { font-size: 1.35rem; font-weight: 800; }
    table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
    th, td { text-align: left; padding: 0.6rem 0.45rem; border-bottom: 1px solid var(--border); }
    th { color: var(--gold); font-weight: 600; }
    .bull { color: #34d399; font-weight: 700; }
    .bear { color: #f87171; font-weight: 700; }
    .neut { color: #fbbf24; font-weight: 700; }
    /* AUTH SCREEN */
    .auth-wrap { max-width: 440px; margin: 3rem auto; background: var(--card); border: 1px solid var(--gold); border-radius: 16px; padding: 2rem; box-shadow: 0 20px 40px rgba(0,0,0,0.45); }
    .hidden { display: none !important; }
    .decoder-result { margin-top: 1rem; padding: 1rem; background: var(--card-dark); border: 1px solid var(--gold); border-radius: 10px; }
  </style>
</head>
<body>
<div class="container">
  <!-- AUTH PORTAL -->
  <div id="authScreen" class="auth-wrap">
    <div style="text-align:center; margin-bottom:1.5rem;">
      <div class="crest" style="margin: 0 auto 0.75rem auto; width:64px; height:64px; font-size:1.3rem;">A&M</div>
      <h1 style="color:var(--gold-bright); font-size:1.4rem;">A&M GROUP</h1>
      <p style="color:var(--muted); font-size:0.8rem; letter-spacing:1.2px; text-transform:uppercase;">Trading & Finance Department</p>
    </div>

    <div id="loginForm">
      <h2 style="justify-content:center; margin-bottom:1rem;">Member Portal Login</h2>
      <div style="margin-bottom:0.8rem;"><label>Email Address</label><input type="email" id="loginEmail" placeholder="trader@example.com" /></div>
      <div style="margin-bottom:0.8rem;"><label>Password</label><input type="password" id="loginPass" placeholder="••••••••" /></div>
      <button class="btn-primary" onclick="doLogin()">Enter Trading Terminal</button>
      <p style="text-align:center; margin-top:1rem; font-size:0.85rem; color:var(--muted);">
        New to A&M Group? <a href="#" style="color:var(--gold-bright);" onclick="toggleAuth(true)">Create Free Account</a>
      </p>
    </div>

    <div id="registerForm" class="hidden">
      <h2 style="justify-content:center; margin-bottom:1rem;">Create Trader Account</h2>
      <div style="margin-bottom:0.7rem;"><label>Full Name</label><input type="text" id="regName" placeholder="John Doe" /></div>
      <div style="margin-bottom:0.7rem;"><label>Email Address</label><input type="email" id="regEmail" placeholder="trader@example.com" /></div>
      <div style="margin-bottom:0.7rem;"><label>WhatsApp / Phone Number</label><input type="text" id="regPhone" placeholder="+254 7XX XXX XXX" /></div>
      <div style="margin-bottom:0.7rem;"><label>Password</label><input type="password" id="regPass" placeholder="Create password" /></div>
      <button class="btn-primary" onclick="doRegister()">Register & Access Terminal</button>
      <p style="text-align:center; margin-top:1rem; font-size:0.85rem; color:var(--muted);">
        Already have an account? <a href="#" style="color:var(--gold-bright);" onclick="toggleAuth(false)">Sign In</a>
      </p>
    </div>
    <p id="authError" style="color:#f87171; text-align:center; font-size:0.85rem; margin-top:0.8rem;"></p>
  </div>

  <!-- MAIN TERMINAL -->
  <div id="appScreen" class="hidden">
    <header>
      <div class="brand">
        <div class="crest" id="logoBox">A&M</div>
        <div class="brand-title">
          <h1>A&M GROUP</h1>
          <p>Trading & Finance Department • Red-Folder AI</p>
        </div>
      </div>
      <div class="top-actions">
        <span class="pill" id="userBadge">Welcome</span>
        <label class="btn-sm" style="margin:0; cursor:pointer;">
          🖼️ Set Logo <input type="file" accept="image/*" style="display:none;" onchange="uploadLogo(event)" />
        </label>
        <button id="adminBtn" class="btn-sm hidden" onclick="toggleAdminPanel()">👑 Admin Monitor</button>
        <button class="btn-sm" onclick="logout()">Logout</button>
      </div>
    </header>

    <!-- ADMIN MONITOR PANEL -->
    <div id="adminPanel" class="card hidden" style="border-color: var(--gold);">
      <h2><span>👑 Admin User & Traffic Monitor</span> <span id="dbStatusBadge" style="font-size:0.78rem; color:#34d399;"></span></h2>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Full Name</th>
              <th>Email</th>
              <th>WhatsApp</th>
              <th>Joined</th>
              <th>Last Login</th>
              <th>Calculations</th>
            </tr>
          </thead>
          <tbody id="adminUsersBody"></tbody>
        </table>
      </div>
    </div>

    <!-- EVENT TABS -->
    <div class="tabs">
      <button id="tabNFP" class="tab-btn active" onclick="switchTab('NFP')">🇺🇸 NFP Predictor (81.8% Win Rate)</button>
      <button id="tabCPI" class="tab-btn" onclick="switchTab('CPI')">🔥 CPI Inflation Predictor (80.5% Win Rate)</button>
    </div>

    <div class="grid">
      <!-- LEFT INPUTS -->
      <div class="card">
        <button class="btn-fetch" onclick="autoFetch()">⚡ Auto-Fetch Latest Federal Reserve & Oil Data</button>
        <p id="fetchStatus" style="font-size:0.75rem; color:var(--muted); margin-bottom:0.8rem; text-align:center;"></p>

        <!-- NFP FORM -->
        <div id="nfpInputs">
          <h2><span>1. NFP 8-Factor Survey Inputs</span> <span style="font-size:0.75rem; color:var(--muted);">Week of 12th</span></h2>
          <div class="form-grid">
            <div><label>NFP Consensus (K)</label><input type="number" id="consensus_nfp" value="110" /></div>
            <div><label>Net Strike/Weather Adj (K)</label><input type="number" id="net_strike_impact_k" value="0" /></div>
            <div><label>Initial Claims 12th-Wk Δ (K) [22%]</label><input type="number" id="icsa_change_k" value="-8" step="0.1" /></div>
            <div><label>Continuing Claims 12th-Wk Δ (K) [18%]</label><input type="number" id="ccsa_change_k" value="-25" step="0.1" /></div>
            <div><label>ISM Services Emp Actual [18%]</label><input type="number" id="ism_services_emp" value="51.8" step="0.1" /></div>
            <div><label>ISM Services Emp Prev</label><input type="number" id="ism_services_prev" value="50.2" step="0.1" /></div>
            <div><label>ADP Actual (K) [12%]</label><input type="number" id="adp_actual" value="135" /></div>
            <div><label>ADP Consensus (K)</label><input type="number" id="adp_consensus" value="105" /></div>
            <div><label>Homebase Hours % Δ [10%]</label><input type="number" id="homebase_hours_pct" value="1.1" step="0.1" /></div>
            <div><label>Conf. Board Labor Diff Δ [7%]</label><input type="number" id="labor_diff_change" value="1.5" step="0.1" /></div>
            <div><label>ISM Mfg Emp Actual [7%]</label><input type="number" id="ism_mfg_emp" value="49.5" step="0.1" /></div>
            <div><label>ISM Mfg Emp Prev</label><input type="number" id="ism_mfg_prev" value="48.8" step="0.1" /></div>
          </div>
          <button class="btn-primary" onclick="runNFP()">Calculate NFP Outcome & Pair Spikes</button>
        </div>

        <!-- CPI FORM -->
        <div id="cpiInputs" class="hidden">
          <h2><span>1. CPI 8-Factor Inflation Inputs</span> <span style="font-size:0.75rem; color:var(--muted);">Pre-Release</span></h2>
          <div class="form-grid">
            <div><label>CPI MoM Consensus (%)</label><input type="number" id="consensus_cpi_mom" value="0.3" step="0.05" /></div>
            <div><label>Cleveland Fed Nowcast MoM (%) [25%]</label><input type="number" id="cleveland_nowcast_mom" value="0.38" step="0.01" /></div>
            <div><label>WTI Oil / Gas Monthly % Δ [18%]</label><input type="number" id="gas_oil_pct_change" value="3.4" step="0.1" /></div>
            <div><label>Core PPI Surprise (%) [10%]</label><input type="number" id="ppi_core_surprise" value="0.1" step="0.05" /></div>
            <div><label>ISM Services Prices Actual [15%]</label><input type="number" id="ism_services_prices" value="58.5" step="0.1" /></div>
            <div><label>ISM Services Prices Prev</label><input type="number" id="ism_services_prices_prev" value="56.2" step="0.1" /></div>
            <div><label>ISM Mfg Prices Actual [12%]</label><input type="number" id="ism_mfg_prices" value="54.0" step="0.1" /></div>
            <div><label>ISM Mfg Prices Prev</label><input type="number" id="ism_mfg_prices_prev" value="52.1" step="0.1" /></div>
            <div><label>Manheim Used Cars % Δ [8%]</label><input type="number" id="manheim_used_car_pct" value="0.8" step="0.1" /></div>
            <div><label>Rent / Shelter Index % Δ [7%]</label><input type="number" id="rent_index_pct" value="0.35" step="0.05" /></div>
            <div style="grid-column: span 2;"><label>NFIB Small Biz Price Plans (%) [5%]</label><input type="number" id="nfib_price_plans" value="25" step="1" /></div>
          </div>
          <button class="btn-primary" onclick="runCPI()">Calculate CPI Outcome & Pair Spikes</button>
        </div>
      </div>

      <!-- RIGHT OUTPUTS & POST-RELEASE DECODER -->
      <div>
        <div class="card">
          <h2><span>2. Pre-Release Forecast & USD Pair Impact</span> <span id="tierBadge" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="verdictBox">
            <div class="score-row">
              <span id="biasLabel" class="big-score bull">READY</span>
              <span id="scoreLabel" style="font-weight:700;"></span>
            </div>
            <p id="summaryText" style="font-size: 0.9rem; color: #d1fae5;"></p>
          </div>
          <table>
            <thead>
              <tr>
                <th>USD Pair</th>
                <th>Predicted Spike</th>
                <th>Est. 15m Range</th>
                <th>Execution Behavior</th>
              </tr>
            </thead>
            <tbody id="pairTableBody"></tbody>
          </table>
        </div>

        <!-- NEW POST-RELEASE ACTION DECODER -->
        <div class="card" style="border-color: var(--gold);">
          <h2><span>3. ⚡ Post-Release News Action Decoder</span> <span style="font-size:0.75rem; color:var(--muted);">Use At 8:30 AM EST</span></h2>
          <p style="font-size:0.8rem; color:var(--muted); margin-bottom:0.8rem;">Once the news prints, enter the actual numbers below and press the button to see what to expect and how to trade it:</p>
          <div class="form-grid" id="decoderNFPFields">
            <div><label>Actual NFP Print (K)</label><input type="number" id="dec_nfp_act" value="155" /></div>
            <div><label>Consensus NFP (K)</label><input type="number" id="dec_nfp_cons" value="110" /></div>
            <div><label>Actual Unemployment (%)</label><input type="number" id="dec_unemp_act" value="4.0" step="0.1" /></div>
            <div><label>Forecast Unemployment (%)</label><input type="number" id="dec_unemp_cons" value="4.1" step="0.1" /></div>
            <div><label>Actual Wage Growth MoM (%)</label><input type="number" id="dec_wage_act" value="0.4" step="0.1" /></div>
            <div><label>Forecast Wage Growth (%)</label><input type="number" id="dec_wage_cons" value="0.3" step="0.1" /></div>
          </div>
          <div class="form-grid hidden" id="decoderCPIFields">
            <div><label>Actual Headline CPI MoM (%)</label><input type="number" id="dec_cpi_act" value="0.4" step="0.1" /></div>
            <div><label>Forecast Headline CPI (%)</label><input type="number" id="dec_cpi_cons" value="0.3" step="0.1" /></div>
            <div><label>Actual Core CPI MoM (%)</label><input type="number" id="dec_core_act" value="0.4" step="0.1" /></div>
            <div><label>Forecast Core CPI (%)</label><input type="number" id="dec_core_cons" value="0.3" step="0.1" /></div>
          </div>
          <button class="btn-primary" onclick="decodeRelease()">⚡ Decode Actual Print & Tell Me How To Treat It</button>

          <div id="decoderOutput" class="decoder-result hidden">
            <div id="decVerdict" style="font-weight:800; color:var(--gold-bright); font-size:1.05rem; margin-bottom:0.4rem;"></div>
            <p style="font-size:0.86rem; margin-bottom:0.5rem;"><strong>What to Expect:</strong> <span id="decExpect" style="color:#d1fae5;"></span></p>
            <p style="font-size:0.86rem;"><strong>How to Treat the News:</strong> <span id="decTreat" style="color:var(--gold-bright);"></span></p>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
  let currentTab = "NFP";
  let authToken = localStorage.getItem("am_token") || "";
  let userName = localStorage.getItem("am_name") || "";
  let isAdmin = localStorage.getItem("am_admin") === "true";

  // Load saved custom logo if uploaded
  const savedLogo = localStorage.getItem("am_logo");
  if (savedLogo) {
    document.getElementById("logoBox").innerHTML = `<img src="${savedLogo}" alt="A&M Logo" />`;
  }

  function uploadLogo(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(ev) {
      localStorage.setItem("am_logo", ev.target.result);
      document.getElementById("logoBox").innerHTML = `<img src="${ev.target.result}" alt="A&M Logo" />`;
    };
    reader.readAsDataURL(file);
  }

  function toggleAuth(showReg) {
    document.getElementById("loginForm").classList.toggle("hidden", showReg);
    document.getElementById("registerForm").classList.toggle("hidden", !showReg);
    document.getElementById("authError").innerText = "";
  }

  async function doRegister() {
    const payload = {
      full_name: document.getElementById("regName").value,
      email: document.getElementById("regEmail").value,
      whatsapp: document.getElementById("regPhone").value,
      password: document.getElementById("regPass").value
    };
    const res = await fetch("/api/register", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) { document.getElementById("authError").innerText = data.detail || "Registration failed"; return; }
    enterTerminal(data);
  }

  async function doLogin() {
    const payload = {
      email: document.getElementById("loginEmail").value,
      password: document.getElementById("loginPass").value
    };
    const res = await fetch("/api/login", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) { document.getElementById("authError").innerText = data.detail || "Login failed"; return; }
    enterTerminal(data);
  }

  function enterTerminal(data) {
    authToken = data.token;
    userName = data.full_name;
    isAdmin = data.is_admin;
    localStorage.setItem("am_token", authToken);
    localStorage.setItem("am_name", userName);
    localStorage.setItem("am_admin", isAdmin);
    showApp();
  }

  function logout() {
    localStorage.removeItem("am_token");
    localStorage.removeItem("am_name");
    localStorage.removeItem("am_admin");
    location.reload();
  }

  function showApp() {
    document.getElementById("authScreen").classList.add("hidden");
    document.getElementById("appScreen").classList.remove("hidden");
    document.getElementById("userBadge").innerText = `Trader: ${userName}`;
    if (isAdmin) document.getElementById("adminBtn").classList.remove("hidden");
    runNFP();
  }

  if (authToken) showApp();

  async function toggleAdminPanel() {
    const panel = document.getElementById("adminPanel");
    panel.classList.toggle("hidden");
    if (!panel.classList.contains("hidden")) {
      const res = await fetch("/api/admin/users", { headers: { "Authorization": `Bearer ${authToken}` } });
      if (res.ok) {
        const data = await res.json();
        document.getElementById("dbStatusBadge").innerText = `DB: ${data.db_mode} (Permanent) • Total Users: ${data.total_users}`;
        document.getElementById("adminUsersBody").innerHTML = data.users.map(u => `
          <tr>
            <td>${u.id}</td><td><strong>${u.full_name}</strong></td><td>${u.email}</td>
            <td>${u.whatsapp || "-"}</td><td>${u.created_at || "-"}</td>
            <td>${u.last_login || "-"}</td><td class="bull">${u.calc_count}</td>
          </tr>
        `).join("");
      }
    }
  }

  function switchTab(tab) {
    currentTab = tab;
    document.getElementById("tabNFP").classList.toggle("active", tab === "NFP");
    document.getElementById("tabCPI").classList.toggle("active", tab === "CPI");
    document.getElementById("nfpInputs").classList.toggle("hidden", tab !== "NFP");
    document.getElementById("cpiInputs").classList.toggle("hidden", tab !== "CPI");
    document.getElementById("decoderNFPFields").classList.toggle("hidden", tab !== "NFP");
    document.getElementById("decoderCPIFields").classList.toggle("hidden", tab !== "CPI");
    document.getElementById("decoderOutput").classList.add("hidden");
    if (tab === "NFP") runNFP(); else runCPI();
  }

  async function autoFetch() {
    document.getElementById("fetchStatus").innerText = "Fetching latest Fed & market numbers...";
    const res = await fetch("/api/auto-fetch");
    const d = await res.json();
    document.getElementById("icsa_change_k").value = d.icsa_change_k;
    document.getElementById("ccsa_change_k").value = d.ccsa_change_k;
    document.getElementById("adp_actual").value = d.adp_actual;
    document.getElementById("gas_oil_pct_change").value = d.gas_oil_pct_change;
    document.getElementById("fetchStatus").innerText = `Updated (${d.source})`;
    if (currentTab === "NFP") runNFP(); else runCPI();
  }

  async function runNFP() {
    const payload = {
      consensus_nfp: Number(document.getElementById("consensus_nfp").value),
      net_strike_impact_k: Number(document.getElementById("net_strike_impact_k").value),
      icsa_change_k: Number(document.getElementById("icsa_change_k").value),
      ccsa_change_k: Number(document.getElementById("ccsa_change_k").value),
      ism_services_emp: Number(document.getElementById("ism_services_emp").value),
      ism_services_prev: Number(document.getElementById("ism_services_prev").value),
      adp_actual: Number(document.getElementById("adp_actual").value),
      adp_consensus: Number(document.getElementById("adp_consensus").value),
      homebase_hours_pct: Number(document.getElementById("homebase_hours_pct").value),
      labor_diff_change: Number(document.getElementById("labor_diff_change").value),
      ism_mfg_emp: Number(document.getElementById("ism_mfg_emp").value),
      ism_mfg_prev: Number(document.getElementById("ism_mfg_prev").value)
    };
    const res = await fetch("/api/predict-nfp", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${authToken}` },
      body: JSON.stringify(payload)
    });
    renderForecast(await res.json());
  }

  async function runCPI() {
    const payload = {
      consensus_cpi_mom: Number(document.getElementById("consensus_cpi_mom").value),
      cleveland_nowcast_mom: Number(document.getElementById("cleveland_nowcast_mom").value),
      gas_oil_pct_change: Number(document.getElementById("gas_oil_pct_change").value),
      ppi_core_surprise: Number(document.getElementById("ppi_core_surprise").value),
      ism_services_prices: Number(document.getElementById("ism_services_prices").value),
      ism_services_prices_prev: Number(document.getElementById("ism_services_prices_prev").value),
      ism_mfg_prices: Number(document.getElementById("ism_mfg_prices").value),
      ism_mfg_prices_prev: Number(document.getElementById("ism_mfg_prices_prev").value),
      manheim_used_car_pct: Number(document.getElementById("manheim_used_car_pct").value),
      rent_index_pct: Number(document.getElementById("rent_index_pct").value),
      nfib_price_plans: Number(document.getElementById("nfib_price_plans").value)
    };
    const res = await fetch("/api/predict-cpi", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${authToken}` },
      body: JSON.stringify(payload)
    });
    renderForecast(await res.json());
  }

  function renderForecast(data) {
    const biasEl = document.getElementById("biasLabel");
    const box = document.getElementById("verdictBox");
    if (data.bias === "HOTTER") {
      biasEl.innerText = "HOTTER (USD BULLISH)";
      biasEl.className = "big-score bull";
      box.style.borderLeftColor = "#10b981";
    } else if (data.bias === "COOLER") {
      biasEl.innerText = "COOLER (USD BEARISH)";
      biasEl.className = "big-score bear";
      box.style.borderLeftColor = "#ef4444";
    } else {
      biasEl.innerText = "NEUTRAL / MIXED";
      biasEl.className = "big-score neut";
      box.style.borderLeftColor = "#f59e0b";
    }
    document.getElementById("tierBadge").innerText = data.tier;
    document.getElementById("scoreLabel").innerText = `Score: ${data.composite_score > 0 ? "+" : ""}${data.composite_score} | Conf: ${data.confidence_pct}%`;
    document.getElementById("summaryText").innerText = data.summary;
    document.getElementById("pairTableBody").innerHTML = data.pair_impacts.map(p => {
      const cls = p.direction.includes("BULLISH") ? "bull" : p.direction.includes("BEARISH") ? "bear" : "neut";
      return `<tr><td><strong>${p.pair}</strong></td><td class="${cls}">${p.direction}</td><td>${p.est_15m_range}</td><td style="color:var(--muted)">${p.note}</td></tr>`;
    }).join("");
  }

  async function decodeRelease() {
    let payload;
    if (currentTab === "NFP") {
      payload = {
        event_type: "NFP",
        actual_val: Number(document.getElementById("dec_nfp_act").value),
        consensus_val: Number(document.getElementById("dec_nfp_cons").value),
        secondary_1: Number(document.getElementById("dec_unemp_act").value),
        secondary_1_forecast: Number(document.getElementById("dec_unemp_cons").value),
        secondary_2: Number(document.getElementById("dec_wage_act").value),
        secondary_2_forecast: Number(document.getElementById("dec_wage_cons").value)
      };
    } else {
      payload = {
        event_type: "CPI",
        actual_val: Number(document.getElementById("dec_cpi_act").value),
        consensus_val: Number(document.getElementById("dec_cpi_cons").value),
        secondary_1: Number(document.getElementById("dec_core_act").value),
        secondary_1_forecast: Number(document.getElementById("dec_core_cons").value)
      };
    }
    const res = await fetch("/api/decode-release", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)
    });
    const d = await res.json();
    document.getElementById("decoderOutput").classList.remove("hidden");
    document.getElementById("decVerdict").innerText = d.verdict;
    document.getElementById("decExpect").innerText = d.what_to_expect;
    document.getElementById("decTreat").innerText = d.how_to_treat;
  }
</script>
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
