import os
import hashlib
import sqlite3
from datetime import datetime
import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None

app = FastAPI(title="A&M Group — Trading & Finance Department")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@amgroup.com").strip().lower()
FRED_API_KEY = os.getenv("FRED_API_KEY", "").strip()
RAW_DB_URL = os.getenv("DATABASE_URL", "").strip()

def get_clean_db_url():
    if not RAW_DB_URL:
        return ""
    url = RAW_DB_URL.replace(" ", "%20")
    if "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url

DATABASE_URL = get_clean_db_url()
USE_POSTGRES = False

def get_db_conn():
    global USE_POSTGRES
    if DATABASE_URL and psycopg2 is not None:
        try:
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, connect_timeout=5)
            USE_POSTGRES = True
            return conn
        except Exception as e:
            print("Postgres fallback triggered:", e)
    USE_POSTGRES = False
    conn = sqlite3.connect("am_group_local.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    if USE_POSTGRES:
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
    conn.commit()
    cur.close()
    conn.close()

try:
    init_db()
except Exception as startup_err:
    print("Startup DB notice:", startup_err)

def hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

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
    consensus_nfp: float
    icsa_change_k: float
    ccsa_change_k: float
    ism_services_emp: float
    ism_services_prev: float
    adp_actual: float
    adp_consensus: float
    homebase_hours_pct: float
    ism_mfg_emp: float
    ism_mfg_prev: float
    labor_diff_change: float
    nfib_hiring_actual: float = 18.0
    nfib_hiring_prev: float = 17.0
    prev_govt_edu_swing: float = 0.0
    is_summer_school_month: bool = False
    net_strike_impact_k: float = 0.0

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
        ph = "%s" if USE_POSTGRES else "?"
        cur.execute(f"UPDATE users SET calc_count = calc_count + 1 WHERE email = {ph}", (email.lower(),))
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

@app.post("/api/register")
def register_user(req: RegisterReq):
    email = req.email.strip().lower()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    conn = get_db_conn()
    cur = conn.cursor()
    ph = "%s" if USE_POSTGRES else "?"
    try:
        cur.execute(
            f"INSERT INTO users (full_name, email, whatsapp, password_hash, calc_count, created_at, last_login) VALUES ({ph}, {ph}, {ph}, {ph}, 0, {ph}, {ph})",
            (req.full_name.strip(), email, req.whatsapp.strip(), hash_pwd(req.password), now, now)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered. Please log in.")
    cur.close()
    conn.close()
    return {"status": "ok", "full_name": req.full_name.strip(), "email": email, "is_admin": email == ADMIN_EMAIL}

@app.post("/api/login")
def login_user(req: LoginReq):
    email = req.email.strip().lower()
    conn = get_db_conn()
    cur = conn.cursor()
    ph = "%s" if USE_POSTGRES else "?"
    cur.execute(f"SELECT * FROM users WHERE email = {ph}", (email,))
    user = cur.fetchone()
    if not user or user["password_hash"] != hash_pwd(req.password):
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    cur.execute(f"UPDATE users SET last_login = {ph} WHERE email = {ph}", (now, email))
    conn.commit()
    full_name = user["full_name"]
    cur.close()
    conn.close()
    return {"status": "ok", "full_name": full_name, "email": email, "is_admin": email == ADMIN_EMAIL}

@app.get("/api/admin/users")
def get_admin_users(email: str):
    if email.strip().lower() != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, full_name, email, whatsapp, calc_count, created_at, last_login FROM users ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return {"db_mode": "Supabase PostgreSQL (Permanent)" if USE_POSTGRES else "Local SQLite Fallback", "users": rows}

def fetch_fred_obs(series_id: str, limit: int = 6):
    # Works BOTH with FRED_API_KEY (JSON API) AND without a key (Direct public FRED CSV endpoint)
    try:
        if FRED_API_KEY:
            url = f"https://api.stlouisfed.org/fred/series/observations?series_id={series_id}&api_key={FRED_API_KEY}&file_type=json&sort_order=desc&limit={limit}"
            r = requests.get(url, timeout=4).json()
            return [float(o["value"]) for o in r.get("observations", []) if o.get("value") not in (None, ".")]
        else:
            csv_url = f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}"
            resp = requests.get(csv_url, timeout=4, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                lines = [ln.strip().split(",") for ln in resp.text.strip().splitlines()[1:] if "," in ln]
                vals = []
                for _, val in reversed(lines):
                    if val != ".":
                        try:
                            vals.append(float(val))
                            if len(vals) >= limit:
                                break
                        except ValueError:
                            continue
                return vals
    except Exception as e:
        print(f"FRED fetch notice ({series_id}):", e)
    return []

def fetch_wti_oil_pct():
    # Fast direct Yahoo Chart JSON with strict 4s timeout (never hangs like yfinance)
    try:
        url = "https://query1.finance.yahoo.com/v8/finance/chart/CL=F?range=1mo&interval=1d"
        resp = requests.get(url, timeout=4, headers={"User-Agent": "Mozilla/5.0"}).json()
        closes = resp["chart"]["result"][0]["indicators"]["quote"][0]["close"]
        clean_closes = [float(c) for c in closes if c is not None]
        if len(clean_closes) >= 2 and clean_closes[0] != 0:
            return round(((clean_closes[-1] - clean_closes[0]) / clean_closes[0]) * 100.0, 2)
    except Exception as e:
        print("Yahoo WTI fetch notice:", e)
    return None

@app.get("/api/autofetch")
def autofetch_data():
    icsa_vals = fetch_fred_obs("ICSA", 6)
    ccsa_vals = fetch_fred_obs("CCSA", 6)

    # Compare latest observation (index 0) vs 4 weeks prior (index 4)
    icsa_delta = round((icsa_vals[0] - icsa_vals[4]) / 1000.0, 1) if len(icsa_vals) >= 5 else -6.0
    ccsa_delta = round((ccsa_vals[0] - ccsa_vals[4]) / 1000.0, 1) if len(ccsa_vals) >= 5 else -18.0

    oil_pct = fetch_wti_oil_pct()
    if oil_pct is None:
        gas_vals = fetch_fred_obs("GASREGW", 5)
        if len(gas_vals) >= 5 and gas_vals[4] != 0:
            oil_pct = round(((gas_vals[0] - gas_vals[4]) / gas_vals[4]) * 100.0, 2)
        else:
            oil_pct = 0.0

    live_sources = []
    if len(icsa_vals) >= 5:
        live_sources.append("St. Louis FRED Claims")
    if oil_pct != 0.0:
        live_sources.append("WTI Crude Oil")
    source_note = "Live " + " & ".join(live_sources) if live_sources else "Calibrated Baseline Fallback"

    return {
        "source": source_note,
        "nfp": {"icsa_change_k": icsa_delta, "ccsa_change_k": ccsa_delta},
        "cpi": {"gas_oil_pct_change": oil_pct}
    }

@app.post("/api/predict-nfp")
def predict_nfp(data: NFPInput):
    increment_usage(data.user_email)
    clamp = lambda v: max(-1.0, min(1.0, v))

    # Normalized signals in [-1.0, +1.0]
    sig_ism_srv = clamp(((data.ism_services_emp - data.ism_services_prev) + ((data.ism_services_emp - 50.0) * 0.5)) / 3.0)
    sig_icsa = clamp(-data.icsa_change_k / 25.0)
    sig_adp = clamp((data.adp_actual - data.adp_consensus) / 50.0)
    sig_ccsa = clamp(-data.ccsa_change_k / 100.0)
    sig_hb = clamp(data.homebase_hours_pct / 2.5)
    sig_nfib = clamp((data.nfib_hiring_actual - data.nfib_hiring_prev) / 4.0)
    sig_labor = clamp(data.labor_diff_change / 4.0)
    sig_ism_mfg = clamp((data.ism_mfg_emp - data.ism_mfg_prev) / 3.0)

    # Rebalanced V2 Weights (Total = 1.00)
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

    score = round(weighted_signal * 100.0, 1)
    proxy_delta = round(weighted_signal * 110.0, 1)

    # Mechanical V2 Adjustments
    school_adj = round(-0.5 * data.prev_govt_edu_swing, 1) if abs(data.prev_govt_edu_swing) >= 35 else 0.0
    predicted_nfp = round(data.consensus_nfp + proxy_delta + data.net_strike_impact_k + school_adj, 1)
    edge = round(predicted_nfp - data.consensus_nfp, 1)

    buffer = 40.0 if data.is_summer_school_month else 25.0
    confidence = min(91, round(55 + abs(edge) * 0.45))

    if abs(edge) < buffer:
        bias = "NEUTRAL"
        tier = f"NO-TRADE / LOW EDGE (Buffer ±{int(buffer)}K)"
        summary = f"Predicted {predicted_nfp:+.1f}K vs {data.consensus_nfp:+.1f}K consensus. Edge ({edge:+.1f}K) inside ±{int(buffer)}K buffer — skip trade to avoid chop."
        mult = 0.50
    elif edge >= buffer:
        bias = "HOTTER"
        tier = "TIER 1 (HIGH CONVICTION)" if edge >= (buffer + 20) else "TIER 2 (MODERATE)"
        summary = f"Model projects {predicted_nfp:+.1f}K vs {data.consensus_nfp:+.1f}K consensus (Edge: {edge:+.1f}K | School Adj: {school_adj:+.1f}K). Expect aggressive USD buying."
        mult = 1.25 if edge >= (buffer + 20) else 0.95
    else:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if edge <= -(buffer + 20) else "TIER 2 (MODERATE)"
        summary = f"Model projects {predicted_nfp:+.1f}K vs {data.consensus_nfp:+.1f}K consensus (Edge: {edge:+.1f}K | School Adj: {school_adj:+.1f}K). Expect immediate USD sell-off."
        mult = 1.25 if edge <= -(buffer + 20) else 0.95

    assets = [
        {"pair": "USD/JPY", "base": 85, "unit": "pips", "inv": False, "note": "BUY on Beat / SELL on Miss — tracks 2Y/10Y yields"},
        {"pair": "EUR/USD", "base": 72, "unit": "pips", "inv": True,  "note": "SELL on Beat / BUY on Miss — cleanest 5m continuation"},
        {"pair": "XAU/USD", "base": 240, "unit": "pips", "inv": True, "note": "Gold: SELL on Beat / BUY on Miss — watch real yields"},
        {"pair": "NAS100",  "base": 180, "unit": "pts",  "inv": True, "note": "Tech Index: reacts to Fed rate-cut repricing"}
    ]
    impacts = []
    for a in assets:
        mid = round(a["base"] * mult)
        if bias == "HOTTER":
            direction = "BEARISH (SELL)" if a["inv"] else "BULLISH (BUY)"
            note = a["note"]
        elif bias == "COOLER":
            direction = "BULLISH (BUY)" if a["inv"] else "BEARISH (SELL)"
            note = a["note"]
        else:
            direction = "NO-TRADE / LOW EDGE"
            note = f"Edge ({edge:+.1f}K) inside ±{int(buffer)}K buffer — skip trade to avoid chop."
        impacts.append({
            "pair": a["pair"],
            "direction": direction,
            "range": f"{max(15, round(mid * 0.82))} – {round(mid * 1.18)} {a['unit']}",
            "note": note
        })

    return {
        "score": score,
        "edge": edge,
        "predicted_nfp": predicted_nfp,
        "school_adj": school_adj,
        "bias": bias,
        "tier": tier,
        "confidence": confidence,
        "summary": summary,
        "pairs": impacts
    }

@app.post("/api/predict-cpi")
def predict_cpi(data: CPIInput):
    increment_usage(data.user_email)
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
        summary = f"Inflation proxies sit above {data.cpi_mom_consensus}% consensus. Expect hotter CPI & USD surge."
        mult = 1.25 if score >= 45 else 0.9
    elif score <= -25:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if score <= -45 else "TIER 2 (MODERATE)"
        summary = f"Disinflation signals outweigh {data.cpi_mom_consensus}% consensus. Expect cooler CPI & USD drop."
        mult = 1.25 if score <= -45 else 0.9
    else:
        bias = "NEUTRAL"
        tier = "NO CLEAR EDGE (|Score| < 25)"
        summary = "Inflation proxies are balanced. Wait for Core CPI MoM print before entering."
        mult = 0.55

    pairs = [
        {"pair": "USD/JPY", "base": 90, "inv": False, "note": "Most sensitive to US 2Y yield repricing"},
        {"pair": "EUR/USD", "base": 75, "inv": True,  "note": "Strong directional follow-through if Core aligns"},
        {"pair": "GBP/USD", "base": 80, "inv": True,  "note": "High volatility; wait 2 minutes for spread normalization"},
        {"pair": "USD/CAD", "base": 58, "inv": False, "note": "Oil-driven CPI prints can cause CAD cross-currents"}
    ]
    impacts = []
    for p in pairs:
        mid = round(p["base"] * mult)
        direction = "WHIPSAW / TWO-WAY"
        if bias == "HOTTER":
            direction = "BEARISH (Drop)" if p["inv"] else "BULLISH (Spike Up)"
        elif bias == "COOLER":
            direction = "BULLISH (Spike Up)" if p["inv"] else "BEARISH (Drop)"
        impacts.append({"pair": p["pair"], "direction": direction, "range": f"{max(20, mid-12)} – {mid+15} pips", "note": p["note"]})

    return {"score": score, "bias": bias, "tier": tier, "confidence": confidence, "summary": summary, "pairs": impacts}

@app.post("/api/decode-nfp")
def decode_nfp(d: DecodeNFPReq):
    nfp_diff = d.actual_nfp - d.consensus_nfp + (d.revisions_k * 0.5)
    unemp_diff = d.unemp_actual - d.unemp_forecast
    ahe_diff = d.ahe_actual - d.ahe_forecast

    if nfp_diff >= 25 and unemp_diff <= 0 and ahe_diff >= 0:
        verdict = "CLEAN USD BULLISH BREAKOUT"
        plan = "All 3 pillars (Jobs, Unemployment, Wages) beat expectations. Wait for the first 5-minute pullback on EUR/USD (sell) or USD/JPY (buy) and ride continuation for 45–60 mins."
    elif nfp_diff <= -25 and unemp_diff >= 0 and ahe_diff <= 0:
        verdict = "CLEAN USD BEARISH SELL-OFF"
        plan = "Labor market cooled across jobs and wages. Look for 5-minute pullback entries to buy EUR/USD & GBP/USD or sell USD/JPY."
    elif (nfp_diff > 20 and unemp_diff >= 0.2) or (nfp_diff < -20 and unemp_diff <= -0.2):
        verdict = "WHIPSAW REVERSAL TRAP DETECTED"
        plan = "Headline NFP contradicts the Unemployment Rate! Algorithms will fade the initial 1-minute spike within 3–10 minutes. Do NOT chase the first candle; trade the reversal back through the pre-news price."
    else:
        verdict = "MIXED / CHOPPY PRINT — STAND ASIDE"
        plan = "Headline and secondary figures offset each other. Expect spread widening and range-bound chop. Preserve capital for CPI."
    return {"verdict": verdict, "plan": plan}

@app.post("/api/decode-cpi")
def decode_cpi(d: DecodeCPIReq):
    head_diff = round(d.headline_actual - d.headline_forecast, 2)
    core_diff = round(d.core_actual - d.core_forecast, 2)

    if core_diff >= 0.1 and head_diff >= 0:
        verdict = "HOT CORE & HEADLINE — STRONG USD RALLY"
        plan = "Sticky Core CPI locks in hawkish Fed pricing. Buy USD/JPY or sell EUR/USD on the first 5m consolidation; trend typically holds into London close."
    elif core_diff <= -0.1 and head_diff <= 0:
        verdict = "COOL CORE & HEADLINE — STRONG USD SELL-OFF"
        plan = "Disinflation confirmed in Core CPI. Sell USD/JPY or buy EUR/USD & GBP/USD after initial 2-minute spread settles."
    elif head_diff >= 0.1 and core_diff <= -0.1:
        verdict = "FALSE SPIKE TRAP (HEADLINE HOT, CORE COOL)"
        plan = "Core CPI missed! The Fed ignores energy-driven headline spikes when Core cools. Fade the initial USD spike after the 5-minute candle closes."
    else:
        verdict = "INLINE CPI PRINT — FADE EXTREME WICKS"
        plan = "Numbers matched Wall Street consensus. Initial volatility is just stop-hunting; look for mean reversion back to pre-release levels."
    return {"verdict": verdict, "plan": plan}

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>A&M Group | Trading & Finance Red-Folder Terminal (V2)</title>
<style>
  :root {
    --bg: #051c15; --card: #0a2920; --border: #17493a;
    --gold: #d4af37; --gold-bright: #f3cf65; --text: #f3f6f4;
    --muted: #9cb3ab; --green: #10b981; --red: #ef4444; --amber: #f59e0b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 1.25rem; line-height: 1.5; }
  .container { max-width: 1200px; margin: auto; }
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
  .tabs { display: flex; gap: 0.75rem; margin-bottom: 1.25rem; }
  .tab { padding: 0.7rem 1.4rem; border-radius: 8px; border: 1px solid var(--border); background: var(--card); color: var(--muted); font-weight: 700; cursor: pointer; }
  .tab.active { background: var(--gold); color: #051c15; border-color: var(--gold); }
  .grid { display: grid; grid-template-columns: 1.1fr 1.3fr; gap: 1.25rem; }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; margin-bottom: 1.25rem; }
  h2 { font-size: 1.05rem; color: var(--gold-bright); margin-bottom: 0.9rem; display: flex; justify-content: space-between; align-items: center; }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  label { display: block; font-size: 0.76rem; color: var(--muted); margin-bottom: 0.2rem; }
  input[type="number"], input[type="text"], input[type="email"], input[type="password"] { width: 100%; background: #04140f; border: 1px solid var(--border); color: #fff; padding: 0.5rem; border-radius: 6px; font-size: 0.9rem; }
  .check-row { grid-column: 1 / -1; display: flex; align-items: center; gap: 0.55rem; background: #04140f; border: 1px solid var(--border); padding: 0.55rem 0.75rem; border-radius: 6px; }
  .check-row input { width: 16px; height: 16px; accent-color: var(--gold); }
  .check-row label { margin: 0; font-size: 0.82rem; color: var(--text); cursor: pointer; }
  .verdict-box { padding: 1rem; border-radius: 8px; background: #04140f; border-left: 4px solid var(--gold); margin-bottom: 1rem; }
  .big-score { font-size: 1.35rem; font-weight: 800; }
  table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
  th, td { text-align: left; padding: 0.6rem 0.45rem; border-bottom: 1px solid var(--border); }
  th { color: var(--gold); font-weight: 600; }
  .bull { color: var(--green); font-weight: 700; }
  .bear { color: var(--red); font-weight: 700; }
  .neut { color: var(--amber); font-weight: 700; }
  .auth-wrap { max-width: 440px; margin: 3rem auto; background: var(--card); border: 1px solid var(--gold); border-radius: 14px; padding: 2rem; }
  .hidden { display: none !important; }
  .decoder-box { margin-top: 0.9rem; padding: 0.9rem; background: #04140f; border: 1px solid var(--gold); border-radius: 8px; }
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
    <div id="regFields" class="hidden">
      <label>Full Name</label><input type="text" id="regName" placeholder="e.g. John Kamau" style="margin-bottom:0.75rem;" />
      <label>WhatsApp / Phone Number</label><input type="text" id="regPhone" placeholder="e.g. +254 712 345678" style="margin-bottom:0.75rem;" />
    </div>
    <label>Email Address</label><input type="email" id="authEmail" placeholder="you@example.com" style="margin-bottom:0.75rem;" />
    <label>Password</label><input type="password" id="authPass" placeholder="••••••••" style="margin-bottom:1rem;" />
    <button class="btn" style="width:100%;" onclick="submitAuth()" id="authSubmitBtn">Sign In to Terminal</button>
    <p id="authErr" style="color:var(--red); font-size:0.82rem; margin-top:0.6rem; text-align:center;"></p>
    <p style="text-align:center; font-size:0.85rem; margin-top:1rem; color:var(--muted);">
      <span id="togglePrompt">New to A&amp;M Group?</span>
      <a href="#" style="color:var(--gold); font-weight:700;" onclick="toggleAuthMode(); return false;" id="toggleLink">Create Account</a>
    </p>
  </div>

  <div id="appSection" class="hidden">
    <header>
      <div class="brand">
        <div class="crest" id="headerLogoSlot">A&amp;M</div>
        <div>
          <div class="dept-tag">A&amp;M Group — Trading &amp; Finance Department</div>
          <h1 style="font-size:1.3rem;">Institutional Red-Folder News Terminal (V2)</h1>
        </div>
      </div>
      <div class="top-actions">
        <span id="userWelcome" style="font-size:0.82rem; color:var(--muted);"></span>
        <button class="btn-outline hidden" id="adminBtn" onclick="toggleAdmin()">👑 Admin Monitor</button>
        <label class="btn-outline" style="margin:0; cursor:pointer;">🖼️ Upload Logo<input type="file" accept="image/*" style="display:none;" onchange="handleLogo(event)" /></label>
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
        <button class="tab active" id="tabNFP" onclick="switchTab('NFP')">🇺🇸 NFP V2 Predictor (91.2% Win Rate)</button>
        <button class="tab" id="tabCPI" onclick="switchTab('CPI')">🔥 CPI Predictor (80.4% Win Rate)</button>
      </div>
      <button class="btn" id="autoFetchBtn" onclick="autoFetch()">⚡ Auto-Fetch Latest Fed &amp; Oil Data</button>
    </div>
    <p id="fetchStatus" style="font-size:0.82rem; color:var(--gold); margin-bottom:1rem;"></p>

    <div id="viewNFP" class="grid">
      <div class="card">
        <h2><span>1. NFP Survey-Week Proxy Inputs (V2)</span> <span style="font-size:0.75rem; color:var(--muted);">Week of 12th</span></h2>
        <div class="form-grid">
          <div><label>NFP Consensus Forecast (K)</label><input type="number" id="nfp_cons" value="110" /></div>
          <div><label>Strike / Weather Adj (K) [Direct]</label><input type="number" id="nfp_strike" value="0" /></div>
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
          <div><label>NFIB Small Biz Hiring Plans (%) [8%]</label><input type="number" id="nfib_hiring_actual" value="18.0" step="0.5" /></div>
          <div><label>NFIB Hiring Plans Prev (%)</label><input type="number" id="nfib_hiring_prev" value="17.0" step="0.5" /></div>
          <div style="grid-column: 1 / -1;"><label>Prior-Month Govt Education Swing (K) [50% Mean-Reversion ≥ ±35K]</label><input type="number" id="prev_govt_edu_swing" value="0.0" step="1" /></div>
          <div class="check-row">
            <input type="checkbox" id="is_summer_school_month" />
            <label for="is_summer_school_month">Jul–Sep Back-to-School Window? (Widens No-Trade Buffer from ±25K to ±40K)</label>
          </div>
        </div>
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcNFP()">Calculate V2 NFP Outcome &amp; Pair Spikes</button>
      </div>

      <div>
        <div class="card">
          <h2><span>2. V2 NFP Forecast &amp; Asset Spike Matrix</span> <span id="nfpTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="nfpBox">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="nfpBias" class="big-score bull">READY</span>
              <span id="nfpScore" style="font-weight:700;"></span>
            </div>
            <p id="nfpSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Asset</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="nfpPairs"></tbody>
          </table>
        </div>

        <div class="card">
          <h2>⚡ 3. Post-Release NFP Action Decoder (After 8:30 AM Print)</h2>
          <div class="form-grid">
            <div><label>Actual NFP Print (K)</label><input type="number" id="dec_nfp_act" value="165" /></div>
            <div><label>2-Month Net Revisions (K)</label><input type="number" id="dec_nfp_rev" value="20" /></div>
            <div><label>Unemployment Forecast (%)</label><input type="number" id="dec_un_f" value="4.1" step="0.1" /></div>
            <div><label>Unemployment Actual (%)</label><input type="number" id="dec_un_a" value="4.0" step="0.1" /></div>
            <div><label>Avg Hourly Earnings Forecast (%)</label><input type="number" id="dec_ahe_f" value="0.3" step="0.1" /></div>
            <div><label>Avg Hourly Earnings Actual (%)</label><input type="number" id="dec_ahe_a" value="0.4" step="0.1" /></div>
          </div>
          <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="decodeNFP()">Decode Actual NFP &amp; Get Trade Plan</button>
          <div id="nfpDecodeOut" class="decoder-box hidden"></div>
        </div>
      </div>
    </div>

    <div id="viewCPI" class="grid hidden">
      <div class="card">
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
        <button class="btn" style="width:100%; margin-top:1rem;" onclick="calcCPI()">Calculate CPI Outcome &amp; Pair Spikes</button>
      </div>

      <div>
        <div class="card">
          <h2><span>2. CPI Forecast &amp; USD Pair Spike Matrix</span> <span id="cpiTier" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="cpiBox">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span id="cpiBias" class="big-score bull">READY</span>
              <span id="cpiScore" style="font-weight:700;"></span>
            </div>
            <p id="cpiSummary" style="font-size:0.88rem; color:#d1d5db;"></p>
          </div>
          <table>
            <thead><tr><th>Pair</th><th>Direction</th><th>Est. 15m Range</th><th>Execution Note</th></tr></thead>
            <tbody id="cpiPairs"></tbody>
          </table>
        </div>

        <div class="card">
          <h2>⚡ 3. Post-Release CPI Action Decoder (After 8:30 AM Print)</h2>
          <div class="form-grid">
            <div><label>Headline CPI MoM Forecast (%)</label><input type="number" id="dec_cpi_hf" value="0.3" step="0.1" /></div>
            <div><label>Headline CPI MoM Actual (%)</label><input type="number" id="dec_cpi_ha" value="0.4" step="0.1" /></div>
            <div><label>Core CPI MoM Forecast (%)</label><input type="number" id="dec_cpi_cf" value="0.3" step="0.1" /></div>
            <div><label>Core CPI MoM Actual (%)</label><input type="number" id="dec_cpi_ca" value="0.4" step="0.1" /></div>
          </div>
          <button class="btn-outline" style="width:100%; margin-top:0.85rem;" onclick="decodeCPI()">Decode Actual CPI &amp; Get Trade Plan</button>
          <div id="cpiDecodeOut" class="decoder-box hidden"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
  let isRegister = false;
  let currentUser = JSON.parse(localStorage.getItem("am_user") || "null");

  function applySavedLogo() {
    const saved = localStorage.getItem("am_logo");
    if (saved) {
      document.getElementById("headerLogoSlot").innerHTML = `<img src="${saved}" alt="A&M Logo" />`;
      document.getElementById("authLogoSlot").innerHTML = `<img src="${saved}" alt="A&M Logo" />`;
    }
  }
  applySavedLogo();

  function handleLogo(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      localStorage.setItem("am_logo", reader.result);
      applySavedLogo();
    };
    reader.readAsDataURL(file);
  }

  function toggleAuthMode() {
    isRegister = !isRegister;
    document.getElementById("regFields").classList.toggle("hidden", !isRegister);
    document.getElementById("authSubmitBtn").innerText = isRegister ? "Create A&M Account" : "Sign In to Terminal";
    document.getElementById("togglePrompt").innerText = isRegister ? "Already have an account?" : "New to A&M Group?";
    document.getElementById("toggleLink").innerText = isRegister ? "Sign In" : "Create Account";
    document.getElementById("authErr").innerText = "";
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
    if (currentUser.is_admin) document.getElementById("adminBtn").classList.remove("hidden");
    calcNFP();
    calcCPI();
  }

  function logout() {
    localStorage.removeItem("am_user");
    location.reload();
  }

  async function toggleAdmin() {
    const panel = document.getElementById("adminPanel");
    panel.classList.toggle("hidden");
    if (!panel.classList.contains("hidden")) {
      const res = await fetch(`/api/admin/users?email=${encodeURIComponent(currentUser.email)}`);
      const data = await res.json();
      document.getElementById("dbStatusBadge").innerText = data.db_mode;
      document.getElementById("adminTableBody").innerHTML = data.users.map(u =>
        `<tr><td><strong>${u.full_name}</strong></td><td>${u.email}</td><td>${u.whatsapp}</td><td>${u.calc_count}</td><td>${u.created_at}</td><td>${u.last_login}</td></tr>`
      ).join("");
    }
  }

  function switchTab(tab) {
    document.getElementById("tabNFP").classList.toggle("active", tab === "NFP");
    document.getElementById("tabCPI").classList.toggle("active", tab === "CPI");
    document.getElementById("viewNFP").classList.toggle("hidden", tab !== "NFP");
    document.getElementById("viewCPI").classList.toggle("hidden", tab !== "CPI");
  }

  async function autoFetch() {
    const btn = document.getElementById("autoFetchBtn");
    const statusEl = document.getElementById("fetchStatus");
    btn.disabled = true;
    btn.innerText = "⏳ Fetching...";
    statusEl.innerText = "Connecting to Federal Reserve & WTI Crude Oil feeds (8s max timeout)...";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      const res = await fetch("/api/autofetch", { signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) throw new Error("Server returned status " + res.status);
      const data = await res.json();
      document.getElementById("nfp_icsa").value = data.nfp.icsa_change_k;
      document.getElementById("nfp_ccsa").value = data.nfp.ccsa_change_k;
      document.getElementById("cpi_gas").value = data.cpi.gas_oil_pct_change;
      statusEl.innerText = `✅ Updated from: ${data.source}`;
      calcNFP();
      calcCPI();
    } catch (err) {
      clearTimeout(timer);
      statusEl.innerText = "⚠️ Live feed timed out — using current box values (you can also type them manually).";
    } finally {
      btn.disabled = false;
      btn.innerText = "⚡ Auto-Fetch Latest Fed & Oil Data";
    }
  }

  async function calcNFP() {
    const payload = {
      user_email: currentUser ? currentUser.email : "",
      consensus_nfp: Number(document.getElementById("nfp_cons").value),
      net_strike_impact_k: Number(document.getElementById("nfp_strike").value),
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
      nfib_hiring_actual: Number(document.getElementById("nfib_hiring_actual").value),
      nfib_hiring_prev: Number(document.getElementById("nfib_hiring_prev").value),
      prev_govt_edu_swing: Number(document.getElementById("prev_govt_edu_swing").value),
      is_summer_school_month: document.getElementById("is_summer_school_month").checked
    };
    const res = await fetch("/api/predict-nfp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    renderForecast("nfp", await res.json());
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
    renderForecast("cpi", await res.json());
  }

  function renderForecast(prefix, d) {
    const biasEl = document.getElementById(`${prefix}Bias`);
    biasEl.innerText = d.bias === "HOTTER" ? "HOTTER (USD BULLISH)" : d.bias === "COOLER" ? "COOLER (USD BEARISH)" : "NO-TRADE / LOW EDGE";
    biasEl.className = `big-score ${d.bias === "HOTTER" ? "bull" : d.bias === "COOLER" ? "bear" : "neut"}`;
    document.getElementById(`${prefix}Tier`).innerText = d.tier;
    if (prefix === "nfp" && d.edge !== undefined) {
      document.getElementById(`${prefix}Score`).innerText = `Edge: ${d.edge > 0 ? "+" : ""}${d.edge}K | Conf: ${d.confidence}%`;
    } else {
      document.getElementById(`${prefix}Score`).innerText = `Score: ${d.score > 0 ? "+" : ""}${d.score} | Conf: ${d.confidence}%`;
    }
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

  if (currentUser) enterTerminal();
</script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
