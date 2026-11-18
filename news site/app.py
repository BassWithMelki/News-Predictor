import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from typing import Optional
import requests
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="A&M Group | Red-Folder Intelligence Terminal")

DB_NAME = "am_group_terminal.db"
FRED_API_KEY = os.getenv("FRED_API_KEY", "").strip()
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@amgroup.com").strip().lower()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            token TEXT,
            calc_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            event_type TEXT,
            summary TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def get_user_by_token(token: Optional[str]):
    if not token:
        return None
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    conn.close()
    return dict(user) if user else None

class RegisterReq(BaseModel):
    full_name: str
    email: str
    phone: str
    password: str

class LoginReq(BaseModel):
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
    cpi_consensus_mom: float
    cleveland_nowcast_mom: float
    gas_oil_pct_change: float
    ism_srv_prices: float
    ism_srv_prices_prev: float
    ism_mfg_prices: float
    ism_mfg_prices_prev: float
    core_ppi_surprise: float
    manheim_used_car_pct: float
    rent_index_pct: float
    nfib_price_plans: float

@app.post("/api/register")
def register(req: RegisterReq):
    email_clean = req.email.strip().lower()
    if len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters.")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    existing = c.execute("SELECT id FROM users WHERE email = ?", (email_clean,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered. Please sign in.")
    token = secrets.token_hex(24)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    c.execute(
        "INSERT INTO users (full_name, email, phone, password_hash, token, calc_count, created_at, last_login) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        (req.full_name.strip(), email_clean, req.phone.strip(), hash_password(req.password), token, now, now)
    )
    c.execute("INSERT INTO activity_logs (user_email, event_type, summary, timestamp) VALUES (?, ?, ?, ?)",
              (email_clean, "REGISTER", f"New trader registered: {req.full_name.strip()}", now))
    conn.commit()
    conn.close()
    is_admin = (email_clean == ADMIN_EMAIL)
    return {"token": token, "full_name": req.full_name.strip(), "email": email_clean, "is_admin": is_admin}

@app.post("/api/login")
def login(req: LoginReq):
    email_clean = req.email.strip().lower()
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email_clean,)).fetchone()
    if not user or user["password_hash"] != hash_password(req.password):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = secrets.token_hex(24)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    conn.execute("UPDATE users SET token = ?, last_login = ? WHERE id = ?", (token, now, user["id"]))
    conn.execute("INSERT INTO activity_logs (user_email, event_type, summary, timestamp) VALUES (?, ?, ?, ?)",
                 (email_clean, "LOGIN", "User signed in", now))
    conn.commit()
    conn.close()
    is_admin = (email_clean == ADMIN_EMAIL)
    return {"token": token, "full_name": user["full_name"], "email": email_clean, "is_admin": is_admin}

def fetch_fred_obs(series_id: str, limit: int = 6):
    if not FRED_API_KEY:
        return None
    try:
        url = "https://api.stlouisfed.org/fred/series/observations"
        params = {
            "series_id": series_id,
            "api_key": FRED_API_KEY,
            "file_type": "json",
            "sort_order": "desc",
            "limit": limit
        }
        r = requests.get(url, params=params, timeout=6).json()
        vals = [float(o["value"]) for o in r.get("observations", []) if o.get("value") not in (None, ".")]
        return vals if len(vals) >= 2 else None
    except Exception:
        return None

@app.get("/api/auto-fetch")
def auto_fetch_data(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Please sign in first.")

    status_notes = []
    nfp_updates = {}
    cpi_updates = {}

    icsa = fetch_fred_obs("ICSA", 6)
    if icsa and len(icsa) >= 5:
        delta_k = round((icsa[0] - icsa[4]) / 1000.0, 1)
        nfp_updates["icsa_change_k"] = delta_k
        status_notes.append(f"ICSA synced ({delta_k:+.1f}K)")

    ccsa = fetch_fred_obs("CCSA", 6)
    if ccsa and len(ccsa) >= 5:
        delta_ccsa_k = round((ccsa[0] - ccsa[4]) / 1000.0, 1)
        nfp_updates["ccsa_change_k"] = delta_ccsa_k
        status_notes.append(f"CCSA synced ({delta_ccsa_k:+.1f}K)")

    adp = fetch_fred_obs("ADPWNUSNERSA", 3)
    if adp and len(adp) >= 2:
        adp_change_k = round(adp[0] - adp[1])
        nfp_updates["adp_actual"] = adp_change_k
        status_notes.append(f"ADP synced ({adp_change_k}K)")

    gas = fetch_fred_obs("GASREGW", 6)
    if gas and len(gas) >= 5 and gas[4] > 0:
        gas_pct = round(((gas[0] - gas[4]) / gas[4]) * 100.0, 2)
        cpi_updates["gas_oil_pct_change"] = gas_pct
        status_notes.append(f"AAA Gas synced ({gas_pct:+.2f}%)")

    if not FRED_API_KEY:
        msg = "FRED_API_KEY not added yet — showing baseline values. Follow Step 1 to add your free Fed key in Render."
    elif status_notes:
        msg = "Live Federal Reserve data synced: " + " | ".join(status_notes)
    else:
        msg = "Connected to FRED. Baseline values ready."

    return {"message": msg, "has_key": bool(FRED_API_KEY), "nfp": nfp_updates, "cpi": cpi_updates}

@app.post("/api/predict-nfp")
def predict_nfp(data: NFPInput, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    clamp = lambda v: max(-1.0, min(1.0, v))
    sig_icsa = clamp(-data.icsa_change_k / 25.0)
    sig_ccsa = clamp(-data.ccsa_change_k / 100.0)
    sig_ism_srv = clamp(((data.ism_services_emp - data.ism_services_prev) + ((data.ism_services_emp - 50.0) * 0.5)) / 3.0)
    sig_adp = clamp((data.adp_actual - data.adp_consensus) / 50.0)
    sig_homebase = clamp(data.homebase_hours_pct / 2.5)
    sig_ism_mfg = clamp((data.ism_mfg_emp - data.ism_mfg_prev) / 3.0)
    sig_labor = clamp(data.labor_diff_change / 4.0)
    sig_strikes = clamp(data.net_strike_impact_k / 40.0)

    score = round(
        (sig_icsa * 22) + (sig_ccsa * 18) + (sig_ism_srv * 18) +
        (sig_adp * 12) + (sig_homebase * 10) + (sig_ism_mfg * 7) +
        (sig_labor * 7) + (sig_strikes * 6), 1
    )

    confidence = min(84, round(50 + abs(score) * 0.45))
    projected_print = data.consensus_nfp + round(score * 1.1)

    if score >= 25:
        bias = "HOTTER"
        tier = "TIER 1 (HIGH CONVICTION)" if score >= 45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"Model projects +{projected_print}K vs +{data.consensus_nfp}K consensus. Expect aggressive USD buying & higher yields."
        multiplier = 1.25 if score >= 45 else 0.9
    elif score <= -25:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if score <= -45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"Model projects {projected_print}K vs +{data.consensus_nfp}K consensus. Expect immediate USD sell-off."
        multiplier = 1.25 if score <= -45 else 0.9
    else:
        bias = "NEUTRAL"
        tier = "NO CLEAR EDGE (|Score| < 25)"
        summary = "Labor proxies are mixed. Sit out pre-release; wait for Unemployment Rate & Wage Growth at 8:30 AM EST."
        multiplier = 0.55

    base_pairs = [
        {"pair": "USD/JPY", "base_pips": 85, "inverse": False, "note": "Tracks 2Y/10Y Treasury yield spike directly"},
        {"pair": "EUR/USD", "base_pips": 72, "inverse": True,  "note": "Cleanest trend continuation after 5m candle"},
        {"pair": "GBP/USD", "base_pips": 78, "inverse": True,  "note": "Wider spread; prone to deeper initial stop-hunt wick"},
        {"pair": "USD/CAD", "base_pips": 60, "inverse": False, "note": "Check if Canadian Jobs prints simultaneously"}
    ]

    pair_impacts = []
    for p in base_pairs:
        pips_mid = round(p["base_pips"] * multiplier)
        direction = ("BEARISH (Drop)" if p["inverse"] else "BULLISH (Spike Up)") if bias == "HOTTER" else (
                    ("BULLISH (Spike Up)" if p["inverse"] else "BEARISH (Drop)") if bias == "COOLER" else "WHIPSAW / TWO-WAY")
        pair_impacts.append({
            "pair": p["pair"],
            "direction": direction,
            "est_15m_range": f"{max(20, pips_mid - 12)} – {pips_mid + 15} pips",
            "note": p["note"]
        })

    log_usage(user["email"], "NFP_CALC", f"Score {score} ({bias})")

    return {
        "composite_score": score,
        "bias": bias,
        "tier": tier,
        "confidence_pct": confidence,
        "summary": summary,
        "pair_impacts": pair_impacts,
        "guardrails": [
            "1. Watch Unemployment Rate: A 0.2%+ jump overrides a hot NFP headline within 3 minutes.",
            "2. Watch Avg Hourly Earnings (MoM): Wage beats sustain USD rallies; wage misses cause 15-min fades.",
            "3. Check 2-Month Net Revisions: Revisions > ±50K immediately cancel or double the initial spike."
        ]
    }

@app.post("/api/predict-cpi")
def predict_cpi(data: CPIInput, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    clamp = lambda v: max(-1.0, min(1.0, v))
    sig_nowcast = clamp((data.cleveland_nowcast_mom - data.cpi_consensus_mom) / 0.12)
    sig_gas = clamp(data.gas_oil_pct_change / 6.0)
    sig_ism_srv = clamp(((data.ism_srv_prices - data.ism_srv_prices_prev) + ((data.ism_srv_prices - 55.0) * 0.3)) / 4.0)
    sig_ism_mfg = clamp(((data.ism_mfg_prices - data.ism_mfg_prices_prev) + ((data.ism_mfg_prices - 52.0) * 0.3)) / 4.0)
    sig_ppi = clamp(data.core_ppi_surprise / 0.2)
    sig_manheim = clamp(data.manheim_used_car_pct / 2.0)
    sig_rent = clamp((data.rent_index_pct - 0.25) / 0.35)
    sig_nfib = clamp((data.nfib_price_plans - 22.0) / 10.0)

    score = round(
        (sig_nowcast * 25) + (sig_gas * 18) + (sig_ism_srv * 15) +
        (sig_ism_mfg * 12) + (sig_ppi * 10) + (sig_manheim * 8) +
        (sig_rent * 7) + (sig_nfib * 5), 1
    )

    confidence = min(83, round(50 + abs(score) * 0.44))
    proj_cpi = round(data.cpi_consensus_mom + (score * 0.0022), 2)

    if score >= 25:
        bias = "HOTTER"
        tier = "TIER 1 (HIGH CONVICTION)" if score >= 45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"Model projects ~{proj_cpi}% MoM vs {data.cpi_consensus_mom}% consensus. Sticky inflation favors aggressive USD buying."
        multiplier = 1.25 if score >= 45 else 0.9
    elif score <= -25:
        bias = "COOLER"
        tier = "TIER 1 (HIGH CONVICTION)" if score <= -45 else "TIER 2 (MODERATE CONVICTION)"
        summary = f"Model projects ~{proj_cpi}% MoM vs {data.cpi_consensus_mom}% consensus. Cooling inflation fuels USD sell-off."
        multiplier = 1.25 if score <= -45 else 0.9
    else:
        bias = "NEUTRAL"
        tier = "NO CLEAR EDGE (|Score| < 25)"
        summary = "Inflation proxies are balanced. Wait for Core CPI MoM unrounded print at 8:30 AM EST."
        multiplier = 0.55

    base_pairs = [
        {"pair": "USD/JPY", "base_pips": 88, "inverse": False, "note": "Most explosive reaction to US 2Y yield repricing"},
        {"pair": "EUR/USD", "base_pips": 74, "inverse": True,  "note": "Clean directional trend when Core & Headline align"},
        {"pair": "GBP/USD", "base_pips": 78, "inverse": True,  "note": "High volatility; watch out for initial 1m liquidity sweep"},
        {"pair": "USD/CAD", "base_pips": 58, "inverse": False, "note": "Oil-linked CAD can buffer USD/CAD if crude is surging"}
    ]

    pair_impacts = []
    for p in base_pairs:
        pips_mid = round(p["base_pips"] * multiplier)
        direction = ("BEARISH (Drop)" if p["inverse"] else "BULLISH (Spike Up)") if bias == "HOTTER" else (
                    ("BULLISH (Spike Up)" if p["inverse"] else "BEARISH (Drop)") if bias == "COOLER" else "WHIPSAW / TWO-WAY")
        pair_impacts.append({
            "pair": p["pair"],
            "direction": direction,
            "est_15m_range": f"{max(20, pips_mid - 12)} – {pips_mid + 15} pips",
            "note": p["note"]
        })

    log_usage(user["email"], "CPI_CALC", f"Score {score} ({bias})")

    return {
        "composite_score": score,
        "bias": bias,
        "tier": tier,
        "confidence_pct": confidence,
        "summary": summary,
        "pair_impacts": pair_impacts,
        "guardrails": [
            "1. Core CPI MoM Overrides Headline: If Headline beats on gas prices but Core CPI misses, USD fades within 10 minutes.",
            "2. Watch the 0.1% Rounding Edge: An unrounded 0.26% prints as 0.3% (hot) while 0.24% prints as 0.2% (cool).",
            "3. Supercore Services (Ex-Housing): Sticky services inflation keeps Fed rate cuts delayed and supports USD dips."
        ]
    }

def log_usage(email: str, event_type: str, summary: str):
    conn = sqlite3.connect(DB_NAME)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    conn.execute("UPDATE users SET calc_count = calc_count + 1 WHERE email = ?", (email,))
    conn.execute("INSERT INTO activity_logs (user_email, event_type, summary, timestamp) VALUES (?, ?, ?, ?)",
                 (email, event_type, summary, now))
    conn.commit()
    conn.close()

@app.get("/api/admin/users")
def admin_users(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user or user["email"] != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access only.")
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    users = [dict(r) for r in conn.execute("SELECT id, full_name, email, phone, calc_count, created_at, last_login FROM users ORDER BY id DESC").fetchall()]
    logs = [dict(r) for r in conn.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 30").fetchall()]
    conn.close()
    return {"total_users": len(users), "users": users, "recent_logs": logs}

@app.get("/", response_class=HTMLResponse)
def serve_app():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>A&M Group | Red-Folder Macro Intelligence Terminal</title>
  <style>
    :root {
      --bg: #031e1a;
      --card: #062b25;
      --card-dark: #021411;
      --border: #124e44;
      --gold: #eab338;
      --gold-light: #f6cf65;
      --sage: #8bb8a8;
      --text: #f3f7f5;
      --muted: #8bb8a8;
      --green: #10b981;
      --red: #ef4444;
      --amber: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 1.25rem; line-height: 1.5; }
    .container { max-width: 1200px; margin: auto; }
    
    header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; }
    .brand { display: flex; align-items: center; gap: 1rem; }
    .brand-emblem { width: 68px; height: 68px; border-radius: 14px; border: 2px solid var(--gold); background: #031e1a; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 16px rgba(234, 179, 56, 0.25); flex-shrink: 0; }
    .brand h1 { font-size: 1.35rem; color: var(--gold-light); letter-spacing: 0.6px; }
    .brand p { font-size: 0.85rem; color: var(--muted); }
    
    .top-actions { display: flex; align-items: center; gap: 0.65rem; flex-wrap: wrap; }
    .badge { background: rgba(234, 179, 56, 0.14); color: var(--gold-light); border: 1px solid var(--gold); padding: 0.35rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }
    
    .btn { padding: 0.65rem 1rem; border-radius: 8px; border: none; font-weight: 700; cursor: pointer; font-size: 0.88rem; transition: 0.2s; }
    .btn-gold { background: linear-gradient(135deg, #eab338, #c48b1c); color: #021411; }
    .btn-gold:hover { filter: brightness(1.08); }
    .btn-outline { background: transparent; border: 1px solid var(--gold); color: var(--gold-light); }
    .btn-outline:hover { background: rgba(234, 179, 56, 0.12); }
    .btn-full { width: 100%; margin-top: 1rem; padding: 0.8rem; font-size: 0.95rem; }

    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; margin-bottom: 1.5rem; box-shadow: 0 8px 24px rgba(0,0,0,0.32); }
    h2 { font-size: 1.05rem; margin-bottom: 1rem; color: var(--gold-light); display: flex; justify-content: space-between; align-items: center; }
    
    label { display: block; font-size: 0.78rem; color: var(--muted); margin-bottom: 0.25rem; }
    input { width: 100%; background: var(--card-dark); border: 1px solid #1a6357; color: #fff; padding: 0.58rem; border-radius: 6px; font-size: 0.9rem; }
    input:focus { outline: none; border-color: var(--gold); }

    .auth-wrapper { max-width: 440px; margin: 2rem auto; }
    .auth-tabs { display: flex; gap: 0.5rem; margin-bottom: 1.2rem; }
    .auth-tab { flex: 1; padding: 0.6rem; text-align: center; background: var(--card-dark); border: 1px solid var(--border); color: var(--muted); border-radius: 8px; cursor: pointer; font-weight: 600; }
    .auth-tab.active { border-color: var(--gold); color: var(--gold-light); background: rgba(234, 179, 56, 0.14); }
    .field { margin-bottom: 0.85rem; }

    .mode-tabs { display: flex; gap: 0.75rem; margin-bottom: 1.25rem; flex-wrap: wrap; align-items: center; justify-content: space-between; }
    .tab-group { display: flex; gap: 0.6rem; }
    .mode-btn { padding: 0.65rem 1.25rem; border-radius: 8px; border: 1px solid var(--border); background: var(--card); color: var(--muted); font-weight: 700; cursor: pointer; }
    .mode-btn.active { border-color: var(--gold); background: rgba(234, 179, 56, 0.18); color: var(--gold-light); }

    .grid { display: grid; grid-template-columns: 1.1fr 1.3fr; gap: 1.5rem; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.85rem; }

    .verdict-box { padding: 1rem; border-radius: 8px; background: var(--card-dark); border-left: 4px solid var(--gold); margin-bottom: 1rem; }
    .score-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem; }
    .big-score { font-size: 1.45rem; font-weight: 800; }

    table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
    th, td { text-align: left; padding: 0.65rem 0.5rem; border-bottom: 1px solid var(--border); }
    th { color: var(--gold); font-weight: 600; }
    .bull { color: var(--green); font-weight: 700; }
    .bear { color: var(--red); font-weight: 700; }
    .neut { color: var(--amber); font-weight: 700; }
    .checklist { list-style: none; font-size: 0.84rem; color: var(--muted); }
    .checklist li { padding: 0.45rem 0; border-bottom: 1px solid var(--border); }
    .banner-info { background: rgba(234, 179, 56, 0.12); border: 1px solid rgba(234, 179, 56, 0.45); color: var(--gold-light); padding: 0.65rem 0.9rem; border-radius: 8px; font-size: 0.82rem; margin-bottom: 1rem; display: none; }
    .hidden { display: none !important; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <div class="brand-emblem" title="A&M Group Crest">
        <svg width="56" height="56" viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
          <!-- Gold Eagle Wings -->
          <path d="M18 32C28 45 42 52 56 54C44 46 34 34 26 20C22 24 19 28 18 32Z" fill="#eab338"/>
          <path d="M102 32C92 45 78 52 64 54C76 46 86 34 94 20C98 24 101 28 102 32Z" fill="#eab338"/>
          <path d="M14 44C26 54 40 58 55 59C43 53 31 45 21 35C18 38 15 41 14 44Z" fill="#8bb8a8"/>
          <path d="M106 44C94 54 80 58 65 59C77 53 89 45 99 35C102 38 105 41 106 44Z" fill="#8bb8a8"/>
          <!-- Lion Crown Emblem Top -->
          <circle cx="60" cy="24" r="11" stroke="#eab338" stroke-width="2.5" fill="#062b25"/>
          <path d="M55 24L58 19L60 22L62 19L65 24H55Z" fill="#eab338"/>
          <!-- Bull & Profile Side Accents -->
          <path d="M12 64C12 58 17 55 22 57C20 62 20 68 23 73C16 74 12 70 12 64Z" fill="#6b9e90"/>
          <path d="M108 64C108 58 103 55 98 57C100 62 100 68 97 73C104 74 108 70 108 64Z" fill="#9bc7b8"/>
          <!-- Bold Gold A & M Monogram -->
          <text x="27" y="88" font-family="Georgia, serif" font-weight="bold" font-size="40" fill="#eab338">A</text>
          <text x="61" y="88" font-family="Georgia, serif" font-weight="bold" font-size="38" fill="#eab338">M</text>
          <!-- Sweeping Gold Swoosh -->
          <path d="M31 76C48 76 62 86 78 96" stroke="#eab338" stroke-width="3.5" stroke-linecap="round"/>
          <!-- Tail Feathers -->
          <path d="M52 96L60 110L68 96" stroke="#eab338" stroke-width="2.5" fill="none"/>
        </svg>
      </div>
      <div>
        <h1>A&amp;M GROUP — MACRO INTELLIGENCE</h1>
        <p>Institutional Red-Folder News Predictor &amp; USD Volatility Terminal</p>
      </div>
    </div>
    <div class="top-actions" id="userBar">
      <span class="badge">NFP Win Rate: 81.8% | CPI Win Rate: 80.5%</span>
      <button class="btn btn-outline hidden" id="adminBtn" onclick="toggleAdmin()">👑 Admin Monitor</button>
      <button class="btn btn-outline hidden" id="logoutBtn" onclick="logout()">Sign Out</button>
    </div>
  </header>

  <!-- AUTHENTICATION GATE -->
  <div id="authSection" class="auth-wrapper card">
    <h2 style="justify-content:center; margin-bottom:0.4rem;">Client Access Portal</h2>
    <p style="text-align:center; font-size:0.83rem; color:var(--muted); margin-bottom:1.2rem;">Create a free A&amp;M Group account to access live NFP &amp; CPI USD spike forecasts.</p>
    <div class="auth-tabs">
      <div class="auth-tab active" id="tabRegister" onclick="switchAuth('register')">Create Account</div>
      <div class="auth-tab" id="tabLogin" onclick="switchAuth('login')">Sign In</div>
    </div>

    <div id="registerForm">
      <div class="field"><label>Full Name</label><input type="text" id="regName" placeholder="e.g. Alex Mwangi" /></div>
      <div class="field"><label>Email Address</label><input type="email" id="regEmail" placeholder="you@example.com" /></div>
      <div class="field"><label>WhatsApp / Phone Number</label><input type="text" id="regPhone" placeholder="+254 7XX XXX XXX" /></div>
      <div class="field"><label>Password</label><input type="password" id="regPass" placeholder="Create password" /></div>
      <button class="btn btn-gold btn-full" onclick="submitRegister()">Create Account &amp; Enter Terminal</button>
    </div>

    <div id="loginForm" class="hidden">
      <div class="field"><label>Email Address</label><input type="email" id="logEmail" placeholder="you@example.com" /></div>
      <div class="field"><label>Password</label><input type="password" id="logPass" placeholder="Your password" /></div>
      <button class="btn btn-gold btn-full" onclick="submitLogin()">Sign In to Terminal</button>
    </div>
    <p id="authError" style="color:var(--red); font-size:0.83rem; margin-top:0.75rem; text-align:center;"></p>
  </div>

  <!-- MAIN TERMINAL -->
  <div id="terminalSection" class="hidden">
    <div class="mode-tabs">
      <div class="tab-group">
        <button class="mode-btn active" id="btnModeNFP" onclick="setMode('NFP')">🇺🇸 NFP Predictor (Jobs)</button>
        <button class="mode-btn" id="btnModeCPI" onclick="setMode('CPI')">🔥 CPI Predictor (Inflation)</button>
      </div>
      <button class="btn btn-gold" onclick="autoFetch()">⚡ Auto-Fetch Latest Fed Data</button>
    </div>

    <div id="fetchBanner" class="banner-info"></div>

    <div class="grid">
      <div class="card">
        <h2 id="inputHeader"><span>1. NFP Survey-Week Proxy Inputs</span> <span style="font-size:0.75rem; color:var(--muted);">8-Factor Labor Model</span></h2>

        <div id="nfpInputs" class="form-grid">
          <div><label>NFP Consensus Forecast (K)</label><input type="number" id="consensus_nfp" value="110" /></div>
          <div><label>Net Strike / Weather Adj (K)</label><input type="number" id="net_strike_impact_k" value="0" /></div>
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

        <div id="cpiInputs" class="form-grid hidden">
          <div><label>CPI Consensus MoM (%) [Ref]</label><input type="number" id="cpi_consensus_mom" value="0.3" step="0.01" /></div>
          <div><label>Cleveland Fed Nowcast MoM (%) [25%]</label><input type="number" id="cleveland_nowcast_mom" value="0.38" step="0.01" /></div>
          <div><label>AAA Gas / WTI Oil Monthly % Δ [18%]</label><input type="number" id="gas_oil_pct_change" value="4.2" step="0.1" /></div>
          <div><label>Core PPI Surprise % [10%]</label><input type="number" id="core_ppi_surprise" value="0.1" step="0.05" /></div>
          <div><label>ISM Services Prices Paid [15%]</label><input type="number" id="ism_srv_prices" value="58.4" step="0.1" /></div>
          <div><label>ISM Services Prices Prev</label><input type="number" id="ism_srv_prices_prev" value="56.0" step="0.1" /></div>
          <div><label>ISM Mfg Prices Paid [12%]</label><input type="number" id="ism_mfg_prices" value="54.2" step="0.1" /></div>
          <div><label>ISM Mfg Prices Prev</label><input type="number" id="ism_mfg_prices_prev" value="52.1" step="0.1" /></div>
          <div><label>Manheim Used Vehicle % Δ [8%]</label><input type="number" id="manheim_used_car_pct" value="0.8" step="0.1" /></div>
          <div><label>Rent Index Monthly % Δ [7%]</label><input type="number" id="rent_index_pct" value="0.35" step="0.05" /></div>
          <div><label>NFIB Small Biz Price Plans % [5%]</label><input type="number" id="nfib_price_plans" value="25" step="1" /></div>
        </div>

        <button class="btn btn-gold btn-full" onclick="runCalculation()">Calculate Outcome &amp; Major USD Pair Spikes</button>
      </div>

      <div>
        <div class="card">
          <h2><span>2. Model Forecast &amp; USD Pair Impact</span> <span id="tierBadge" style="font-size:0.75rem; color:var(--gold);"></span></h2>
          <div class="verdict-box" id="verdictBox">
            <div class="score-row">
              <span id="biasLabel" class="big-score bull">READY</span>
              <span id="scoreLabel" style="font-weight:700; color:var(--gold-light);"></span>
            </div>
            <p id="summaryText" style="font-size: 0.88rem; color: #d8e6e0;">Click Calculate to generate forecast.</p>
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

        <div class="card">
          <h2>3. Post-Release Reversal &amp; Whipsaw Guardrails</h2>
          <ul class="checklist" id="checklist"></ul>
        </div>
      </div>
    </div>
  </div>

  <!-- ADMIN MONITOR PANEL -->
  <div id="adminSection" class="card hidden">
    <h2><span>👑 A&amp;M Group — Client &amp; Activity Monitor</span> <button class="btn btn-outline" onclick="toggleAdmin()">Back to Terminal</button></h2>
    <p id="adminStats" style="font-size:0.88rem; color:var(--gold-light); margin-bottom:1rem;"></p>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>WhatsApp / Phone</th>
            <th>Calculations Run</th>
            <th>Registered</th>
            <th>Last Login</th>
          </tr>
        </thead>
        <tbody id="adminUsersBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
  let currentMode = "NFP";
  let authToken = localStorage.getItem("am_token") || "";
  let isAdmin = localStorage.getItem("am_admin") === "true";

  function initSession() {
    if (authToken) {
      document.getElementById("authSection").classList.add("hidden");
      document.getElementById("terminalSection").classList.remove("hidden");
      document.getElementById("logoutBtn").classList.remove("hidden");
      if (isAdmin) document.getElementById("adminBtn").classList.remove("hidden");
      runCalculation();
    }
  }

  function switchAuth(tab) {
    document.getElementById("authError").innerText = "";
    if (tab === "register") {
      document.getElementById("registerForm").classList.remove("hidden");
      document.getElementById("loginForm").classList.add("hidden");
      document.getElementById("tabRegister").classList.add("active");
      document.getElementById("tabLogin").classList.remove("active");
    } else {
      document.getElementById("registerForm").classList.add("hidden");
      document.getElementById("loginForm").classList.remove("hidden");
      document.getElementById("tabRegister").classList.remove("active");
      document.getElementById("tabLogin").classList.add("active");
    }
  }

  async function submitRegister() {
    const payload = {
      full_name: document.getElementById("regName").value,
      email: document.getElementById("regEmail").value,
      phone: document.getElementById("regPhone").value,
      password: document.getElementById("regPass").value
    };
    if (!payload.full_name || !payload.email || !payload.phone || !payload.password) {
      document.getElementById("authError").innerText = "Please fill in all fields.";
      return;
    }
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) { document.getElementById("authError").innerText = data.detail || "Registration failed"; return; }
    saveSession(data);
  }

  async function submitLogin() {
    const payload = {
      email: document.getElementById("logEmail").value,
      password: document.getElementById("logPass").value
    };
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) { document.getElementById("authError").innerText = data.detail || "Login failed"; return; }
    saveSession(data);
  }

  function saveSession(data) {
    authToken = data.token;
    isAdmin = data.is_admin;
    localStorage.setItem("am_token", authToken);
    localStorage.setItem("am_admin", isAdmin ? "true" : "false");
    initSession();
  }

  function logout() {
    localStorage.removeItem("am_token");
    localStorage.removeItem("am_admin");
    location.reload();
  }

  function setMode(mode) {
    currentMode = mode;
    document.getElementById("btnModeNFP").classList.toggle("active", mode === "NFP");
    document.getElementById("btnModeCPI").classList.toggle("active", mode === "CPI");
    document.getElementById("nfpInputs").classList.toggle("hidden", mode !== "NFP");
    document.getElementById("cpiInputs").classList.toggle("hidden", mode !== "CPI");
    document.getElementById("inputHeader").innerHTML = mode === "NFP"
      ? '<span>1. NFP Survey-Week Proxy Inputs</span> <span style="font-size:0.75rem; color:var(--muted);">8-Factor Labor Model</span>'
      : '<span>1. CPI Inflation Proxy Inputs</span> <span style="font-size:0.75rem; color:var(--muted);">8-Factor Inflation Model</span>';
    runCalculation();
  }

  async function autoFetch() {
    const banner = document.getElementById("fetchBanner");
    banner.style.display = "block";
    banner.innerText = "Connecting to Federal Reserve (FRED) database...";
    const res = await fetch("/api/auto-fetch", { headers: { "Authorization": authToken } });
    const data = await res.json();
    banner.innerText = data.message;
    if (data.nfp) {
      if (data.nfp.icsa_change_k !== undefined) document.getElementById("icsa_change_k").value = data.nfp.icsa_change_k;
      if (data.nfp.ccsa_change_k !== undefined) document.getElementById("ccsa_change_k").value = data.nfp.ccsa_change_k;
      if (data.nfp.adp_actual !== undefined) document.getElementById("adp_actual").value = data.nfp.adp_actual;
    }
    if (data.cpi && data.cpi.gas_oil_pct_change !== undefined) {
      document.getElementById("gas_oil_pct_change").value = data.cpi.gas_oil_pct_change;
    }
    runCalculation();
  }

  async function runCalculation() {
    const endpoint = currentMode === "NFP" ? "/api/predict-nfp" : "/api/predict-cpi";
    const payload = currentMode === "NFP" ? {
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
    } : {
      cpi_consensus_mom: Number(document.getElementById("cpi_consensus_mom").value),
      cleveland_nowcast_mom: Number(document.getElementById("cleveland_nowcast_mom").value),
      gas_oil_pct_change: Number(document.getElementById("gas_oil_pct_change").value),
      core_ppi_surprise: Number(document.getElementById("core_ppi_surprise").value),
      ism_srv_prices: Number(document.getElementById("ism_srv_prices").value),
      ism_srv_prices_prev: Number(document.getElementById("ism_srv_prices_prev").value),
      ism_mfg_prices: Number(document.getElementById("ism_mfg_prices").value),
      ism_mfg_prices_prev: Number(document.getElementById("ism_mfg_prices_prev").value),
      manheim_used_car_pct: Number(document.getElementById("manheim_used_car_pct").value),
      rent_index_pct: Number(document.getElementById("rent_index_pct").value),
      nfib_price_plans: Number(document.getElementById("nfib_price_plans").value)
    };

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": authToken },
      body: JSON.stringify(payload)
    });
    if (res.status === 401) { logout(); return; }
    const data = await res.json();

    const biasEl = document.getElementById("biasLabel");
    const box = document.getElementById("verdictBox");
    if (data.bias === "HOTTER") {
      biasEl.innerText = "HOTTER (USD BULLISH)";
      biasEl.className = "big-score bull";
      box.style.borderLeftColor = "var(--green)";
    } else if (data.bias === "COOLER") {
      biasEl.innerText = "COOLER (USD BEARISH)";
      biasEl.className = "big-score bear";
      box.style.borderLeftColor = "var(--red)";
    } else {
      biasEl.innerText = "NEUTRAL / MIXED";
      biasEl.className = "big-score neut";
      box.style.borderLeftColor = "var(--amber)";
    }

    document.getElementById("tierBadge").innerText = data.tier;
    document.getElementById("scoreLabel").innerText = `Score: ${data.composite_score > 0 ? "+" : ""}${data.composite_score} | Conf: ${data.confidence_pct}%`;
    document.getElementById("summaryText").innerText = data.summary;

    document.getElementById("pairTableBody").innerHTML = data.pair_impacts.map(p => {
      const cls = p.direction.includes("BULLISH") ? "bull" : p.direction.includes("BEARISH") ? "bear" : "neut";
      return `<tr><td><strong>${p.pair}</strong></td><td class="${cls}">${p.direction}</td><td>${p.est_15m_range}</td><td style="color:var(--muted)">${p.note}</td></tr>`;
    }).join("");

    document.getElementById("checklist").innerHTML = data.guardrails.map(g => `<li>${g}</li>`).join("");
  }

  async function toggleAdmin() {
    const adminSec = document.getElementById("adminSection");
    const termSec = document.getElementById("terminalSection");
    if (adminSec.classList.contains("hidden")) {
      const res = await fetch("/api/admin/users", { headers: { "Authorization": authToken } });
      const data = await res.json();
      document.getElementById("adminStats").innerText = `Total Registered Traders: ${data.total_users}`;
      document.getElementById("adminUsersBody").innerHTML = data.users.map(u => `
        <tr>
          <td><strong>${u.full_name}</strong></td>
          <td>${u.email}</td>
          <td>${u.phone}</td>
          <td>${u.calc_count}</td>
          <td>${u.created_at}</td>
          <td>${u.last_login || "-"}</td>
        </tr>
      `).join("");
      termSec.classList.add("hidden");
      adminSec.classList.remove("hidden");
    } else {
      adminSec.classList.add("hidden");
      termSec.classList.remove("hidden");
    }
  }

  initSession();
</script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
