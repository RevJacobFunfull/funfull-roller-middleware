# app.py
"""
Tiny OAuth2 middleware for Intercom → ROLLER (Altitude Huntsville)

Endpoints
- GET /availability               → proxy to ROLLER validate+reserve OR availability lookup
- POST /bookings                  → create booking with details & reserve token
- POST /bookings/{id}/checkout   → (optional) progressive/online checkout session creator
- GET /healthz                    → health probe

Security
- Server-to-server only. Put behind HTTPS. Never expose ROLLER Client Secret to clients.
- Add an incoming shared secret with the X-API-Key header so only Intercom can call this.

Env Vars (examples)
- MW_API_KEY=<random shared secret for Intercom to call this>
- ROLLER_BASE_URL=https://api.your-roller-tenant.com
- ROLLER_AUTH_TYPE=oauth  # or key
- ROLLER_TOKEN_URL=https://auth.your-roller-tenant.com/oauth/token
- ROLLER_CLIENT_ID=***
- ROLLER_CLIENT_SECRET=***
- ROLLER_API_KEY=<if using static key auth instead of oauth>

Run locally
  pip install fastapi uvicorn[standard] pydantic requests python-dotenv
  uvicorn app:app --host 0.0.0.0 --port 8080 --reload
"""
from __future__ import annotations
import os, time
from typing import Optional, List

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Funfull ROLLER Middleware", version="1.0.0")

# ---- CONFIG ----
MW_API_KEY = os.getenv("MW_API_KEY", "")  # shared secret expected in X-API-Key from Intercom
ROLLER_BASE = os.getenv("ROLLER_BASE_URL", "").rstrip("/")
AUTH_TYPE   = os.getenv("ROLLER_AUTH_TYPE", "oauth").lower()  # "oauth" | "key"
TOKEN_URL   = os.getenv("ROLLER_TOKEN_URL", "")
CLIENT_ID   = os.getenv("ROLLER_CLIENT_ID", "")
CLIENT_SEC  = os.getenv("ROLLER_CLIENT_SECRET", "")
API_KEY     = os.getenv("ROLLER_API_KEY", "")  # only if AUTH_TYPE=key

# Local in-memory token cache
_token_cache = {"token": None, "exp": 0}

# ---- UTILITIES ----

def _require_mw_key(x_api_key: Optional[str]):
    if not MW_API_KEY:
        return
    if x_api_key != MW_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: bad X-API-Key")

def _bearer() -> Optional[str]:
    if AUTH_TYPE == "key":
        return None
    now = time.time()
    if _token_cache["token"] and _token_cache["exp"] - 60 > now:
        return _token_cache["token"]
    if not (TOKEN_URL and CLIENT_ID and CLIENT_SEC):
        raise HTTPException(500, "OAuth configured but TOKEN_URL/CLIENT_ID/CLIENT_SECRET missing")
    try:
        resp = requests.post(
            TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SEC,
            },
            timeout=12,
        )
    except requests.RequestException as e:
        raise HTTPException(502, f"Auth network error: {e}")
    if resp.status_code != 200:
        raise HTTPException(502, f"Auth failed: {resp.text}")
    data = resp.json()
    _token_cache["token"] = data.get("access_token")
    _token_cache["exp"] = now + int(data.get("expires_in", 3600))
    return _token_cache["token"]


def _headers():
    h = {"Content-Type": "application/json"}
    if AUTH_TYPE == "key":
        if not API_KEY:
            raise HTTPException(500, "ROLLER_API_KEY missing for key auth")
        h["x-api-key"] = API_KEY
    else:
        h["Authorization"] = f"Bearer {_bearer()}"
    return h

# ---- MODELS ----
class AddOn(BaseModel):
    sku: str
    qty: int

class Contact(BaseModel):
    firstName: str
    lastName: Optional[str] = ""
    email: str
    phone: Optional[str] = ""

class GuestOfHonor(BaseModel):
    name: str
    dob: Optional[str] = None  # YYYY-MM-DD

class BookingIn(BaseModel):
    productId: str
    start: str  # ISO8601
    durationMinutes: int = Field(default=120, ge=60, le=300)
    resourceType: str = Field(pattern="^(room|table)$")
    headcount: int = Field(ge=1, le=1000)
    reserveToken: Optional[str] = None
    addons: List[AddOn] = []
    contact: Contact
    partyLabel: str
    guestOfHonor: Optional[GuestOfHonor] = None
    notes: Optional[str] = ""
    pricing: Optional[dict] = None  # optional total/deposit hints
    hold: Optional[dict] = None     # {"expiresAt": ISO8601}

# ---- ROUTES ----
@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/availability")
def availability(
    productId: str,
    date: str,  # YYYY-MM-DD
    duration: int = 120,
    resourceType: str = "room",
    quantity: int = 1,
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
):
    _require_mw_key(x_api_key)
    # This route demonstrates the Validate-and-Reserve flow
    url = f"{ROLLER_BASE}/api/v1/capacity/validate-and-reserve"
    payload = {
        "productId": productId,
        "date": date,
        "durationMinutes": duration,
        "resourceType": resourceType,
        "quantity": quantity,
        "hold": {"ttlSeconds": 900},  # 15-min soft hold while caller decides
    }
    try:
        r = requests.post(url, headers=_headers(), json=payload, timeout=12)
    except requests.RequestException as e:
        raise HTTPException(502, f"ROLLER error: {e}")
    if r.status_code != 200:
        raise HTTPException(502, r.text)
    data = r.json()
    # Optional convenience: compute two nearest alternative times if not available
    slots = data.get("slots") or []
    data["nearest"] = slots[:2]
    return data

@app.post("/bookings")
def create_booking(
    b: BookingIn,
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
):
    _require_mw_key(x_api_key)
    url = f"{ROLLER_BASE}/api/v1/bookings"
    try:
        r = requests.post(url, headers=_headers(), json=b.dict(), timeout=20)
    except requests.RequestException as e:
        raise HTTPException(502, f"ROLLER error: {e}")
    if r.status_code not in (200, 201):
        raise HTTPException(502, r.text)
    return r.json()

class CheckoutIn(BaseModel):
    amount: float
    purpose: str = "deposit"  # or "balance"
    returnUrl: Optional[str] = None
    sendReceipt: bool = True

@app.post("/bookings/{booking_id}/checkout")
def checkout(
    booking_id: str,
    body: CheckoutIn,
    x_api_key: Optional[str] = Header(default=None, convert_underscores=False),
):
    _require_mw_key(x_api_key)
    # This path name matches the convention we discussed; confirm in your tenant docs
    url = f"{ROLLER_BASE}/api/v1/bookings/{booking_id}/checkout"
    try:
        r = requests.post(url, headers=_headers(), json=body.dict(), timeout=20)
    except requests.RequestException as e:
        raise HTTPException(502, f"ROLLER error: {e}")
    if r.status_code not in (200, 201):
        raise HTTPException(502, r.text)
    return r.json()

# (Optional) Webhook receivers for ROLLER payments/booking updates
@app.post("/webhooks/roller")
async def roller_webhook(request: Request):
    # TODO: verify signature if ROLLER provides one (implementation varies by tenant)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    # Example: react to payment.succeeded / booking.updated
    # For now, just 200 OK so ROLLER doesn't retry endlessly
    return JSONResponse({"received": True})
