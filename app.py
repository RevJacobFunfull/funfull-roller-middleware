# app.py
"""
Tiny OAuth2 middleware for Intercom → ROLLER (Altitude Huntsville)

Endpoints
- GET /product-availability               → proxy to ROLLER validate+reserve OR availability lookup
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

@app.get("/")
def root():
    return {"status": "ok", "message": "Funfull Roller middleware is running", "routes": ["/healthz","/catalog","/product-availability","/bookings"]}


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

# ---- CATALOG HELPERS ---------------------------------------------------------
import time, difflib

PRODUCTS_PATH = os.getenv("ROLLER_PRODUCTS_PATH", "/api/v1/products")
CATALOG_TTL = int(os.getenv("CATALOG_TTL_SECONDS", "600"))
CATALOG_NAME_FILTER = os.getenv("CATALOG_NAME_FILTER", "").lower()

_catalog_cache = {"at": 0.0, "items": []}

def _fetch_catalog_from_roller():
    url = f"{ROLLER_BASE}{PRODUCTS_PATH}"
    r = requests.get(url, headers=_headers(), timeout=15)
    if r.status_code != 200:
        raise HTTPException(502, f"Catalog fetch failed: {r.text}")
    data = r.json()

    # Normalize to a simple shape. Adjust keys to match your tenant’s fields.
    items = []
    for p in (data if isinstance(data, list) else data.get("items", [])):
        # Common field names used by many tenants; change if yours differ:
        pid = p.get("id") or p.get("productId") or p.get("code")
        name = p.get("name") or p.get("title")
        duration = p.get("durationMinutes") or p.get("duration") or 120
        res_types = p.get("resourceTypes") or p.get("resourceType") or []
        if isinstance(res_types, str):
            res_types = [res_types]

        if not pid or not name:
            continue
        if CATALOG_NAME_FILTER and CATALOG_NAME_FILTER not in name.lower():
            # Optional name filter (e.g., only show “party” items)
            continue

        items.append({
            "productId": pid,
            "name": name,
            "durationMinutes": duration,
            "resourceTypes": res_types
        })
    return items

def _get_catalog():
    now = time.time()
    if _catalog_cache["items"] and now - _catalog_cache["at"] < CATALOG_TTL:
        return _catalog_cache["items"]
    items = _fetch_catalog_from_roller()
    _catalog_cache["items"] = items
    _catalog_cache["at"] = now
    return items

def _norm(s: str) -> str:
    return "".join(ch.lower() for ch in (s or "") if ch.isalnum() or ch.isspace()).strip()

# ---- CATALOG ENDPOINTS -------------------------------------------------------

@app.get("/catalog")
def list_catalog(x_api_key: Optional[str] = Header(default=None)):
    _require_mw_key(x_api_key)
    items = _get_catalog()
    # sort by name for a nicer list
    items = sorted(items, key=lambda x: x["name"].lower())
    return {"items": items, "count": len(items)}

@app.get("/resolve-package")
def resolve_package(q: str, x_api_key: Optional[str] = Header(default=None)):
    _require_mw_key(x_api_key)
    text = _norm(q)
    items = _get_catalog()
    if not text or not items:
        return {"matched": False, "choices": items[:10]}  # show first 10 as a hint

    candidates = []
    for item in items:
        score = difflib.SequenceMatcher(None, text, _norm(item["name"])).ratio()
        candidates.append((score, item))
    score, best = max(candidates, key=lambda t: t[0]) if candidates else (0, None)

    if not best or score < 0.62:
        # Not confident—return top options so the bot can present buttons
        choices = [{"productId": it["productId"], "name": it["name"]} for it in items[:10]]
        return {"matched": False, "choices": choices, "confidence": round(score, 3)}

    return {
        "matched": True,
        "confidence": round(score, 3),
        "productId": best["productId"],
        "name": best["name"],
        "resourceTypes": best.get("resourceTypes", []),
        "durationMinutes": best.get("durationMinutes", 120)
    }

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

    style = os.getenv("ROLLER_TOKEN_STYLE", "basic").lower()  # basic | body
    scope = os.getenv("ROLLER_OAUTH_SCOPE")
    audience = os.getenv("ROLLER_OAUTH_AUDIENCE")

    form = {"grant_type": "client_credentials"}
    if style == "body":
        form["client_id"] = CLIENT_ID
        form["client_secret"] = CLIENT_SEC
        if scope: form["scope"] = scope
        if audience: form["audience"] = audience
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        r = requests.post(TOKEN_URL, data=form, headers=headers, timeout=20)
    else:
        # default to HTTP Basic Auth
        from requests.auth import HTTPBasicAuth
        if scope: form["scope"] = scope
        if audience: form["audience"] = audience
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        r = requests.post(TOKEN_URL, data=form, headers=headers, auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SEC), timeout=20)

        # if server rejects Basic, try body as a fallback
        if r.status_code in (400, 401, 415):
            form["client_id"] = CLIENT_ID
            form["client_secret"] = CLIENT_SEC
            r = requests.post(TOKEN_URL, data=form, headers=headers, timeout=20)

    if r.status_code != 200:
        raise HTTPException(502, f"Auth failed: {r.text}")

    data = r.json()
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
    x_api_key: Optional[str] = Header(default=None),
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
    x_api_key: Optional[str] = Header(default=None),
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
    x_api_key: Optional[str] = Header(default=None),
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

@app.get("/debug/oauth")
def debug_oauth(x_api_key: Optional[str] = Header(default=None)):
    _require_mw_key(x_api_key)
    form = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SEC,
    }
    scope = os.getenv("ROLLER_OAUTH_SCOPE")
    audience = os.getenv("ROLLER_OAUTH_AUDIENCE")
    if scope: form["scope"] = scope
    if audience: form["audience"] = audience

    try:
        r = requests.post(
            TOKEN_URL,
            data=form,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            timeout=20,
        )
        if r.status_code in (400, 401, 415):
            from requests.auth import HTTPBasicAuth
            r = requests.post(
                TOKEN_URL,
                data={k: v for k, v in form.items() if k not in ("client_id","client_secret")},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SEC),
                timeout=20,
            )
        return {
            "status_code": r.status_code,
            "text": (r.text or "")[:600],
        }
    except requests.RequestException as e:
        raise HTTPException(502, f"Auth network error: {e}")


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
