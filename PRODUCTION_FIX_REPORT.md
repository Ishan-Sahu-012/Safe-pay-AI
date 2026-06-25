# SafePay AI — Production Readiness Fix Report

**Date:** 2026-06-01  
**Scope:** Full backend audit, runtime fixes, JWT/auth, database, ML pipeline, endpoint verification

---

## Executive Summary

All **29 smoke-tested API endpoints** return success (2xx) after fixes. JWT register/login/profile/refresh work end-to-end. ML models train and load correctly. Swagger (`/docs`) can exercise the full flow: register → Authorize with Bearer token → call protected routes.

---

## Issues Found & Fixes Applied

| # | File | Line(s) | Root Cause | Fix Applied |
|---|------|---------|------------|-------------|
| 1 | `app/api/routes/auth_routes.py` | 31–34, 68–81 | **passlib + bcrypt 5.x** incompatibility (`ValueError: password cannot be longer than 72 bytes` during backend detection) | Replaced passlib with `app/utils/password.py` using **bcrypt** directly |
| 2 | `app/api/middleware/logging_middleware.py` | 67–78 | `await request.body()` consumed the request stream before route handlers, risking empty POST bodies | Removed body consumption from middleware; log metadata only |
| 3 | `app/api/middleware/auth_middleware.py` | 14–27, 65, 127 | Debug `print`, `/auth/refresh-token` listed as public while route requires JWT; `/auth/health` not public; raw JWT payload on `request.state.user` | Logger-based errors; public list fixed; `_normalize_user()` sets consistent `request.state.user` |
| 4 | `app/dependencies.py` | 161–284 | `get_current_user` ignored middleware state; missing `phone`/`name` for refresh; `user_id` left as string | Reads `request.state.user` first; `_user_from_payload()` with int coercion |
| 5 | `app/api/routes/auth_routes.py` | 332–345 | `refresh_token` used `current_user["phone"]` / `["name"]` not returned by dependency → **KeyError** | Token includes email/role; refresh uses `.get()`; JWT payload extended on register/login |
| 6 | `app/api/routes/auth_routes.py` | 300–302 | Profile lookup compared string `sub` to integer DB id | Cast `user_id` to `int` before query |
| 7 | `app/ml/models/*.pkl` | — | Model files missing from repo → import-time crash | Ran `python -m app.ml.training.train_models`; added lazy `_ensure_model()` in predictors |
| 8 | `app/ml/inference/upi_predictor.py` | 150 | `load_upi_model()` at import crashed app if models absent | try/except on startup load + `_ensure_model()` before predict |
| 9 | `app/ml/inference/text_predictor.py` | 125 | Same as above for text model | Same lazy-load pattern |
| 10 | `app/main.py` | 280–287, 658–685 | Static mount failed if `static/` missing; 500 responses lacked trace in DEBUG | Conditional static mount; DEBUG adds `detail` + `traceback` |
| 11 | `app/api/routes/auth_routes.py` | 399 | `print("AUTH ROUTES LOADED")` in production | Removed |

---

## Verification Results

### Authentication (JWT)

| Step | Endpoint | Status |
|------|----------|--------|
| Register | `POST /auth/register` | ✅ 200 + `access_token` |
| Login | `POST /auth/login` | ✅ 200 |
| Profile | `GET /auth/profile` | ✅ 200 (Bearer) |
| Refresh | `POST /auth/refresh-token` | ✅ 200 (Bearer) |
| Logout | `POST /auth/logout` | ✅ 200 (Bearer) |
| Middleware | `request.state.user` | ✅ Normalized dict on protected routes |
| Dependency | `Depends(get_current_user)` | ✅ Uses middleware state or Bearer |

### Public endpoints (no token)

`GET /`, `/ping`, `/system/info`, `/health/*`, `/fraud/health`, `/qr/health`, `/sms/health`, `/auth/login`, `/auth/register`, `/auth/health`, `/docs`, `/openapi.json`

### Protected endpoints (Bearer required)

`POST /fraud/scan-qr`, `/fraud/scan-text`, `/fraud/bulk-scan`, `GET /fraud/history`, `POST /fraud/report-upi`, `POST /sms/scan`, `/sms/bulk-scan`, `GET /sms/history`, `POST /sms/report`, `GET /qr/history`, `GET /auth/profile`, `POST /auth/refresh-token`, `POST /auth/logout`

**Smoke test:** `python scripts/test_all_endpoints.py` → **29/29 passed**

---

## How to Run

```powershell
cd "s:\working cp python\BACKEND"
$env:PYTHONPATH="."

# First-time: install deps + train models
pip install -r requirements.txt
python -m app.ml.training.train_models

# Start API
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Swagger
# http://127.0.0.1:8000/docs
```

### Swagger workflow

1. `POST /auth/register` or `POST /auth/login` → copy `access_token`
2. Click **Authorize** → `Bearer <token>`
3. Call any protected fraud/SMS/QR endpoint

---

## Remaining Recommendations (not blocking)

1. **Pin bcrypt** in `requirements.txt` to `bcrypt>=4.0,<5` OR keep direct bcrypt usage (current fix).
2. **Alembic migrations** for schema changes instead of `create_all` only.
3. **Redis token blacklist** for true logout/revocation.
4. **Rate limiting** on auth and scan endpoints.
5. **Remove optional heavy deps** (`torch`, `transformers`) from default `requirements.txt` if unused at runtime.
6. Add **`/qr/scan-image`** to automated tests (requires multipart file upload).

---

## Files Created

- `app/utils/password.py` — production password hashing
- `scripts/test_all_endpoints.py` — automated smoke tests
- `PRODUCTION_FIX_REPORT.md` — this report
