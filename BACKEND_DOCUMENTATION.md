# SafePay AI Backend Documentation

## Overview

SafePay AI is a Python backend that provides hybrid fraud detection for UPI ID transactions, QR codes, phishing SMS, and suspicious links. The backend combines:

- FastAPI REST API endpoints
- WebSockets for real-time threat alerts
- SQLAlchemy persistence (MySQL)
- JWT authentication
- QR image decoding and UPI parsing
- SMS/text scam detection
- Rule-based risk analysis and heuristics
- Health and system monitoring

This documentation replaces the previous backend notes with an accurate reference for the current codebase.

---

## Repository Layout

### Root files

- `README.md` — repository overview and quick start.
- `Dockerfile` — production container build instructions.
- `requirements.txt` — Python dependencies.
- `run.py` — application launcher, diagnostics, and server runner.
- `BACKEND_DOCUMENTATION.md` — backend reference documentation.
- `.env` — environment configuration file (not committed).

### Main backend package: `app/`

- `app/main.py` — FastAPI app definition, startup lifecycle, middleware registration, WebSocket mounting, and route mounting.
- `app/config.py` — centralized Pydantic settings, feature flags, and environment loading.
- `app/dependencies.py` — FastAPI dependency providers, JWT decoding, current user extraction, and admin guard.
- `app/database/db.py` — SQLAlchemy engine initialization, session management, health helpers, and schema creation.
- `app/database/models.py` — SQLAlchemy ORM models for users, scan history, SMS history, QR history, registries, and audit logs.
- `app/database/schemas.py` — data validation and response models for API payloads.
- `app/api/middleware/` — custom middleware for request logging and authentication.
- `app/api/routes/` — API routers for authentication, fraud detection, QR scanning, SMS scanning, and health checks.
- `app/services/` — core business logic for fraud detection, QR processing, risk scoring, rule evaluation, and SMS scanning.
- `app/ml/` — machine learning training, inference wrappers, feature engineering, and serialized model files (if applicable).
- `app/utils/` — shared helpers, constants, validators, cache implementation, and structured logging.
- `app/tests/` — automated test cases for API and fraud logic.

---

## Architecture

SafePay AI uses a layered architecture:

1. Client sends HTTP requests to the FastAPI server.
2. Middleware validates requests and optionally authenticates JWT tokens.
3. Route controllers parse request payloads and inject dependencies.
4. Services orchestrate fraud detection logic.
5. Heuristics engines compute risk scores based on explicit rules and behavioral flags.
6. Scan results are persisted to the database and returned to the caller, while also being broadcasted over WebSockets.

### Core components

- `app/api/routes/` — endpoint definitions and request/response handling.
- `app/services/fraud_detection_service.py` — centralized fraud logic and response normalization.
- `app/services/risk_score_service.py` — calculates dynamic risk scores based on multiple threat vectors.
- `app/database/models.py` — primary data schema for users and scans.
- `app/config.py` — app settings and feature toggles.

---

## Setup

### Prerequisites

- Python 3.10 or 3.11
- pip
- Recommended: system libraries for pyzbar and OpenCV to support QR image scanning.
- MySQL Database

### Install dependencies

```bash
cd BACKEND
python -m venv env
.\env\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Environment variables

Create a `.env` file in the backend root with values such as:

```ini
APP_NAME=SafePay AI
APP_VERSION=1.0.0
DEBUG=True
ENVIRONMENT=development
HOST=0.0.0.0
PORT=8000
SECRET_KEY=YOUR_SECURE_SECRET_KEY
JWT_SECRET_KEY=YOUR_SECURE_JWT_SECRET_KEY
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/safepay
```

---

## Running the Backend

### Development mode

```bash
python run.py
```

### Production mode

```bash
python run.py --prod
```

### Custom host/port

```bash
python run.py --host 127.0.0.1 --port 9000
```

### Direct FastAPI launch

```bash
uvicorn app.main:app --reload
```

### Useful runtime URLs

- http://localhost:8000/
- http://localhost:8000/docs
- http://localhost:8000/redoc
- http://localhost:8000/dashboard
- http://localhost:8000/ping

---

## API Endpoints

### Authentication

#### POST `/auth/register`

Registers a new user.

Request body:
```json
{
  "name": "string",
  "email": "email@example.com",
  "phone": "9999999999",
  "password": "securepassword"
}
```

#### POST `/auth/login`

Authenticates an existing user.

Request body:
```json
{
  "phone": "9999999999",
  "password": "securepassword"
}
```

---

### Fraud Detection

All protected routes require `Authorization: Bearer <token>`.

#### POST `/fraud/scan-qr`

Detects UPI fraud risk.

Request body:
```json
{
  "upi_id": "rahul@oksbi",
  "amount": 500.0,
  "merchant_name": "Merchant Name"
}
```

#### POST `/fraud/bulk-scan`

Analyzes multiple UPI IDs concurrently for scam risk.

---

### QR Detection

#### POST `/qr/analyze-payload`

Decodes and evaluates raw string payloads from scanned QR codes, avoiding the need for image uploads when the payload is already known.

#### POST `/qr/scan-image`

Uploads and decodes a physical QR image file.

- Accepts `multipart/form-data`
- Field: `file`
- Accepts `image/png`, `image/jpeg`, `image/jpg`

---

### SMS Scam Detection

#### POST `/sms/scan`

Analyzes text messages or URLs for fraud.

Request body:
```json
{
  "message": "Urgent: update your bank account details.",
  "sender": "BankName"
}
```

#### POST `/sms/bulk-scan`

Analyzes an array of strings (URLs or texts) concurrently.

---

### Real-Time Alerts (WebSocket)

#### WS `/ws/alerts?token=<jwt_token>`

Connect to this WebSocket to receive real-time streams of newly detected threats and system alerts.

---

### Health & Monitoring

- `GET /health/` — Lightweight service health check.
- `GET /health/database` — Validates DB connectivity, returns latency.
- `GET /health/system` — Returns CPU, memory, disk, and uptime metrics.
- `GET /health/full-report` — Enterprise status report for DB, ML, and system.
- `GET /ping` — Simple ping test.

---

## Authentication Flow

- User registration and login create JWT tokens.
- Tokens encode `user_id`, `phone`, `name`, `email`, and `role`.
- `app/dependencies.py` decodes JWT tokens and verifies expiration.
- `get_current_user` is the dependency used by protected routes.
- Invalid or expired tokens return HTTP 401.

---

## Database Schema

The backend stores:

### `users`
- `id`, `name`, `email`, `phone`, `password`, `role`, `is_active`, `created_at`

### `scan_history`
Generic scan records used by fraud and text scanning routes.

### `sms_scan_history`
Stores SMS scan details, including sender and message content.

### `qr_scan_history`
Stores QR scan results, raw QR payload, parsed UPI ID, merchant name, and risk score.

### `messages`
Dataset examples and labeled messages used for analysis.

### `upi_merchant_registry`
Merchant reputation registry with verification and report metadata.

### `url_security_registry`
URL threat registry for suspicious domain tracking.

### `communication_intercept_logs`
Audit trail for intercepted communications and reported scams.

---

## Fraud Intelligence

### Fraud scoring

- `app/services/fraud_detection_service.py` formats and normalizes the final risk response.
- `app/services/risk_score_service.py` calculates the hybrid risk score using behavioral and rule-based heuristic weights.
- `app/services/fraud_patterns/message_analyzer.py` handles NLP heuristics for SMS text and shortened links.
- The hybrid intelligence combines threat keyword detection, structural analysis, and historical database matching.

---

## Services and Business Logic

- `app/services/fraud_detection_service.py` — orchestrates prediction and response formatting.
- `app/services/qr_service.py` — QR image handling and payload parsing.
- `app/services/risk_score_service.py` — risk level mapping and score interpretation.
- `app/services/rule_engine.py` — threat rules and heuristic evaluations.
- `app/services/sms_service.py` — SMS text analysis and recommendation generation.

---

## Configuration

`app/config.py` contains settings and feature flags loaded from `.env`.

Important flags:
- `APP_NAME`, `APP_VERSION`, `DEBUG`, `ENVIRONMENT`
- `HOST`, `PORT`, `WORKERS`
- `SECRET_KEY`, `JWT_SECRET_KEY`, `JWT_ALGORITHM`
- `DATABASE_URL`
- `ENABLE_QR_SCANNING`, `ENABLE_SMS_ANALYSIS`, `ENABLE_REALTIME_ALERTS`, `ENABLE_HYBRID_INTELLIGENCE`
- `ALLOWED_ORIGINS`

---

## Chrome Extension Integration

The Chrome extension is located in `chrome-extension/` and communicates with the backend via REST APIs and WebSockets.

### Install guide

1. Run the backend (`python run.py`).
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable "Developer mode".
4. Click "Load unpacked" and select the `BACKEND/chrome-extension` folder.
