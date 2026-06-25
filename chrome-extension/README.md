# SafePay Chrome Extension

This Chrome extension is bundled with the SafePay backend project and provides an interactive popup UI to analyze SMS/text fraud, UPI/QR fraud, and page threats.

## Installation

1. Start the SafePay backend server:
   ```bash
   python run.py
   ```
2. Open Chrome and go to `chrome://extensions`
3. Enable **Developer mode**
4. Choose **Load unpacked**
5. Select the `chrome-extension/` directory in this repository

## Features

* Login and register with the SafePay backend
* Scan SMS/text messages for fraud
* Verify UPI IDs and transaction amounts
* Upload QR images for QR fraud detection
* View scan history and health reports
* Detect suspicious page content via content script highlights

## Backend API

The extension uses these backend endpoints:

* `POST /auth/login`
* `POST /auth/register`
* `GET /auth/profile`
* `POST /auth/refresh-token`
* `POST /auth/logout`
* `POST /fraud/scan-text`
* `POST /fraud/scan-qr`
* `POST /sms/scan`
* `POST /qr/scan-image`
* `GET /fraud/history`
* `GET /sms/history`
* `GET /qr/history`
* `GET /health/full-report`
* `GET /ping`

## Notes

* The extension currently uses `http://localhost:8000` as the backend URL.
* If the backend host or port changes, update `background.js` and `api.js` accordingly.
* The backend is configured to allow Chrome extension origins.
