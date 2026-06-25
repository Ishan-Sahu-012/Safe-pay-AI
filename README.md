Here’s the cleaned README in plain text format so you can copy-paste directly:

---

 SafePay AI — Enterprise-Grade Fraud Intelligence

SafePay AI is an enterprise-grade hybrid AI backend designed to secure digital payments. It targets UPI ID fraud, QR code scams, phishing SMS, and malicious URLs by combining Machine Learning (Scikit-Learn/NLP) with Heuristic Rule Engines. The system delivers real-time risk scores, behavioral threat intelligence, and automatic alerts to safeguard financial applications.

---

   Key Features
-  JWT Authentication: Secure user management with roles (user, moderator, admin)
-  Hybrid Intelligence Engine: ML probability models + heuristic rules for risk scoring
-  QR Code Scanner: Real-time decoding (PNG, JPEG, JPG) via OpenCV/pyzbar, UPI parsing
-  SMS Intelligence: Detects phishing, OTP fraud, spam keywords, sender reputation, URL extraction
-  URL Fraud Analysis: Evaluates links using entropy, subdomain counts, IP hosts, blacklist checks
-  Startup Diagnostics: Auto-checks DB connectivity, ML model health, directory integrity
-  Dockerized Deployment: Hardened, lightweight containers with API-level health checks

---

 Repository Structure
BACKEND/
├── .env                  # Environment variables
├── Dockerfile            # Hardened multi-stage container
├── requirements.txt      # Dependencies (FastAPI, ML, CV)
├── run.py                # CLI launcher with diagnostics
├── safepay.db            # SQLite fallback DB
└── app/
    ├── main.py           # FastAPI entrypoint
    ├── config.py         # Settings & env loader
    ├── dependencies.py   # Auth, DB, API key guards
    ├── api/routes/       # REST API endpoints
    ├── database/         # Persistence layer
    ├── ml/               # AI models & training
    ├── services/         # Core services
    ├── utils/            # Helpers & validators
    └── tests/            # Automated test suite

---

 Architecture
Client → FastAPI → Middleware → Routes → Services → Rule Engine + ML → Orchestrator → DB → Risk Score → Client

---

 Setup
Prerequisites:
- Python 3.10 or 3.11
- Windows: Install OpenCV redistributables & zbar for QR scanning

Steps:
1. Enter backend directory  
   cd BACKEND  

2. Configure environment  
   cp .env.example .env  

3. Create & activate virtual environment  
   python -m venv env  
   .\env\Scripts\activate.ps1   # PowerShell  
   .\env\Scripts\activate.bat   # CMD  

4. Install dependencies  
   pip install -r requirements.txt  

5. Train ML models  
   python app/ml/training/train_models.py  

---

  Running
Development (auto-reload):  
python run.py  

Production mode:  
python run.py --prod  

Custom host/port:  
python run.py --host 127.0.0.1 --port 9000  

Access:  
- Server → http://localhost:8000  
- Swagger → /docs  
- ReDoc → /redoc  
- Ping → /ping  
- Dashboard → /dashboard  

---

--> Chrome Extension
1. Start backend (python run.py)  
2. Open Chrome → chrome://extensions  
3. Enable Developer Mode → Load unpacked → BACKEND/chrome-extension  
4. Register/login and scan text, UPI, or QR codes  

---

--> Docker Deployment
Build image:  
docker build -t safepay-ai:latest .  

Run container:  
docker run -d --name safepay-backend -p 8000:8000 safepay-ai:latest  

---

--> Testing
Run tests:  
pytest app/tests/  

Coverage report:  
pytest --cov=app app/tests/  

---

