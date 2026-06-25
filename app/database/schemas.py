# app/database/schemas.py

from datetime import datetime
from typing import Optional, List

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    ConfigDict
)

# ============================================================================
# BASE RESPONSE
# ============================================================================

class BaseResponse(BaseModel):

    success: bool = True

    message: str = "Request successful"

# ============================================================================
# AUTH SCHEMAS
# ============================================================================

class RegisterSchema(BaseModel):

    name: str = Field(
        min_length=2,
        max_length=100,
        examples=["Ishan"]
    )

    email: EmailStr

    phone: str = Field(
        min_length=10,
        max_length=15,
        examples=["9876543210"]
    )

    password: str = Field(
        max_length=100
    )


class LoginSchema(BaseModel):

    phone: str

    password: str


class UserResponseSchema(BaseModel):

    id: int

    name: str

    email: str

    phone: str

    model_config = ConfigDict(
        from_attributes=True
    )


class AuthResponseSchema(BaseResponse):

    access_token: str

    token_type: str = "bearer"

    user: UserResponseSchema

# ============================================================================
# QR SCHEMAS
# ============================================================================

class QRScanSchema(BaseModel):

    upi_id: str = Field(
        min_length=3,
        max_length=150,
        examples=["rahul@oksbi"]
    )

    amount: float = Field(
        ge=0,
        examples=[500]
    )

    merchant_name: Optional[str] = None


class QRDataSchema(BaseModel):

    upi_id: str

    merchant_name: Optional[str]

    amount: float

    raw_qr: Optional[str] = None


class FraudAnalysisSchema(BaseModel):

    risk_score: float

    risk_level: str

    status: str

    ml_probability: Optional[float] = None

    matched_rules: Optional[List[str]] = []


class QRScanResponseSchema(BaseResponse):

    qr_data: QRDataSchema

    analysis: FraudAnalysisSchema

# ============================================================================
# SMS SCHEMAS
# ============================================================================

class SMSScanSchema(BaseModel):

    message: str = Field(
        min_length=5,
        max_length=5000
    )

    sender: Optional[str] = None


class SMSAnalysisSchema(BaseModel):

    risk_score: float

    risk_level: str

    status: str

    ml_score: Optional[float] = None

    matched_keywords: List[str] = []

    detected_urls: List[str] = []

    phone_numbers: List[str] = []


class SMSResponseSchema(BaseResponse):

    analysis: SMSAnalysisSchema

# ============================================================================
# HISTORY SCHEMAS
# ============================================================================

class ScanHistorySchema(BaseModel):

    id: int

    scan_type: str

    input_value: str

    risk_score: float

    risk_level: str

    status: str

    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


class ScanHistoryResponseSchema(BaseResponse):

    total_records: int

    history: List[ScanHistorySchema]

# ============================================================================
# FRAUD REPORT SCHEMAS
# ============================================================================

class FraudReportSchema(BaseModel):

    upi_id: Optional[str] = None

    sender: Optional[str] = None

    reason: str = Field(
        min_length=5,
        max_length=500
    )

    message: Optional[str] = None

# ============================================================================
# HEALTH SCHEMAS
# ============================================================================

class HealthResponseSchema(BaseModel):

    success: bool

    service: str

    status: str

    timestamp: datetime


class SystemResourceSchema(BaseModel):

    cpu_percent: float

    memory_percent: float

    disk_percent: float


class FullHealthSchema(BaseModel):

    success: bool

    overall_status: str

    timestamp: datetime

    resources: SystemResourceSchema

# ============================================================================
# ML MODEL RESPONSE
# ============================================================================

class MLModelPredictionSchema(BaseModel):

    prediction: str

    probability: float

    confidence: float

    model_version: Optional[str] = "v1"

# ============================================================================
# BULK SCAN
# ============================================================================

class BulkQRScanSchema(BaseModel):

    scans: List[QRScanSchema]


class BulkSMSScanSchema(BaseModel):

    messages: List[str]


class BulkScanResultSchema(BaseModel):

    input_value: str

    risk_score: float

    risk_level: str

    status: str


class BulkScanResponseSchema(BaseResponse):

    total_scans: int

    results: List[BulkScanResultSchema]

# ============================================================================
# TOKEN SCHEMAS
# ============================================================================

class TokenSchema(BaseModel):

    access_token: str

    token_type: str


class TokenPayloadSchema(BaseModel):

    user_id: int

    phone: str

    name: str

# ============================================================================
# ERROR RESPONSE
# ============================================================================

class ErrorResponseSchema(BaseModel):

    success: bool = False

    error: str

    detail: Optional[str] = None

# ============================================================================
# PAGINATION
# ============================================================================

class PaginationSchema(BaseModel):

    page: int = 1

    limit: int = 10


class PaginatedResponseSchema(BaseResponse):

    page: int

    limit: int

    total: int

# ============================================================================
# DATABASE STATUS
# ============================================================================

class DatabaseHealthSchema(BaseModel):

    success: bool

    latency_ms: Optional[float]

    database: str

# ============================================================================
# AI EXPLANATION SCHEMA
# ============================================================================

class AIExplanationSchema(BaseModel):

    explanation: str

    reasons: List[str]

    suggestions: List[str]

# ============================================================================
# WEBSOCKET MESSAGE SCHEMA
# ============================================================================

class WebSocketMessageSchema(BaseModel):

    type: str

    message: str

    timestamp: datetime

# ============================================================================
# SECURITY ALERT SCHEMA
# ============================================================================

class SecurityAlertSchema(BaseModel):

    alert_type: str

    severity: str

    message: str

    created_at: datetime

# ============================================================================
# API METADATA SCHEMA
# ============================================================================

class APIMetadataSchema(BaseModel):

    request_id: Optional[str]

    process_time_ms: Optional[float]

# ============================================================================
# STANDARDIZED API RESPONSE
# ============================================================================

class StandardAPIResponseSchema(BaseModel):

    success: bool

    message: str

    data: Optional[dict] = None

    metadata: Optional[APIMetadataSchema] = None

# ============================================================================
# EXAMPLE SCHEMA FOR DOCUMENTATION
# ============================================================================

class ExampleFraudResponseSchema(BaseModel):

    success: bool = True

    message: str = "Fraud analysis completed"

    data: dict = {

        "risk_score": 87,

        "risk_level": "HIGH",

        "status": "FRAUD",

        "reasons": [

            "High entropy UPI",

            "Blacklisted merchant",

            "Suspicious transaction amount"
        ]
    }

# ============================================================================
# OPENAPI TAG DESCRIPTIONS
# ============================================================================

API_TAGS_METADATA = [

    {
        "name": "Authentication",

        "description":
            "🔐 User authentication and JWT management"
    },

    {
        "name": "Fraud Detection",

        "description":
            "🚨 AI-powered fraud analysis APIs"
    },

    {
        "name": "QR Detection",

        "description":
            "📸 QR code scanning and UPI extraction"
    },

    {
        "name": "SMS Scam Detection",

        "description":
            "📩 Scam SMS and phishing analysis"
    },

    {
        "name": "Health Monitoring",

        "description":
            "🩺 System monitoring and diagnostics"
    }
]