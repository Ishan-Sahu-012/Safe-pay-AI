# app/database/models.py
# ============================================================================
# DATABASE MODELS
# ============================================================================

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Boolean,
    Text,
)
from sqlalchemy.orm import relationship

from app.database.db import Base


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    qr_history = relationship(
        "QRScanHistory",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    scan_history = relationship(
        "ScanHistory",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    sms_history = relationship(
        "SMSScanHistory",
        back_populates="user",
        cascade="all, delete-orphan"
    )


class ScanHistory(Base):

    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_type = Column(String, nullable=False)
    input_value = Column(Text, nullable=False)
    risk_score = Column(Float)
    risk_level = Column(String)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship(
        "User",
        back_populates="scan_history"
    )


class SMSScanHistory(Base):

    __tablename__ = "sms_scan_history"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    sender = Column(String)
    message = Column(Text)
    risk_score = Column(Float)
    risk_level = Column(String)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship(
        "User",
        back_populates="sms_history"
    )


class QRScanHistory(Base):

    __tablename__ = "qr_scan_history"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    upi_id = Column(String)
    merchant_name = Column(String)
    amount = Column(Float)
    raw_qr = Column(String)
    risk_score = Column(Float)
    risk_level = Column(String)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship(
        "User",
        back_populates="qr_history"
    )


class Message(Base):

    __tablename__ = "messages"

    message_id = Column(Integer, primary_key=True, autoincrement=True)
    label = Column(String)
    message = Column(Text)
    message_length = Column(Integer)
    scam_category = Column(String)
    marathi_category = Column(String)
    risk_score = Column(Integer)
    risk_level = Column(String)


class UPIMerchantRegistry(Base):

    __tablename__ = "upi_merchant_registry"

    merchant_id = Column(String, primary_key=True)
    upi_id = Column(String, unique=True, index=True)
    merchant_name = Column(String)
    is_verified_merchant = Column(Integer)
    historical_report_count = Column(Integer)
    merchant_avg_transaction_val = Column(Float)


class URLSecurityRegistry(Base):

    __tablename__ = "url_security_registry"

    url_id = Column(String, primary_key=True)
    raw_target_url = Column(String)
    associated_brand = Column(String)
    safety_status = Column(String)
    tld_extension = Column(String)


class CommunicationInterceptLog(Base):

    __tablename__ = "communication_intercept_logs"

    message_id = Column(String, primary_key=True)
    sender_address = Column(String)
    message_body = Column(Text)
    timestamp_received = Column(DateTime, default=datetime.utcnow)
    reported_scam_category = Column(String)

