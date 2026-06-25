import pytest

from app.services.fraud_patterns.message_analyzer import analyze_message
from app.services.fraud_patterns.qr_analyzer import analyze_qr_content
from app.services.fraud_patterns.url_intel import analyze_single_url


def test_legit_message_with_keyword_stays_low_or_medium():
    msg = "Your OTP for login is 123456. Do not share it with anyone."
    result = analyze_message(msg, sender="AD-SECURE", use_ml=False)
    assert result["fraud_assessment"]["type"] == "message"
    assert result["fraud_assessment"]["risk_level"] in {"low", "medium"}


def test_impersonation_free_email_flagged():
    msg = "Dear customer, SBI account blocked. Verify password now."
    result = analyze_message(
        msg,
        sender="Bank Support",
        sender_email="banksupporthelp@gmail.com",
        use_ml=False,
    )
    assert result["fraud_assessment"]["risk_level"] in {"medium", "high"}
    assert any("Sender mismatch" in i for i in result["fraud_assessment"]["issues"])


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.8/verify?token=abc",
        "http://bit.ly/fakeoffer",
        "ftp://secure-login-update.xyz/sessionid=2",
    ],
)
def test_suspicious_url_patterns(url: str):
    detail = analyze_single_url(url, expand_shorteners=False)
    assert detail["score"] >= 25
    assert detail["issues"]


def test_safe_qr_url_redirect_like_param_medium_or_high():
    qr_text = "https://payments.example.com/pay?sessionid=abc123"
    result = analyze_qr_content(qr_text=qr_text, user_id=1)
    assert result["fraud_assessment"]["type"] == "qr"
    assert result["fraud_assessment"]["risk_level"] in {"medium", "high"}


def test_safe_qr_upi_stays_not_high():
    qr_text = "upi://pay?pa=rahul123@oksbi&pn=Rahul&am=250"
    result = analyze_qr_content(qr_text=qr_text, user_id=1)
    assert result["fraud_assessment"]["type"] == "qr"
    assert result["fraud_assessment"]["risk_level"] in {"low", "medium"}

