from app.services.engine.feature_extractor import FeatureExtractor
from app.services.engine.domain_analysis import DomainAnalyzer
from app.services.engine.upi_analysis import UPIAnalyzer
from app.services.engine.sender_verification import SenderVerifier
from app.services.engine.social_engineering import SocialEngineeringAnalyzer
from app.services.engine.risk_scoring import RiskScoringEngine
from app.services.engine.explainable_ai import ExplainableDecisionEngine
from app.utils.logger import logger
from app.ml.inference.upi_predictor import predict_upi_fraud
from app.ml.inference.text_predictor import predict_text_scam

def execute_fraud_pipeline(
    text: str = None,
    ocr_text: str = None,
    upi_id: str = None,
    amount: float = None,
    merchant_name: str = None,
    sender: str = None,
    url: str = None
) -> dict:
    """
    Main orchestration function for the multi-layer fraud detection engine.
    """
    logger.info("🚀 Starting Multi-Layer Fraud Pipeline")
    
    signal_results = []
    ml_probability = 0.0
    
    # 1. Input Sources & Feature Extraction
    extracted_features = {
        "urls": [],
        "emails": [],
        "phones": [],
        "upi_ids": []
    }
    
    combined_text = " ".join(filter(None, [text, ocr_text]))
    
    if combined_text:
        extracted_features = FeatureExtractor.extract_features(combined_text)
        
    # Explicit inputs take precedence, but we also analyze extracted features
    all_urls = set(extracted_features["urls"])
    if url:
        all_urls.add(url)
        
    all_upis = set(extracted_features["upi_ids"])
    if upi_id:
        all_upis.add(upi_id)
        
    # 2. Domain Reputation Analysis
    for u in all_urls:
        domain_res = DomainAnalyzer.analyze(u)
        if domain_res["score"] > 0:
            signal_results.append(domain_res)
            
    # 3. UPI Fraud Detection
    for u in all_upis:
        upi_res = UPIAnalyzer.analyze(u, merchant_name)
        if upi_res["score"] > 0:
            signal_results.append(upi_res)
            
    # 4. Sender Verification
    if combined_text and sender:
        sender_res = SenderVerifier.analyze(combined_text, sender)
        if sender_res["score"] > 0:
            signal_results.append(sender_res)
            
    # 5. Social Engineering Detection
    if combined_text:
        social_res = SocialEngineeringAnalyzer.analyze(combined_text)
        if social_res["score"] > 0:
            signal_results.append(social_res)
            
    # 6. ML Prediction Layer
    # Call existing ML models to get probability
    if upi_id and amount is not None:
        try:
            # We use seen_before=False etc as defaults for pipeline unless we want to query DB here
            upi_ml = predict_upi_fraud(upi_id, amount)
            # convert risk score out of 100 to probability
            ml_prob = upi_ml.get("risk_score", 0) / 100.0
            if ml_prob > ml_probability:
                ml_probability = ml_prob
        except Exception as e:
            logger.error(f"UPI ML Error: {e}")
            
    if text:
        try:
            # existing text model wrapper
            text_ml = predict_text_scam(text)
            ml_prob = text_ml.get("risk_score", 0) / 100.0
            if ml_prob > ml_probability:
                ml_probability = ml_prob
        except Exception as e:
            logger.error(f"Text ML Error: {e}")

    # 7. Risk Scoring Engine
    scoring_res = RiskScoringEngine.calculate_score(signal_results, ml_probability)
    
    # 8. Explainable Decision Engine
    decision = ExplainableDecisionEngine.get_decision(
        risk_score=scoring_res["risk_score"],
        reasons=scoring_res["reasons"]
    )
    
    logger.info(f"✅ Pipeline Complete: Score {decision['risk_score']} | Level {decision['level']}")
    
    return decision
