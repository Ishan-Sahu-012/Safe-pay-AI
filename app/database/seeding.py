import csv
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from app.config import BASE_DIR
from app.database.models import UPIMerchantRegistry, URLSecurityRegistry, CommunicationInterceptLog, Message
from app.utils.logger import logger

def seed_database_registry(db: Session):
    """
    Check if registry tables are empty and seed them from CSV datasets if they are.
    """
    # 1. UPIMerchantRegistry
    try:
        if db.query(UPIMerchantRegistry).first() is None:
            csv_path = BASE_DIR / "app" / "database" / "datasets" / "db_upi_merchant_registry.csv"
            if csv_path.exists():
                logger.info(f"🗄️ Seeding UPIMerchantRegistry from {csv_path}...")
                with csv_path.open(mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    merchants = []
                    for row in reader:
                        merchants.append(UPIMerchantRegistry(
                            merchant_id=row["merchant_id"],
                            upi_id=row["upi_id"],
                            merchant_name=row["merchant_name"],
                            is_verified_merchant=int(row["is_verified_merchant"]),
                            historical_report_count=int(row["historical_report_count"]),
                            merchant_avg_transaction_val=float(row["merchant_avg_transaction_val"])
                        ))
                    db.bulk_save_objects(merchants)
                    db.commit()
                    logger.info(f"✅ Seeded {len(merchants)} merchants.")
            else:
                logger.warning(f"⚠️ Seeding skipped: {csv_path} not found.")
    except Exception as e:
        logger.error(f"❌ Error seeding merchants: {e}")
        db.rollback()

    # 2. URLSecurityRegistry
    try:
        if db.query(URLSecurityRegistry).first() is None:
            csv_path = BASE_DIR / "app" / "database" / "datasets" / "db_url_security_registry.csv"
            if csv_path.exists():
                logger.info(f"🗄️ Seeding URLSecurityRegistry from {csv_path}...")
                with csv_path.open(mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    urls = []
                    for row in reader:
                        urls.append(URLSecurityRegistry(
                            url_id=row["url_id"],
                            raw_target_url=row["raw_target_url"],
                            associated_brand=row["associated_brand"],
                            safety_status=row["safety_status"],
                            tld_extension=row["tld_extension"]
                        ))
                    db.bulk_save_objects(urls)
                    db.commit()
                    logger.info(f"✅ Seeded {len(urls)} URLs.")
            else:
                logger.warning(f"⚠️ Seeding skipped: {csv_path} not found.")
    except Exception as e:
        logger.error(f"❌ Error seeding URLs: {e}")
        db.rollback()

    # 3. CommunicationInterceptLog
    try:
        if db.query(CommunicationInterceptLog).first() is None:
            csv_path = BASE_DIR / "app" / "database" / "datasets" / "db_communication_intercept_logs.csv"
            if csv_path.exists():
                logger.info(f"🗄️ Seeding CommunicationInterceptLog from {csv_path}...")
                with csv_path.open(mode="r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    logs = []
                    for row in reader:
                        ts = datetime.utcnow()
                        if row["timestamp_received"]:
                            try:
                                ts = datetime.strptime(row["timestamp_received"], "%Y-%m-%d %H:%M:%S")
                            except ValueError:
                                pass
                        logs.append(CommunicationInterceptLog(
                            message_id=row["message_id"],
                            sender_address=row["sender_address"],
                            message_body=row["message_body"],
                            timestamp_received=ts,
                            reported_scam_category=row["reported_scam_category"]
                        ))
                    db.bulk_save_objects(logs)
                    db.commit()
                    logger.info(f"✅ Seeded {len(logs)} communication intercept logs.")
            else:
                logger.warning(f"⚠️ Seeding skipped: {csv_path} not found.")
    except Exception as e:
        logger.error(f"❌ Error seeding communication logs: {e}")
        db.rollback()

    # 4. Message
    try:
        if db.query(Message).first() is None:
            csv_path = BASE_DIR / "app" / "database" / "datasets" / "cleaned_spam_v2.csv"
            if csv_path.exists():
                logger.info(f"🗄️ Seeding Message from {csv_path}...")
                with csv_path.open(mode="r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    messages = []
                    for row in reader:
                        messages.append(Message(
                            label=row["label"],
                            message=row["message"],
                            message_length=int(row["message_length"]),
                            scam_category=row["scam_category"],
                            marathi_category=row["marathi_category"],
                            risk_score=int(row["risk_score"]),
                            risk_level=row["risk_level"]
                        ))
                    db.bulk_save_objects(messages)
                    db.commit()
                    logger.info(f"✅ Seeded {len(messages)} messages.")
            else:
                logger.warning(f"⚠️ Seeding skipped: {csv_path} not found.")
    except Exception as e:
        logger.error(f"❌ Error seeding messages: {e}")
        db.rollback()
