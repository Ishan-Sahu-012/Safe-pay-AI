# app/ml/training/train_models.py

"""
==============================================================================
SafePay AI — Master Training Script
==============================================================================

Purpose
-------
Train and save all SafePay ML models.

Models
------
1. model1_upi.pkl
   → UPI Fraud Detection

2. model2_text.pkl
   → SMS / Email Scam Detection

3. model3.pkl
   → Transaction / URL Fraud Detection

Run Once
--------
python app/ml/training/train_models.py

Output
------
app/ml/models/
    ├── model1_upi.pkl
    ├── model2_text.pkl
    └── model3.pkl

app/ml/plots/
    ├── model1/
    ├── model2/
    └── model3/

==============================================================================

Reference Architecture:
:contentReference[oaicite:0]{index=0}

==============================================================================
"""

import os
import time
import traceback
from datetime import datetime

from app.utils.logger import logger

# ============================================================================
# MODEL 1 IMPORTS
# ============================================================================

from app.ml.training.dataset_loader import (
    load_combined_text_dataset,
    load_combined_upi_dataset,
    load_combined_url_dataset,
)

from app.ml.training.model1_upi_fraud_classifier import (

    UPIFraudClassifier,
)

# ============================================================================
# MODEL 2 IMPORTS
# ============================================================================

from app.ml.training.model2_text_classifier import (

    TextScamClassifier,
)

# ============================================================================
# MODEL 3 IMPORTS
# ============================================================================

from app.ml.training.model3_url_fraud_analyzer import (

    URLFraudAnalyzer,
)

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = "app/ml"

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

PLOT_DIR = os.path.join(
    BASE_DIR,
    "plots"
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

# ============================================================================
# MODEL SAVE PATHS
# ============================================================================

MODEL1_SAVE_PATH = os.path.join(

    MODEL_DIR,

    "model1_upi.pkl"
)

MODEL2_SAVE_PATH = os.path.join(

    MODEL_DIR,

    "model2_text.pkl"
)

MODEL3_SAVE_PATH = os.path.join(

    MODEL_DIR,

    "model3.pkl"
)

# ============================================================================
# DIRECTORY SETUP
# ============================================================================

def setup_directories():

    """
    Create required directories.
    """

    directories = [

        MODEL_DIR,

        PLOT_DIR,

        DATA_DIR,

        os.path.join(PLOT_DIR, "model1"),

        os.path.join(PLOT_DIR, "model2"),

        os.path.join(PLOT_DIR, "model3")
    ]

    for directory in directories:

        os.makedirs(
            directory,
            exist_ok=True
        )

    logger.info(
        "📂 Training directories initialized"
    )

# ============================================================================
# TRAIN MODEL 1
# ============================================================================

def train_model1():

    """
    Train UPI Fraud Model.
    """

    try:

        logger.info(
            """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🏦 TRAINING MODEL 1
UPI FRAUD CLASSIFIER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        start = time.time()

        # --------------------------------------------------------------------
        # Dataset
        # --------------------------------------------------------------------

        dataset = load_combined_upi_dataset(include_synthetic=True)

        dataset_path = os.path.join(

            DATA_DIR,

            "upi_fraud_dataset.csv"
        )

        dataset.to_csv(

            dataset_path,

            index=False
        )

        logger.info(
            f"📊 Dataset saved: {dataset_path}"
        )

        # --------------------------------------------------------------------
        # Model
        # --------------------------------------------------------------------

        classifier = UPIFraudClassifier()

        classifier.fit(dataset)

        classifier.save(
            MODEL1_SAVE_PATH
        )

        # --------------------------------------------------------------------
        # Time
        # --------------------------------------------------------------------

        duration = round(

            time.time() - start,

            2
        )

        logger.info(
            f"""
✅ MODEL 1 TRAINED SUCCESSFULLY

💾 Saved:
{MODEL1_SAVE_PATH}

⏱️ Duration:
{duration} sec
"""
        )

        return {

            "success": True,

            "model": "model1_upi",

            "duration": duration
        }

    except Exception as e:

        logger.error(
            f"""
❌ MODEL 1 TRAINING FAILED

🧠 Error:
{str(e)}

📌 Traceback:
{traceback.format_exc()}
"""
        )

        return {

            "success": False,

            "error": str(e)
        }

# ============================================================================
# TRAIN MODEL 2
# ============================================================================

def train_model2():

    """
    Train Text Scam Model.
    """

    try:

        logger.info(
            """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📩 TRAINING MODEL 2
TEXT SCAM CLASSIFIER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        start = time.time()

        # --------------------------------------------------------------------
        # Dataset
        # --------------------------------------------------------------------

        dataset = load_combined_text_dataset(include_synthetic=True)

        dataset_path = os.path.join(

            DATA_DIR,

            "text_scam_dataset.csv"
        )

        dataset.to_csv(

            dataset_path,

            index=False
        )

        logger.info(
            f"📊 Dataset saved: {dataset_path}"
        )

        # --------------------------------------------------------------------
        # Model
        # --------------------------------------------------------------------

        classifier = TextScamClassifier()

        classifier.fit(dataset)

        classifier.save(
            MODEL2_SAVE_PATH
        )

        # --------------------------------------------------------------------
        # Time
        # --------------------------------------------------------------------

        duration = round(

            time.time() - start,

            2
        )

        logger.info(
            f"""
✅ MODEL 2 TRAINED SUCCESSFULLY

💾 Saved:
{MODEL2_SAVE_PATH}

⏱️ Duration:
{duration} sec
"""
        )

        return {

            "success": True,

            "model": "model2_text",

            "duration": duration
        }

    except Exception as e:

        logger.error(
            f"""
❌ MODEL 2 TRAINING FAILED

🧠 Error:
{str(e)}

📌 Traceback:
{traceback.format_exc()}
"""
        )

        return {

            "success": False,

            "error": str(e)
        }

# ============================================================================
# TRAIN MODEL 3
# ============================================================================

def train_model3():

    """
    Train URL / Transaction Fraud Model.
    """

    try:

        logger.info(
            """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 TRAINING MODEL 3
URL FRAUD ANALYZER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        start = time.time()

        # --------------------------------------------------------------------
        # Dataset
        # --------------------------------------------------------------------

        dataset = load_combined_url_dataset(include_synthetic=True)

        dataset_path = os.path.join(

            DATA_DIR,

            "url_fraud_dataset.csv"
        )

        dataset.to_csv(

            dataset_path,

            index=False
        )

        logger.info(
            f"📊 Dataset saved: {dataset_path}"
        )

        # --------------------------------------------------------------------
        # Model
        # --------------------------------------------------------------------

        analyzer = URLFraudAnalyzer()

        analyzer.fit(dataset)

        analyzer.save(
            MODEL3_SAVE_PATH
        )

        # --------------------------------------------------------------------
        # Time
        # --------------------------------------------------------------------

        duration = round(

            time.time() - start,

            2
        )

        logger.info(
            f"""
✅ MODEL 3 TRAINED SUCCESSFULLY

💾 Saved:
{MODEL3_SAVE_PATH}

⏱️ Duration:
{duration} sec
"""
        )

        return {

            "success": True,

            "model": "model3",

            "duration": duration
        }

    except Exception as e:

        logger.error(
            f"""
❌ MODEL 3 TRAINING FAILED

🧠 Error:
{str(e)}

📌 Traceback:
{traceback.format_exc()}
"""
        )

        return {

            "success": False,

            "error": str(e)
        }

# ============================================================================
# TRAIN ALL MODELS
# ============================================================================

def train_all_models():

    """
    Master training orchestrator.
    """

    logger.info(
        """
══════════════════════════════════════
🚀 SAFEPAY AI TRAINING STARTED
══════════════════════════════════════
"""
    )

    overall_start = time.time()

    # ------------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------------

    setup_directories()

    # ------------------------------------------------------------------------
    # Train Sequentially
    # ------------------------------------------------------------------------

    results = []

    results.append(
        train_model1()
    )

    results.append(
        train_model2()
    )

    results.append(
        train_model3()
    )

    # ------------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------------

    total_time = round(

        time.time() - overall_start,

        2
    )

    successful = sum(

        1 for r in results

        if r["success"]
    )

    failed = len(results) - successful

    logger.info(
        f"""
══════════════════════════════════════
🎯 TRAINING COMPLETE
══════════════════════════════════════

✅ Successful Models : {successful}
❌ Failed Models     : {failed}

⏱️ Total Time:
{total_time} sec

🕒 Finished At:
{datetime.utcnow()}

📦 Models Saved:
{MODEL_DIR}

📊 Plots Saved:
{PLOT_DIR}

══════════════════════════════════════
"""
    )

    return {

        "success": failed == 0,

        "successful_models": successful,

        "failed_models": failed,

        "results": results,

        "total_time_sec": total_time
    }

# ============================================================================
# VERIFY SAVED MODELS
# ============================================================================

def verify_models():

    """
    Verify all model files exist.
    """

    required = [

        MODEL1_SAVE_PATH,

        MODEL2_SAVE_PATH,

        MODEL3_SAVE_PATH
    ]

    missing = []

    for path in required:

        if not os.path.exists(path):

            missing.append(path)

    if missing:

        logger.error(
            f"""
❌ MODEL VERIFICATION FAILED

Missing:
{missing}
"""
        )

        return False

    logger.info(
        """
✅ ALL MODELS VERIFIED
"""
    )

    return True

# ============================================================================
# MAIN ENTRY
# ============================================================================

if __name__ == "__main__":

    print(
        """
╔════════════════════════════════════╗
║      SAFEPAY AI TRAINING ENGINE   ║
╚════════════════════════════════════╝
"""
    )

    result = train_all_models()

    verify_models()

    print(

        f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎉 TRAINING FINISHED

Success:
{result['success']}

Models Trained:
{result['successful_models']}

Total Time:
{result['total_time_sec']} sec
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )