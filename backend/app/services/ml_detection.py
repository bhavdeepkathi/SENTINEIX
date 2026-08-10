import os
import joblib
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional

# Determine model directory: assume project root is two levels up from this file (backend/app/services)
BASE_DIR = Path(__file__).resolve().parents[3]  # sentinelx root
MODEL_DIR = BASE_DIR / "ml" / "models"

class MLEngine:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_models()
        return cls._instance

    def _load_models(self):
        self.scaler = joblib.load(MODEL_DIR / "scaler.joblib")
        self.iso_forest = joblib.load(MODEL_DIR / "isolation_forest.joblib")
        self.rf = joblib.load(MODEL_DIR / "random_forest.joblib")
        xgb_path = MODEL_DIR / "xgboost.joblib"
        self.xgb = joblib.load(xgb_path) if xgb_path.exists() else None

    def predict(self, features: List[float]) -> Dict[str, Any]:
        """
        features: list of 7 numeric values in order:
        [hour, failed_logins, success_logins, privileged_cmds, data_mb, unique_ips, user_id]
        """
        arr = np.array(features, dtype=float).reshape(1, -1)
        # Scale for supervised models
        arr_scaled = self.scaler.transform(arr)

        # Isolation Forest anomaly score (lower more anomalous)
        iso_score = float(self.iso_forest.decision_function(arr)[0])
        iso_anomaly = bool(iso_score < 0)

        # Random Forest probability of malicious (class 1)
        rf_proba = float(self.rf.predict_proba(arr_scaled)[0][1])
        rf_pred = int(rf_proba >= 0.5)

        result = {
            "isolation_forest": {
                "anomaly_score": iso_score,
                "is_anomaly": iso_anomaly,
            },
            "random_forest": {
                "malicious_probability": rf_proba,
                "prediction": rf_pred,
            },
        }

        if self.xgb:
            xgb_proba = float(self.xgb.predict_proba(arr_scaled)[0][1])
            xgb_pred = int(xgb_proba >= 0.5)
            result["xgboost"] = {
                "malicious_probability": xgb_proba,
                "prediction": xgb_pred,
            }

        return result

# Global instance
ml_engine = MLEngine()