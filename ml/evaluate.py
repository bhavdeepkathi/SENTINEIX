import pandas as pd
import numpy as np
from pathlib import Path
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

DATA_PATH = Path(__file__).parent / "datasets" / "synthetic_logs.csv"
MODEL_DIR = Path(__file__).parent / "models"

feature_cols = ["hour", "failed_logins", "success_logins", "privileged_cmds", "data_mb", "unique_ips", "user_id"]

# Load data and split same as train
df = pd.read_csv(DATA_PATH)
X = df[feature_cols].values
y = df["label"].values

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = joblib.load(MODEL_DIR / "scaler.joblib")
X_test_scaled = scaler.transform(X_test)

print("=== Evaluation on Test Set ===")

# Isolation Forest (anomaly scores)
iso = joblib.load(MODEL_DIR / "isolation_forest.joblib")
# decision_function: lower = more anomalous
anomaly_scores = iso.decision_function(X_test)
# Predict anomalies (threshold 0)
iso_pred = (anomaly_scores < 0).astype(int)
print("\n--- Isolation Forest (anomaly detection) ---")
print(f"Anomaly rate predicted: {iso_pred.mean():.3f}")
print(classification_report(y_test, iso_pred, target_names=["Benign","Malicious"]))
print("Confusion Matrix:")
print(confusion_matrix(y_test, iso_pred))

# Random Forest
rf = joblib.load(MODEL_DIR / "random_forest.joblib")
rf_pred = rf.predict(X_test_scaled)
print("\n--- Random Forest ---")
print(classification_report(y_test, rf_pred, target_names=["Benign","Malicious"]))
print("Confusion Matrix:")
print(confusion_matrix(y_test, rf_pred))

# XGBoost if exists
xgb_path = MODEL_DIR / "xgboost.joblib"
if xgb_path.exists():
    xgb = joblib.load(xgb_path)
    xgb_pred = xgb.predict(X_test_scaled)
    print("\n--- XGBoost ---")
    print(classification_report(y_test, xgb_pred, target_names=["Benign","Malicious"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, xgb_pred))
else:
    print("\nXGBoost model not found, skipping.")