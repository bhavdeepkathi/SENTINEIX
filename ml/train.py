import pandas as pd
import numpy as np
from pathlib import Path
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

DATA_PATH = Path(__file__).parent / "datasets" / "synthetic_logs.csv"
MODEL_DIR = Path(__file__).parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Load data
df = pd.read_csv(DATA_PATH)
print(f"Loaded {len(df)} samples")

# Features and target
feature_cols = ["hour", "failed_logins", "success_logins", "privileged_cmds", "data_mb", "unique_ips", "user_id"]
X = df[feature_cols].values
y = df["label"].values

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Scaler for supervised models
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Save scaler
joblib.dump(scaler, MODEL_DIR / "scaler.joblib")

# ---------- Isolation Forest (unsupervised anomaly detection) ----------
print("\nTraining IsolationForest...")
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
iso.fit(X_train)  # fit on raw features (or scaled)
joblib.dump(iso, MODEL_DIR / "isolation_forest.joblib")
print("IsolationForest saved.")

# ---------- Random Forest ----------
print("\nTraining RandomForestClassifier...")
rf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, class_weight="balanced")
rf.fit(X_train_scaled, y_train)
joblib.dump(rf, MODEL_DIR / "random_forest.joblib")
print("RandomForest saved.")

# Evaluate RF
y_pred_rf = rf.predict(X_test_scaled)
print("\nRandomForest Evaluation:")
print(classification_report(y_test, y_pred_rf))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred_rf))

# ---------- XGBoost (if available) ----------
if XGB_AVAILABLE:
    print("\nTraining XGBoostClassifier...")
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )
    xgb.fit(X_train_scaled, y_train)
    joblib.dump(xgb, MODEL_DIR / "xgboost.joblib")
    print("XGBoost saved.")

    y_pred_xgb = xgb.predict(X_test_scaled)
    print("\nXGBoost Evaluation:")
    print(classification_report(y_test, y_pred_xgb))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_xgb))
else:
    print("\nXGBoost not installed, skipping.")

print("\nAll models trained and saved to", MODEL_DIR)