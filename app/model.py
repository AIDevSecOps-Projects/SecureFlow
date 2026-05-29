# app/model.py
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import os

# Feature columns — must match training order exactly
FEATURE_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

MODEL_PATH = "app/secureflow_model.pkl"

def train_and_save():
    """Train model on NSL-KDD and save to disk."""
    print("Training SecureFlow model...")
    url = ("https://raw.githubusercontent.com/defcom17/"
           "NSL_KDD/master/KDDTrain+.txt")

    cols = FEATURE_COLS + ['label', 'difficulty']
    df   = pd.read_csv(url, names=cols)
    df.drop('difficulty', axis=1, inplace=True)
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

    le = LabelEncoder()
    for col in ['protocol_type', 'service', 'flag']:
        df[col] = le.fit_transform(df[col])

    df_sample = df.sample(n=20000, random_state=42)
    X = df_sample[FEATURE_COLS]
    y = df_sample['label']

    X_train, _, y_train, _ = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1
    )
    model.fit(X_train, y_train)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    print(f"Model saved to {MODEL_PATH}")
    return model

def load_model():
    """Load model from disk, train if not found."""
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    return train_and_save()

def predict(features: dict) -> dict:
    """Run prediction on a single connection."""
    model = load_model()

    # Validate input
    missing = [f for f in FEATURE_COLS if f not in features]
    if missing:
        return {"error": f"Missing fields: {missing}"}

    df = pd.DataFrame([features])[FEATURE_COLS]
    proba  = model.predict_proba(df)[0][1]
    pred   = int(proba > 0.5)

    # Risk tiering
    if proba >= 0.85:
        risk, action = "CRITICAL", "BLOCK_AND_ALERT"
    elif proba >= 0.60:
        risk, action = "HIGH",     "BLOCK"
    elif proba >= 0.40:
        risk, action = "MEDIUM",   "FLAG_FOR_REVIEW"
    else:
        risk, action = "LOW",      "ALLOW"

    return {
        "prediction"  : "MALICIOUS" if pred else "NORMAL",
        "confidence"  : round(float(proba), 4),
        "risk_level"  : risk,
        "action"      : action,
        "model"       : "SecureFlow-IDS-v1.0"
    }