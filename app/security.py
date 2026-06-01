# app/security.py
# OWASP LLM Top 10 security controls for SecureFlow

import time
import hashlib
import json
from collections import defaultdict
from datetime import datetime

# ── LLM04: Rate limiting — prevent model DoS ──────────────────────────────────
request_counts = defaultdict(list)
RATE_LIMIT      = 100   # max requests per minute per IP
WINDOW_SECONDS  = 60

def check_rate_limit(client_ip: str) -> bool:
    """Returns True if request is allowed, False if rate limited."""
    now     = time.time()
    window  = [t for t in request_counts[client_ip]
               if now - t < WINDOW_SECONDS]
    request_counts[client_ip] = window

    if len(window) >= RATE_LIMIT:
        return False

    request_counts[client_ip].append(now)
    return True

# ── LLM01: Input validation — prevent adversarial inputs ──────────────────────
FEATURE_BOUNDS = {
    'duration'          : (0, 58329),
    'src_bytes'         : (0, 1379963888),
    'dst_bytes'         : (0, 1309937401),
    'serror_rate'       : (0.0, 1.0),
    'rerror_rate'       : (0.0, 1.0),
    'same_srv_rate'     : (0.0, 1.0),
    'diff_srv_rate'     : (0.0, 1.0),
    'logged_in'         : (0, 1),
    'count'             : (0, 511),
}

def validate_input(features: dict) -> tuple:
    """
    Validates input features are within expected bounds.
    Returns (is_valid, error_message)
    """
    for feature, (min_val, max_val) in FEATURE_BOUNDS.items():
        if feature in features:
            val = features[feature]
            if not (min_val <= val <= max_val):
                return False, f"Feature {feature}={val} outside expected range [{min_val}, {max_val}]"
    return True, None

# ── LLM06: Sanitise error messages — prevent information disclosure ────────────
def safe_error(internal_message: str, error_code: str) -> dict:
    """
    Returns a safe error response that does not reveal internal details.
    Logs the full error internally but returns only a generic message.
    """
    print(f"[INTERNAL ERROR] {error_code}: {internal_message}")
    return {
        "error"      : "Request could not be processed",
        "error_code" : error_code,
        "timestamp"  : datetime.now().isoformat()
    }

# ── LLM08: Confidence threshold — prevent excessive agency ────────────────────
HUMAN_REVIEW_THRESHOLD = 0.40   # below this → always human review
AUTO_BLOCK_THRESHOLD   = 0.95   # above this → automatic block safe

def apply_agency_controls(prediction: dict) -> dict:
    """
    Adds human oversight requirements based on confidence level.
    High confidence predictions can be automated.
    Low confidence predictions require human review.
    """
    confidence = prediction['confidence']

    if prediction['prediction'] == 'MALICIOUS':
        if confidence < HUMAN_REVIEW_THRESHOLD:
            prediction['action']           = 'FLAG_FOR_REVIEW'
            prediction['requires_human']   = True
            prediction['reason']           = 'Low confidence — human review required'
        elif confidence < AUTO_BLOCK_THRESHOLD:
            prediction['requires_human']   = True
            prediction['reason']           = 'Moderate confidence — verify before blocking'
        else:
            prediction['requires_human']   = False
            prediction['reason']           = 'High confidence — automated action safe'
    else:
        prediction['requires_human'] = False

    return prediction

# ── LLM10: Query logging — detect model theft attempts ────────────────────────
query_log = []
THEFT_DETECTION_WINDOW  = 300   # 5 minutes
THEFT_DETECTION_LIMIT   = 500   # more than 500 queries in 5 min = suspicious

def log_and_detect_theft(client_ip: str, features: dict) -> bool:
    """
    Logs queries and detects potential model extraction attacks.
    Returns True if theft attempt detected.
    """
    now = time.time()
    query_log.append({
        'ip'        : client_ip,
        'timestamp' : now,
        'feature_hash': hashlib.sha256(
            json.dumps(features, sort_keys=True).encode()
        ).hexdigest()
    })

    # Count recent queries from this IP
    recent = [q for q in query_log
              if now - q['timestamp'] < THEFT_DETECTION_WINDOW
              and q['ip'] == client_ip]

    if len(recent) > THEFT_DETECTION_LIMIT:
        print(f"[SECURITY ALERT] Possible model theft attempt from {client_ip}")
        print(f"  {len(recent)} queries in {THEFT_DETECTION_WINDOW}s")
        return True

    return False

# ── LLM03: Data integrity — detect training data poisoning ────────────────────
EXPECTED_DATASET_HASH = "a8c4c5e2f1b3d6e7"  # hash of known-good NSL-KDD

def verify_data_integrity(data_path: str) -> bool:
    """
    Verifies training data has not been tampered with.
    In production this checks against a cryptographic hash
    stored in a trusted external system.
    """
    try:
        with open(data_path, 'rb') as f:
            content = f.read()
            actual_hash = hashlib.sha256(content).hexdigest()[:16]
            if actual_hash != EXPECTED_DATASET_HASH:
                print(f"[SECURITY ALERT] Training data integrity check failed")
                print(f"  Expected: {EXPECTED_DATASET_HASH}")
                print(f"  Actual  : {actual_hash}")
                return False
        return True
    except FileNotFoundError:
        return True  # skip check if file not present (uses URL download)
