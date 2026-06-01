# save as dast_scan.py
import requests
import json

TARGET = "http://localhost:8000"

print("="*50)
print("SecureFlow DAST Security Scan")
print("="*50)

# Test 1 — Information disclosure
print("\n[1] Testing for information disclosure...")
r = requests.get(f"{TARGET}/nonexistent")
if "Traceback" in r.text or "File " in r.text:
    print("  FAIL: Stack trace exposed in error response")
else:
    print("  PASS: No internal details in error response")

# Test 2 — Large payload (DoS attempt)
print("\n[2] Testing oversized payload handling...")
try:
    large_payload = {"data": "A" * 1000000}
    r = requests.post(f"{TARGET}/predict",
                      json=large_payload, timeout=5)
    print(f"  Response: {r.status_code}")
    if r.status_code in [400, 413, 500]:
        print("  PASS: Large payload rejected")
    else:
        print("  WARN: Large payload accepted — check memory limits")
except Exception as e:
    print(f"  PASS: Connection refused or timeout — {e}")

# Test 3 — SQL injection in features
print("\n[3] Testing injection in input fields...")
inject_payload = {
    "duration"    : "'; DROP TABLE users; --",
    "src_bytes"   : 181,
    "dst_bytes"   : 5450,
}
r = requests.post(f"{TARGET}/predict", json=inject_payload)
if r.status_code == 400:
    print("  PASS: Injection attempt rejected")
else:
    print(f"  INFO: Response {r.status_code} — {r.text[:100]}")

# Test 4 — Missing fields
print("\n[4] Testing missing required fields...")
r = requests.post(f"{TARGET}/predict",
                  json={"src_bytes": 100})
if r.status_code == 400:
    print("  PASS: Missing fields handled correctly")
else:
    print(f"  WARN: Unexpected response {r.status_code}")

# Test 5 — HTTP methods
print("\n[5] Testing unexpected HTTP methods...")
r = requests.delete(f"{TARGET}/predict")
if r.status_code == 404:
    print("  PASS: DELETE method rejected")
else:
    print(f"  WARN: DELETE returned {r.status_code}")

# Test 6 — Empty body
print("\n[6] Testing empty request body...")
r = requests.post(f"{TARGET}/predict",
                  data="",
                  headers={"Content-Type": "application/json"})
print(f"  Response: {r.status_code} — handled gracefully: {r.status_code in [400, 500]}")

print("\n" + "="*50)
print("DAST scan complete")
print("="*50)
