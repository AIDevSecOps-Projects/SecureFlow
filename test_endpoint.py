import urllib.request
import json

BASE = "http://127.0.0.1:21696"

# 1. Health check
print("=== Health Check ===")
with urllib.request.urlopen(f"{BASE}/health") as r:
    print(json.dumps(json.loads(r.read()), indent=2))

# 2. Normal traffic
print("\n=== Test: Normal Traffic ===")
normal_payload = {
    "duration": 0, "protocol_type": 2, "service": 20,
    "flag": 10, "src_bytes": 181, "dst_bytes": 5450,
    "land": 0, "wrong_fragment": 0, "urgent": 0,
    "hot": 0, "num_failed_logins": 0, "logged_in": 1,
    "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
    "num_root": 0, "num_file_creations": 0, "num_shells": 0,
    "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0,
    "count": 8, "srv_count": 8, "serror_rate": 0.0,
    "srv_serror_rate": 0.0, "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
    "dst_host_count": 9, "dst_host_srv_count": 9,
    "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.11, "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
}

req = urllib.request.Request(
    f"{BASE}/predict",
    data=json.dumps(normal_payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as r:
    print(json.dumps(json.loads(r.read()), indent=2))

# 3. Attack traffic
print("\n=== Test: Attack Traffic ===")
attack_payload = normal_payload.copy()
attack_payload.update({
    "src_bytes": 0, "dst_bytes": 0,
    "num_failed_logins": 15, "logged_in": 0,
    "count": 511, "serror_rate": 1.0,
    "srv_serror_rate": 1.0, "same_srv_rate": 1.0,
    "dst_host_count": 255, "dst_host_serror_rate": 1.0
})

req2 = urllib.request.Request(
    f"{BASE}/predict",
    data=json.dumps(attack_payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req2) as r:
    print(json.dumps(json.loads(r.read()), indent=2))

print("\n=== Container is serving live ML predictions ===")