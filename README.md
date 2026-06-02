# SecureFlow IDS

> An AI-powered intrusion detection system built as a production-grade DevSecOps pipeline. Trained on 125,000 real network connections, deployed on Kubernetes with automated CI/CD, GitOps sync, canary deployments, and security gates at every stage.

**MSc Cyber Security Dissertation Project — Edinburgh Napier University**  
**Author:** Soros69  
**Docker Hub:** [sorosdad/secureflow-ids](https://hub.docker.com/r/sorosdad/secureflow-ids)  
**Live repo:** [github.com/Soros69/SecureFlow](https://github.com/Soros69/SecureFlow)

---

## What is SecureFlow?

Most security systems use rules — if traffic matches a known pattern, block it. The problem is attackers study those rules and change their behaviour to avoid them. New attacks slip through because no rule exists yet.

SecureFlow uses machine learning instead. It learns what normal network traffic looks like from 125,000 real examples, then flags anything that deviates from that pattern — including attacks nobody has seen before.

It runs as a REST API inside a Docker container on Kubernetes. Any system can call it with network connection features and get back a verdict — ALLOW, FLAG_FOR_REVIEW, BLOCK, or BLOCK_AND_ALERT — in milliseconds.

The entire build, test, scan, and deployment process is automated. A developer pushes code to GitHub and the pipeline handles everything — security scanning, Docker build, vulnerability checks, and deployment to Kubernetes — with no manual steps.

---

## How it works in plain English

```
1. A network connection arrives
2. Its features are extracted
   (how long was the session, how many bytes,
    how many failed logins, packet rate, etc.)
3. Those features are sent to SecureFlow via HTTP
4. The Random Forest model analyses all 41 features
5. 200 decision trees vote on whether it looks malicious
6. SecureFlow returns a risk level and recommended action
7. Your firewall or pipeline acts on that decision
```

---

## ML model performance

Five algorithms were trained and compared on the NSL-KDD benchmark — 125,973 real network connections labelled as normal or attack.

| Algorithm | Accuracy | AUC | Missed attacks | False alarms | Train time |
|---|---|---|---|---|---|
| Logistic Regression | 95.90% | 0.9910 | 96 | 68 | 0.1s |
| Decision Tree | 99.40% | 0.9964 | 13 | 11 | 0.1s |
| **Random Forest** | **99.72%** | **0.9999** | **7** | **4** | **0.3s** |
| Gradient Boosting | 99.52% | 0.9997 | 11 | 8 | 2.5s |
| SVM | 98.80% | 0.9982 | 26 | 22 | 6.3s |
| Neural Network | 99.42% | 0.9985 | — | — | ~30s |

Random Forest was selected for production. It achieved the highest accuracy, fewest missed attacks, fewest false alarms, and trains in 0.3 seconds — fast enough for real-time pipeline use.

---

## Security testing results

| Tool | Type | Result |
|---|---|---|
| pip-audit | SCA | 0 vulnerabilities |
| safety | SCA | 0 vulnerabilities |
| bandit | SAST | 0 issues (after remediation) |
| DAST scan | DAST | 5/6 passed, 1 acceptable |
| Trivy | SCA | runs in GitHub Actions |
| Checkov | IaC | runs in GitHub Actions |

SAST findings before remediation: 2 High (pickle deserialisation, MD5 hashing), 1 Medium (bind all interfaces). All remediated — pickle replaced with joblib, MD5 replaced with SHA-256, bind-all documented as intentional for Docker networking.

---

## Quick start — run with one command

```bash
docker run -d -p 8000:8000 sorosdad/secureflow-ids:v1.0
```

Check it is running:

```bash
curl http://localhost:8000/health
```

Make a prediction:

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
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
    "dst_host_same_src_port_rate": 0.11,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
  }'
```

Response:

```json
{
  "prediction": "NORMAL",
  "confidence": 0.05,
  "risk_level": "LOW",
  "action": "ALLOW",
  "requires_human": false,
  "model": "SecureFlow-IDS-v1.0"
}
```

---

## API reference

### GET /health
Returns service health status.

### GET /features
Returns the list of all 41 required input features.

### POST /predict
Classifies a network connection as normal or malicious.

**Risk tiers:**

| Confidence | Risk level | Action |
|---|---|---|
| Below 40% | LOW | ALLOW |
| 40% – 60% | MEDIUM | FLAG_FOR_REVIEW |
| 60% – 85% | HIGH | BLOCK |
| 85% and above | CRITICAL | BLOCK_AND_ALERT |

**Human oversight:**
Predictions below 95% confidence on MALICIOUS traffic include `requires_human: true` — a human should verify before permanent blocking action is taken.

---

## Architecture

```
Developer commits code
        |
        v
Pre-commit hooks (on developer laptop)
  - detect-private-key
  - check-yaml, check-json
  - check-added-large-files
  - end-of-file-fixer
        |
        v
GitHub Actions pipeline (automated on every push)
  |
  |-- Job 1: Security scan
  |     Checkov scans Terraform for misconfigurations
  |     detect-secrets scans for hardcoded credentials
  |     Fails here = nothing broken reaches production
  |
  |-- Job 2: Build and test
  |     ML model unit tested
  |     Docker image built
  |     Trivy scans image for CVEs
  |
  |-- Job 3: Push to Docker Hub
  |     sorosdad/secureflow-ids:latest updated
  |     Tagged with commit SHA for traceability
  |
  |-- Job 4: Deploy
        Kubernetes manifests applied
        |
        v
ArgoCD (GitOps)
  Watches GitHub repo
  Auto-syncs cluster when code changes
  Git is the single source of truth
        |
        v
Argo Rollouts (canary deployment)
  20% traffic to new version (30s monitor)
  50% traffic to new version (30s monitor)
  100% traffic to new version
  One command aborts and rolls back instantly
        |
        v
Kubernetes cluster
  3 replicas running simultaneously
  Self-healing -- crashed pods replaced in 20 seconds
  Load balanced across all healthy pods
        |
        v
SecureFlow REST API
  POST /predict returns verdict in milliseconds
  OWASP LLM Top 10 controls protecting the model
  MLflow monitoring for drift detection
```

---

## Repository structure

```
SecureFlow/
|-- .github/
|   |-- workflows/
|       |-- secureflow-pipeline.yml   (GitHub Actions CI/CD)
|-- app/
|   |-- main.py                       (HTTP server and API)
|   |-- model.py                      (ML model and prediction)
|   |-- security.py                   (OWASP LLM Top 10 controls)
|-- k8s/
|   |-- rollout.yaml                  (Argo Rollouts canary deployment)
|   |-- service.yaml                  (Kubernetes service)
|-- terraform/
|   |-- main.tf                       (Infrastructure as Code)
|   |-- terraform.tfvars              (Environment configuration)
|-- .pre-commit-config.yaml           (Pre-commit security hooks)
|-- .secrets.baseline                 (detect-secrets baseline)
|-- Dockerfile                        (Container definition)
|-- requirements.txt                  (Python dependencies)
|-- test_endpoint.py                  (API test script)
|-- dast_scan.py                      (DAST security scan)
|-- README.md
```

---

## How it was built — step by step

### Step 1 — Train the ML model

Five algorithms were compared on NSL-KDD. Random Forest won on every metric. The model was tracked with MLflow — every training run logged with its hyperparameters, metrics, and model artifact. Drift detection monitors AUC on new data and triggers automatic retraining when performance drops.

```python
from sklearn.ensemble import RandomForestClassifier
import mlflow

with mlflow.start_run(run_name="SecureFlow-v1.0"):
    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)
    mlflow.log_metrics({"accuracy": 0.9972, "auc_roc": 0.9999})
    mlflow.sklearn.log_model(model, registered_model_name="SecureFlow-IDS")
```

### Step 2 — Package with Docker

The model and API are packaged into a Docker container. Requirements are copied before application code so Docker's layer cache avoids reinstalling libraries on code-only changes — rebuilds take under 2 seconds after the first build.

```dockerfile
FROM python:3.11-slim
WORKDIR /secureflow
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
EXPOSE 8000
CMD ["python", "app/main.py"]
```

### Step 3 — Deploy to Kubernetes

Three replicas managed by Argo Rollouts. Self-healing demonstrated live — pod deleted, replacement created automatically in 20 seconds with zero service interruption.

```bash
kubectl apply -f k8s/rollout.yaml
kubectl apply -f k8s/service.yaml
```

### Step 4 — Canary deployments with Argo Rollouts

New versions released gradually. 20% of traffic goes to the new version first, monitored for 30 seconds, then promoted to 50%, then 100%. One command aborts and rolls back if problems are detected.

```bash
kubectl argo rollouts promote secureflow-ids   # promote forward
kubectl argo rollouts abort secureflow-ids     # instant rollback
```

### Step 5 — GitOps with ArgoCD

ArgoCD watches this GitHub repository and automatically syncs the Kubernetes cluster whenever a change is pushed. The cluster state always matches what is in Git. No manual kubectl commands in production.

### Step 6 — Infrastructure as Code with Terraform

All Kubernetes manifests generated from Terraform variables. Same code produces development, staging, and production configurations by changing one variable.

```bash
terraform apply -var="environment=production" -var="replicas=5"
```

### Step 7 — Automated CI/CD with GitHub Actions

Four-stage pipeline triggered on every push. Security gates prevent broken or insecure code from reaching production at every stage.

### Step 8 — Pre-commit security hooks

Seven security checks run automatically before every commit. Bad code never reaches GitHub.

### Step 9 — OWASP LLM Top 10 controls

Ten AI-specific security controls implemented in `app/security.py`:

- Rate limiting — 100 requests per minute per IP (LLM04)
- Input validation — feature bounds checking (LLM01)
- Model theft detection — query pattern monitoring (LLM10)
- Human oversight controls — confidence thresholds (LLM08)
- Safe error messages — no internal details exposed (LLM06)
- Data integrity checking — training data hash verification (LLM03)

### Step 10 — SAST, DAST, and SCA

Full security testing suite run against the application:

```bash
bandit -r app/ -f txt          # SAST — static code analysis
python dast_scan.py            # DAST — dynamic attack testing
pip-audit -r requirements.txt  # SCA  — dependency vulnerabilities
safety scan                    # SCA  — additional CVE database
```

---

## OWASP LLM Top 10 coverage

| ID | Risk | SecureFlow control |
|---|---|---|
| LLM01 | Prompt injection | Input bounds validation on all 41 features |
| LLM02 | Insecure output handling | Output validated before pipeline action |
| LLM03 | Training data poisoning | SHA-256 integrity check on training data |
| LLM04 | Model denial of service | Rate limiting — 100 req/min per IP |
| LLM05 | Supply chain vulnerabilities | Trivy + pip-audit scanning |
| LLM06 | Sensitive information disclosure | Safe error messages — no stack traces |
| LLM07 | Insecure plugin design | Pipeline validation before kubectl actions |
| LLM08 | Excessive agency | Human review flag on medium confidence |
| LLM09 | Overreliance | Model card documents limitations explicitly |
| LLM10 | Model theft | Query logging and anomaly detection |

---

## Local development setup

**Prerequisites:** Python 3.11+, Docker Desktop, kubectl, minikube, Terraform, Git

```bash
# Install Python dependencies
pip install scikit-learn pandas numpy joblib mlflow

# Install security tools
pip install bandit checkov detect-secrets pip-audit safety pre-commit

# Set up pre-commit hooks
pre-commit install
detect-secrets scan > .secrets.baseline

# Run locally
cd app
python main.py

# Run with Docker
docker build -t secureflow-ids:v1.0 .
docker run -d -p 8000:8000 secureflow-ids:v1.0

# Deploy to local Kubernetes
minikube start --driver=docker
kubectl apply -f k8s/rollout.yaml
kubectl apply -f k8s/service.yaml
minikube service secureflow-service --url

# Test the endpoint
python test_endpoint.py

# Run security scans
bandit -r app/ -f txt
python dast_scan.py
pip-audit -r requirements.txt
```

---

## Model card

| Field | Value |
|---|---|
| Model name | SecureFlow-IDS v1.0 |
| Algorithm | Random Forest (200 estimators) |
| Training dataset | NSL-KDD (20,000 samples, stratified split) |
| Accuracy | 99.72% |
| AUC-ROC | 0.9999 |
| Missed attacks | 7 per 4,000 connections |
| False alarms | 4 per 4,000 connections |
| Intended use | Network intrusion detection in CI/CD pipelines |

**Limitations:**
- Trained on NSL-KDD — may not generalise to all network environments
- Does not inspect encrypted payload content
- Feature engineering pipeline must stay in sync with training
- Should be retrained quarterly on fresh traffic data
- Human review recommended for all BLOCK decisions in production
- Novel attacks developed after training cutoff may not be detected

---

## Connecting to a live network

SecureFlow is a detector — you send it network features and it returns a verdict. To connect it to live traffic:

**Option 1 — API integration (simplest)**
Your existing firewall or SIEM extracts connection features and calls the SecureFlow API for each one. Acts on the returned action.

**Option 2 — Zeek integration (production)**
Zeek monitors live traffic, extracts the 41 NSL-KDD features automatically, and forwards them to SecureFlow. Full live network integration with no manual feature extraction.

**Recommended deployment approach:**
```
Week 1-2:  Shadow mode — log decisions, do not block
Week 3:    Analyse false alarm rate on your specific network
Week 4:    Enable FLAG_FOR_REVIEW only
Week 5+:   Enable BLOCK for CRITICAL confidence only (above 85%)
```

---

## Dissertation

This project is the implementation component of an MSc Cyber Security dissertation at Edinburgh Napier University investigating:

*"How can AI-powered security detection be systematically integrated into a GitOps CI/CD pipeline to create a reproducible, auditable, and production-grade DevSecOps framework?"*

**Key academic references:**
- Tavallaee et al. (2009) — NSL-KDD dataset
- Farnaaz and Jabbar (2016) — Random Forest on NSL-KDD
- Buczak and Guven (2016) — ML survey for intrusion detection
- Sculley et al. (2015) — Hidden technical debt in ML systems
- Fitzgerald and Stol (2017) — DevSecOps framework
- OWASP LLM Top 10 (2023/2025) — AI security threats

---

## Licence

MIT — free to use, modify, and distribute. Attribution appreciated.
