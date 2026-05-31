# SecureFlow IDS

> An AI-powered intrusion detection system built as a production-grade DevSecOps pipeline. Detects malicious network traffic using machine learning, deployed on Kubernetes with automated CI/CD, GitOps sync, and canary deployments.

**MSc Cyber Security Dissertation Project — Edinburgh Napier University**  
**Author:** Soros69  
**Docker Hub:** [sorosdad/secureflow-ids](https://hub.docker.com/r/sorosdad/secureflow-ids)

---

## What is SecureFlow?

SecureFlow is an open-source AI-powered Intrusion Detection System (IDS) that sits inside a DevSecOps pipeline. It analyses network connection features and classifies them as normal or malicious in real time, returning a risk-tiered action (ALLOW, FLAG_FOR_REVIEW, BLOCK, BLOCK_AND_ALERT) via a REST API.

The project demonstrates how machine learning and modern DevSecOps practices can be combined into a single automated pipeline — from a developer committing code to a model serving live predictions on Kubernetes, with security gates at every stage.

---

## Architecture overview

```
Developer commits code
        │
        ▼
Pre-commit hooks          ← security gates on the developer's machine
(detect private keys,       blocks bad commits before they reach GitHub
check YAML, detect secrets)
        │
        ▼
GitHub Actions pipeline   ← runs automatically on every push
┌───────────────────────────────────────────┐
│  Job 1: Security scan                     │
│    - Checkov scans Terraform for          │
│      misconfigurations                    │
│    - detect-secrets scans for credentials │
│                                           │
│  Job 2: Build and test                    │
│    - ML model unit tested                 │
│    - Docker image built                   │
│    - Trivy scans image for CVEs           │
│                                           │
│  Job 3: Push to Docker Hub                │
│    - sorosdad/secureflow-ids:latest       │
│    - sorosdad/secureflow-ids:<commit-sha> │
│                                           │
│  Job 4: Deploy                            │
│    - Kubernetes manifests applied         │
└───────────────────────────────────────────┘
        │
        ▼
ArgoCD (GitOps)           ← watches GitHub, auto-syncs cluster
        │
        ▼
Kubernetes cluster        ← 3 replicas, self-healing
Argo Rollouts             ← canary deployments (20% → 50% → 100%)
        │
        ▼
SecureFlow REST API       ← serving live ML predictions
POST /predict → { prediction, confidence, risk_level, action }
```

---

## ML model performance

Trained and evaluated on the NSL-KDD benchmark dataset (125,973 real network connections).

| Algorithm           | Accuracy | AUC    | Missed attacks | False alarms | Train time |
|---------------------|----------|--------|----------------|--------------|------------|
| Logistic Regression | 95.90%   | 0.9910 | 96             | 68           | 0.1s       |
| Decision Tree       | 99.40%   | 0.9964 | 13             | 11           | 0.1s       |
| **Random Forest**   | **99.72%** | **0.9999** | **7**    | **4**        | **0.3s**   |
| Gradient Boosting   | 99.52%   | 0.9997 | 11             | 8            | 2.5s       |
| SVM                 | 98.80%   | 0.9982 | 26             | 22           | 6.3s       |
| Neural Network      | 99.42%   | 0.9985 | -              | -            | ~30s       |

Random Forest was selected for production deployment based on its optimal balance of accuracy, missed attack rate, false alarm rate, and inference latency (0.3s).

---

## Quick start — run with one command

```bash
docker run -d -p 8000:8000 sorosdad/secureflow-ids:v1.0
```

Test the health check:

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
  "model": "SecureFlow-IDS-v1.0"
}
```

---

## API reference

### GET /health

Returns service health status.

```json
{
  "status": "healthy",
  "service": "SecureFlow-IDS",
  "version": "1.0.0",
  "model": "Random Forest — NSL-KDD"
}
```

### GET /features

Returns the list of required input features.

```json
{
  "required_features": ["duration", "protocol_type", ...],
  "count": 41
}
```

### POST /predict

Classifies a network connection as normal or malicious.

**Input:** JSON object with 41 NSL-KDD feature values.

**Output:**

| Field       | Type   | Description                                      |
|-------------|--------|--------------------------------------------------|
| prediction  | string | NORMAL or MALICIOUS                              |
| confidence  | float  | Probability score 0.0–1.0                        |
| risk_level  | string | LOW, MEDIUM, HIGH, or CRITICAL                   |
| action      | string | ALLOW, FLAG_FOR_REVIEW, BLOCK, BLOCK_AND_ALERT   |
| model       | string | Model version identifier                         |

**Risk tiers:**

| Confidence  | Risk level | Action           |
|-------------|------------|------------------|
| < 40%       | LOW        | ALLOW            |
| 40% – 60%   | MEDIUM     | FLAG_FOR_REVIEW  |
| 60% – 85%   | HIGH       | BLOCK            |
| ≥ 85%       | CRITICAL   | BLOCK_AND_ALERT  |

---

## Repository structure

```
SecureFlow/
├── .github/
│   └── workflows/
│       └── secureflow-pipeline.yml   ← GitHub Actions CI/CD pipeline
├── app/
│   ├── main.py                       ← HTTP server and API endpoints
│   └── model.py                      ← ML model loading and prediction
├── k8s/
│   ├── rollout.yaml                  ← Argo Rollouts canary deployment
│   └── service.yaml                  ← Kubernetes service
├── terraform/
│   ├── main.tf                       ← Infrastructure as Code
│   └── terraform.tfvars              ← Environment configuration
├── .pre-commit-config.yaml           ← Pre-commit security hooks
├── .secrets.baseline                 ← detect-secrets baseline
├── Dockerfile                        ← Container definition
├── requirements.txt                  ← Python dependencies
└── test_endpoint.py                  ← API test script
```

---

## How it was built — step by step

### Step 1 — Train the ML model

The model was trained on the NSL-KDD dataset, a standard academic benchmark for network intrusion detection. Five algorithms were compared across accuracy, AUC, missed attack rate, false alarm rate, and training time. Random Forest was selected as the production model.

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pandas as pd

# Load NSL-KDD dataset
url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
df  = pd.read_csv(url, names=FEATURE_COLS + ['label', 'difficulty'])
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

# Train Random Forest
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Result: 99.72% accuracy, AUC 0.9999, 7 missed attacks per 4000 connections
```

### Step 2 — Track experiments with MLflow

Every training run is logged to MLflow with its hyperparameters, metrics, and model artifact. Drift detection monitors the model's AUC on new data and triggers automatic retraining when performance drops below a threshold.

```python
import mlflow

with mlflow.start_run(run_name="SecureFlow-v1.0"):
    mlflow.log_params({"n_estimators": 200, "max_depth": None})
    mlflow.log_metrics({"accuracy": 0.9972, "auc_roc": 0.9999})
    mlflow.sklearn.log_model(model, registered_model_name="SecureFlow-IDS")
```

### Step 3 — Package with Docker

The model and API are packaged into a Docker container using a multi-layer Dockerfile. Requirements are copied before application code so Docker's layer cache skips reinstalling libraries on code-only changes — rebuilds take under 2 seconds after the first build.

```dockerfile
FROM python:3.11-slim
WORKDIR /secureflow
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
EXPOSE 8000
CMD ["python", "app/main.py"]
```

Build and push:

```bash
docker build -t sorosdad/secureflow-ids:v1.0 .
docker push sorosdad/secureflow-ids:v1.0
```

### Step 4 — Deploy to Kubernetes

The application runs as three replicas managed by Argo Rollouts. Kubernetes automatically replaces any crashed pod within seconds — demonstrated live by deleting a pod and watching the replacement appear.

```bash
kubectl apply -f k8s/rollout.yaml
kubectl apply -f k8s/service.yaml
kubectl get pods  # shows 3/3 Running
```

### Step 5 — Canary deployments with Argo Rollouts

New versions are released gradually using a canary strategy — 20% of traffic goes to the new version first, monitored for 30 seconds, then promoted to 50%, then 100%. A single command aborts and rolls back if problems are detected.

```yaml
strategy:
  canary:
    steps:
    - setWeight: 20
    - pause: {duration: 30s}
    - setWeight: 50
    - pause: {duration: 30s}
    - setWeight: 100
```

```bash
# Promote a canary
kubectl argo rollouts promote secureflow-ids

# Abort and rollback instantly
kubectl argo rollouts abort secureflow-ids
```

### Step 6 — GitOps with ArgoCD

ArgoCD watches this GitHub repository and automatically syncs the Kubernetes cluster whenever a change is pushed. The cluster state is always identical to what is in Git — no manual kubectl commands in production.

```bash
# Push a change to GitHub
git commit -m "Scale to 4 replicas"
git push

# ArgoCD detects the change and syncs automatically
# kubectl get pods shows 4 pods without any manual kubectl apply
```

### Step 7 — Infrastructure as Code with Terraform

All Kubernetes manifests are generated from Terraform variables. The same code produces development, staging, and production configurations by changing a single variable.

```bash
terraform apply -var="environment=production" -var="replicas=5"
# Generates production-ready manifests automatically
```

### Step 8 — Automated CI/CD with GitHub Actions

Every push to the main branch triggers a four-stage pipeline that runs security scans before allowing code to reach production.

```
Push to GitHub
      ↓
Security scan (Checkov + detect-secrets)
      ↓
Build and test (model test + Docker build + Trivy scan)
      ↓
Push to Docker Hub
      ↓
Deploy to Kubernetes
```

### Step 9 — Pre-commit security hooks

Seven security checks run automatically on every commit before code reaches GitHub. If any check fails, the commit is blocked.

```yaml
hooks:
  - id: trailing-whitespace
  - id: check-yaml
  - id: check-json
  - id: check-merge-conflict
  - id: check-added-large-files
  - id: detect-private-key
  - id: end-of-file-fixer
```

---

## Local development setup

### Prerequisites

- Python 3.11+
- Docker Desktop
- kubectl
- minikube
- Terraform
- Git

### Install dependencies

```bash
pip install scikit-learn pandas numpy mlflow pre-commit detect-secrets checkov
```

### Set up pre-commit hooks

```bash
pre-commit install
detect-secrets scan > .secrets.baseline
```

### Run locally without Docker

```bash
cd app
python main.py
# Server starts at http://localhost:8000
```

### Run with Docker

```bash
docker build -t secureflow-ids:v1.0 .
docker run -d -p 8000:8000 secureflow-ids:v1.0
```

### Deploy to local Kubernetes

```bash
minikube start --driver=docker
kubectl apply -f k8s/rollout.yaml
kubectl apply -f k8s/service.yaml
minikube service secureflow-service --url
```

### Test the endpoint

```bash
python test_endpoint.py
```

---

## Security features

| Layer          | Tool            | What it checks                              |
|----------------|-----------------|---------------------------------------------|
| Pre-commit     | detect-secrets  | Hardcoded credentials in code               |
| Pre-commit     | pre-commit-hooks| Private keys, YAML syntax, file sizes       |
| CI/CD          | Checkov         | Terraform misconfigurations                 |
| CI/CD          | Trivy           | Container image CVEs (CRITICAL and HIGH)    |
| Runtime        | Kubernetes RBAC | Pod access controls                         |
| Deployment     | Argo Rollouts   | Canary gates — bad versions never reach 100%|
| GitOps         | ArgoCD          | Prevents configuration drift               |

---

## Model card

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| Model name        | SecureFlow-IDS v1.0                                |
| Algorithm         | Random Forest (200 estimators)                     |
| Training dataset  | NSL-KDD (20,000 samples, stratified split)         |
| Accuracy          | 99.72%                                             |
| AUC-ROC           | 0.9999                                             |
| Missed attacks    | 7 per 4,000 connections                            |
| False alarms      | 4 per 4,000 connections                            |
| Intended use      | Network intrusion detection in CI/CD pipelines     |

**Limitations:**
- Trained on NSL-KDD — may not generalise to all network environments
- Does not inspect encrypted payload content
- Requires feature engineering pipeline to stay in sync with training
- Should be retrained quarterly on fresh traffic data
- Human review recommended for all BLOCK decisions in production

---

## Dissertation

This project was built as the implementation component of an MSc Cyber Security dissertation at Edinburgh Napier University. The dissertation investigates the research question:

*"How can AI-powered security detection be systematically integrated into a GitOps CI/CD pipeline to create a reproducible, auditable, and production-grade DevSecOps framework?"*

The SecureFlow framework provides empirical evidence across five evaluation dimensions: detection accuracy, pipeline automation, infrastructure reproducibility, security gate coverage, and deployment safety.

---

## Licence

MIT — free to use, modify, and distribute. Attribution appreciated.

---

## Connect

- GitHub: [github.com/Soros69/SecureFlow](https://github.com/Soros69/SecureFlow)
- Docker Hub: [hub.docker.com/r/sorosdad/secureflow-ids](https://hub.docker.com/r/sorosdad/secureflow-ids)
