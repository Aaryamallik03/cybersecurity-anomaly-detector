# 🛡️ Cybersecurity Anomaly Detector

A machine-learning-assisted cybersecurity monitoring system for detecting suspicious network activity and behavioral anomalies.

The project combines a **FastAPI backend**, **MongoDB event persistence**, **rule-based detection**, **behavioral feature engineering**, and **Isolation Forest-based anomaly detection** to analyze network/security events and generate actionable alerts.

> **Project status:** Active development
> **Primary language:** Python
> **Backend:** FastAPI
> **ML:** scikit-learn / Isolation Forest
> **Database:** MongoDB

---

## 📌 Overview

Traditional security systems often rely heavily on predefined rules and known attack signatures. While these approaches are useful, they can struggle when activity deviates from previously defined patterns.

This project explores a complementary approach: learning patterns from network and behavioral data and identifying events that significantly deviate from expected behavior.

The system currently supports:

* Network/security event ingestion through a REST API
* Persistent event storage using MongoDB
* Rule-based suspicious activity detection
* Behavioral feature extraction
* Machine-learning-based anomaly scoring
* Isolation Forest models for unsupervised anomaly detection
* Failed-login anomaly detection
* Alert generation
* Audit trails
* Event-specific audit queries
* Deterministic event replay
* Model training and evaluation scripts
* Automated API and ML testing

---

## 🧠 Detection Pipeline

The project follows a multi-stage detection pipeline:

```text
Network / Security Events
          │
          ▼
     Event Ingestion
          │
          ▼
    Data Validation
          │
          ▼
   Feature Engineering
          │
          ├───────────────┐
          ▼               ▼
 Rule-Based Detection   Behavioral Analysis
          │               │
          │               ▼
          │        Anomaly Detection
          │        (Isolation Forest)
          │               │
          └───────┬───────┘
                  ▼
             Alert Engine
                  │
                  ▼
          Audit / Persistence
```

---

## 🚀 Key Features

### 🔹 REST API

The FastAPI backend provides endpoints for:

* Health checks
* Event ingestion
* Detection
* Alert generation
* Audit queries
* Event replay

Example health endpoint:

```http
GET /health
```

---

### 🔹 Event Processing

Incoming events are validated and normalized before being processed.

The system is designed to handle security-related events such as:

* Authentication activity
* Failed login attempts
* Network connection activity
* Port scanning behavior
* Unusual connection patterns
* Other behavioral security events

---

### 🔹 Behavioral Feature Engineering

The ML pipeline extracts behavioral characteristics from network activity, including temporal and connection-based features.

Examples include:

* Source connection counts
* Unique destination ports
* Connection frequency
* Destination diversity
* Time-window-based behavioral statistics

These features allow the anomaly detector to evaluate behavior rather than relying only on individual event attributes.

---

### 🔹 Machine Learning Anomaly Detection

The project uses **Isolation Forest**, an unsupervised anomaly detection algorithm, to identify observations that differ significantly from the learned behavioral patterns.

Multiple trained model versions are maintained during experimentation so that different feature sets and model configurations can be evaluated.

The repository also contains preprocessing, training, evaluation, and model-testing scripts.

---

### 🔹 Rule-Based Detection

Machine learning is complemented by deterministic security rules.

This provides a hybrid approach:

```text
Known / Explicit Pattern
        ↓
   Rule Detection

Unknown / Unusual Pattern
        ↓
  ML Anomaly Detection
```

This combination is useful because ML-based detection should not be treated as a replacement for deterministic security controls.

---

### 🔹 Audit Trail

Detection results and relevant events can be persisted for later investigation.

This provides a foundation for:

* Security analysis
* Incident investigation
* Event tracing
* Detection debugging
* Model evaluation

---

## 🏗️ Project Structure

```text
cybersecurity-anomaly-detector/
│
├── backend/
│   ├── config.py
│   ├── detection.py
│   └── main.py
│
├── ml/
│   ├── behavior_features.py
│   ├── evaluate.py
│   ├── feature_engineering.py
│   ├── preprocess.py
│   │
│   ├── train.py
│   ├── train_v2.py
│   ├── train_v3.py
│   ├── train-model.py
│   │
│   ├── test-api.py
│   ├── test-ingest.py
│   ├── test-model.py
│   ├── test_behavior_features.py
│   │
│   └── models/
│       ├── features.joblib
│       ├── features_v2.joblib
│       ├── features_v3.joblib
│       ├── isolation_forest.joblib
│       ├── scaler.joblib
│       ├── threshold_v2.joblib
│       └── threshold_v3.joblib
│
├── .env.example
├── .gitignore
└── README.md
```

> Large raw datasets and generated processed datasets are intentionally excluded from the Git repository.

---

## 🛠️ Technology Stack

| Component               | Technology       |
| ----------------------- | ---------------- |
| Programming Language    | Python           |
| API Framework           | FastAPI          |
| Server                  | Uvicorn          |
| Data Validation         | Pydantic         |
| Database                | MongoDB          |
| Machine Learning        | scikit-learn     |
| Anomaly Detection       | Isolation Forest |
| Data Processing         | Pandas           |
| Model Serialization     | Joblib / Pickle  |
| Version Control         | Git & GitHub     |
| Development Environment | VS Code          |

---

## ⚙️ Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Aaryamallik03/cybersecurity-anomaly-detector.git
cd cybersecurity-anomaly-detector
```

---

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

---

### 3. Install dependencies

If a `requirements.txt` file is available:

```powershell
pip install -r requirements.txt
```

Otherwise, install the required packages according to the project's backend and ML modules.

---

### 4. Configure environment variables

Create a local `.env` file based on:

```text
.env.example
```

Do **not** commit your real `.env` file.

It may contain credentials or database connection information.

---

### 5. Start the backend

From the project root:

```powershell
uvicorn backend.main:app --reload
```

The API should become available at:

```text
http://127.0.0.1:8000
```

FastAPI interactive documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 🧪 API Health Check

Once the server is running:

```bash
curl -X GET "http://127.0.0.1:8000/health"
```

Expected response:

```json
{
  "status": "ok"
}
```

The exact response structure may vary depending on the current backend implementation.

---

## 🤖 Machine Learning Workflow

The ML pipeline is organized around four main stages:

### 1. Data Preparation

Raw network/security data is cleaned and transformed into a format suitable for model training.

Large datasets are intentionally kept outside the Git repository.

### 2. Feature Engineering

Behavioral and network-level features are generated using the scripts in:

```text
ml/feature_engineering.py
ml/behavior_features.py
```

### 3. Model Training

Training experiments are implemented in:

```text
ml/train.py
ml/train_v2.py
ml/train_v3.py
ml/train-model.py
```

### 4. Evaluation

Model and detection performance can be evaluated using:

```text
ml/evaluate.py
```

---

## 📊 Dataset

The project uses network traffic/security data for developing and evaluating anomaly detection techniques.

Because the local dataset and processed files occupy several gigabytes, they are **not stored directly in this Git repository**.

The `.gitignore` configuration excludes:

```text
ml/data/
ml/flow_data/
ml/flow_data_clean/
ml/processed/
```

This keeps the source repository manageable while allowing the complete dataset to remain available in the local development environment.

---

## 🔐 Security Considerations

This project is intended for **research, educational, and defensive cybersecurity purposes**.

Important considerations:

* Do not commit API keys, passwords, or database credentials.
* Keep `.env` files out of version control.
* ML anomaly detection can produce false positives and false negatives.
* An anomaly should be treated as a signal for investigation, not automatic proof of an attack.
* Models should be evaluated against representative data before being used in a production security environment.

---

## 🧪 Testing

The repository contains tests for different components of the system, including:

```text
ml/test-api.py
ml/test-ingest.py
ml/test-model.py
ml/test_behavior_features.py
```

Run the relevant test scripts from the project environment.

---

## 🔮 Future Improvements

Potential future development includes:

* [ ] Real-time network traffic ingestion
* [ ] Improved model evaluation and benchmarking
* [ ] Automated threshold calibration
* [ ] Precision/recall/F1 reporting
* [ ] Confusion matrix and ROC analysis
* [ ] Detection dashboard
* [ ] Streaming anomaly detection
* [ ] Model version management
* [ ] Explainable anomaly scores
* [ ] Alert severity classification
* [ ] SIEM integration
* [ ] Docker deployment
* [ ] CI/CD testing
* [ ] Monitoring and model drift detection

---

## ⚠️ Current Limitations

This project is still under active development.

The current implementation should **not** be described as a fully autonomous enterprise-grade intrusion detection system. Model performance depends heavily on the training data, feature engineering, threshold selection, and operating environment.

In particular, anomaly detection does not automatically determine whether an event is malicious. It identifies behavior that appears unusual relative to the learned patterns.

---

## 📚 Project Goals

The main goals of this project are to explore:

* Cybersecurity anomaly detection
* Network behavioral analysis
* Unsupervised machine learning
* Feature engineering for security data
* Hybrid rule-based + ML detection
* REST-based security event processing
* Practical deployment of ML models in backend systems

---

## 👩‍💻 Author

**Aarya Mallik**
B.Tech — Computer Science & Engineering

GitHub: [@Aaryamallik03](https://github.com/Aaryamallik03)

---

## 📄 License

This project is currently intended as an academic/development project.

A formal open-source license can be added when the project is ready for public distribution.

