# 🛡️ Cybersecurity Anomaly Detector

🔗 **Live Demo:** [API Docs](https://anomaly-detector-488945240645.us-central1.run.app/docs)

A machine-learning-assisted cybersecurity monitoring system for detecting suspicious network activity and behavioral anomalies.

The project combines a FastAPI backend, MongoDB event persistence, rule-based detection, behavioral feature engineering, and Isolation Forest-based anomaly detection to analyze network and security events.

> **Project Status:** Active Development
> **Primary Language:** Python
> **Backend:** FastAPI
> **Machine Learning:** Scikit-learn / Isolation Forest
> **Database:** MongoDB

---

## 📌 Overview

Traditional cybersecurity systems often rely heavily on predefined rules and known attack patterns. While these approaches are useful, they may not identify unusual behavior that does not match an existing rule.

This project explores a hybrid approach that combines rule-based detection with machine-learning-based anomaly detection.

The system currently includes:

* Network and security event ingestion through a REST API
* MongoDB-based event and alert persistence
* Rule-based suspicious activity detection
* Behavioral feature engineering
* Machine-learning-based anomaly scoring
* Isolation Forest anomaly detection
* Behavioral analysis of network activity
* Failed-login anomaly detection
* Alert generation
* Audit trails
* Event replay
* Model training and evaluation scripts
* API and machine-learning testing

---

## 🧠 Detection Pipeline

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
          ├─────────────────┐
          ▼                 ▼
 Rule-Based Detection   Behavioral Analysis
          │                 │
          │                 ▼
          │          Anomaly Detection
          │          (Isolation Forest)
          │                 │
          └────────┬────────┘
                   ▼
              Alert Engine
                   │
                   ▼
          Audit / Persistence
```

The system combines explicit security rules with behavioral anomaly detection so that both known suspicious patterns and unusual activity can be investigated.

---

## 🚀 Key Features

### 🔹 REST API

The FastAPI backend provides functionality for:

* Health checks
* Security event ingestion
* Detection
* Alert generation
* Audit queries
* Event replay

Example:

```text
GET /health
```

---

### 🔹 Event Processing

Incoming security events are validated and processed before detection.

The project supports behavioral analysis of activities such as:

* Authentication activity
* Failed login attempts
* Network connections
* Port scanning behavior
* Unusual connection patterns
* Other security-related events

---

### 🔹 Behavioral Feature Engineering

The project extracts behavioral features from network activity.

Examples include:

```text
src_conn_count_10s
src_conn_count_60s
src_unique_dst_ports_10s
```

These features help represent how a source behaves over a period of time instead of evaluating each network connection independently.

---

### 🔹 Machine Learning Anomaly Detection

The machine-learning pipeline uses **Isolation Forest**, an unsupervised anomaly-detection algorithm.

The model is used to identify observations that behave significantly differently from the learned patterns.

Multiple model versions are maintained during experimentation and evaluation.

---

### 🔹 Hybrid Detection

The project combines two detection approaches:

```text
Known / Explicit Pattern
        ↓
Rule-Based Detection

Unknown / Unusual Pattern
        ↓
Machine Learning
```

This allows traditional security rules and behavioral anomaly detection to work together.

---

### 🔹 Audit Trail

Detection results and relevant events can be persisted for:

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
| Machine Learning        | Scikit-learn     |
| Anomaly Detection       | Isolation Forest |
| Data Processing         | Pandas           |
| Numerical Computing     | NumPy            |
| Model Serialization     | Joblib / Pickle  |
| Version Control         | Git & GitHub     |
| Development Environment | VS Code          |

---

## ⚙️ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Aaryamallik03/cybersecurity-anomaly-detector.git
cd cybersecurity-anomaly-detector
```

### 2. Create a Virtual Environment

On Windows:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

Install the required Python packages used by the backend and machine-learning pipeline.

If a requirements file is available in your local setup:

```powershell
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a local `.env` file using `.env.example` as a reference.

Do not commit `.env` to GitHub.

### 5. Start the Backend

```powershell
uvicorn backend.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 🧪 API Health Check

Once the backend is running:

```bash
curl -X GET "http://127.0.0.1:8000/health"
```

The endpoint should return a successful response when the backend is running correctly.

---

## 🤖 Machine Learning Workflow

### 1. Data Preparation

Network/security data is cleaned and transformed before being used for model development.

Large datasets are intentionally excluded from GitHub.

### 2. Feature Engineering

Behavioral features are generated using:

```text
ml/feature_engineering.py
ml/behavior_features.py
```

### 3. Model Training

Training scripts include:

```text
ml/train.py
ml/train_v2.py
ml/train_v3.py
ml/train-model.py
```

### 4. Evaluation

Model evaluation is handled through:

```text
ml/evaluate.py
```

---

## 📊 Dataset

The project uses network traffic and security-event data for developing and evaluating anomaly-detection models.

Large raw and processed datasets are not stored in the Git repository because of their size.

The following local directories are excluded from Git:

```text
ml/data/
ml/flow_data/
ml/flow_data_clean/
ml/processed/
```

This keeps the GitHub repository focused on the source code, models, configuration, and documentation.

---

## 🔐 Security Considerations

This project is intended for academic, research, and defensive cybersecurity purposes.

Important considerations:

* Never commit API keys, passwords, or database credentials.
* Keep `.env` out of Git.
* Anomaly detection can produce false positives and false negatives.
* An anomaly does not automatically mean that an attack has occurred.
* Models should be evaluated using representative security data before being considered for production use.

---

## 🧪 Testing

The project contains testing scripts covering API, ingestion, model, and behavioral-feature functionality.

```text
ml/test-api.py
ml/test-ingest.py
ml/test-model.py
ml/test_behavior_features.py
```

---

## 🔮 Future Improvements

Planned improvements include:

* Real-time network traffic ingestion
* Improved model evaluation and benchmarking
* Automated threshold calibration
* Precision, recall, and F1-score reporting
* Confusion matrix and ROC analysis
* Security monitoring dashboard
* Streaming anomaly detection
* Improved model version management
* Explainable anomaly scores
* Alert severity classification
* SIEM integration
* Docker deployment
* CI/CD testing
* Model drift monitoring

---

## ⚠️ Current Limitations

This project is currently under active development.

It should not be considered a fully autonomous enterprise-grade Intrusion Detection System.

Detection performance depends on:

* Training data
* Feature engineering
* Model configuration
* Detection thresholds
* Network environment

Machine-learning anomaly detection identifies unusual behavior; it does not by itself prove that activity is malicious.

---

## 🎯 Project Goals

The main goals of this project are:

* Cybersecurity anomaly detection
* Network behavioral analysis
* Unsupervised machine learning
* Security feature engineering
* Hybrid rule-based and ML detection
* REST-based security event processing
* Practical ML backend development
* Applying machine learning to cybersecurity monitoring

---

## 👩‍💻 Author

**Aarya Mallik**

B.Tech — Computer Science & Engineering
National Institute of Technology Meghalaya

GitHub:
https://github.com/Aaryamallik03

---

## 📄 License

This project is currently maintained as an academic/development project.

A formal open-source license can be added when the project is ready for public distribution.

