# Cybersecurity Anomaly Detector 🛡️

A cybersecurity project that detects unusual and potentially suspicious network activity using behavioral analysis and machine learning.

The goal of this project is to identify abnormal patterns in network traffic and generate alerts when something looks suspicious.

## What it does

* Processes network traffic data
* Extracts useful network and behavioral features
* Looks for unusual connection patterns
* Detects suspicious activity such as port scanning
* Generates alerts for detected anomalies
* Provides an API for processing network events
* Stores events and alerts using MongoDB
* Includes testing and event replay functionality

## How it works

```text
Network Traffic
      ↓
Data Preprocessing
      ↓
Feature Extraction
      ↓
Behavioral Analysis
      ↓
Anomaly Detection
      ↓
Alert
```

One of the main ideas is to look at **how a source behaves over time**, rather than looking at every network connection separately.

For example, features such as:

```text
src_conn_count_10s
src_conn_count_60s
src_unique_dst_ports_10s
```

can help identify behavior that may be associated with activities like port scanning.

## Tech Stack

* Python
* FastAPI
* MongoDB
* Pandas
* NumPy
* Scikit-learn
* Pydantic
* Uvicorn
* Git & GitHub

## Project Structure

```text
cybersecurity-anomaly-detector/
│
├── backend/
│   ├── main.py
│   ├── model.json
│   ├── replay.py
│   ├── test_main.py
│   └── fixtures/
│       └── edge_cases.json
│
├── .env.example
├── .gitignore
└── README.md
```

## Running the Project

### 1. Clone the repository

```bash
git clone https://github.com/Aaryamallik03/cybersecurity-anomaly-detector.git
cd cybersecurity-anomaly-detector
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\activate
```

### 3. Install the dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Start the API

```bash
uvicorn backend.main:app --reload
```

The API will then be available at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

## Current Status

This project is currently under development.

The backend and initial detection pipeline are implemented, while the machine-learning and behavioral analysis components are being improved and expanded.

## Future Plans

* Improve anomaly detection accuracy
* Add more behavioral features
* Compare different machine-learning models
* Improve detection of different types of network attacks
* Add real-time traffic monitoring
* Build a monitoring dashboard
* Improve alert explanations

## Author

**Aarya Mallik**

B.Tech Computer Science & Engineering
National Institute of Technology Meghalaya

[GitHub](https://github.com/Aaryamallik03)
