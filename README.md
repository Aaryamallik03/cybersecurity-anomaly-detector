# Real-Time Cybersecurity Anomaly Detection System

A local cybersecurity monitoring system that ingests network events, detects suspicious activity using rule-based and deterministic ML-style scoring, generates alerts, maintains an audit trail, and supports event replay.

## Features

- REST API for network event ingestion
- MongoDB persistence
- Unified event schema
- Duplicate event protection
- Failed-login anomaly detection
- Rule-based detection
- Local deterministic scoring model
- Alert generation
- Audit trail
- Event-specific audit queries
- Deterministic event replay
- Automated tests
- Edge-case fixture dataset

## Technologies

- Python
- FastAPI
- MongoDB
- Pydantic
- Uvicorn
- Git
- VS Code

## Project Structure

```text
cybersecurity_anomaly_detector/
│
├── backend/
│   ├── main.py
│   ├── model.json
│   ├── replay.py
│   ├── test_main.py
│   │
│   └── fixtures/
│       └── edge_cases.json
│
└── README.md