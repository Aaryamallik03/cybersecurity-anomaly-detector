"""
Centralized configuration, read from environment variables.

Nothing here is hardcoded, so the same code can run against a local
Mongo instance, a Docker container, or a hosted cluster just by
changing the environment — no source edits needed.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("DB_NAME", "cybersecurity_db")

MODEL_PATH = Path(os.environ.get(
    "MODEL_PATH",
    str(Path(__file__).parent / "model.json"),
))

# Simple shared-secret API key for the ingestion endpoint.
# In production, prefer a real secrets manager over an env var.
API_KEY = os.environ.get("INGEST_API_KEY", "dev-only-change-me")

# Rule tuning (can be overridden per-environment without a code change)
FAILED_LOGIN_WINDOW_MINUTES = int(os.environ.get("FAILED_LOGIN_WINDOW_MINUTES", "10"))
FAILED_LOGIN_THRESHOLD = int(os.environ.get("FAILED_LOGIN_THRESHOLD", "5"))
HIGH_RATE_WINDOW_SECONDS = int(os.environ.get("HIGH_RATE_WINDOW_SECONDS", "60"))
HIGH_RATE_THRESHOLD = int(os.environ.get("HIGH_RATE_THRESHOLD", "20"))
