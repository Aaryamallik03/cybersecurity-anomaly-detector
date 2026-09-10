import pandas as pd
import requests
import uuid
from datetime import datetime, timezone

file_path = "ml/processed/cicids2017_features.csv"

df = pd.read_csv(file_path)

sample = df[df["Label"] != "BENIGN"].iloc[0]

features = sample.drop(
    labels=["Label", "Timestamp"],
    errors="ignore"
).to_dict()

event = {
    "event_id": str(uuid.uuid4()),
    "source": "CICIDS2017",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "ip_address": "192.168.1.100",
    "action": "connection",
    "duration": float(sample["Flow Duration"]),
    "confidence_score": 0.98,
    "ml_features": features
}

response = requests.post(
    "http://127.0.0.1:8000/ingest",
    headers={
        "X-API-Key": "205912"
    },
    json=event
)

print("Actual label:", sample["Label"])
print("API status:", response.status_code)
print("API response:")
print(response.json())