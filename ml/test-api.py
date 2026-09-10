import pandas as pd
import requests

file_path = "ml/processed/cicids2017_features.csv"

df = pd.read_csv(file_path)

sample = df[df["Label"] != "BENIGN"].iloc[0]

features = sample.drop(labels=["Label", "Timestamp"], errors="ignore").to_dict()

response = requests.post(
    "http://127.0.0.1:8000/ml/predict",
    json=features,
)

print("Actual label:", sample["Label"])
print("API status:", response.status_code)
print("API response:", response.json())