from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score

DATA = Path("ml/processed/cicids2017_features.csv")
MODEL = Path("ml/model.pkl")
ENCODER = Path("ml/label_encoder.pkl")

df = pd.read_csv(DATA, low_memory=False)

model = joblib.load(MODEL)
encoder = joblib.load(ENCODER)

labels_to_test = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "DoS Hulk",
    "FTP-Patator",
    "SSH-Patator",
    "Bot",
]

drop_columns = [
    "Label",
    "Timestamp",
    "Flow ID",
    "Source IP",
    "Destination IP",
]

print("\nMULTI-SAMPLE ATTACK TEST\n")

for label in labels_to_test:
    sample = df[df["Label"] == label].sample(
        n=min(100, len(df[df["Label"] == label])),
        random_state=42
    )

    X = sample.drop(columns=[c for c in drop_columns if c in sample.columns])

    predictions = model.predict(X)
    predicted_labels = encoder.inverse_transform(predictions)

    accuracy = accuracy_score(
        sample["Label"],
        predicted_labels
    )

    print(f"{label}: {accuracy * 100:.2f}%")

print("\nTest completed.")