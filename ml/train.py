from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


DATA_FILE = Path("ml/processed/cicids2017_clean.csv")
MODEL_DIR = Path("ml/models")

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    print("Loading cleaned dataset...")

    df = pd.read_csv(DATA_FILE)

    print(f"Dataset shape: {df.shape}")

    # Separate labels
    benign = df[df["Label"] == "BENIGN"].copy()

    print(f"Benign samples: {len(benign):,}")

    # Remove label
    X = benign.drop(columns=["Label"])

    # Keep only numeric features
    X = X.select_dtypes(include=["number"])

    print(f"Numeric features: {X.shape[1]}")

    # Use a manageable training sample
    sample_size = min(300_000, len(X))

    X_train = X.sample(
        n=sample_size,
        random_state=42
    )

    print(f"Training samples: {len(X_train):,}")

    # Replace any remaining invalid values
    X_train = X_train.replace(
        [float("inf"), float("-inf")],
        pd.NA
    ).dropna()

    print(f"Training samples after cleaning: {len(X_train):,}")

    # Scale features
    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X_train)

    print("Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    # Save model and scaler
    joblib.dump(
        model,
        MODEL_DIR / "isolation_forest.joblib"
    )

    joblib.dump(
        scaler,
        MODEL_DIR / "scaler.joblib"
    )

    # Save feature names
    joblib.dump(
        list(X_train.columns),
        MODEL_DIR / "features.joblib"
    )

    print("\nTraining complete!")

    print(
        f"Model saved to: "
        f"{(MODEL_DIR / 'isolation_forest.joblib').resolve()}"
    )


if __name__ == "__main__":
    main()