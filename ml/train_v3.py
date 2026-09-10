from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


DATA_FILE = Path("ml/processed/cicids2017_features.csv")
MODEL_DIR = Path("ml/models")

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    print("Loading feature-engineered dataset...")

    df = pd.read_csv(DATA_FILE)

    df["Label"] = df["Label"].astype(str).str.strip()

    benign = df[df["Label"] == "BENIGN"].copy()
    attacks = df[df["Label"] != "BENIGN"].copy()

    print(f"Benign flows: {len(benign):,}")
    print(f"Attack flows: {len(attacks):,}")

    # ---------------------------------------------------------
    # Create fixed train / validation / test sets
    # ---------------------------------------------------------

    benign = benign.sample(
        n=min(900_000, len(benign)),
        random_state=42,
    )

    benign_train, benign_remaining = train_test_split(
        benign,
        test_size=0.40,
        random_state=42,
    )

    benign_validation, benign_test = train_test_split(
        benign_remaining,
        test_size=0.50,
        random_state=42,
    )

    attacks = attacks.sample(
        n=min(400_000, len(attacks)),
        random_state=42,
    )

    attack_validation, attack_test = train_test_split(
        attacks,
        test_size=0.50,
        random_state=42,
    )

    print("\nSplit sizes:")
    print(f"Benign train:      {len(benign_train):,}")
    print(f"Benign validation: {len(benign_validation):,}")
    print(f"Benign test:       {len(benign_test):,}")
    print(f"Attack validation: {len(attack_validation):,}")
    print(f"Attack test:       {len(attack_test):,}")

    # ---------------------------------------------------------
    # Select numeric features
    # ---------------------------------------------------------

    feature_columns = (
        benign_train
        .drop(columns=["Label"])
        .select_dtypes(include=["number"])
        .columns
        .tolist()
    )

    print(f"\nNumeric features: {len(feature_columns)}")

    def prepare_features(dataframe: pd.DataFrame) -> pd.DataFrame:
        X = dataframe[feature_columns].copy()

        X.replace(
            [np.inf, -np.inf],
            np.nan,
            inplace=True,
        )

        X.dropna(inplace=True)

        return X

    X_train = prepare_features(benign_train)
    X_val_benign = prepare_features(benign_validation)
    X_val_attack = prepare_features(attack_validation)
    X_test_benign = prepare_features(benign_test)
    X_test_attack = prepare_features(attack_test)

    # ---------------------------------------------------------
    # Train Isolation Forest
    # ---------------------------------------------------------

    print(f"\nTraining samples: {len(X_train):,}")
    print("Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=300,
        max_samples=50_000,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train)

    print("Training complete.")

    # ---------------------------------------------------------
    # Validation scores
    # ---------------------------------------------------------

    val_benign_scores = -model.score_samples(X_val_benign)
    val_attack_scores = -model.score_samples(X_val_attack)

    val_scores = np.concatenate(
        [
            val_benign_scores,
            val_attack_scores,
        ]
    )

    val_labels = np.concatenate(
        [
            np.zeros(len(val_benign_scores), dtype=int),
            np.ones(len(val_attack_scores), dtype=int),
        ]
    )

    # ---------------------------------------------------------
    # Threshold tuning
    # ---------------------------------------------------------

    print("\nSearching for best threshold...")

    candidate_thresholds = np.percentile(
        val_scores,
        np.arange(80, 100, 0.5),
    )

    best_threshold = None
    best_f1 = -1.0

    for threshold in candidate_thresholds:
        predictions = (
            val_scores >= threshold
        ).astype(int)

        current_f1 = f1_score(
            val_labels,
            predictions,
            zero_division=0,
        )

        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = threshold

    print(f"Best threshold: {best_threshold:.6f}")
    print(f"Validation F1:   {best_f1:.4f}")

    # ---------------------------------------------------------
    # Test
    # ---------------------------------------------------------

    X_test = pd.concat(
        [
            X_test_benign,
            X_test_attack,
        ],
        ignore_index=True,
    )

    y_test = np.concatenate(
        [
            np.zeros(len(X_test_benign), dtype=int),
            np.ones(len(X_test_attack), dtype=int),
        ]
    )

    test_scores = -model.score_samples(X_test)

    predictions = (
        test_scores >= best_threshold
    ).astype(int)

    print("\n==============================")
    print("V3 FINAL TEST RESULTS")
    print("==============================")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    print(f"\nPrecision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["BENIGN", "ATTACK"],
            zero_division=0,
        )
    )

    # ---------------------------------------------------------
    # Save artifacts
    # ---------------------------------------------------------

    joblib.dump(
        model,
        MODEL_DIR / "isolation_forest_v3.joblib",
    )

    joblib.dump(
        feature_columns,
        MODEL_DIR / "features_v3.joblib",
    )

    joblib.dump(
        best_threshold,
        MODEL_DIR / "threshold_v3.joblib",
    )

    print("\nSaved V3 model artifacts.")


if __name__ == "__main__":
    main()