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


DATA_FILE = Path("ml/processed/cicids2017_clean.csv")
MODEL_DIR = Path("ml/models")

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    print("Loading cleaned dataset...")

    df = pd.read_csv(DATA_FILE)

    print(f"Dataset shape: {df.shape}")

    # ---------------------------------------------------------
    # 1. Separate benign and attack traffic
    # ---------------------------------------------------------

    df["Label"] = df["Label"].astype(str).str.strip()

    benign = df[df["Label"] == "BENIGN"].copy()
    attacks = df[df["Label"] != "BENIGN"].copy()

    print(f"Benign flows: {len(benign):,}")
    print(f"Attack flows: {len(attacks):,}")

    # ---------------------------------------------------------
    # 2. Create train / validation / test splits
    # ---------------------------------------------------------

    # We don't need every benign flow for the first experiment.
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

    print("\nSplit sizes:")
    print(f"Benign train:       {len(benign_train):,}")
    print(f"Benign validation:  {len(benign_validation):,}")
    print(f"Benign test:        {len(benign_test):,}")

    # Use a separate attack subset for validation and test.
    attacks = attacks.sample(
        n=min(400_000, len(attacks)),
        random_state=42,
    )

    attack_validation, attack_test = train_test_split(
        attacks,
        test_size=0.50,
        random_state=42,
    )

    print(f"Attack validation:  {len(attack_validation):,}")
    print(f"Attack test:        {len(attack_test):,}")

    # ---------------------------------------------------------
    # 3. Prepare feature matrix
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
    X_validation_benign = prepare_features(benign_validation)
    X_validation_attack = prepare_features(attack_validation)

    X_test_benign = prepare_features(benign_test)
    X_test_attack = prepare_features(attack_test)

    # ---------------------------------------------------------
    # 4. Train Isolation Forest
    # ---------------------------------------------------------

    print(f"\nTraining samples after cleaning: {len(X_train):,}")
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
    # 5. Generate anomaly scores
    # ---------------------------------------------------------
    #
    # IsolationForest.score_samples():
    # higher = more normal
    # lower  = more anomalous
    #
    # We invert it so:
    # higher = more anomalous
    # ---------------------------------------------------------

    benign_validation_scores = -model.score_samples(
        X_validation_benign
    )

    attack_validation_scores = -model.score_samples(
        X_validation_attack
    )

    validation_scores = np.concatenate(
        [
            benign_validation_scores,
            attack_validation_scores,
        ]
    )

    validation_labels = np.concatenate(
        [
            np.zeros(len(benign_validation_scores), dtype=int),
            np.ones(len(attack_validation_scores), dtype=int),
        ]
    )

    # ---------------------------------------------------------
    # 6. Tune threshold using validation data
    # ---------------------------------------------------------

    print("\nSearching for best anomaly threshold...")

    candidate_thresholds = np.percentile(
        validation_scores,
        np.arange(80, 100, 0.5),
    )

    best_threshold = None
    best_f1 = -1.0

    for threshold in candidate_thresholds:
        predictions = (
            validation_scores >= threshold
        ).astype(int)

        score = f1_score(
            validation_labels,
            predictions,
            zero_division=0,
        )

        if score > best_f1:
            best_f1 = score
            best_threshold = threshold

    print(f"Best threshold: {best_threshold:.6f}")
    print(f"Validation F1:   {best_f1:.4f}")

    # ---------------------------------------------------------
    # 7. Evaluate on completely unseen test data
    # ---------------------------------------------------------

    test_data = pd.concat(
        [
            X_test_benign.assign(_true_label=0),
            X_test_attack.assign(_true_label=1),
        ],
        ignore_index=False,
    )

    X_test = test_data.drop(columns=["_true_label"])
    y_test = test_data["_true_label"].astype(int).to_numpy()

    print(f"\nTest samples: {len(X_test):,}")

    test_scores = -model.score_samples(X_test)

    test_predictions = (
        test_scores >= best_threshold
    ).astype(int)

    print("\n==============================")
    print("FINAL TEST RESULTS")
    print("==============================")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, test_predictions))

    print("\nMetrics:")
    print(
        f"Precision: "
        f"{precision_score(y_test, test_predictions, zero_division=0):.4f}"
    )

    print(
        f"Recall:    "
        f"{recall_score(y_test, test_predictions, zero_division=0):.4f}"
    )

    print(
        f"F1 Score:  "
        f"{f1_score(y_test, test_predictions, zero_division=0):.4f}"
    )

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            test_predictions,
            target_names=["BENIGN", "ATTACK"],
            zero_division=0,
        )
    )

    # ---------------------------------------------------------
    # 8. Save model artifacts
    # ---------------------------------------------------------

    joblib.dump(
        model,
        MODEL_DIR / "isolation_forest_v2.joblib",
    )

    joblib.dump(
        feature_columns,
        MODEL_DIR / "features_v2.joblib",
    )

    joblib.dump(
        best_threshold,
        MODEL_DIR / "threshold_v2.joblib",
    )

    print("\nSaved:")
    print(
        MODEL_DIR / "isolation_forest_v2.joblib"
    )
    print(
        MODEL_DIR / "features_v2.joblib"
    )
    print(
        MODEL_DIR / "threshold_v2.joblib"
    )


if __name__ == "__main__":
    main()