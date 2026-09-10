from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
)


DATA_FILE = Path("ml/processed/cicids2017_clean.csv")
MODEL_DIR = Path("ml/models")


def main() -> None:
    print("Loading dataset and model...")

    df = pd.read_csv(DATA_FILE)

    model = joblib.load(
        MODEL_DIR / "isolation_forest_v2.joblib"
    )

    features = joblib.load(
        MODEL_DIR / "features_v2.joblib"
    )

    threshold = joblib.load(
        MODEL_DIR / "threshold_v2.joblib"
    )

    # Clean labels
    df["Label"] = df["Label"].astype(str).str.strip()

    # Use the same numeric features as training
    X = df[features].copy()

    X.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    valid_rows = X.notna().all(axis=1)

    X = X.loc[valid_rows]
    labels = df.loc[valid_rows, "Label"]

    print(f"Evaluation samples: {len(X):,}")
    print(f"Threshold: {threshold:.6f}")

    print("\nGenerating anomaly scores...")

    scores = -model.score_samples(X)

    predictions = (
        scores >= threshold
    ).astype(int)

    # ---------------------------------------------------------
    # Overall metrics
    # ---------------------------------------------------------

    y_true = (labels != "BENIGN").astype(int).to_numpy()

    print("\n==============================")
    print("OVERALL RESULTS")
    print("==============================")

    print(
        f"Precision: "
        f"{precision_score(y_true, predictions, zero_division=0):.4f}"
    )

    print(
        f"Recall:    "
        f"{recall_score(y_true, predictions, zero_division=0):.4f}"
    )

    print(
        f"F1 Score:  "
        f"{f1_score(y_true, predictions, zero_division=0):.4f}"
    )

    # ---------------------------------------------------------
    # Per-attack results
    # ---------------------------------------------------------

    print("\n==============================")
    print("PER-ATTACK RESULTS")
    print("==============================")

    results = []

    attack_labels = sorted(
        label for label in labels.unique()
        if label != "BENIGN"
    )

    for attack in attack_labels:

        mask = labels == attack

        attack_predictions = predictions[mask]

        detected = int(attack_predictions.sum())
        total = len(attack_predictions)

        recall = (
            detected / total
            if total > 0
            else 0
        )

        results.append(
            {
                "Attack": attack,
                "Samples": total,
                "Detected": detected,
                "Recall": recall,
            }
        )

    results_df = pd.DataFrame(results)

    results_df["Recall"] = (
        results_df["Recall"] * 100
    )

    results_df = results_df.sort_values(
        "Recall",
        ascending=False,
    )

    for _, row in results_df.iterrows():
        print(
            f"{row['Attack']:<35}"
            f"{int(row['Samples']):>10,}"
            f"{int(row['Detected']):>12,}"
            f"{row['Recall']:>9.2f}%"
        )

    # Save results
    output_file = Path(
        "ml/per_attack_results.csv"
    )

    results_df.to_csv(
        output_file,
        index=False,
    )

    print(
        f"\nSaved detailed results to:"
        f"\n{output_file.resolve()}"
    )


if __name__ == "__main__":
    main()