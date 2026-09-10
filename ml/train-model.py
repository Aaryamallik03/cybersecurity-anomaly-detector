from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


DATA = Path("ml/processed/cicids2017_features.csv")

print("Loading dataset...")

df = pd.read_csv(
    DATA,
    low_memory=False,
)

print("Original shape:", df.shape)

df["Timestamp"] = pd.to_datetime(
    df["Timestamp"],
    errors="coerce",
)

df = df.dropna(
    subset=["Timestamp"]
)

df = df.sort_values(
    "Timestamp"
).reset_index(
    drop=True
)


# Balanced sampling

sample_size = min(
    300000,
    len(df),
)

parts = []

for label, group in df.groupby(
    "Label",
    sort=False,
):
    n = max(
        2,
        int(
            sample_size
            * len(group)
            / len(df)
        ),
    )

    n = min(
        n,
        len(group),
    )

    if n >= 2:
        parts.append(
            group.sample(
                n=n,
                random_state=42,
            )
        )

df = pd.concat(
    parts,
    ignore_index=True,
)

df = df.sort_values(
    "Timestamp"
).reset_index(
    drop=True
)

print("Sampled shape:", df.shape)

print("\nClasses in sampled dataset:")
print(df["Label"].value_counts())


# Feature preparation

drop_columns = [
    "Label",
    "Timestamp",
    "Flow ID",
    "Source IP",
    "Destination IP",
]

X = df.drop(
    columns=[
        column
        for column in drop_columns
        if column in df.columns
    ]
)

y_labels = df["Label"]

encoder = LabelEncoder()

y = encoder.fit_transform(
    y_labels
)

print(
    "\nNumber of classes:",
    len(encoder.classes_),
)

print("Classes:")

for class_name in encoder.classes_:
    print(" -", class_name)


# Random stratified evaluation

print("\n========================================")
print("RANDOM STRATIFIED EVALUATION")
print("========================================")

X_train_random, X_test_random, y_train_random, y_test_random = (
    train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )
)

random_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
)

print("\nTraining Random Forest...")

random_model.fit(
    X_train_random,
    y_train_random,
)

random_pred = random_model.predict(
    X_test_random
)

random_accuracy = accuracy_score(
    y_test_random,
    random_pred,
)

random_macro_f1 = f1_score(
    y_test_random,
    random_pred,
    average="macro",
    zero_division=0,
)

random_weighted_f1 = f1_score(
    y_test_random,
    random_pred,
    average="weighted",
    zero_division=0,
)

print(
    "\nRandom Split Accuracy:",
    random_accuracy,
)

print(
    "Random Split Macro F1:",
    random_macro_f1,
)

print(
    "Random Split Weighted F1:",
    random_weighted_f1,
)

print("\nRandom Split Classification Report:\n")

print(
    classification_report(
        y_test_random,
        random_pred,
        labels=range(
            len(encoder.classes_)
        ),
        target_names=encoder.classes_,
        zero_division=0,
    )
)


# Temporal evaluation

print("\n========================================")
print("TEMPORAL EVALUATION")
print("========================================")

split_index = int(
    len(df) * 0.8
)

X_train_temporal = X.iloc[
    :split_index
]

X_test_temporal = X.iloc[
    split_index:
]

y_train_temporal = y[
    :split_index
]

y_test_temporal = y[
    split_index:
]

print(
    "\nTraining rows:",
    len(X_train_temporal),
)

print(
    "Testing rows:",
    len(X_test_temporal),
)

print(
    "Training period:",
    df["Timestamp"].iloc[0],
    "to",
    df["Timestamp"].iloc[split_index - 1],
)

print(
    "Testing period:",
    df["Timestamp"].iloc[split_index],
    "to",
    df["Timestamp"].iloc[-1],
)

train_classes = set(
    y_train_temporal
)

test_classes = set(
    y_test_temporal
)

common_classes = sorted(
    train_classes.intersection(
        test_classes
    )
)

print(
    "\nClasses present in BOTH training and testing:"
)

for class_index in common_classes:
    print(
        " -",
        encoder.classes_[class_index],
    )

missing_from_training = sorted(
    test_classes - train_classes
)

missing_from_testing = sorted(
    train_classes - test_classes
)

if missing_from_training:
    print(
        "\nClasses present in testing but missing from training:"
    )

    for class_index in missing_from_training:
        print(
            " -",
            encoder.classes_[class_index],
        )

if missing_from_testing:
    print(
        "\nClasses present in training but missing from testing:"
    )

    for class_index in missing_from_testing:
        print(
            " -",
            encoder.classes_[class_index],
        )


temporal_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
)

print("\nTraining temporal Random Forest...")

temporal_model.fit(
    X_train_temporal,
    y_train_temporal,
)

temporal_pred = temporal_model.predict(
    X_test_temporal
)


# Fair temporal evaluation

evaluation_mask = pd.Series(
    y_test_temporal
).isin(
    common_classes
).to_numpy()

fair_y_test = y_test_temporal[
    evaluation_mask
]

fair_pred = temporal_pred[
    evaluation_mask
]

if len(fair_y_test) > 0:

    temporal_accuracy = accuracy_score(
        fair_y_test,
        fair_pred,
    )

    temporal_macro_f1 = f1_score(
        fair_y_test,
        fair_pred,
        labels=common_classes,
        average="macro",
        zero_division=0,
    )

    temporal_weighted_f1 = f1_score(
        fair_y_test,
        fair_pred,
        labels=common_classes,
        average="weighted",
        zero_division=0,
    )

    print(
        "\nFair Temporal Accuracy:",
        temporal_accuracy,
    )

    print(
        "Fair Temporal Macro F1:",
        temporal_macro_f1,
    )

    print(
        "Fair Temporal Weighted F1:",
        temporal_weighted_f1,
    )

    print(
        "\nFair Temporal Classification Report:\n"
    )

    print(
        classification_report(
            fair_y_test,
            fair_pred,
            labels=common_classes,
            target_names=[
                encoder.classes_[index]
                for index in common_classes
            ],
            zero_division=0,
        )
    )

else:
    print(
        "\nNo common classes available for fair temporal evaluation."
    )


# Feature importance

importance = pd.Series(
    random_model.feature_importances_,
    index=X.columns,
).sort_values(
    ascending=False
)

print("\nTop 20 Features:")

print(
    importance.head(20)
)


# Final production model

print("\n========================================")
print("FINAL PRODUCTION MODEL")
print("========================================")

print(
    "\nTraining final production Random Forest on the complete balanced sample..."
)

production_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
)

production_model.fit(
    X,
    y,
)


# Save production model

joblib.dump(
    production_model,
    "ml/model.pkl",
)

joblib.dump(
    encoder,
    "ml/label_encoder.pkl",
)

print(
    "\nFinal production model saved successfully."
)

print(
    "Model path: ml/model.pkl"
)

print(
    "Encoder path: ml/label_encoder.pkl"
)

print(
    "\nThe production model was trained on all classes in the balanced dataset."
)