from pathlib import Path

import numpy as np
import pandas as pd


DATA_DIR = Path("ml/flow_data_clean/TrafficLabelling")
OUTPUT_DIR = Path("ml/processed")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Remove leading/trailing whitespace from column names."""
    df.columns = df.columns.str.strip()
    return df


def load_and_clean_file(file_path: Path) -> pd.DataFrame:
    """Load one CICIDS2017 CSV and clean invalid values."""
    print(f"Reading: {file_path.name}")

    # CICIDS2017 files contain occasional Windows-1252 bytes in text fields.
    df = pd.read_csv(file_path, low_memory=False, encoding="latin1")
    df = clean_columns(df)

    # Replace infinity values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Remove rows containing missing values
    before = len(df)
    df.dropna(inplace=True)
    removed = before - len(df)

    if removed:
        print(f"  Removed {removed:,} invalid rows")

    return df


def main() -> None:
    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in: {DATA_DIR.resolve()}"
        )

    print(f"Found {len(csv_files)} CSV files.\n")

    frames = []

    for file_path in csv_files:
        frames.append(load_and_clean_file(file_path))

    print("\nCombining datasets...")
    df = pd.concat(frames, ignore_index=True)

    print(f"Total rows: {len(df):,}")
    print(f"Total columns: {len(df.columns)}")

    if "Label" not in df.columns:
        raise ValueError("Expected 'Label' column was not found.")

    df["Label"] = df["Label"].astype(str).str.strip()

    print("\nClass distribution:")
    print(df["Label"].value_counts())

    output_file = OUTPUT_DIR / "cicids2017_clean.csv"
    df.to_csv(output_file, index=False)

    print("\nSaved cleaned dataset to:")
    print(output_file.resolve())


if __name__ == "__main__":
    main()
