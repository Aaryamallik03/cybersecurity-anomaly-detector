from pathlib import Path

import numpy as np
import pandas as pd


INPUT_FILE = Path("ml/processed/cicids2017_clean.csv")
OUTPUT_FILE = Path("ml/processed/cicids2017_features.csv")


# ---------------------------------------------------------
# Behavioral (time-window) feature helpers
# ---------------------------------------------------------

def add_group_rolling_count(
    df: pd.DataFrame,
    group_column: str,
    window_seconds: int,
    feature_name: str,
) -> None:
    """
    Count events for each group within a backward-looking time window.
    The current event is included in the count.
    """

    result = np.zeros(len(df), dtype=np.float64)

    work = df[[group_column, "Timestamp"]].copy()
    work["_row_position"] = np.arange(len(work))

    window = pd.Timedelta(seconds=window_seconds)

    for _, group in work.groupby(group_column, sort=False):
        group = group.sort_values("Timestamp")

        times = group["Timestamp"].to_numpy()
        positions = group["_row_position"].to_numpy()

        left_times = times - window

        left_indices = np.searchsorted(
            times,
            left_times,
            side="left",
        )

        right_indices = np.arange(1, len(times) + 1)

        counts = right_indices - left_indices

        result[positions] = counts

    df[feature_name] = result


def add_bucket_nunique(
    df: pd.DataFrame,
    group_column: str,
    value_column: str,
    seconds: int,
    feature_name: str,
) -> None:
    """Calculate distinct values per group within fixed time buckets."""

    bucket_column = f"_bucket_{seconds}"

    df[bucket_column] = df["Timestamp"].dt.floor(f"{seconds}s")

    grouped = (
        df.groupby(
            [group_column, bucket_column],
            sort=False,
        )[value_column]
        .nunique()
    )

    keys = pd.MultiIndex.from_frame(
        df[[group_column, bucket_column]]
    )

    df[feature_name] = grouped.reindex(keys).to_numpy()

    df[feature_name] = (
        pd.Series(
            df[feature_name].to_numpy(),
            index=df.index,
        ).fillna(0)
    )


def add_bucket_sum(
    df: pd.DataFrame,
    group_column: str,
    value_column: str,
    seconds: int,
    feature_name: str,
) -> None:
    """Calculate grouped traffic volume per fixed time bucket."""

    bucket_column = f"_bucket_{seconds}"

    grouped = (
        df.groupby(
            [group_column, bucket_column],
            sort=False,
        )[value_column]
        .sum()
    )

    keys = pd.MultiIndex.from_frame(
        df[[group_column, bucket_column]]
    )

    df[feature_name] = grouped.reindex(keys).to_numpy()

    df[feature_name] = (
        pd.Series(
            df[feature_name].to_numpy(),
            index=df.index,
        ).fillna(0)
    )


def main() -> None:
    print("Loading cleaned dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False,
    )

    df.columns = df.columns.str.strip()

    required_columns = {
        "Label",
        "Timestamp",
        "Source IP",
        "Destination IP",
    }

    missing_columns = required_columns.difference(
        df.columns
    )

    if missing_columns:
        missing = ", ".join(
            sorted(missing_columns)
        )

        raise ValueError(
            f"Input dataset is missing required columns: {missing}. "
            "Run ml/preprocess.py first to rebuild the cleaned dataset."
        )

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    print(f"Rows: {len(df):,}")
    print(
        f"Columns before engineering: {len(df.columns)}"
    )

    # ---------------------------------------------------------
    # Basic numerical safety
    # ---------------------------------------------------------

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    # ---------------------------------------------------------
    # Flow-level behavioral features
    # ---------------------------------------------------------

    duration = df["Flow Duration"].clip(lower=1)

    df["bytes_per_second"] = (
        df["Total Length of Fwd Packets"]
        + df["Total Length of Bwd Packets"]
    ) / duration

    df["packets_per_second"] = (
        df["Total Fwd Packets"]
        + df["Total Backward Packets"]
    ) / duration

    df["fwd_bwd_packet_ratio"] = (
        df["Total Fwd Packets"]
        / (
            df["Total Backward Packets"]
            + 1
        )
    )

    df["fwd_bwd_byte_ratio"] = (
        df["Total Length of Fwd Packets"]
        / (
            df["Total Length of Bwd Packets"]
            + 1
        )
    )

    df["packet_size_ratio"] = (
        df["Total Length of Fwd Packets"]
        + df["Total Length of Bwd Packets"]
    ) / (
        df["Total Fwd Packets"]
        + df["Total Backward Packets"]
        + 1
    )

    # ---------------------------------------------------------
    # TCP flag concentration
    # ---------------------------------------------------------

    df["tcp_flag_total"] = (
        df["FIN Flag Count"]
        + df["SYN Flag Count"]
        + df["RST Flag Count"]
        + df["PSH Flag Count"]
        + df["ACK Flag Count"]
        + df["URG Flag Count"]
    )

    df["syn_ack_ratio"] = (
        df["SYN Flag Count"]
        / (
            df["ACK Flag Count"]
            + 1
        )
    )

    df["rst_ratio"] = (
        df["RST Flag Count"]
        / (
            df["Total Fwd Packets"]
            + 1
        )
    )

    # ---------------------------------------------------------
    # Time-window behavioral features
    # ---------------------------------------------------------

    print("\nParsing timestamps for behavioral features...")

    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"]
        .astype(str)
        .str.strip(),
        dayfirst=True,
        errors="coerce",
        format="mixed",
    )

    before_ts = len(df)

    df.dropna(
        subset=["Timestamp"],
        inplace=True,
    )

    print(
        f"Removed {before_ts - len(df):,} rows "
        "with unparseable timestamps."
    )

    df.sort_values(
        "Timestamp",
        inplace=True,
    )

    df.reset_index(
        drop=True,
        inplace=True,
    )

    # ---------------------------------------------------------
    # Traffic totals
    # ---------------------------------------------------------

    df["total_packets"] = (
        df["Total Fwd Packets"]
        + df["Total Backward Packets"]
    )

    df["total_bytes"] = (
        df["Total Length of Fwd Packets"]
        + df["Total Length of Bwd Packets"]
    )

    # ---------------------------------------------------------
    # Source activity
    # ---------------------------------------------------------

    print(
        "Calculating source activity "
        "(60s / 5min / 15min)..."
    )

    add_group_rolling_count(
        df,
        "Source IP",
        60,
        "src_conn_count_60s",
    )

    add_group_rolling_count(
        df,
        "Source IP",
        300,
        "src_conn_count_5min",
    )

    add_group_rolling_count(
        df,
        "Source IP",
        900,
        "src_conn_count_15min",
    )

    # ---------------------------------------------------------
    # Destination activity
    # ---------------------------------------------------------

    print("Calculating destination activity...")

    add_group_rolling_count(
        df,
        "Destination IP",
        60,
        "dst_conn_count_60s",
    )

    # ---------------------------------------------------------
    # Destination diversity
    # ---------------------------------------------------------

    print("Calculating destination diversity...")

    add_bucket_nunique(
        df,
        "Source IP",
        "Destination Port",
        60,
        "src_unique_dst_ports_60s",
    )

    add_bucket_nunique(
        df,
        "Source IP",
        "Destination Port",
        300,
        "src_unique_dst_ports_5min",
    )

    add_bucket_nunique(
        df,
        "Source IP",
        "Destination IP",
        60,
        "src_unique_dst_ips_60s",
    )

    add_bucket_nunique(
        df,
        "Destination IP",
        "Source IP",
        60,
        "dst_unique_src_ips_60s",
    )

    # ---------------------------------------------------------
    # Source traffic volume
    # ---------------------------------------------------------

    print("Calculating source traffic volume...")

    add_bucket_sum(
        df,
        "Source IP",
        "total_bytes",
        60,
        "src_bytes_60s",
    )

    add_bucket_sum(
        df,
        "Source IP",
        "total_packets",
        60,
        "src_packets_60s",
    )

    # ---------------------------------------------------------
    # Remove temporary columns
    # ---------------------------------------------------------

    temporary_columns = [
        column
        for column in df.columns
        if column.startswith("_bucket_")
    ]

    df.drop(
        columns=temporary_columns,
        inplace=True,
        errors="ignore",
    )

    # ---------------------------------------------------------
    # Clean engineered data
    # ---------------------------------------------------------

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    before = len(df)

    df.dropna(
        inplace=True,
    )

    print(
        f"Removed {before - len(df):,} rows "
        "after feature engineering."
    )

    print(
        f"Columns after engineering: {len(df.columns)}"
    )

    # ---------------------------------------------------------
    # Save
    # ---------------------------------------------------------

    df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print("\nSaved:")
    print(OUTPUT_FILE.resolve())


if __name__ == "__main__":
    main()