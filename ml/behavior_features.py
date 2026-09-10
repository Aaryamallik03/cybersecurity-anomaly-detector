from pathlib import Path

import numpy as np
import pandas as pd


INPUT_DIR = Path("ml/flow_data_clean")
OUTPUT_DIR = Path("ml/processed/behavioral")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


BEHAVIOR_FEATURES = [
    "src_conn_count_60s",
    "src_conn_count_5min",
    "src_conn_count_15min",
    "src_unique_dst_ports_60s",
    "src_unique_dst_ports_5min",
    "src_unique_dst_ips_60s",
    "dst_conn_count_60s",
    "dst_unique_src_ips_60s",
    "src_bytes_60s",
    "src_packets_60s",
]


def add_group_rolling_count(
    df: pd.DataFrame,
    group_column: str,
    window_seconds: int,
    feature_name: str,
) -> None:
    """
    Count events for each group within a backward-looking time window.

    This implementation uses merge_asof separately for each group,
    avoiding pandas grouped-rolling index ambiguities.
    """

    result = np.zeros(len(df), dtype=np.float64)

    # Work with original row positions.
    work = df[
        [group_column, "Timestamp"]
    ].copy()

    work["_row_position"] = np.arange(len(work))

    # Process each group independently.
    for _, group in work.groupby(group_column, sort=False):
        group = group.sort_values("Timestamp")

        times = group["Timestamp"]

        right = pd.DataFrame(
            {
                "Timestamp": times,
                "count": np.arange(1, len(group) + 1),
            }
        )

        left = pd.DataFrame(
            {
                "Timestamp": times,
                "_row_position": group["_row_position"].to_numpy(),
            }
        )

        # Find the first timestamp >= current - window.
        starts = pd.DataFrame(
            {
                "Timestamp": times - pd.Timedelta(
                    seconds=window_seconds
                ),
                "_row_position": group["_row_position"].to_numpy(),
            }
        )

        starts = starts.sort_values("Timestamp")

        matched = pd.merge_asof(
            starts,
            right,
            on="Timestamp",
            direction="forward",
        )

        counts = (
            matched["count"]
            .fillna(len(group))
            .to_numpy()
        )

        # Number of records inside the interval.
        result[
            group["_row_position"].to_numpy()
        ] = counts

    df[feature_name] = result


def add_bucket_nunique(
    df: pd.DataFrame,
    group_column: str,
    value_column: str,
    seconds: int,
    feature_name: str,
) -> None:
    """
    Calculate distinct values per group within fixed time buckets.

    Fixed buckets are used deliberately to keep memory usage reasonable.
    """

    bucket_column = f"_bucket_{seconds}"

    df[bucket_column] = (
        df["Timestamp"]
        .dt.floor(f"{seconds}s")
    )

    grouped = (
        df.groupby(
            [
                group_column,
                bucket_column,
            ],
            sort=False,
        )[value_column]
        .nunique()
    )

    keys = pd.MultiIndex.from_frame(
        df[
            [
                group_column,
                bucket_column,
            ]
        ]
    )

    df[feature_name] = (
        grouped
        .reindex(keys)
        .to_numpy()
    )

    df[feature_name] = (
        pd.Series(
            df[feature_name].to_numpy(),
            index=df.index,
        )
        .fillna(0)
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
            [
                group_column,
                bucket_column,
            ],
            sort=False,
        )[value_column]
        .sum()
    )

    keys = pd.MultiIndex.from_frame(
        df[
            [
                group_column,
                bucket_column,
            ]
        ]
    )

    df[feature_name] = (
        grouped
        .reindex(keys)
        .to_numpy()
    )

    df[feature_name] = (
        pd.Series(
            df[feature_name].to_numpy(),
            index=df.index,
        )
        .fillna(0)
    )


def process_file(file_path: Path) -> None:

    print("=" * 60)
    print(f"Processing: {file_path.name}")

    df = pd.read_csv(
    file_path,
    low_memory=False,
    encoding="latin1",
    )
    print(
        f"Original rows: {len(df):,}"
    )

    # ---------------------------------------------------------
    # Clean columns
    # ---------------------------------------------------------

    df.columns = df.columns.str.strip()

    # ---------------------------------------------------------
    # Parse timestamp
    # ---------------------------------------------------------

    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        dayfirst=True,
        errors="coerce",
    )

    # ---------------------------------------------------------
    # Clean identifiers
    # ---------------------------------------------------------

    for column in [
        "Source IP",
        "Destination IP",
        "Label",
    ]:
        df[column] = (
            df[column]
            .astype(str)
            .str.strip()
        )

    # ---------------------------------------------------------
    # Numeric fields
    # ---------------------------------------------------------

    numeric_columns = [
        "Source Port",
        "Destination Port",
        "Protocol",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        )

    df.dropna(
        subset=[
            "Timestamp",
            *numeric_columns,
        ],
        inplace=True,
    )

    df.reset_index(
        drop=True,
        inplace=True,
    )

    # Sort by timestamp.
    df.sort_values(
        "Timestamp",
        inplace=True,
    )

    df.reset_index(
        drop=True,
        inplace=True,
    )

    # ---------------------------------------------------------
    # Basic traffic quantities
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
    # Source connection counts
    # ---------------------------------------------------------

    print("Calculating source activity...")

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
    # Destination connection count
    # ---------------------------------------------------------

    print("Calculating destination activity...")

    add_group_rolling_count(
        df,
        "Destination IP",
        60,
        "dst_conn_count_60s",
    )

    # ---------------------------------------------------------
    # Port / IP diversity
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
    # Cleanup
    # ---------------------------------------------------------

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    for column in BEHAVIOR_FEATURES:

        if column not in df.columns:
            raise RuntimeError(
                f"Missing behavioral feature: {column}"
            )

        df[column] = (
            pd.to_numeric(
                df[column],
                errors="coerce",
            )
            .fillna(0)
        )

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
    # Save
    # ---------------------------------------------------------

    output_file = (
        OUTPUT_DIR / file_path.name
    )

    df.to_csv(
        output_file,
        index=False,
    )

    print(
        f"Output rows: {len(df):,}"
    )

    print(
        f"Output columns: {len(df.columns)}"
    )

    print(
        f"Saved: {output_file}"
    )


def main() -> None:

    files = sorted(
        INPUT_DIR.rglob("*.csv")
    )

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {INPUT_DIR.resolve()}"
        )

    print(
        f"Found {len(files)} flow files.\n"
    )

    for file_path in files:
        process_file(file_path)

    print(
        "\nBehavioral feature engineering complete."
    )


if __name__ == "__main__":
    main()