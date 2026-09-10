from pathlib import Path

import numpy as np
import pandas as pd


FILE = Path(
    "ml/flow_data_clean/"
    "TrafficLabelling/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)


def rolling_count(times_ns: np.ndarray, window_seconds: int) -> np.ndarray:
    """Count events in [current_time - window, current_time]."""

    window_ns = window_seconds * 1_000_000_000

    result = np.empty(len(times_ns), dtype=np.int32)

    for i, current_time in enumerate(times_ns):
        start_time = current_time - window_ns

        left = np.searchsorted(
            times_ns,
            start_time,
            side="left",
        )

        result[i] = i - left + 1

    return result


def main() -> None:
    print("Loading DDoS file...")

    df = pd.read_csv(
        FILE,
        low_memory=False,
        encoding="latin1",
    )

    df.columns = df.columns.str.strip()
    print("\nRaw timestamp strings (first 10, before parsing):")
    print(df["Timestamp"].head(10).tolist())

    df["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        dayfirst=True,
        errors="coerce",
    )

    df.dropna(subset=["Timestamp"], inplace=True)

    df.sort_values("Timestamp", inplace=True)

    df.reset_index(drop=True, inplace=True)

    print("\nLabel counts (full file):")
    print(df["Label"].value_counts())

    first_ddos_idx = df.index[df["Label"] == "DDoS"][0]
    print(f"\nFirst DDoS row appears at index: {first_ddos_idx}")

    # Use the full file this time to include DDoS traffic.
    # df = df.iloc[:20_000].copy()

    print(f"Rows: {len(df):,}")
    print(f"Time span: {df['Timestamp'].max() - df['Timestamp'].min()}")

    # ---------------------------------------------------------
    # Source connection counts
    # ---------------------------------------------------------

    print("Calculating source counts...")

    df["test_src_conn_10s"] = 0
    df["test_src_conn_60s"] = 0

    for source_ip, group in df.groupby(
        "Source IP",
        sort=False,
    ):
        positions = group.index.to_numpy()

        times_ns = (
            group["Timestamp"]
            .astype("int64")
            .to_numpy()
        )

        df.loc[
            positions,
            "test_src_conn_10s",
        ] = rolling_count(
            times_ns,
            10,
        )

        df.loc[
            positions,
            "test_src_conn_60s",
        ] = rolling_count(
            times_ns,
            60,
        )

    # ---------------------------------------------------------
    # Sanity checks
    # ---------------------------------------------------------

    print("\nFeature statistics:")

    print(
        df[
            [
                "test_src_conn_10s",
                "test_src_conn_60s",
            ]
        ].describe().round(2)
    )

    span_check = (
        df.groupby("Source IP")["Timestamp"]
        .agg(lambda x: x.max() - x.min())
        .sort_values(ascending=False)
    )
    print("\nPer-source-IP time span (top 10):")
    print(span_check.head(10))

    gaps = (
        df.groupby("Source IP")["Timestamp"]
        .apply(lambda x: x.diff().dt.total_seconds())
    )
    print("\nGap distribution (seconds) between consecutive events per IP:")
    print(gaps.describe())

    invalid = (
        df["test_src_conn_10s"]
        > df["test_src_conn_60s"]
    ).sum()

    print(
        f"\nRows where 10s > 60s: {invalid}"
    )

    print("\nSample around first DDoS row:")
    start = max(first_ddos_idx - 5, 0)
    print(
        df[
            [
                "Timestamp",
                "Source IP",
                "test_src_conn_10s",
                "test_src_conn_60s",
                "Label",
            ]
        ].iloc[start:start + 20].to_string(index=False)
    )

    print("\nAttacker 172.16.0.1 activity over time:")
    attacker = df[df["Source IP"] == "172.16.0.1"]
    print(f"Total events from this IP: {len(attacker)}")
    print(
        attacker[
            [
                "Timestamp",
                "test_src_conn_10s",
                "test_src_conn_60s",
            ]
        ].iloc[::500].to_string(index=False)
    )

    # ---------------------------------------------------------
    # Timestamp resolution diagnostic
    # ---------------------------------------------------------

    print("\nUnique timestamps for attacker (first 10):")
    print(attacker["Timestamp"].value_counts().sort_index().head(10))

    print("\nRows per unique timestamp (describe):")
    print(attacker["Timestamp"].value_counts().describe())

    attacker_times_ns = attacker["Timestamp"].astype("int64").to_numpy()
    diffs_sec = np.diff(attacker_times_ns) / 1_000_000_000
    print("\nConsecutive time diffs (seconds) within attacker, unique values:")
    print(np.unique(diffs_sec))


if __name__ == "__main__":
    main()