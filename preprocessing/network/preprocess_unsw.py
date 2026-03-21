from __future__ import annotations

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "UNSW_NB15.csv"
OUTPUT_DIR = Path(__file__).resolve().parent
SUMMARY_PATH = Path(__file__).resolve().parents[1] / "unsw_summary.json"

NON_FEATURE_PARTS = [
    "flow id",
    "timestamp",
    "time",
    "date",
    "src ip",
    "dst ip",
    "source ip",
    "destination ip",
    "srcip",
    "dstip",
    "stime",
    "ltime",
    "starttime",
    "endtime",
]


def _find_label_column(df: pd.DataFrame) -> str:
    candidates = ["label", "class", "target", "attack", "y"]
    lower_map = {col.lower(): col for col in df.columns}
    for key in candidates:
        if key in lower_map:
            return lower_map[key]
    raise ValueError("Could not find a label column.")


def _drop_non_feature_columns(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    drop_cols: list[str] = []
    for col in df.columns:
        if col == label_col:
            continue
        lower = col.lower()
        is_id = (
            lower == "id"
            or lower.endswith("_id")
            or lower.endswith(" id")
            or lower.startswith("id_")
            or " id " in lower
        )
        if is_id or any(part in lower for part in NON_FEATURE_PARTS):
            drop_cols.append(col)
    if drop_cols:
        df = df.drop(columns=drop_cols)
    return df


def _encode_categoricals(df: pd.DataFrame) -> dict[str, LabelEncoder]:
    encoders: dict[str, LabelEncoder] = {}
    cat_cols = df.select_dtypes(include=["object", "category"]).columns
    for col in cat_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    return encoders


def _map_labels(series: pd.Series) -> pd.Series:
    if series.dtype.kind in "biu":
        unique_vals = set(pd.unique(series))
        if unique_vals.issubset({0, 1}):
            return series.astype(int)
    lowered = series.astype(str).str.lower().str.strip()
    return lowered.apply(lambda v: 0 if ("benign" in v or "normal" in v) else 1).astype(int)


def load_processed_data() -> tuple[np.ndarray, np.ndarray, dict[str, object]]:
    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()

    placeholder_values = {"?", "-", "", "nan", "NaN"}
    numeric_df = df.select_dtypes(include=["number"])
    invalid_row_mask = (
        df.isna().any(axis=1)
        | np.isinf(numeric_df.to_numpy()).any(axis=1)
        | df.astype(str).isin(placeholder_values).any(axis=1)
    )
    label_col = _find_label_column(df)
    rows_before = int(df.shape[0])
    raw_features = int(df.shape[1] - 1)

    df = _drop_non_feature_columns(df, label_col)

    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.replace(list(placeholder_values), np.nan).dropna()
    rows_after = int(df.shape[0])

    encoders = _encode_categoricals(df)

    y = _map_labels(df[label_col])
    X = df.drop(columns=[label_col])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    processed_features = int(X_scaled.shape[1])
    summary = {
        "dataset_name": "UNSW-NB15",
        "rows_before": rows_before,
        "rows_after": rows_after,
        "invalid_records_removed": rows_before - rows_after,
        "features_used": processed_features,
        "preprocessing_status": "Completed",
    }

    joblib.dump(scaler, OUTPUT_DIR / "scaler.pkl")
    joblib.dump(encoders, OUTPUT_DIR / "encoder.pkl")
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return X_scaled, y.to_numpy(), summary


if __name__ == "__main__":
    X, y, summary = load_processed_data()
    print("X:", X.shape)
    print("y:", y.shape)
