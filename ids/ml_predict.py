"""Batch CSV prediction and feature-importance helpers for the Prediction UI."""

from __future__ import annotations

import ipaddress
from collections import Counter

import pandas as pd

from . import ml

FEATURE_IMPORTANCE_LABELS = [
    ("Protocol Type", "protocol_type"),
    ("Packet Length", "src_bytes"),
    ("Flow Duration", "duration"),
    ("Total Fwd Packets", "count"),
    ("Total Backward Packets", "srv_count"),
    ("Fwd Packet Length Max", "dst_bytes"),
]

_FLAG_DISPLAY = {"S0": "SYN", "SF": "FIN", "REJ": "REJ", "RSTO": "RST"}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    return df


def _cell(row: pd.Series, *names, default=None):
    for name in names:
        if name in row.index and pd.notna(row[name]):
            return row[name]
    return default


def _default_features() -> dict:
    return {
        "duration": 0.0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 10,
        "srv_count": 10,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 0.5,
        "diff_srv_rate": 0.5,
        "srv_diff_host_rate": 0.5,
        "dst_host_count": 50,
        "dst_host_srv_count": 50,
        "dst_host_same_srv_rate": 0.5,
        "dst_host_diff_srv_rate": 0.5,
        "dst_host_same_src_port_rate": 0.5,
        "dst_host_srv_diff_host_rate": 0.5,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }


def _parse_ip(value, fallback: str) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    text = str(value).strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return fallback


def row_to_features(row: pd.Series, row_index: int) -> tuple[dict, dict]:
    features = _default_features()

    duration = _cell(row, "flow_duration", "duration", default=125)
    features["duration"] = float(duration)

    protocol = str(_cell(row, "protocol", "protocol_type", default="tcp")).lower()
    features["protocol_type"] = protocol

    packet_len = _cell(row, "packet_length", "src_bytes", "bytes", default=512)
    features["src_bytes"] = int(float(packet_len))
    dst = _cell(row, "dst_bytes", default=features["src_bytes"])
    features["dst_bytes"] = int(float(dst))

    flag = str(_cell(row, "connection_state", "conn_state", "flag", default="SF")).upper()
    if flag == "SYN":
        flag = "S0"
    features["flag"] = flag

    for col in ml.FEATURE_NAMES:
        if col in row.index and pd.notna(row[col]):
            val = row[col]
            if col in ("protocol_type", "service"):
                features[col] = str(val).lower()
            elif col == "flag":
                features[col] = str(val).upper()
            elif isinstance(val, (int, float)):
                features[col] = float(val) if col not in ("src_bytes", "dst_bytes", "land", "count", "srv_count") else int(val)
            else:
                features[col] = val

    src_ip = _parse_ip(_cell(row, "source_ip", "src_ip", "source"), f"192.168.1.{(row_index % 254) + 1}")
    dest_ip = _parse_ip(
        _cell(row, "destination_ip", "dest_ip", "dst_ip", "destination"),
        f"172.16.0.{(row_index % 254) + 1}",
    )

    meta = {
        "source_ip": src_ip,
        "dest_ip": dest_ip,
        "protocol": protocol.upper(),
        "packet_length": features["src_bytes"],
        "flow_duration": round(features["duration"], 1),
        "connection_state": _FLAG_DISPLAY.get(flag, flag),
    }
    return features, meta


def get_display_feature_importance() -> list[dict]:
    model, _ = ml.get_model_and_encoders()
    if model is None:
        return [{"label": label, "value": 0.0} for label, _ in FEATURE_IMPORTANCE_LABELS] + [
            {"label": "Others", "value": 1.0}
        ]

    name_to_imp = dict(zip(ml.FEATURE_NAMES, model.feature_importances_))
    items: list[dict] = []
    mapped: set[str] = set()
    for label, fname in FEATURE_IMPORTANCE_LABELS:
        val = float(name_to_imp.get(fname, 0.0))
        items.append({"label": label, "value": val})
        mapped.add(fname)

    others = sum(v for k, v in name_to_imp.items() if k not in mapped)
    items.append({"label": "Others", "value": float(others)})

    total = sum(x["value"] for x in items) or 1.0
    rounded: list[dict] = []
    running = 0.0
    for i, item in enumerate(items):
        if i == len(items) - 1:
            val = round(1.0 - running, 2)
        else:
            val = round(item["value"] / total, 2)
            running += val
        rounded.append({"label": item["label"], "value": max(val, 0.0)})
    return rounded


def predict_dataset(file_obj) -> dict:
    ml.ensure_model()
    df = pd.read_csv(file_obj)
    df = _normalize_columns(df)
    if df.empty:
        raise ValueError("The CSV file contains no data rows.")

    records: list[dict] = []
    protocols: list[str] = []
    flags: list[str] = []
    durations: list[float] = []
    packet_lengths: list[int] = []

    for idx, row in df.iterrows():
        features, meta = row_to_features(row, int(idx) + 1)
        label, confidence = ml.predict_traffic(features)
        is_malicious = label != "normal"
        conf_pct = round(float(confidence) * 100, 1)

        records.append(
            {
                "source_ip": meta["source_ip"],
                "dest_ip": meta["dest_ip"],
                "protocol": meta["protocol"],
                "packet_length": meta["packet_length"],
                "flow_duration": meta["flow_duration"],
                "prediction": "Malicious" if is_malicious else "Normal",
                "prediction_raw": label,
                "confidence": conf_pct,
            }
        )
        protocols.append(meta["protocol"])
        flags.append(meta["connection_state"])
        durations.append(float(meta["flow_duration"]))
        packet_lengths.append(int(meta["packet_length"]))

    total = len(records)
    malicious_count = sum(1 for r in records if r["prediction"] == "Malicious")
    malicious_pct = round(malicious_count / total * 100, 1)
    normal_pct = round(100.0 - malicious_pct, 1)
    overall_malicious = malicious_count >= (total / 2)
    confidence_score = malicious_pct if overall_malicious else normal_pct

    proto_counter = Counter(protocols)
    dominant_protocol = proto_counter.most_common(1)[0][0] if proto_counter else "TCP"
    flag_counter = Counter(flags)
    dominant_state = flag_counter.most_common(1)[0][0] if flag_counter else "SYN"

    avg_duration = round(sum(durations) / len(durations), 1) if durations else 0
    avg_packet = int(sum(packet_lengths) / len(packet_lengths)) if packet_lengths else 0

    return {
        "total_records": total,
        "overall_class": "malicious" if overall_malicious else "normal",
        "confidence_score": confidence_score,
        "malicious_percent": malicious_pct,
        "normal_percent": normal_pct,
        "model_name": "Random Forest",
        "feature_importance": get_display_feature_importance(),
        "traffic_summary": {
            "flow_duration_ms": avg_duration,
            "packet_length_bytes": avg_packet,
            "protocol": dominant_protocol,
            "connection_state": dominant_state,
        },
        "results": records,
    }
