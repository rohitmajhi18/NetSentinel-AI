import random

import joblib
import pandas as pd
from django.conf import settings
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

ATTACK_TYPES = ["normal", "dos", "probe", "r2l", "u2r", "brute_force"]
FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

MODEL_PATH = settings.MODEL_DIR / "ids_model.joblib"
ENCODER_PATH = settings.MODEL_DIR / "encoders.joblib"

_model = None
_encoders = None


def _generate_synthetic_data(n_samples=2000):
    """Generate NSL-KDD-style synthetic traffic for demo."""
    rows = []
    for _ in range(n_samples):
        attack = random.choices(
            ATTACK_TYPES, weights=[0.55, 0.15, 0.12, 0.08, 0.05, 0.05]
        )[0]
        is_attack = attack != "normal"
        row = {
            "duration": random.uniform(0, 500 if is_attack else 30),
            "protocol_type": random.choice(["tcp", "udp", "icmp"]),
            "service": random.choice(["http", "smtp", "ftp", "ssh", "dns", "other"]),
            "flag": random.choice(["SF", "S0", "REJ", "RSTO"]),
            "src_bytes": random.randint(0, 50000 if is_attack else 5000),
            "dst_bytes": random.randint(0, 50000 if is_attack else 5000),
            "land": random.randint(0, 1 if is_attack else 0),
            "wrong_fragment": random.randint(0, 3 if is_attack else 0),
            "urgent": 0,
            "hot": random.randint(0, 5 if is_attack else 0),
            "num_failed_logins": random.randint(0, 5 if attack == "brute_force" else 0),
            "logged_in": random.randint(0, 1),
            "num_compromised": random.randint(0, 3 if attack in ("r2l", "u2r") else 0),
            "root_shell": 1 if attack == "u2r" and random.random() > 0.7 else 0,
            "su_attempted": random.randint(0, 2 if attack == "u2r" else 0),
            "num_root": random.randint(0, 2 if attack == "u2r" else 0),
            "num_file_creations": random.randint(0, 3 if attack == "u2r" else 0),
            "num_shells": random.randint(0, 2 if attack == "u2r" else 0),
            "num_access_files": random.randint(0, 2),
            "num_outbound_cmds": 0,
            "is_host_login": random.randint(0, 1 if attack == "r2l" else 0),
            "is_guest_login": random.randint(0, 1),
            "count": random.randint(1, 511 if attack == "dos" else 50),
            "srv_count": random.randint(1, 511 if attack == "dos" else 50),
            "serror_rate": random.uniform(0, 1 if attack == "dos" else 0.1),
            "srv_serror_rate": random.uniform(0, 1 if attack == "dos" else 0.1),
            "rerror_rate": random.uniform(0, 0.5),
            "srv_rerror_rate": random.uniform(0, 0.5),
            "same_srv_rate": random.uniform(0, 1),
            "diff_srv_rate": random.uniform(0, 1),
            "srv_diff_host_rate": random.uniform(0, 1),
            "dst_host_count": random.randint(1, 255),
            "dst_host_srv_count": random.randint(1, 255),
            "dst_host_same_srv_rate": random.uniform(0, 1),
            "dst_host_diff_srv_rate": random.uniform(0, 1),
            "dst_host_same_src_port_rate": random.uniform(0, 1),
            "dst_host_srv_diff_host_rate": random.uniform(0, 1),
            "dst_host_serror_rate": random.uniform(0, 0.5),
            "dst_host_srv_serror_rate": random.uniform(0, 0.5),
            "dst_host_rerror_rate": random.uniform(0, 0.5),
            "dst_host_srv_rerror_rate": random.uniform(0, 0.5),
            "label": attack,
        }
        rows.append(row)
    return pd.DataFrame(rows)


def _encode_features(df, encoders=None):
    df = df.copy()
    cat_cols = ["protocol_type", "service", "flag"]
    if encoders is None:
        encoders = {}
        for col in cat_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
    else:
        for col in cat_cols:
            le = encoders[col]
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )
    return df, encoders


def train_model(n_samples=3000):
    df = _generate_synthetic_data(n_samples)
    df_encoded, encoders = _encode_features(df)
    X = df_encoded[FEATURE_NAMES]
    y = df_encoded["label"]

    le_label = LabelEncoder()
    y_enc = le_label.fit_transform(y)
    encoders["label"] = le_label

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, average="weighted", zero_division=0),
        "recall": recall_score(y_test, y_pred, average="weighted", zero_division=0),
        "f1_score": f1_score(y_test, y_pred, average="weighted", zero_division=0),
        "samples_trained": len(X_train),
    }

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(encoders, ENCODER_PATH)
    global _model, _encoders
    _model, _encoders = clf, encoders
    return metrics


def _load_model():
    global _model, _encoders
    if _model is not None:
        return _model, _encoders
    if MODEL_PATH.exists() and ENCODER_PATH.exists():
        _model = joblib.load(MODEL_PATH)
        _encoders = joblib.load(ENCODER_PATH)
    return _model, _encoders


def ensure_model():
    if not MODEL_PATH.exists():
        return train_model()
    return None


def predict_traffic(features_dict):
    model, encoders = _load_model()
    if model is None:
        ensure_model()
        model, encoders = _load_model()

    df = pd.DataFrame([features_dict])
    df_encoded, _ = _encode_features(df, encoders)
    X = df_encoded[FEATURE_NAMES]
    pred_idx = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    label = encoders["label"].inverse_transform([pred_idx])[0]
    confidence = float(max(proba))
    return label, confidence


def random_traffic_sample():
    """Generate a single random traffic record for simulation."""
    df = _generate_synthetic_data(1)
    row = df.iloc[0].to_dict()
    features = {k: row[k] for k in FEATURE_NAMES}
    return features, f"192.168.{random.randint(1,254)}.{random.randint(1,254)}", f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"


SEVERITY_MAP = {
    "normal": "low",
    "probe": "medium",
    "dos": "high",
    "r2l": "high",
    "u2r": "critical",
    "brute_force": "high",
}
