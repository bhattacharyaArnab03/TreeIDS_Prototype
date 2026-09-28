"""Benchmark supervised Random Forest and XGBoost baselines locally."""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from src.data_loader import DataLoader


FEATURE_COLUMNS = [
    "src_port",
    "dst_port",
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_byte_rate",
    "flow_packet_rate",
]


def prepare_features(frame):
    features = frame[FEATURE_COLUMNS].copy()
    features["protocol"] = frame["protocol"].astype(str)
    return features.join(
        pd.get_dummies(features.pop("protocol"), prefix="protocol", dtype=float)
    ).fillna(0.0)


def evaluate_model(name, model, x_train, x_test, y_train, y_test, labels, label_names):
    train_started = time.perf_counter()
    model.fit(x_train, y_train)
    train_ms = (time.perf_counter() - train_started) * 1000

    predict_started = time.perf_counter()
    predictions = model.predict(x_test)
    predict_ms = (time.perf_counter() - predict_started) * 1000
    report = classification_report(
        y_test, predictions, labels=labels, target_names=label_names,
        output_dict=True, zero_division=0
    )
    return {
        "model": name,
        "train_time_ms": round(train_ms, 2),
        "predict_time_ms": round(predict_ms, 2),
        "inference_api_cost_usd": 0.0,
        "accuracy": round(accuracy_score(y_test, predictions), 4),
        "precision_weighted": round(precision_score(y_test, predictions, average="weighted", zero_division=0), 4),
        "recall_weighted": round(recall_score(y_test, predictions, average="weighted", zero_division=0), 4),
        "f1_weighted": round(f1_score(y_test, predictions, average="weighted", zero_division=0), 4),
        "classification_report": report,
        "feature_importances": {
            column: round(float(importance), 6)
            for column, importance in zip(x_train.columns, model.feature_importances_)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--output", default="outputs/baseline_benchmark.json")
    parser.add_argument("--estimators", type=int, default=100)
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file)
    if args.dataset:
        config.setdefault("dataset", {})["active_day"] = args.dataset

    loader = DataLoader(config)
    frame = loader.fetch_dataset()
    raw_labels = loader.last_ground_truth
    if raw_labels is None:
        raw_labels = pd.Series(["UNKNOWN"] * len(frame), index=frame.index)
    labels = raw_labels.astype(str).reset_index(drop=True)
    features = prepare_features(frame.reset_index(drop=True))

    # Reduce labels to the benchmark target: BENIGN versus any attack family.
    target = labels.map(lambda value: "BENIGN" if value.strip().upper() == "BENIGN" else "ATTACK")
    counts = target.value_counts()

    benchmark = {
        "dataset": config.get("dataset", {}).get("active_day", "Unknown"),
        "rows_processed": len(frame),
        "class_distribution": counts.to_dict(),
        "features": list(features.columns),
        "models": [],
    }

    if len(counts) < 2 or counts.min() < 2:
        benchmark["status"] = "Single-class baseline dataset (BENIGN-only normal baseline day)"
        benchmark["note"] = (
            "Supervised binary classifiers (Random Forest / XGBoost) require at least two distinct "
            "classes (BENIGN vs ATTACK) to train. TreeIDS zero-shot structural reasoning operates "
            "natively on single-class baseline traffic without requiring retraining."
        )
        with open(args.output, "w", encoding="utf-8") as output_file:
            json.dump(benchmark, output_file, indent=2)
        print(json.dumps(benchmark, indent=2))
        print(f"[+] Baseline report saved to {args.output}")
        return

    x_train, x_test, y_train, y_test = train_test_split(
        features, target, test_size=0.25, random_state=42, stratify=target
    )
    encoder = LabelEncoder()
    y_train_encoded = encoder.fit_transform(y_train)
    y_test_encoded = encoder.transform(y_test)
    class_ids = list(range(len(encoder.classes_)))
    benchmark["split"] = {"train_rows": len(x_train), "test_rows": len(x_test), "random_state": 42}


    random_forest = RandomForestClassifier(
        n_estimators=args.estimators, random_state=42, n_jobs=-1, class_weight="balanced"
    )
    benchmark["models"].append(
        evaluate_model("RandomForest", random_forest, x_train, x_test, y_train_encoded, y_test_encoded, class_ids, encoder.classes_.tolist())
    )

    try:
        from xgboost import XGBClassifier

        xgboost = XGBClassifier(
            n_estimators=args.estimators,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=42,
            n_jobs=2,
        )
        benchmark["models"].append(
            evaluate_model("XGBoost", xgboost, x_train, x_test, y_train_encoded, y_test_encoded, class_ids, encoder.classes_.tolist())
        )
    except ImportError:
        benchmark["xgboost"] = "unavailable"

    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(benchmark, output_file, indent=2)
    print(json.dumps(benchmark, indent=2))
    print(f"[+] Baseline report saved to {args.output}")


if __name__ == "__main__":
    main()