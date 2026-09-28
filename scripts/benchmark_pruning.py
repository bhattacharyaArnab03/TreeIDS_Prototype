"""Measure dynamic tree pruning impact on the configured bounded dataset."""

import argparse
import json
import sys
import time
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from src.data_loader import DataLoader
from src.tree_builder import TreeBuilder


def build_measurement(config: dict, frame) -> dict:
    started = time.perf_counter()
    tree = TreeBuilder(config).build_tree(frame)
    elapsed_ms = (time.perf_counter() - started) * 1000
    serialized = json.dumps(tree, separators=(",", ":"))
    pruning = tree.get("pruning", {})
    return {
        "build_time_ms": round(elapsed_ms, 2),
        "json_size_bytes": len(serialized.encode("utf-8")),
        "hosts": len(tree.get("hosts", {})),
        "sessions": sum(len(host.get("sessions", {})) for host in tree.get("hosts", {}).values()),
        "pruning": pruning,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--output", default="outputs/pruning_benchmark.json")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file)

    if args.dataset:
        config.setdefault("dataset", {})["active_day"] = args.dataset

    frame = DataLoader(config).fetch_dataset()
    unpruned_config = deepcopy(config)
    unpruned_config.setdefault("tree_pruning", {})["enabled"] = False

    static_config = deepcopy(config)
    static_config.setdefault("tree_pruning", {})["enabled"] = True
    static_config.setdefault("tree_pruning", {})["mode"] = "static"

    adaptive_config = deepcopy(config)
    adaptive_config.setdefault("tree_pruning", {})["enabled"] = True
    adaptive_config.setdefault("tree_pruning", {})["mode"] = "adaptive"

    report = {
        "dataset": config.get("dataset", {}).get("active_day", "Unknown"),
        "rows_processed": len(frame),
        "without_pruning": build_measurement(unpruned_config, frame),
        "static_pruning": build_measurement(static_config, frame),
        "adaptive_pruning": build_measurement(adaptive_config, frame),
    }
    before = report["without_pruning"]
    stat = report["static_pruning"]
    adap = report["adaptive_pruning"]

    report["static_reduction"] = {
        "size_reduction_percent": round((1 - stat["json_size_bytes"] / before["json_size_bytes"]) * 100, 2) if before["json_size_bytes"] else 0.0,
        "session_reduction_percent": round((1 - stat["sessions"] / before["sessions"]) * 100, 2) if before["sessions"] else 0.0,
    }
    report["adaptive_reduction"] = {
        "size_reduction_percent": round((1 - adap["json_size_bytes"] / before["json_size_bytes"]) * 100, 2) if before["json_size_bytes"] else 0.0,
        "session_reduction_percent": round((1 - adap["sessions"] / before["sessions"]) * 100, 2) if before["sessions"] else 0.0,
    }

    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2)

    print(json.dumps(report, indent=2))
    print(f"[+] Benchmark saved to {args.output}")


if __name__ == "__main__":
    main()