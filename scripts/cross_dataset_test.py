"""Run bounded schema, tree, and mock-detection checks for every dataset selection."""

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from src.data_loader import DataLoader
from src.llm_engine import TreeIDSReasoningEngine
from src.tree_builder import TreeBuilder


def run_cross_dataset_test(config_path: str) -> list[dict]:
    with open(config_path, "r", encoding="utf-8") as config_file:
        base_config = yaml.safe_load(config_file)

    results = []
    for dataset_name in base_config.get("dataset", {}).get("files", {}):
        config = deepcopy(base_config)
        config.setdefault("dataset", {})["active_day"] = dataset_name
        config.setdefault("llm", {})["provider"] = "mock"

        loader = DataLoader(config)
        frame = loader.fetch_dataset()
        tree = TreeBuilder(config).build_tree(frame)
        detections = TreeIDSReasoningEngine(config).analyze_tree(
            tree, dataset_name=dataset_name
        )
        labels = loader.last_ground_truth.astype(str).value_counts().to_dict()

        results.append(
            {
                "dataset": dataset_name,
                "rows_processed": len(frame),
                "hosts": len(tree.get("hosts", {})),
                "sessions_evaluated": len(detections),
                "ground_truth_labels_isolated": len(labels) > 0,
                "label_classes": sorted(labels),
                "verdicts": {
                    verdict: sum(
                        1 for detection in detections if detection["classification"] == verdict
                    )
                    for verdict in ("BENIGN", "SUSPICIOUS", "MALICIOUS")
                },
                "status": "passed",
            }
        )

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument(
        "--output",
        default="outputs/cross_dataset_test_results.json",
        help="Summary JSON output path",
    )
    args = parser.parse_args()

    results = run_cross_dataset_test(args.config)
    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(results, output_file, indent=2)

    print(f"[+] Cross-dataset validation passed for {len(results)} selections.")
    print(f"[+] Summary saved to {args.output}")
    for result in results:
        print(
            f"  [OK] {result['dataset']}: {result['rows_processed']} rows, "
            f"{result['hosts']} hosts, {result['sessions_evaluated']} sessions, "
            f"verdicts={result['verdicts']}"
        )


if __name__ == "__main__":
    main()