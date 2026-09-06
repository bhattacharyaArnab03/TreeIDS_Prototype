import os
import json
import yaml
import argparse
from dotenv import load_dotenv
from src.detector import TreeIDSDetector


def load_config(config_path="config/config.yaml") -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="TreeIDS: Structure-Aware Vectorless RAG NIDS")
    parser.add_argument("--mode", choices=["batch", "live"], default=None, help="Execution mode ('batch' or 'live')")
    parser.add_argument("--dataset", type=str, default=None, help="Active dataset name override (e.g. Friday_DDoS, Friday_PortScan)")
    parser.add_argument("--windows", type=int, default=None, help="Max sliding windows to evaluate in live mode")
    parser.add_argument("--config", type=str, default="config/config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    print("=" * 55)
    print("   TreeIDS: Structure-Aware Vectorless RAG NIDS   ")
    print("=" * 55 + "\n")

    config = load_config(args.config)

    # Apply CLI overrides
    if args.mode:
        config.setdefault("pipeline", {})["mode"] = args.mode
    if args.dataset:
        config.setdefault("dataset", {})["active_day"] = args.dataset

    active_mode = config.get("pipeline", {}).get("mode", "batch")
    detector = TreeIDSDetector(config)

    if active_mode.lower() == "live":
        results = detector.run_live(max_windows=args.windows)
    else:
        results = detector.run_batch()

    # Dynamically read output path from config.yaml
    output_file = config.get("output", {}).get("results_path", "outputs/detection_results.json")
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] Pipeline Complete ({len(results)} sessions evaluated). Output saved to {output_file}\n")

    if results:
        print("--- DEMO OUTPUT SAMPLE (Explainable Inferences) ---")
        for res in results[:3]:
            print(f"Host: {res['source_ip']} -> Session: {res['session']}")
            print(f"Verdict: {res['classification']} (Confidence: {res.get('confidence', 'N/A')}) | Threat: {res['threat_type']}")
            mitre = res.get('mitre_attack', {})
            if isinstance(mitre, dict) and mitre.get('technique_id') and mitre.get('technique_id') != 'N/A':
                print(f"MITRE ATT&CK: [{mitre.get('tactic')}] {mitre.get('technique_id')} - {mitre.get('technique_name')}")
            print(f"Reasoning: {res['explanation']}")
            print(f"Mitigation: {res.get('recommended_mitigation', 'N/A')}")
            print("-" * 50)


if __name__ == "__main__":
    main()
