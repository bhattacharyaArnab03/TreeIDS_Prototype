import os
import json
import yaml
from dotenv import load_dotenv
from src.detector import TreeIDSDetector

def load_config(config_path="config/config.yaml") -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def main():
    load_dotenv()

    print("=" * 50)
    print("   TreeIDS: Structure-Aware Vectorless RAG NIDS   ")
    print("=" * 50 + "\n")

    config = load_config()

    detector = TreeIDSDetector(config)
    results = detector.run_pipeline()

    # Dynamically read output path from config.yaml
    output_file = config.get("output", {}).get("results_path", "outputs/detection_results.json")
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] Pipeline Complete. Output saved to {output_file}\n")

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