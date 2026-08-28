import os
import json
from datetime import datetime

class AuditLogger:
    """
    Maintains persistent, structured audit records and human-readable SOC logs
    for every classified network session across different dataset runs.
    """
    def __init__(self, config: dict = None, log_dir: str = "outputs"):
        self.config = config or {}
        out_cfg = self.config.get("output", {})
        
        self.text_log_path = out_cfg.get("audit_log_path", os.path.join(log_dir, "classification_audit.log"))
        self.jsonl_path = out_cfg.get("audit_jsonl_path", os.path.join(log_dir, "audit_log.jsonl"))

        os.makedirs(os.path.dirname(self.text_log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.jsonl_path), exist_ok=True)


    def log_evaluation(self, dataset_name: str, result_entry: dict):
        timestamp = datetime.now().isoformat()
        
        record = {
            "timestamp": timestamp,
            "dataset": dataset_name,
            **result_entry
        }

        # 1. Append to machine-readable JSONL
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        # 2. Append to human-readable text audit log
        verdict = result_entry.get("classification", "UNKNOWN")
        threat = result_entry.get("threat_type", "N/A")
        src_ip = result_entry.get("source_ip", "N/A")
        session = result_entry.get("session", "N/A")
        confidence = result_entry.get("confidence", "N/A")
        mitre = result_entry.get("mitre_attack", {})
        mitre_str = f"{mitre.get('tactic', 'N/A')} - {mitre.get('technique_id', 'N/A')} ({mitre.get('technique_name', 'N/A')})" if isinstance(mitre, dict) and mitre.get('technique_id') else "N/A"
        explanation = result_entry.get("explanation", "")
        mitigation = result_entry.get("recommended_mitigation", "N/A")

        log_banner = (
            f"\n[{timestamp}] DATASET: {dataset_name} | VERDICT: [{verdict}] (Confidence: {confidence})\n"
            f"  Host: {src_ip} -> Session: {session}\n"
            f"  Threat Classification: {threat}\n"
            f"  MITRE ATT&CK: {mitre_str}\n"
            f"  Reasoning Path: {explanation}\n"
            f"  Recommended Mitigation: {mitigation}\n"
            f"{'-'*80}\n"
        )

        with open(self.text_log_path, "a", encoding="utf-8") as f:
            f.write(log_banner)
