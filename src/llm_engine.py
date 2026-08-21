import os
import json
import time
import google.generativeai as genai

class TreeIDSReasoningEngine:
    """
    Vectorless RAG Engine with silent backend multi-tier fallback architecture:
    Primary: gemini-3.6-flash
    Secondary: gemini-2.0-flash
    Tertiary: Mock Rule-Based Heuristic
    """
    def __init__(self, config: dict):
        self.config = config
        self.api_key = os.getenv("GEMINI_API_KEY")
        
        if self.api_key:
            genai.configure(api_key=self.api_key)

    def analyze_tree(self, tree_index: dict) -> list:
        # Read session limit from tree_builder section in config.yaml
        tree_cfg = self.config.get('tree_builder', {})
        max_sessions = tree_cfg.get('max_sessions_eval', 10)
        
        print("[+] Executing Vectorless Reasoning Traversal...")
        results = []
        evaluated_count = 0

        hosts = tree_index.get("hosts", {})
        print(f"[+] Found {len(hosts)} hosts in tree index. Evaluating up to {max_sessions} sessions...")

        for src_ip, host_node in hosts.items():
            if evaluated_count >= max_sessions:
                break

            reasoning_path = [f"Root -> Inspected Host [{src_ip}] with {host_node['total_flows']} flows"]

            for session_key, session_node in host_node.get("sessions", {}).items():
                if evaluated_count >= max_sessions:
                    break

                evaluated_count += 1
                print(f"  [->] [{evaluated_count}/{max_sessions}] Analyzing Host: {src_ip} | Session: {session_key}...")

                # Execute Silent Backend Cascading Evaluation
                classification = self._evaluate_node_with_fallback(session_node)

                results.append({
                    "source_ip": src_ip,
                    "session": session_key,
                    "classification": classification.get("status", "UNKNOWN"),
                    "threat_type": classification.get("threat_type", "N/A"),
                    "reasoning_path": list(reasoning_path),
                    "explanation": classification.get("explanation", "No reasoning provided.")
                })

                time.sleep(1.2)  # Gentle rate-limiting delay

        print(f"[+] Completed evaluation of {len(results)} session nodes.")
        return results

    def _evaluate_node_with_fallback(self, session_node: dict) -> dict:
        """Silently attempts Primary -> Secondary -> Mock fallback behind the scenes."""
        prompt = self._build_prompt(session_node)
        
        llm_cfg = self.config.get('llm', {})
        primary = llm_cfg.get('primary_model', llm_cfg.get('model_name', 'gemini-3.6-flash'))
        secondary = llm_cfg.get('secondary_model', 'gemini-2.0-flash')
        use_mock = llm_cfg.get('fallback_to_mock', True)
        temp = llm_cfg.get('temperature', 0.1)

        gen_config = {
            "response_mime_type": "application/json",
            "temperature": temp
        }

        # If provider is explicitly set to "mock", bypass API entirely
        if llm_cfg.get("provider") == "mock":
            return self._mock_evaluation(session_node)

        # Tier 1: Primary Model (gemini-3.6-flash)
        if self.api_key:
            try:
                model_tier_1 = genai.GenerativeModel(model_name=primary, generation_config=gen_config)
                response = model_tier_1.generate_content(prompt)
                return json.loads(response.text)
            except Exception:
                pass  # Silent failover to Tier 2

            # Tier 2: Secondary Model (gemini-2.0-flash)
            try:
                model_tier_2 = genai.GenerativeModel(model_name=secondary, generation_config=gen_config)
                response = model_tier_2.generate_content(prompt)
                return json.loads(response.text)
            except Exception:
                pass  # Silent failover to Tier 3

        # Tier 3: Local Mock Engine
        if use_mock:
            return self._mock_evaluation(session_node)

        return {
            "status": "ERROR",
            "threat_type": "Inference Failure",
            "explanation": "Unable to obtain evaluation from reasoning engine."
        }

    def _build_prompt(self, session_node: dict) -> str:
        return f"""
        You are TreeIDS, a cognitive network intrusion detection reasoning agent.
        Evaluate this hierarchical session telemetry node extracted from network logs:

        Session Metadata:
        - Target IP: {session_node.get('destination_ip', 'N/A')}
        - Target Port: {session_node.get('destination_port', 'N/A')}
        - Total Forward Packets: {session_node.get('total_fwd_packets', 0)}
        - Average Flow Duration: {session_node.get('avg_duration', 0)} ms
        - Aggregated Flow Count: {session_node.get('flow_count', 0)}

        Task: Analyze the traffic pattern for security threats (e.g., DDoS flooding, Port Scans, SSH/RDP Brute Force, or Benign).
        Return ONLY a JSON response in this exact format:
        {{
            "status": "BENIGN" | "SUSPICIOUS" | "MALICIOUS",
            "threat_type": "short title of threat or traffic classification",
            "explanation": "concise, step-by-step forensic reasoning path"
        }}
        """

    def _mock_evaluation(self, session_node: dict) -> dict:
        fwd_pkts = session_node.get("total_fwd_packets", 0)
        avg_dur = session_node.get("avg_duration", 0)

        if fwd_pkts > 1000 or (avg_dur < 100 and fwd_pkts > 500):
            return {
                "status": "MALICIOUS",
                "threat_type": "DDoS / High-Volume Flooding",
                "explanation": f"Abnormal forward packet count ({fwd_pkts}) detected within short duration."
            }
        elif session_node.get("destination_port") in [22, 23, 3389] and fwd_pkts > 50:
            return {
                "status": "SUSPICIOUS",
                "threat_type": "Port Scan / Brute Force",
                "explanation": f"Elevated connection attempts targeting administrative port {session_node.get('destination_port')}."
            }
        else:
            return {
                "status": "BENIGN",
                "threat_type": "Normal Traffic",
                "explanation": "Traffic metrics fall within baseline operational thresholds."
            }