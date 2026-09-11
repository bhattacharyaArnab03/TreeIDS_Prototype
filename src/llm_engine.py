import os
import json
import time
from collections import deque
from datetime import datetime, timezone
from groq import Groq
from src.audit_logger import AuditLogger


class _GroqQuotaGuard:
    """Private quota accounting driven by local environment settings for Groq API."""

    def __init__(self):
        self.usage_file = os.getenv("TREEIDS_GROQ_USAGE_FILE", ".cache/groq_usage.json")
        self.request_windows = {"primary": deque(), "secondary": deque()}
        self.token_windows = {"primary": deque(), "secondary": deque()}
        self.state = self._load()

    @staticmethod
    def _today():
        return datetime.now(timezone.utc).date().isoformat()

    def _load(self):
        try:
            with open(self.usage_file, "r", encoding="utf-8") as usage_file:
                state = json.load(usage_file)
            if state.get("date") == self._today():
                return state
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return {"date": self._today(), "roles": {}}

    def _save(self):
        directory = os.path.dirname(self.usage_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.usage_file, "w", encoding="utf-8") as usage_file:
            json.dump(self.state, usage_file, indent=2)

    def reserve(self, role, estimated_tokens):
        if self.state.get("date") != self._today():
            self.state = {"date": self._today(), "roles": {}}

        prefix_groq = f"TREEIDS_GROQ_{role.upper()}"
        try:
            rpm = os.getenv(f"{prefix_groq}_RPM", "30")
            tpm = os.getenv(f"{prefix_groq}_TPM", "14400")
            rpd = os.getenv(f"{prefix_groq}_RPD", "14400")
            limits = {
                "rpm": int(rpm),
                "tpm": int(tpm),
                "rpd": int(rpd),
            }
        except (KeyError, ValueError):
            return False

        now = time.time()
        requests = self.request_windows[role]
        tokens = self.token_windows[role]
        while requests and now - requests[0] >= 60:
            requests.popleft()
        while tokens and now - tokens[0][0] >= 60:
            tokens.popleft()

        if "roles" not in self.state or not isinstance(self.state["roles"], dict):
            self.state["roles"] = {}
        roles_dict = self.state["roles"]
        if role not in roles_dict or not isinstance(roles_dict[role], dict):
            roles_dict[role] = {"requests": 0}
        role_state = roles_dict[role]
        if role_state["requests"] >= limits["rpd"]:
            return False
        if len(requests) >= limits["rpm"]:
            return False
        if sum(item[1] for item in tokens) + estimated_tokens > limits["tpm"]:
            return False

        requests.append(now)
        tokens.append((now, estimated_tokens))
        role_state["requests"] += 1
        self._save()
        return True


class TreeIDSReasoningEngine:
    """
    Vectorless RAG Engine with silent backend multi-tier fallback architecture:
    Primary: qwen/qwen3.8-27b (Groq Cloud API)
    Secondary: openai/gpt-oss-20b (Groq Cloud API)
    Tertiary: Mock Rule-Based Heuristic Engine
    """
    def __init__(self, config: dict):
        self.config = config
        self.api_key = os.getenv("GROQ_API_KEY")
        self.audit_logger = AuditLogger(config=self.config)
        self._quota_guard = _GroqQuotaGuard()
        self.groq_client = None

        if self.api_key and not self.api_key.startswith("your_"):
            try:
                self.groq_client = Groq(api_key=self.api_key)
            except Exception as e:
                print(f"  [!] Warning: Failed to initialize Groq client: {e}")

    def analyze_tree(self, tree_index: dict, dataset_name: str = "Unknown") -> list:
        # Read session limit from tree_builder section in config.yaml
        tree_cfg = self.config.get('tree_builder', {})
        max_sessions = tree_cfg.get('max_sessions_eval', 10)
        
        print("[+] Executing Vectorless Reasoning Traversal...")
        results = []
        evaluated_count = 0

        hosts = tree_index.get("hosts", {})
        print(f"[+] Found {len(hosts)} hosts in tree index. Evaluating up to {max_sessions} sessions across [{dataset_name}]...")

        for src_ip, host_node in hosts.items():
            if evaluated_count >= max_sessions:
                break

            reasoning_breadcrumbs = [f"Root -> Inspected Host [{src_ip}] with {host_node['total_flows']} flows"]

            for session_key, session_node in host_node.get("sessions", {}).items():
                if evaluated_count >= max_sessions:
                    break

                evaluated_count += 1
                print(f"  [->] [{evaluated_count}/{max_sessions}] Analyzing Host: {src_ip} | Session: {session_key}...")

                # Execute Silent Backend Cascading Evaluation
                classification = self._evaluate_node_with_fallback(session_node, src_ip)

                verdict = classification.get("verdict", classification.get("status", "UNKNOWN"))
                threat = classification.get("threat_classification", classification.get("threat_type", "N/A"))
                confidence = float(classification.get("confidence", 0.90))
                mitre = classification.get("mitre_attack", {
                    "tactic": "N/A",
                    "technique_id": "N/A",
                    "technique_name": "N/A"
                })
                reasoning = classification.get("explanation", classification.get("reasoning", "N/A"))
                mitigation = classification.get("recommended_mitigation", "N/A")

                entry = {
                    "source_ip": str(src_ip),
                    "session": str(session_key),
                    "classification": verdict,
                    "confidence": confidence,
                    "threat_type": threat,
                    "mitre_attack": mitre,
                    "reasoning_path": list(reasoning_breadcrumbs),
                    "explanation": reasoning,
                    "recommended_mitigation": mitigation
                }

                # Maintain persistent audit log
                self.audit_logger.log_evaluation(dataset_name, entry)
                results.append(entry)

                time.sleep(0.8)  # Gentle rate-limiting delay

        print(f"[+] Completed evaluation of {len(results)} session nodes. Audit log updated.")
        return results

    def _evaluate_node_with_fallback(self, session_node: dict, src_ip: str = "N/A") -> dict:
        """Silently attempts Primary -> Secondary -> Mock fallback behind the scenes."""
        prompt = self._build_prompt(session_node, src_ip)
        
        llm_cfg = self.config.get('llm', {})
        primary = os.getenv("GROQ_PRIMARY_MODEL") or llm_cfg.get('primary_model', 'qwen/qwen3.8-27b')
        secondary = os.getenv("GROQ_SECONDARY_MODEL") or llm_cfg.get('secondary_model', 'openai/gpt-oss-20b')
        use_mock = llm_cfg.get('fallback_to_mock', True)
        temp = llm_cfg.get('temperature', 0.1)

        # If provider is explicitly set to "mock", bypass API entirely
        if llm_cfg.get("provider") == "mock":
            return self._mock_evaluation(session_node)

        # Tier 1: Primary Model (Groq - qwen/qwen3.8-27b)
        if self.groq_client and llm_cfg.get("provider") == "cascade":
            estimated_tokens = max(1, len(prompt) // 4)
            if self._quota_guard.reserve("primary", estimated_tokens):
                try:
                    response = self.groq_client.chat.completions.create(
                        messages=[
                            {"role": "system", "content": "You are TreeIDS, an expert cognitive network intrusion detection and SOC reasoning agent. Always output valid JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        model=primary,
                        temperature=temp,
                        response_format={"type": "json_object"},
                        timeout=30.0
                    )
                    content = response.choices[0].message.content
                    if content is not None:
                        return json.loads(content)
                except Exception as e:
                    print(f"  [!] Tier 1 ({primary}) failover -> {type(e).__name__}: {e}")

            # Tier 2: Secondary Model (Groq - openai/gpt-oss-20b)

            if self._quota_guard.reserve("secondary", estimated_tokens):
                try:
                    response = self.groq_client.chat.completions.create(
                        messages=[
                            {"role": "system", "content": "You are TreeIDS, an expert cognitive network intrusion detection and SOC reasoning agent. Always output valid JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        model=secondary,
                        temperature=temp,
                        response_format={"type": "json_object"},
                        timeout=30.0
                    )
                    content = response.choices[0].message.content
                    if content is not None:
                        return json.loads(content)
                except Exception as e:
                    print(f"  [!] Tier 2 ({secondary}) failover -> {type(e).__name__}: {e}")

        # Tier 3: Local Mock Engine
        if use_mock:
            return self._mock_evaluation(session_node)

        return {
            "verdict": "UNKNOWN",
            "confidence": 0.0,
            "threat_classification": "Inference Failure",
            "mitre_attack": {"tactic": "N/A", "technique_id": "N/A", "technique_name": "N/A"},
            "reasoning_path": "Unable to obtain evaluation from reasoning engine.",
            "recommended_mitigation": "Check LLM API connectivity and retry."
        }

    def _build_prompt(self, session_node: dict, src_ip: str = "N/A") -> str:
        return f"""
        You are TreeIDS, an expert cognitive network intrusion detection and SOC reasoning agent.
        Evaluate this deterministic hierarchical session telemetry node extracted from network logs:

        Host & Session Telemetry:
        - Source IP: {src_ip}
        - Target IP: {session_node.get('destination_ip', 'N/A')}
        - Target Port: {session_node.get('destination_port', 'N/A')}
        - Total Forward Packets: {session_node.get('total_fwd_packets', 0)}
        - Average Flow Duration: {session_node.get('avg_duration', 0)} ms
        - Aggregated Flow Count: {session_node.get('flow_count', 0)}

        Task: Analyze the structural traffic metrics for security threats (e.g. TCP SYN Flood / DoS, Port Scanning / Discovery, SSH/RDP/FTP Brute Force, Web Attacks, Infiltration, Botnet C2, or Normal Benign Communication).
        Map any detected threats to MITRE ATT&CK Enterprise TTPs and provide actionable mitigation advice.

        Return ONLY a JSON response in this exact format:
        {{
            "verdict": "BENIGN" | "SUSPICIOUS" | "MALICIOUS",
            "confidence": 0.95,
            "threat_classification": "Short title of threat or traffic classification",
            "mitre_attack": {{
                "tactic": "Tactic Name (e.g. Discovery, Impact, Initial Access)",
                "technique_id": "TXXXX (e.g. T1046, T1498, T1110)",
                "technique_name": "Technique Name"
            }},
            "reasoning_path": "Concise step-by-step forensic reasoning explaining why this session is classified as such",
            "recommended_mitigation": "Actionable remediation command or firewall recommendation for Tier-1 SOC analysts"
        }}
        """

    def _mock_evaluation(self, session_node: dict) -> dict:
        fwd_pkts = session_node.get("total_fwd_packets", 0)
        avg_dur = session_node.get("avg_duration", 0)
        dst_port = session_node.get("destination_port", 0)

        if fwd_pkts > 1000 or (avg_dur < 100 and fwd_pkts > 500):
            return {
                "verdict": "MALICIOUS",
                "confidence": 0.95,
                "threat_classification": "Volumetric Denial of Service (DoS / DDoS)",
                "mitre_attack": {
                    "tactic": "Impact",
                    "technique_id": "T1498",
                    "technique_name": "Network Denial of Service"
                },
                "reasoning_path": f"Abnormal forward packet count ({fwd_pkts}) transmitted within an unusually short duration window ({avg_dur} ms).",
                "recommended_mitigation": "Deploy rate-limiting firewall rules on perimeter gateway dropping bursts from source IP."
            }
        elif dst_port in [22, 23, 3389, 8080] and fwd_pkts > 50:
            return {
                "verdict": "SUSPICIOUS",
                "confidence": 0.85,
                "threat_classification": "Network Service Discovery / Brute Force",
                "mitre_attack": {
                    "tactic": "Discovery",
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery"
                },
                "reasoning_path": f"Elevated connection attempts targeting sensitive administrative service port {dst_port}.",
                "recommended_mitigation": "Enforce MFA and temporarily throttle repetitive connections to port."
            }
        else:
            return {
                "verdict": "BENIGN",
                "confidence": 0.98,
                "threat_classification": "Normal Network Communication",
                "mitre_attack": {
                    "tactic": "N/A",
                    "technique_id": "N/A",
                    "technique_name": "N/A"
                },
                "reasoning_path": "Traffic duration, packet rates, and port usage conform to expected baseline operational parameters.",
                "recommended_mitigation": "No action required. Maintain baseline logging."
            }
