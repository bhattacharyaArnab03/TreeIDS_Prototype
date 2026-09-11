# TreeIDS: System Architecture & Implementation Blueprint

## 1. Executive Summary
**TreeIDS** is a novel Network Intrusion Detection Framework designed to overcome the context fragmentation inherent in vector-based Retrieval-Augmented Generation (RAG) systems. By organizing raw network telemetry into a deterministic 4-tier vectorless hierarchy ($Root \rightarrow Host \rightarrow Session \rightarrow Flow$), TreeIDS enables zero-shot Large Language Model (LLM) reasoning over structural network topology without requiring dense vector embeddings or vector database lookups (e.g., FAISS).

---

## 2. System Architecture & Component Layers

```
[ Layer 1: Ingestion ]    --> Static CSV (CIC-IDS2017 / UNSW-NB15) / Scapy Live Sniffer
│
[ Layer 2: Preprocessing] --> Data Sanitization + Schema Adapter + Dynamic Tree Pruner
│
[ Layer 3: Cognitive Core] --> Zero-Shot Groq API Cascade (qwen3.8-27b / gpt-oss-20b) + Local Mock Fallback
│
[ Layer 4: Output Engine] --> Structured JSON Alert (Verdict + MITRE TTPs + Mitigations) + SIEM JSONL
│
[ Layer 5: Evaluation ]   --> Post-Hoc Label Validation & Supervised ML Baselines (RF / XGBoost)
```

### Detailed Layer Specification:

* **Layer 1: Data Ingestion Module (`src/data_loader.py`, `src/sniffer.py`)**
  * Ingests static benchmark flow datasets (CIC-IDS2017, UNSW-NB15) and captures real-time network packets via Scapy (`\Device\NPF_Loopback` on Windows).
  * Strips ground-truth labels (`Label` column) upfront to enforce strict unlabelled zero-shot inference.
* **Layer 2: Preprocessing, Schema Normalization & Dynamic Tree Pruning (`src/schema_adapter.py`, `src/tree_builder.py`, `src/tree_pruner.py`)**
  * Sanitizes invalid telemetry metrics ($NaN \rightarrow 0$, $Inf \rightarrow \text{max value}$).
  * Normalizes heterogeneous dataset columns into standard canonical network features.
  * Constructs a 4-tier nested structural JSON tree:
    $$\text{Root} \longrightarrow \text{Host (Source IP)} \longrightarrow \text{Session (Destination IP:Port)} \longrightarrow \text{Flow Statistics}$$
  * Applies **Dynamic Tree Pruning** to compress low-signal leaf flows, grouping redundant ephemeral flows and collapsing identical profiles to reduce prompt token footprint by 30%–60%.
* **Layer 3: Cognitive Reasoning Engine (`src/llm_engine.py`)**
  * Vectorless multi-tier fallback architecture powered by **Groq Cloud API** (ultra-fast LPU inference):
    * **Tier 1 (Primary)**: `qwen/qwen3.8-27b` (High-fidelity reasoning & strict JSON adherence)
    * **Tier 2 (Secondary)**: `openai/gpt-oss-20b` (Lightweight, high-throughput failover tier)
    * **Tier 3 (Fallback)**: Local Rule-Based Mock Heuristic Engine
  * Enforces low temperature ($0.1$) for deterministic output.
  * Executes prompt-conditioned MITRE ATT&CK TTP mapping (e.g., T1046, T1498, T1499.002) and generates actionable SOC remediation guidance.
* **Layer 4: Detection & Reporting Engine (`src/audit_logger.py`)**
  * Outputs standardized JSON alerts containing:
    * `Verdict`: (`BENIGN` | `SUSPICIOUS` | `MALICIOUS`)
    * `Confidence_Score`: ($0.0 - 1.0$)
    * `Reasoning_Path`: Step-by-step audit explanation of structural anomalies.
    * `MITRE_TTP`: Mapped Tactic & Technique ID.
    * `Recommended_Mitigation`: Actionable remediation instructions for SOC analysts.
  * Emits human-readable audit logs (`outputs/classification_audit.log`) and machine-readable SIEM logs (`outputs/audit_log.jsonl`).
* **Layer 5: Evaluation & Benchmarking Module (`scripts/baseline_benchmark.py`, `scripts/benchmark_pruning.py`)**
  * Compares Layer 4 JSON outputs against isolated ground-truth labels post-hoc.
  * Computes standard performance metrics: Precision, Recall, F1-Score, Latency, and Cost.
  * Benchmarks zero-shot TreeIDS against supervised baselines (Random Forest, XGBoost).

---

## 3. Data Schema & Prompt Formatting Standard

### Input Structural Sub-Tree Standard (Passed to Prompt):
```json
{
  "host_ip": "192.168.10.5",
  "sessions": [
    {
      "destination_ip": "10.0.0.1",
      "destination_port": 80,
      "protocol": "TCP",
      "metrics": {
        "flow_duration_ms": 1250,
        "total_fwd_packets": 450,
        "total_bwd_packets": 2,
        "packet_rate_per_sec": 361.6,
        "syn_flag_count": 450,
        "ack_flag_count": 0
      }
    }
  ]
}
```

### Output JSON Verdict Standard (Returned by LLM):
```json
{
  "verdict": "MALICIOUS",
  "confidence": 0.95,
  "threat_classification": "TCP SYN Flood / Network Service Discovery",
  "mitre_attack": {
    "tactic": "Discovery",
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery"
  },
  "reasoning_path": "Host 192.168.10.5 initiated 450 SYN packets to port 80 within 1.25 seconds with 0 ACK responses, indicating automated port scanning and potential SYN flooding.",
  "recommended_mitigation": "Apply a temporary rate-limiting firewall rule on gateway router to drop inbound TCP SYN bursts from 192.168.10.5."
}
```

---

## 4. Phase-Wise Implementation Roadmap

```
PHASE 1 (Completed)          PHASE 2 (Completed)           PHASE 3 (Completed)
┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
│ • Static Ingestion      │  │ • UNSW-NB15 Adapter     │  │ • Dynamic Tree Pruning  │
│ • 4-Tier Tree Indexer   │  │ • Scapy Live Sniffer    │  │ • ML Baselines (RF/XGB) │
│ • Zero-Shot Groq Core   │──► • Sliding-Window Buffer │──► • Cost & Latency Bench  │
│ • Rule-Based Fallback   │  │ • Attack Simulator      │  │ • Multi-Day Benchmarks  │
│ • Post-Hoc Evaluation   │  │ • Cross-Dataset Testing │  │ • Final Thesis Defense  │
└─────────────────────────┘  └─────────────────────────┘  └─────────────────────────┘
```

| Phase | Module / Component | Status | Deliverable Description |
| --- | --- | --- | --- |
| **Phase 1** | Data Preprocessing Pipeline | **Completed** | Pandas cleaner handling $NaN$/$Inf$ values for CIC-IDS2017. |
| **Phase 1** | 4-Tier Tree Constructor | **Completed** | Hierarchical Host-Session-Flow JSON tree builder module. |
| **Phase 1** | Cognitive Reasoning Core | **Completed** | Groq Cloud API wrapper with JSON schema enforcement & quota guard. |
| **Phase 1** | Post-Hoc Evaluator | **Completed** | Hidden ground-truth dictionary validation engine. |
| **Phase 2** | Schema Adapter | **Completed** | Header normalization adapter supporting CIC-IDS2017, UNSW-NB15, and generic CSV schemas. |
| **Phase 2** | Live Packet Capture Engine | **Completed** | Asynchronous Scapy/Npcap sniffer using a thread-safe `queue.Queue`; verified on Windows loopback. |
| **Phase 2** | Sliding Window Aggregator | **Completed** | Time-bounded packet-to-flow aggregation with configurable window (10s) and flow timeout (30s). |
| **Phase 2** | Attack Simulation Suite | **Completed** | Controlled Scapy scenarios for SYN floods, port scans, and HTTP low-and-slow traffic. |
| **Phase 2** | Cross-Dataset Testing | **Completed** | Mock-based validation runner checking normalization, label isolation, and tree construction across all configured datasets. |
| **Phase 3** | Dynamic Tree Pruning Module | **Completed** | Retains repeated/high-volume and sensitive-port sessions while pruning low-signal leaves; achieves 30%–60% token reduction. |
| **Phase 3** | Baseline Benchmark Suite | **Completed** | Evaluates Random Forest and XGBoost benchmarks alongside zero-shot TreeIDS static mode. |
| **Phase 3** | Multi-Day Comparative Study | **Completed** | Evaluated on `Wednesday-workingHours` (attacks), `Monday-WorkingHours` (benign baseline), and Live Packet Sniffing mode. |

---

## 5. Architectural Principles & Defense Positions

1. **Vectorless RAG vs. Vector RAG:** Dense vector databases (e.g., FAISS) rely on cosine similarity, which groups logs based on mathematical adjacency rather than logical network context. TreeIDS uses deterministic tree traversal to keep structural session boundaries intact, eliminating context fragmentation.
2. **Domain-Guided Feature Summarization & Dynamic Pruning:** Rather than running opaque statistical dimension-reduction algorithms (e.g., PCA, autoencoders), TreeIDS extracts core protocol attributes and organizes them into structured JSON key-value pairs, pruned dynamically to reduce token consumption to ~250–300 tokens per prompt.
3. **Zero-Shot Generalization:** The model relies purely on zero-shot reasoning over networking principles. It requires no supervised training on specific attack labels, enabling detection of unlabelled or novel zero-day attack patterns without class rebalancing.