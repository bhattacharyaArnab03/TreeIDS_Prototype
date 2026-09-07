```markdown
# TreeIDS: System Architecture & Implementation Blueprint

## 1. Executive Summary
**TreeIDS** is a novel Network Intrusion Detection Framework designed to overcome the context fragmentation inherent in vector-based Retrieval-Augmented Generation (RAG) systems. By organizing raw network telemetry into a deterministic 4-tier vectorless hierarchy ($Root \rightarrow Host \rightarrow Session \rightarrow Flow$), TreeIDS enables zero-shot Large Language Model (LLM) reasoning over structural network topology without requiring dense vector embeddings or vector database lookups (e.g., FAISS).

---

## 2. System Architecture & Component Layers


```

[ Layer 1: Ingestion ]    --> Static CSV (CIC-IDS2017) / Scapy Live Packet Sniffer
│
[ Layer 2: Preprocessing] --> Data Sanitization + 4-Tier JSON Tree Index Builder
│
[ Layer 3: Cognitive Core] --> Zero-Shot Gemini API (Temp: 0.1) + Offline Fallback
│
[ Layer 4: Output Engine] --> Structured JSON Alert (Verdict + TTPs + Mitigations)
│
[ Layer 5: Evaluation ]   --> Post-Hoc Label Validation & Baseline ML Benchmarks

```

### Detailed Layer Specification:

* **Layer 1: Data Ingestion Module**
  * Ingests static benchmark flow datasets (CIC-IDS2017, UNSW-NB15) and captures real-time interface packets via Scapy.
  * Strips ground-truth labels (`Label` column) upfront to enforce strict unlabelled zero-shot inference.
* **Layer 2: Preprocessing & Vectorless Tree Builder**
  * Sanitizes invalid telemetry metrics ($NaN \rightarrow 0$, $Inf \rightarrow \text{max value}$).
  * Constructs a 4-tier nested structural JSON tree:
    $$\text{Root} \longrightarrow \text{Host (Source IP)} \longrightarrow \text{Session (Destination IP:Port)} \longrightarrow \text{Flow Statistics}$$
  * Applies dataset header normalization mappers to maintain schema consistency across heterogeneous telemetry sources.
* **Layer 3: Cognitive Reasoning Engine**
  * Orchestrates zero-shot prompts via Gemini API with system instructions enforcing low temperature ($0.1$) for deterministic output.
  * Formats telemetry into key-value JSON nodes to maintain low token overhead (~250–300 tokens per prompt).
  * Executes prompt-conditioned MITRE ATT&CK TTP mapping (e.g., T1046) and generates context-aware SOC mitigations.
  * Incorporates an offline rule-based mock engine to handle API rate limits and connection drops seamlessly.
* **Layer 4: Detection & Reporting Engine**
  * Outputs standardized JSON alerts containing:
    * `Verdict`: (`BENIGN` | `SUSPICIOUS` | `MALICIOUS`)
    * `Confidence_Score`: ($0.0 - 1.0$)
    * `Reasoning_Path`: Step-by-step audit explanation of structural anomalies.
    * `MITRE_TTP`: Mapped Tactic & Technique ID.
    * `Recommended_Mitigation`: Actionable remediation instructions for Tier-1 SOC analysts.
* **Layer 5: Evaluation & Benchmarking Module**
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
PHASE 1 (Completed)          PHASE 2 (Review 2)            PHASE 3 (Review 3)
┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
│ • Static Ingestion      │  │ • UNSW-NB15 Adapter     │  │ • Dynamic Tree Pruning  │
│ • 4-Tier Tree Indexer   │  │ • Scapy Live Sniffer    │  │ • ML Baselines (RF/XGB) │
│ • Zero-Shot Gemini Core │──► • Sliding-Window Buffer │──► • Cost & Latency Bench  │
│ • Rule-Based Fallback   │  │ • Attack Simulator      │  │ • Thesis Manuscript     │
│ • Post-Hoc Evaluation   │  │ • Cross-Dataset Testing │  │ • Final Defense Prep    │
└─────────────────────────┘  └─────────────────────────┘  └─────────────────────────┘

```

| Phase | Module / Component | Status | Deliverable Description |
| --- | --- | --- | --- |
| **Phase 1** | Data Preprocessing Pipeline | **Completed** | Pandas cleaner handling $NaN$/$Inf$ values for CIC-IDS2017. |
| **Phase 1** | 4-Tier Tree Constructor | **Completed** | Hierarchical Host-Session-Flow JSON tree builder module. |
| **Phase 1** | Cognitive Reasoning Core | **Completed** | Gemini 0.1 API wrapper with JSON schema enforcement & fallback. |
| **Phase 1** | Post-Hoc Evaluator | **Completed** | Hidden ground-truth dictionary validation engine. |
| **Phase 2** | UNSW-NB15 Schema Adapter | **Completed** | Header normalization adapter supports CIC-IDS2017, UNSW-NB15, and generic CSV schemas. |
| **Phase 2** | Live Packet Capture Engine | **Completed** | Asynchronous Scapy/Npcap sniffer using a thread-safe `queue.Queue`; verified on Windows. |
| **Phase 2** | Sliding Window Aggregator | **Completed** | Time-bounded packet-to-flow aggregation with configurable window and flow timeout. |
| **Phase 2** | Attack Simulation Suite | **Completed** | Controlled Scapy scenarios for SYN floods, port scans, UDP bursts, low-and-slow traffic, benign traffic, and dry-run validation. |
| **Phase 2** | Cross-Dataset Testing | **Completed** | Mock-based validation runner checks normalization, label isolation, tree construction, and bounded detection across all configured dataset selections. |
| **Phase 3** | Dynamic Tree Pruning Module | **Completed** | Conservative local pruning retains repeated/high-volume and sensitive-port sessions while removing low-signal leaves; integrated into tree construction. |
| **Phase 3** | Baseline Benchmark Suite | **Completed** | Local Random Forest and XGBoost binary benign-versus-attack benchmark with accuracy, precision, recall, F1, training/prediction latency, and feature importance reporting. |
| **Phase 3** | Capstone Thesis Manuscript | *Pending* | Complete academic documentation and final presentation deck. |

---

## 5. Current Implementation State

### Completed

* **Batch execution:** Loads the configured static dataset, samples up to 1,000 records, normalizes the schema, builds the tree index, and evaluates up to 10 session nodes.
* **Live execution:** Captures packets through Scapy/Npcap, aggregates 10-second windows, expires flows after 30 seconds, builds a tree per window, and evaluates up to 10 sessions per window.
* **Reasoning fallback:** Uses the configured primary Gemini model, secondary Gemini model, and rule-based mock fallback.
* **Development/API modes:** Mock inference is the default for routine development. Gemini is opt-in with `--llm-provider cascade`, which uses the configured primary-to-secondary-to-mock fallback chain.
* **Outputs:** Writes detection results, human-readable audit logs, JSONL audit records, and the processed tree index.
* **Cross-dataset validation:** `scripts/cross_dataset_test.py` passed all 10 configured CIC-IDS2017 selections using bounded 1,000-row samples and mock inference. Every selection normalized successfully, isolated ground-truth labels, built a tree, and evaluated 10 sessions. The compact report is saved at `outputs/cross_dataset_test_results.json`.
* **Dynamic tree pruning:** `src/tree_pruner.py` is integrated into tree construction. On the bounded `Friday_DDoS` sample, it reduced sessions from 301 to 115 and serialized tree size from 152,592 to 73,961 bytes (51.53% smaller) with comparable build time. The benchmark is saved at `outputs/pruning_benchmark.json`.
* **Supervised baselines:** `scripts/baseline_benchmark.py` evaluated Random Forest and XGBoost on a stratified 75/25 split of 1,000 bounded `Friday_DDoS` rows, using binary `BENIGN` versus `ATTACK` labels. Random Forest achieved 1.000 accuracy/F1 with 275.45 ms training and 60.23 ms prediction; XGBoost achieved 0.996 accuracy/F1 with 154.61 ms training and 4.19 ms prediction. Full metrics, class reports, feature importance, and zero API cost are saved at `outputs/baseline_benchmark.json`.

### Latest Pending Tasks

1. Complete thesis documentation and final defense material.

---

## 6. Architectural Principles & Defense Positions

1. **Vectorless RAG vs. Vector RAG:** Dense vector databases (e.g., FAISS) rely on cosine similarity, which groups logs based on mathematical adjacency rather than logical network context. TreeIDS uses deterministic tree traversal to keep structural session boundaries intact, eliminating context fragmentation.
2. **Domain-Guided Feature Summarization:** Rather than running statistical dimension-reduction algorithms (e.g., SHAP, ExtraTrees), TreeIDS extracts core protocol attributes and organizes them into structured JSON key-value pairs, reducing token consumption to ~250–300 tokens per prompt.
3. **Zero-Shot Generalization:** The model relies purely on zero-shot reasoning over networking principles. It requires no supervised training on specific attack labels, enabling detection of unlabelled or novel zero-day attack patterns.

```

```