# TreeIDS: Structure-Aware Vectorless RAG Network Intrusion Detection System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Groq Cloud LPU](https://img.shields.io/badge/Inference-Groq%20LPU%20Cascade-orange.svg)](https://groq.com/)
[![CIC-IDS2017](https://img.shields.io/badge/Dataset-CIC--IDS2017-lightgrey.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

**TreeIDS** is a high-throughput, explainable Network Intrusion Detection System (NIDS) that eliminates the context fragmentation of traditional vector-based Retrieval-Augmented Generation (RAG). By transforming raw tabular flow telemetry and live network packets into a deterministic **4-tier vectorless hierarchy** ($Root \rightarrow Host \rightarrow Session \rightarrow Flow$), TreeIDS empowers Large Language Models (LLMs) to perform zero-shot cyber reasoning directly over network topology without dense vector embeddings, vector databases (e.g. FAISS), or costly fine-tuning.

---

## Table of Contents

1. [Key Architectural Highlights](#key-architectural-highlights)
2. [System Architecture](#system-architecture)
3. [Prerequisites & Environment Setup](#prerequisites--environment-setup)
4. [Step-by-Step Command Execution Guide](#step-by-step-command-execution-guide)
5. [Weekday Static Dataset Execution Reference](#weekday-static-dataset-execution-reference)
6. [Live Streaming Mode: Telemetry & Numeric Configurations](#live-streaming-mode-telemetry--numeric-configurations)
7. [Adaptive Tree Pruning & Token Cost Control](#adaptive-tree-pruning--token-cost-control)
8. [Machine Learning Baselines vs. TreeIDS Benchmark](#machine-learning-baselines-vs-treeids-benchmark)
9. [Project Directory Structure](#project-directory-structure)
10. [Output Logs & SIEM Destinations](#output-logs--siem-destinations)
11. [License](#license)

---

## Key Architectural Highlights

* **Vectorless 4-Tier Hierarchical Indexing**: Aggregates raw flows into structured topological graphs ($Root \rightarrow Host \rightarrow Session \rightarrow Flow$), keeping multi-flow attack contexts intact.
* **Groq Cloud Multi-Tier Cascade**: Ultra-fast LPU inference (~0.8s per session) with quota-guarded automatic failover:
  * **Tier 1 (Primary)**: `qwen/qwen3.8-27b` (High-fidelity threat classification & MITRE TTP mapping)
  * **Tier 2 (Secondary)**: `openai/gpt-oss-20b` (Lightweight, high-throughput overflow tier)
  * **Tier 3 (Fallback)**: Local Rule-Based Mock Heuristic Engine
* **Adaptive (Data-Driven) Tree Pruning**: Dynamically scales packet thresholds using Interquartile Range (IQR) traffic dispersion and fan-out reconnaissance detection, eliminating blind spots against stealth port scans while compressing DoS floods by 30%–60%.
* **Dual Pipeline Execution Modes**:
  * **Static Batch Ingestion**: Ingests multi-day CIC-IDS2017 / UNSW-NB15 CSV datasets with automated schema normalization and ground-truth label isolation.
  * **Live Packet Capture & Injection**: Captures real-time packets using Scapy/Npcap across 10-second sliding windows with concurrent multi-vector synthetic breach injection.
* **Explainable SOC Outputs & MITRE ATT&CK Attribution**: Emits structured JSON alerts, human-readable SOC audit trails, and machine-readable SIEM JSONL events with mapped MITRE TTPs and remediation actions.

---

## System Architecture

```
[ Layer 1: Ingestion ]    --> Static CSV (CIC-IDS2017 / UNSW-NB15) / Scapy Live Sniffer
│
[ Layer 2: Preprocessing] --> Data Sanitization + Schema Normalizer + Adaptive Tree Pruner
│
[ Layer 3: Cognitive Core] --> Zero-Shot Groq API Cascade (qwen3.8-27b / gpt-oss-20b) + Mock Fallback
│
[ Layer 4: Output Engine] --> Structured JSON Alert (Verdict + MITRE TTPs + Mitigations) + SIEM JSONL
│
[ Layer 5: Evaluation ]   --> Post-Hoc Label Validation & Supervised ML Baselines (RF / XGBoost)
```

---

## Prerequisites & Environment Setup

### 1. Requirements
* **Python**: 3.10 or higher
* **Operating System**: Windows 10/11 (with [Npcap](https://npcap.com/) installed for live sniffing) or Linux
* **Groq Cloud API Key**: Free tier available from [Groq Console](https://console.groq.com)

### 2. Installation

Clone the repository and install dependencies in a virtual environment:

```powershell
# Clone the repository
git clone https://github.com/bhattacharyaArnab03/TreeIDS_Prototype.git
cd TreeIDS_Prototype

# Create and activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # On Windows PowerShell
# source .venv/bin/activate    # On Linux/macOS

# Install required packages
pip install -r requirements.txt
```

### 3. Environment Configuration (`.env`)

Create or update the `.env` file in the root directory:

```env
GROQ_API_KEY=gsk_your_actual_groq_api_key_here
GROQ_PRIMARY_MODEL=qwen/qwen3.8-27b
GROQ_SECONDARY_MODEL=openai/gpt-oss-20b
TREEIDS_GROQ_PRIMARY_RPM=30
TREEIDS_GROQ_PRIMARY_TPM=14400
TREEIDS_GROQ_PRIMARY_RPD=14400
TREEIDS_GROQ_SECONDARY_RPM=30
TREEIDS_GROQ_SECONDARY_TPM=14400
TREEIDS_GROQ_SECONDARY_RPD=14400
TREEIDS_GROQ_USAGE_FILE=.cache/groq_usage.json
```

---

## Step-by-Step Command Execution Guide

Below is the complete sequence of PowerShell/CMD commands to verify, benchmark, and demonstrate the entire TreeIDS system end-to-end:

### Step 0: Test Groq API Connectivity & Dual Model Verification
```powershell
python test_groq.py
```
*Tests both `qwen/qwen3.8-27b` (Primary) and `openai/gpt-oss-20b` (Secondary) against Groq Cloud.*

---

### Step 1: Clear Previous Output Records & Logs
```powershell
Get-ChildItem -Path "outputs\*" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
if (Test-Path "data\processed\tree_index.json") { Remove-Item "data\processed\tree_index.json" -Force }
if (Test-Path ".cache\groq_usage.json") { Remove-Item ".cache\groq_usage.json" -Force }
```

---

### Step 2: Run Static Batch Pipeline on Weekday Datasets
```powershell
# Run static pipeline on Monday (Benign baseline)
python main.py --mode batch --dataset Monday

# Run static pipeline on Friday Combined (PortScan, DDoS, Botnet)
python main.py --mode batch --dataset Friday_Combined

# Run static pipeline with Groq Cloud LLM cascade enabled
python main.py --mode batch --dataset Friday_DDoS --llm-provider cascade
```

---

### Step 3: Run Adaptive vs. Static Tree Pruning Benchmark
```powershell
# Benchmark dynamic tree pruning on Monday
python scripts/benchmark_pruning.py --dataset Monday --output outputs/pruning_monday.json

# Benchmark dynamic tree pruning on Friday PortScan
python scripts/benchmark_pruning.py --dataset Friday_PortScan --output outputs/pruning_adaptive_portscan.json

# Benchmark dynamic tree pruning on Friday Combined
python scripts/benchmark_pruning.py --dataset Friday_Combined --output outputs/pruning_friday_combined.json
```

---

### Step 4: Run Supervised ML Baselines (Random Forest & XGBoost)
```powershell
# Run ML baselines on Friday Combined (Binary BENIGN vs ATTACK classification)
python scripts/baseline_benchmark.py --dataset Friday_Combined --output outputs/baseline_friday_combined.json

# Run ML baseline check on Monday baseline
python scripts/baseline_benchmark.py --dataset Monday --output outputs/baseline_monday.json
```

---

### Step 5: Run Full Cross-Dataset Normalization & Validation Suite
```powershell
# Runs bounded schema normalization, tree building, and mock reasoning across all 10 CIC-IDS2017 selections
python scripts/cross_dataset_test.py --output outputs/cross_dataset_test_results.json
```

---

### Step 6: Run Phase 2 Live Packet Sniffing & Real-Time Attack Simulation
```powershell
# Executes live packet capture on Npcap loopback with 10s windows,
# injects 3 breach instances (SYN Flood, Port Scan, Slowloris),
# applies Adaptive Pruning, and runs the Groq LLM Cascade.
python scripts/demo_phase2_live.py
```

---

## Weekday Static Dataset Execution Reference

The `data/raw/` directory hosts the CIC-IDS2017 PCAP-extracted CSV files. TreeIDS supports both individual weekday attack sessions and multi-file concatenations configured in `config/config.yaml`:

| CLI Dataset Name (`--dataset`) | Source PCAP CSV File(s) | Traffic Characteristics & Attack Types |
|:---|:---|:---|
| `Monday` | `Monday-WorkingHours.pcap_ISCX.csv` | Normal benign operational baseline (100% Benign) |
| `Tuesday` | `Tuesday-WorkingHours.pcap_ISCX.csv` | FTP-Patator, SSH-Patator (Brute Force) |
| `Wednesday` | `Wednesday-workingHours.pcap_ISCX.csv` | DoS (Slowloris, Slowhttptest, Hulk, GoldenEye), Heartbleed |
| `Thursday_WebAttacks` | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Web Attacks (Brute Force, XSS, SQL Injection) |
| `Thursday_Infiltration` | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Infiltration, Dropbox compromise, Portscan |
| `Thursday_Combined` | *Merged Morning + Afternoon files* | Full Thursday composite profile |
| `Friday_Botnet` | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | ARES Botnet C2 communication |
| `Friday_PortScan` | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Network Port Scanning Reconnaissance |
| `Friday_DDoS` | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | High-volume Volumetric LOIC DDoS |
| `Friday_Combined` | *Merged Morning + PortScan + DDoS files* | Comprehensive Friday multi-vector attack suite |

### How to Run Any Specific Weekday:
```powershell
python main.py --mode batch --dataset Tuesday
python main.py --mode batch --dataset Thursday_WebAttacks
python main.py --mode batch --dataset Friday_Combined
```

---

## Live Streaming Mode: Telemetry & Numeric Configurations

When running in live streaming mode (`--mode live` or `scripts/demo_phase2_live.py`), the system reconstructs network packets into time-bounded bi-directional flows and evaluates them incrementally.

### Key Numeric Parameters in `config/config.yaml`:

```yaml
pipeline:
  mode: "live"                        # Default pipeline mode ("batch" | "live")

live_capture:
  interface: '\Device\NPF_Loopback'   # Npcap loopback device or interface name
  bpf_filter: "ip and (tcp or udp or icmp)" # Berkeley Packet Filter expression
  window_duration_sec: 10.0           # Sliding window duration (10.0 seconds per window)
  flow_timeout_sec: 30.0              # Idle flow expiration threshold (30.0 seconds)
  max_queue_size: 10000               # Thread-safe packet buffer limit to prevent drops

tree_builder:
  max_flows_per_leaf: 10              # Maximum flow telemetry records serialized per leaf
  max_sessions_eval: 10               # Maximum session nodes evaluated by LLM per window

tree_pruning:
  enabled: true                       # Master toggle for tree index compression
  mode: "adaptive"                    # Pruning mode: "adaptive" (data-driven) | "static"
  adaptive_packet_quantile: 0.50      # Median traffic density quantile for dynamic cutoff
  scan_fanout_threshold: 5            # Preserves reconnaissance if >= 5 target ports probed
  min_flow_count: 2                   # Static fallback flow count threshold
  min_forward_packets: 50             # Static fallback forward packet threshold
  retain_ports: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]

llm:
  provider: "cascade"                 # Options: "mock" (offline rules) | "cascade" (Groq Cloud)
  primary_model: "qwen/qwen3.8-27b"   # Tier 1 Groq Cloud model
  secondary_model: "openai/gpt-oss-20b" # Tier 2 Groq Cloud fallback model
  fallback_to_mock: true              # Gracefully drop to Tier 3 mock heuristics on quota exhaust
  temperature: 0.1                    # Low temperature for deterministic security reasoning
```

### Manual Tuning Guidelines:
1. **Window Size / Aggregation (`window_duration_sec: 10.0`)**: For high-bandwidth 1Gbps/10Gbps links, reduce window duration to `2.0s - 5.0s` to prevent memory accumulation.
2. **Evaluated Sessions per Window (`max_sessions_eval: 10`)**: Limits the number of Groq LLM API calls per sliding window to prevent exceeding Rate-Per-Minute (RPM) quotas.
3. **Scan Fan-out Threshold (`scan_fanout_threshold: 5`)**: If a host probes $\ge 5$ distinct destination ports within a window, all probe sessions are retained regardless of packet count, ensuring stealth reconnaissance is never pruned.

---

## Adaptive Tree Pruning & Token Cost Control

TreeIDS induces an **Adaptive (Data-Driven) Tree Pruning Engine** prior to prompting the LLM cascade, resolving the over-pruning failure mode of static thresholds:

| Dataset / Context | Total Raw Sessions | Static Pruning (Retained) | Static Pruning (Reduction %) | Adaptive Pruning (Retained) | Adaptive Pruning (Reduction %) | Primary Benefit of Adaptive Pruning |
|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **`Friday_PortScan`** | 660 | 267 | 59.55% | **602** | 8.79% | **Protects 335 stealth scan probes** from being pruned |
| **`Friday_Combined`** | 510 | 221 | 56.67% | **423** | 17.06% | Retains multi-vector session fan-outs while pruning noise |
| **`Wednesday-workingHours`** | 343 | 212 | 38.19% | **245** | 28.57% | Preserves web injection attempts on non-standard ports |
| **`Monday-WorkingHours`** | 582 | 360 | 38.14% | **391** | 32.82% | Compresses benign background IPC traffic |
| **Live Packet Stream** | 30 | 18 | 40.00% | **22** | 26.67% | Preserves 100% of injected multi-port scan probes |

---

## Machine Learning Baselines vs. TreeIDS Benchmark

Comparative evaluation on `Friday_Combined` (605 BENIGN, 394 ATTACK):

| Feature / Metric | Random Forest Baseline | XGBoost Baseline | TreeIDS Static Mode (Adaptive Heuristics) | TreeIDS Live Mode (Groq LLM Cascade) |
|:---|:---:|:---:|:---:|:---:|
| **Training Time** | 253.99 ms | 215.61 ms | **0.00 ms** (Zero-shot) | **0.00 ms** (Zero-shot) |
| **Inference Latency** | 31.59 ms (batch) | 4.72 ms (batch) | ~0.42 ms per session | ~0.82s per Groq LPU call |
| **Accuracy** | **99.60%** | **99.60%** | 99.00% | **100.0%** (Live Injected Attacks) |
| **Weighted F1-Score** | **99.60%** | **99.60%** | 99.00% | **1.0000** |
| **API / Token Cost** | $0.00 | $0.00 | **$0.00** | **~$0.0003 USD / window** |
| **Zero-day Resilience**| Low (Requires labeled retraining) | Low (Requires labeled retraining) | Medium (Rule heuristics) | **High (Generative reasoning)** |
| **Explainability** | Low (Feature weights only) | Low (Feature weights only) | Moderate (Topological paths) | **Comprehensive (Full Narrative + MITRE TTPs + Mitigations)** |

*For complete benchmark tables across all days, see [`COMPARATIVE_STUDY_BENCHMARK.md`](COMPARATIVE_STUDY_BENCHMARK.md).*

---

## Project Directory Structure

```text
TreeIDS_Prototype/
├── .env                              # Environment variables (Groq API keys & quota limits)
├── ARCHITECTURE_AND_ROADMAP.md       # Full architecture specification & phase roadmap
├── COMPARATIVE_STUDY_BENCHMARK.md    # Empirical benchmark reports & comparative study
├── LICENSE                           # MIT License
├── README.md                         # Repository documentation and run guide
├── main.py                           # CLI entry point for batch and live execution
├── test_groq.py                      # Multi-model Groq API connectivity verification
├── requirements.txt                  # Python package dependencies
├── config/
│   └── config.yaml                   # Global runtime, dataset, sniffer, and LLM configuration
├── data/
│   ├── raw/                          # Benchmark dataset CSV files (CIC-IDS2017)
│   └── processed/
│       └── tree_index.json           # Cached 4-tier vectorless JSON tree index
├── outputs/
│   ├── detection_results.json        # Batch detection verdicts & structured JSON alerts
│   ├── live_detection_results.json   # Live streaming detection results across windows
│   ├── classification_audit.log      # Human-readable SOC audit log
│   ├── audit_log.jsonl               # Machine-readable JSONL audit log for SIEM ingestion
│   ├── baseline_monday.json          # Monday baseline evaluation report
│   ├── baseline_friday_combined.json # Supervised ML baseline metrics (RF & XGBoost)
│   └── pruning_friday_combined.json  # Pruning token cost reduction metrics
├── scripts/
│   ├── attack_simulator.py           # Scapy synthetic breach injector (SYN Flood, Port Scan, Slowloris)
│   ├── baseline_benchmark.py         # Supervised ML baseline benchmark runner
│   ├── benchmark_pruning.py          # Dynamic vs. Adaptive tree pruning benchmark
│   ├── cross_dataset_test.py         # 10-selection multi-dataset schema validation harness
│   └── demo_phase2_live.py           # End-to-end live streaming demonstration runner
└── src/
    ├── audit_logger.py               # Dual-format SOC text & SIEM JSONL audit logger
    ├── data_loader.py                # Dataset sampler and tabular loader
    ├── detector.py                   # Master pipeline coordinator (batch & live dispatch)
    ├── llm_engine.py                 # Groq LPU cascade reasoning engine with quota guard
    ├── schema_adapter.py             # Canonical schema normalizer & ground-truth isolator
    ├── sniffer.py                    # Asynchronous Scapy/Npcap live packet capture worker
    ├── tree_builder.py               # 4-tier vectorless JSON tree constructor
    ├── tree_pruner.py                # Adaptive data-driven & static tree pruning engine
    └── window_aggregator.py          # Sliding-window packet-to-flow reconstruction buffer
```

---

## Output Logs & SIEM Destinations

All execution telemetry and classifications are persisted across standard output destinations:

1. **`outputs/detection_results.json`**: Structured JSON array containing session classifications, confidence scores, MITRE TTPs, and remediation steps.
2. **`outputs/live_detection_results.json`**: Real-time sliding window detection telemetry from the Groq LLM cascade.
3. **`outputs/classification_audit.log`**: Human-readable SOC audit log formatted with timestamps, structural reasoning paths, and mitigation instructions.
4. **`outputs/audit_log.jsonl`**: Machine-readable JSON Lines log for real-time ingestion by SIEM/SOAR platforms (Splunk, Elastic, Sentinel).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
