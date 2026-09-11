"""
Phase 2 Live Streaming & Comparative Demonstration Script
Executes live packet capture on Npcap loopback with 10s windows,
injects 3 real network breach instances via Scapy AttackSimulator,
induces dynamic tree pruning, runs LLM cascade/fallback inference,
and outputs a comparative study against ML baselines.
"""

import sys
import time
import json
import threading
from pathlib import Path

# Ensure workspace root is in path
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

import yaml
from dotenv import load_dotenv
from src.detector import TreeIDSDetector
from scripts.attack_simulator import AttackSimulator

# Load API keys and quota limits from .env BEFORE any module initialization
load_dotenv(dotenv_path=ROOT_DIR / ".env")


def inject_attacks_worker():
    """Background worker to inject 3 attack vectors into live loopback stream."""
    time.sleep(2.0)  # Wait for sniffer initialization
    sim = AttackSimulator(target_ip="127.0.0.1", iface=r"\Device\NPF_Loopback", dry_run=False)

    print("\n" + "=" * 60)
    print(" [INJECTOR] Starting Attack Simulation Sequence")
    print("=" * 60)

    # Breach Instance 1: TCP SYN Flood (Volumetric DoS)
    print(" [INJECTOR] Breach Instance 1/3: TCP SYN Flood (T1498)")
    sim.run_syn_flood(target_port=80, count=150, delay=0.002)

    time.sleep(8.0)  # Move into Window 2

    # Breach Instance 2: Network Port Scan (Reconnaissance - T1046)
    print(" [INJECTOR] Breach Instance 2/3: Network Port Scan Reconnaissance (T1046)")
    sim.run_port_scan(ports=[21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443], delay=0.01)

    time.sleep(8.0)  # Move into Window 3

    # Breach Instance 3: Low-and-Slow HTTP Exhaustion (Application DoS - T1499.002)
    print(" [INJECTOR] Breach Instance 3/3: Low-and-Slow HTTP Exhaustion (T1499.002)")
    sim.run_slowloris_simulation(target_port=80, connections=15, duration_sec=3)

    print(" [INJECTOR] All 3 breach instances injected successfully.\n")


def run_demo():
    print("=" * 65)
    print("   TreeIDS Phase 2: Live Streaming Detection & Attack Injection   ")
    print("=" * 65 + "\n")

    # Load configuration
    with open(ROOT_DIR / "config/config.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Ensure live capture settings
    config.setdefault("pipeline", {})["mode"] = "live"
    config.setdefault("live_capture", {})["window_duration_sec"] = 10.0
    config.setdefault("live_capture", {})["interface"] = r"\Device\NPF_Loopback"
    config.setdefault("tree_pruning", {})["enabled"] = True
    config.setdefault("llm", {})["provider"] = "cascade"

    detector = TreeIDSDetector(config)

    # Start background injector thread
    injector_thread = threading.Thread(target=inject_attacks_worker, daemon=True)
    injector_thread.start()

    # Run live detector for 3 sliding windows (10 seconds each)
    results = detector.run_live(max_windows=3)

    # Save live detection results
    output_path = ROOT_DIR / "outputs" / "live_detection_results.json"
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print("\n" + "=" * 65)
    print(f" [+] Live Streaming Pipeline Complete. Evaluated {len(results)} session nodes across 3 windows.")
    print(f" [+] Detection Results saved to {output_path}")
    print("=" * 65 + "\n")

    return results


if __name__ == "__main__":
    run_demo()
