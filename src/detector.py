import os
import json
import time
import pandas as pd
from typing import List, Optional
from src.data_loader import DataLoader
from src.tree_builder import TreeBuilder
from src.llm_engine import TreeIDSReasoningEngine
from src.sniffer import LivePacketSniffer
from src.window_aggregator import SlidingWindowAggregator


class TreeIDSDetector:
    """
    Core Pipeline Coordinator for TreeIDS (Phases 1 & 2).
    Orchestrates both static dataset ingestion (batch mode) and real-time
    asynchronous packet sniffing with sliding-window flow aggregation (live mode).
    """
    def __init__(self, config: dict):
        self.config = config
        self.data_loader = DataLoader(config)
        self.tree_builder = TreeBuilder(config)
        self.llm_engine = TreeIDSReasoningEngine(config)
        
        self.sniffer: Optional[LivePacketSniffer] = None
        self.aggregator: Optional[SlidingWindowAggregator] = None

    def run_pipeline(self, mode: Optional[str] = None) -> list:
        """Dispatches execution based on configuration or explicit mode argument."""
        active_mode = mode or self.config.get("pipeline", {}).get("mode", "batch")
        
        if active_mode.lower() == "live":
            return self.run_live()
        else:
            return self.run_batch()

    def run_batch(self) -> list:
        """Executes static dataset ingestion and vectorless tree reasoning."""
        print("[+] Starting Batch Execution Mode...")
        # Step 1: Load and clean telemetry with schema normalization
        df = self.data_loader.fetch_dataset()

        # Step 2: Build Vectorless Hierarchical Tree Index
        print("[+] Constructing Vectorless Hierarchical Tree Index...")
        tree_index = self.tree_builder.build_tree(df)

        # Save processed tree index JSON if path specified
        tree_path = self.config.get('dataset', {}).get('processed_tree_path')
        if tree_path:
            os.makedirs(os.path.dirname(tree_path), exist_ok=True)
            with open(tree_path, "w") as f:
                json.dump(tree_index, f, indent=4)
            print(f"[+] Tree index cached to {tree_path}")

        # Step 3: Run Vectorless Traversal
        active_day = self.config.get('dataset', {}).get('active_day', 'Default_Dataset')
        results = self.llm_engine.analyze_tree(tree_index, dataset_name=active_day)

        return results

    def run_live(self, max_windows: Optional[int] = None) -> list:
        """
        Executes real-time sliding-window intrusion detection over live streaming packets.
        Asynchronously buffers packets, aggregates temporal flows, builds sub-trees,
        and runs zero-shot cognitive reasoning on each window.
        """
        print("[+] Starting Real-Time Streaming Detection Mode (Phase 2)...")
        self.sniffer = LivePacketSniffer(self.config)
        self.aggregator = SlidingWindowAggregator(self.config)

        self.sniffer.start()
        all_results = []
        window_count = 0

        try:
            print(f"[+] Streaming window monitor active (window: {self.aggregator.window_duration}s). Press Ctrl+C to stop.")
            while True:
                # 1. Drain sniffer queue into sliding window aggregator
                self.aggregator.process_queue_batch(self.sniffer.packet_queue, max_batch=1000)

                # 2. Check if temporal window duration elapsed
                if self.aggregator.should_flush():
                    window_count += 1
                    flow_df, flow_count = self.aggregator.flush_window()
                    
                    if flow_count > 0:
                        print(f"\n{'='*60}")
                        print(f"[*] Window #{window_count} Snapshot: {flow_count} Active Flows Reconstructed")
                        print(f"{'='*60}")

                        # Build real-time 4-tier sub-tree
                        tree_index = self.tree_builder.build_tree(flow_df)

                        # Evaluate structural sessions in this window
                        window_results = self.llm_engine.analyze_tree(
                            tree_index, 
                            dataset_name=f"Live_Stream_Window_{window_count}"
                        )
                        all_results.extend(window_results)

                    if max_windows and window_count >= max_windows:
                        print(f"[+] Reached maximum evaluation windows ({max_windows}). Exiting.")
                        break

                time.sleep(0.2)

        except KeyboardInterrupt:
            print("\n[!] Received stop signal from user.")
        finally:
            if self.sniffer:
                self.sniffer.stop()

        return all_results

