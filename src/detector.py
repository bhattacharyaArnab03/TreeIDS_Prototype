import os
import json
import pandas as pd
from src.data_loader import DataLoader
from src.tree_builder import TreeBuilder
from src.llm_engine import TreeIDSReasoningEngine

class TreeIDSDetector:
    """
    Core Pipeline Coordinator for TreeIDS.
    Orchestrates ingestion, tree index construction, index caching, and LLM reasoning traversal.
    """
    def __init__(self, config: dict):
        self.config = config
        self.data_loader = DataLoader(config)
        self.tree_builder = TreeBuilder(config)
        self.llm_engine = TreeIDSReasoningEngine(config)

    def run_pipeline(self) -> list:
        # Step 1: Load and clean telemetry
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
        results = self.llm_engine.analyze_tree(tree_index)

        return results