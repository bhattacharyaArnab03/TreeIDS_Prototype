import pandas as pd
from src.tree_pruner import DynamicTreePruner

class TreeBuilder:
    """
    Constructs a Vectorless Hierarchical Tree Index from network flow telemetry DataFrames.
    Hierarchy Topology: Root -> Host Node (Source IP) -> Session Node (Dest IP : Dest Port)
    """
    def __init__(self, config: dict):
        self.config = config
        self.tree_cfg = config.get("tree_builder", {})
        self.pruner = DynamicTreePruner(config)

    def build_tree(self, df: pd.DataFrame) -> dict:
        """
        Builds the hierarchical JSON tree index by aggregating session flows.
        """
        # Read parameters from config.yaml
        max_flows = self.tree_cfg.get("max_flows_per_leaf", 10)
        
        # Locate canonical or raw column names in telemetry DataFrame
        src_col = self._find_column(df, ["src_ip", "Source IP", "Src IP", "source_ip", "srcip"])
        dst_col = self._find_column(df, ["dst_ip", "Destination IP", "Dst IP", "destination_ip", "dstip"])
        port_col = self._find_column(df, ["dst_port", "Destination Port", "Dst Port", "destination_port", "dsport"])
        pkt_col = self._find_column(df, ["total_fwd_packets", "Total Fwd Packets", "Total Fwd Packet", "spkts"])
        dur_col = self._find_column(df, ["flow_duration_ms", "Flow Duration", "flow_duration", "dur"])

        tree_index = {
            "root": "Network_Flow_Index",
            "total_records_ingested": len(df),
            "hosts": {}
        }

        # Group telemetry by Source IP (Host Level)
        grouped_hosts = df.groupby(src_col)

        for src_ip, host_df in grouped_hosts:
            host_node = {
                "total_flows": len(host_df),
                "sessions": {}
            }

            # Group telemetry by Destination IP and Destination Port (Session Level)
            session_groups = host_df.groupby([dst_col, port_col])

            for (dst_ip, dst_port), session_df in session_groups:
                try:
                    clean_port = int(float(dst_port))
                except (ValueError, TypeError):
                    clean_port = 0
                session_key = f"{dst_ip}:{clean_port}"

                # Calculate aggregated session metrics
                flow_count = len(session_df)
                total_fwd_pkts = int(session_df[pkt_col].sum()) if pkt_col in session_df else 0
                avg_dur = float(session_df[dur_col].mean()) if dur_col in session_df else 0.0

                # Cap flows per leaf if set in config.yaml
                sample_df = session_df.head(max_flows)

                host_node["sessions"][session_key] = {
                    "destination_ip": str(dst_ip),
                    "destination_port": clean_port,
                    "flow_count": flow_count,
                    "total_fwd_packets": total_fwd_pkts,
                    "avg_duration": round(avg_dur, 2),
                    "sampled_flows": sample_df.to_dict(orient="records")
                }

            tree_index["hosts"][str(src_ip)] = host_node

        tree_index = self.pruner.prune(tree_index)
        pruning = tree_index.get("pruning", {})
        print(f"[+] Tree Index built successfully with {len(tree_index['hosts'])} unique Host nodes.")
        if pruning.get("enabled"):
            print(
                f"[+] Dynamic pruning retained {pruning['sessions_after']}/"
                f"{pruning['sessions_before']} sessions and removed "
                f"{pruning['flow_samples_removed']} low-signal flow samples."
            )
        return tree_index


    def _find_column(self, df: pd.DataFrame, possible_names: list) -> str:
        """Helper method to match dataset columns against flexible list of headers."""
        for name in possible_names:
            if name in df.columns:
                return name
        raise KeyError(f"Could not find required column from possible list {possible_names} in dataset headers: {list(df.columns)}")