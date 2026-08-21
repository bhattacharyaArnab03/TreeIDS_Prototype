import pandas as pd

class TreeBuilder:
    """
    Constructs a Vectorless Hierarchical Tree Index from network flow telemetry DataFrames.
    Hierarchy Topology: Root -> Host Node (Source IP) -> Session Node (Dest IP : Dest Port)
    """
    def __init__(self, config: dict):
        self.config = config
        self.tree_cfg = config.get("tree_builder", {})

    def build_tree(self, df: pd.DataFrame) -> dict:
        """
        Builds the hierarchical JSON tree index by aggregating session flows.
        """
        # Read parameters from config.yaml
        max_flows = self.tree_cfg.get("max_flows_per_leaf", 10)
        
        # Flexibly locate target column names in stripped CIC-IDS2017 DataFrame
        src_col = self._find_column(df, ["Source IP", "Src IP", "source_ip"])
        dst_col = self._find_column(df, ["Destination IP", "Dst IP", "destination_ip"])
        port_col = self._find_column(df, ["Destination Port", "Dst Port", "destination_port"])
        pkt_col = self._find_column(df, ["Total Fwd Packets", "Total Fwd Packet", "total_fwd_packets"])
        dur_col = self._find_column(df, ["Flow Duration", "flow_duration", "dur"])

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
                session_key = f"{dst_ip}:{dst_port}"

                # Calculate aggregated session metrics
                flow_count = len(session_df)
                total_fwd_pkts = int(session_df[pkt_col].sum()) if pkt_col in session_df else 0
                avg_dur = float(session_df[dur_col].mean()) if dur_col in session_df else 0.0

                # Cap flows per leaf if set in config.yaml
                sample_df = session_df.head(max_flows)

                host_node["sessions"][session_key] = {
                    "destination_ip": str(dst_ip),
                    "destination_port": int(dst_port),
                    "flow_count": flow_count,
                    "total_fwd_packets": total_fwd_pkts,
                    "avg_duration": round(avg_dur, 2),
                    "sampled_flows": sample_df.to_dict(orient="records")
                }

            tree_index["hosts"][str(src_ip)] = host_node

        print(f"[+] Tree Index built successfully with {len(tree_index['hosts'])} unique Host nodes.")
        return tree_index

    def _find_column(self, df: pd.DataFrame, possible_names: list) -> str:
        """Helper method to match dataset columns against flexible list of headers."""
        for name in possible_names:
            if name in df.columns:
                return name
        raise KeyError(f"Could not find required column from possible list {possible_names} in dataset headers: {list(df.columns)}")