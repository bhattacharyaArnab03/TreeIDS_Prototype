import numpy as np
import pandas as pd
from typing import Tuple, Optional


class SchemaNormalizer:
    """
    Unified Schema Normalization Pipeline for TreeIDS (Phase 2).
    Standardizes heterogeneous tabular network flow telemetry (e.g., CIC-IDS2017,
    UNSW-NB15, and Generic/Live Streams) into a canonical structural schema.
    
    Enforces strict Ground-Truth Isolation:
    Extracts and decouples ground-truth labels into an isolated validation series
    so that downstream hierarchical tree construction and cognitive LLM reasoning
    operate exclusively on unlabelled, zero-shot telemetry.
    """

    # Canonical column standard
    CANONICAL_COLUMNS = [
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "flow_duration_ms",
        "total_fwd_packets",
        "total_bwd_packets",
        "total_fwd_bytes",
        "total_bwd_bytes",
        "flow_byte_rate",
        "flow_packet_rate"
    ]

    # Predefined dataset schema mapping dictionaries
    MAPPINGS = {
        "cic_ids2017": {
            "src_ip": ["Source IP", "Src IP", "source_ip"],
            "src_port": ["Source Port", "Src Port", "source_port"],
            "dst_ip": ["Destination IP", "Dst IP", "destination_ip"],
            "dst_port": ["Destination Port", "Dst Port", "destination_port"],
            "protocol": ["Protocol", "protocol"],
            "flow_duration_ms": ["Flow Duration", "flow_duration"],  # in microseconds in CIC-IDS2017 -> convert to ms
            "total_fwd_packets": ["Total Fwd Packets", "Total Fwd Packet", "total_fwd_packets"],
            "total_bwd_packets": ["Total Backward Packets", "Total Backward Packet", "total_bwd_packets"],
            "total_fwd_bytes": ["Total Length of Fwd Packets", "total_fwd_bytes"],
            "total_bwd_bytes": ["Total Length of Bwd Packets", "total_bwd_bytes"],
            "flow_byte_rate": ["Flow Bytes/s", "flow_byte_rate"],
            "flow_packet_rate": ["Flow Packets/s", "flow_packet_rate"],
            "ground_truth": ["Label", "label", "Attack", "attack"]
        },
        "unsw_nb15": {
            "src_ip": ["srcip", "src_ip", "Source IP"],
            "src_port": ["sport", "src_port", "Source Port"],
            "dst_ip": ["dstip", "dst_ip", "Destination IP"],
            "dst_port": ["dsport", "dst_port", "Destination Port"],
            "protocol": ["proto", "protocol", "Protocol"],
            "flow_duration_ms": ["dur", "duration", "flow_duration"],  # in seconds in UNSW-NB15 -> convert to ms
            "total_fwd_packets": ["spkts", "total_fwd_packets"],
            "total_bwd_packets": ["dpkts", "total_bwd_packets"],
            "total_fwd_bytes": ["sbytes", "total_fwd_bytes"],
            "total_bwd_bytes": ["dbytes", "total_bwd_bytes"],
            "flow_byte_rate": ["sload", "flow_byte_rate"],
            "flow_packet_rate": ["rate", "flow_packet_rate"],
            "ground_truth": ["attack_cat", "label", "Label", "attack"]
        },
        "generic": {
            "src_ip": ["src_ip", "source_ip", "srcip", "Source IP"],
            "src_port": ["src_port", "source_port", "sport", "Source Port"],
            "dst_ip": ["dst_ip", "destination_ip", "dstip", "Destination IP"],
            "dst_port": ["dst_port", "destination_port", "dsport", "Destination Port"],
            "protocol": ["protocol", "proto", "Protocol"],
            "flow_duration_ms": ["flow_duration_ms", "duration_ms", "dur_ms", "Flow Duration"],
            "total_fwd_packets": ["total_fwd_packets", "fwd_packets", "spkts", "Total Fwd Packets"],
            "total_bwd_packets": ["total_bwd_packets", "bwd_packets", "dpkts", "Total Backward Packets"],
            "total_fwd_bytes": ["total_fwd_bytes", "fwd_bytes", "sbytes"],
            "total_bwd_bytes": ["total_bwd_bytes", "bwd_bytes", "dbytes"],
            "flow_byte_rate": ["flow_byte_rate", "byte_rate", "rate"],
            "flow_packet_rate": ["flow_packet_rate", "packet_rate"],
            "ground_truth": ["label", "ground_truth", "attack_cat", "Label"]
        }
    }

    @classmethod
    def detect_dataset_type(cls, df: pd.DataFrame) -> str:
        """Heuristically infers dataset schema from DataFrame column headers."""
        cols = {str(c).strip().lower() for c in df.columns}
        
        if "srcip" in cols or "dsport" in cols or "attack_cat" in cols:
            return "unsw_nb15"
        if "source ip" in cols or "flow duration" in cols or "total fwd packets" in cols:
            return "cic_ids2017"
        return "generic"

    @classmethod
    def normalize(cls, df: pd.DataFrame, dataset_type: Optional[str] = None) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Normalizes a telemetry DataFrame into canonical schema and isolates ground-truth labels.
        
        Args:
            df: Raw DataFrame containing network flow telemetry.
            dataset_type: Optional explicit dataset identifier ("cic_ids2017", "unsw_nb15", "generic").
        
        Returns:
            Tuple of (canonical_telemetry_df, isolated_ground_truth_series)
        """
        # Clean column names by stripping leading/trailing whitespace
        df_clean = df.copy()
        df_clean.columns = df_clean.columns.astype(str).str.strip()

        if not dataset_type or dataset_type.lower() == "auto":
            dataset_type = cls.detect_dataset_type(df_clean)
        
        mapping_key = dataset_type.lower()
        if mapping_key not in cls.MAPPINGS:
            mapping_key = "generic"
            
        mapping = cls.MAPPINGS[mapping_key]

        # 1. Decouple Ground-Truth Labels (Strict Zero-Shot Isolation)
        ground_truth_series = pd.Series(["UNKNOWN"] * len(df_clean), index=df_clean.index, name="ground_truth_label")
        gt_candidates = mapping.get("ground_truth", [])
        
        for candidate in gt_candidates:
            matched_col = next((c for c in df_clean.columns if c.lower() == candidate.lower()), None)
            if matched_col:
                ground_truth_series = df_clean[matched_col].astype(str).fillna("BENIGN")
                df_clean = df_clean.drop(columns=[matched_col])
                break

        # 2. Map Columns into Canonical Schema
        canonical_dict = {}
        for canonical_col in cls.CANONICAL_COLUMNS:
            candidates = mapping.get(canonical_col, [])
            matched_col = None
            for cand in candidates:
                matched_col = next((c for c in df_clean.columns if c.lower() == cand.lower()), None)
                if matched_col:
                    break
            
            if matched_col:
                canonical_dict[canonical_col] = df_clean[matched_col]
            else:
                # Default fallback values for missing attributes
                if canonical_col in ["src_ip", "dst_ip"]:
                    canonical_dict[canonical_col] = "0.0.0.0"
                elif canonical_col in ["src_port", "dst_port"]:
                    canonical_dict[canonical_col] = 0
                elif canonical_col == "protocol":
                    canonical_dict[canonical_col] = "TCP"
                else:
                    canonical_dict[canonical_col] = 0.0

        canonical_df = pd.DataFrame(canonical_dict, index=df_clean.index)

        # 3. Unit Normalization (Durations to Milliseconds)
        if mapping_key == "cic_ids2017":
            # CIC-IDS2017 records duration in microseconds -> convert to ms
            canonical_df["flow_duration_ms"] = pd.to_numeric(canonical_df["flow_duration_ms"], errors="coerce").fillna(0.0) / 1000.0
        elif mapping_key == "unsw_nb15":
            # UNSW-NB15 records duration in seconds -> convert to ms
            canonical_df["flow_duration_ms"] = pd.to_numeric(canonical_df["flow_duration_ms"], errors="coerce").fillna(0.0) * 1000.0
        else:
            canonical_df["flow_duration_ms"] = pd.to_numeric(canonical_df["flow_duration_ms"], errors="coerce").fillna(0.0)

        # 4. Strict Type Sanitization & Port Cleaning
        canonical_df["src_ip"] = canonical_df["src_ip"].astype(str).str.strip()
        canonical_df["dst_ip"] = canonical_df["dst_ip"].astype(str).str.strip()
        canonical_df["protocol"] = canonical_df["protocol"].astype(str).str.strip()

        for port_col in ["src_port", "dst_port"]:
            canonical_df[port_col] = pd.to_numeric(canonical_df[port_col], errors="coerce").fillna(0).astype(int)

        for numeric_col in ["total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes"]:
            canonical_df[numeric_col] = pd.to_numeric(canonical_df[numeric_col], errors="coerce").fillna(0).astype(int)

        for rate_col in ["flow_byte_rate", "flow_packet_rate", "flow_duration_ms"]:
            canonical_df[rate_col] = pd.to_numeric(canonical_df[rate_col], errors="coerce")
            canonical_df[rate_col] = canonical_df[rate_col].replace([np.inf, -np.inf], 0.0).fillna(0.0)
            canonical_df[rate_col] = canonical_df[rate_col].clip(lower=0.0)

        return canonical_df, ground_truth_series
