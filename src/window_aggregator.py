import time
import queue
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from src.schema_adapter import SchemaNormalizer


class FlowRecord:
    """Represents an active bi-directional network conversation between two endpoints."""

    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str, start_time: float):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_time = start_time

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.is_closed = False

    def add_packet(self, src_ip: str, length: int, timestamp: float, tcp_flags: str = "") -> None:
        self.last_time = max(self.last_time, timestamp)
        
        # Check direction
        if src_ip == self.src_ip:
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length

        # TCP connection termination flags
        if "F" in tcp_flags or "R" in tcp_flags:
            self.is_closed = True

    def to_canonical_dict(self) -> Dict[str, Any]:
        duration_s = max(self.last_time - self.start_time, 0.001)
        duration_ms = round(duration_s * 1000.0, 2)
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        byte_rate = round(total_bytes / duration_s, 2)
        pkt_rate = round(total_pkts / duration_s, 2)

        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration_ms": duration_ms,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "flow_byte_rate": byte_rate,
            "flow_packet_rate": pkt_rate
        }


class SlidingWindowAggregator:
    """
    Sliding-Window Flow Aggregator for TreeIDS (Phase 2).
    Assembles incoming asynchronous packet telemetry into time-bounded,
    bi-directional flow sessions and generates canonical flow DataFrames.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        live_cfg = self.config.get("live_capture", {})
        
        self.window_duration = live_cfg.get("window_duration_sec", 5.0)
        self.flow_timeout = live_cfg.get("flow_timeout_sec", 15.0)
        self.last_flush_time = time.time()
        
        # Active flow table keyed by (min_endpoint, max_endpoint, protocol)
        self.active_flows: Dict[Tuple, FlowRecord] = {}

    def _get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Tuple:
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            return (ep1, ep2, protocol)
        return (ep2, ep1, protocol)

    def process_packet(self, pkt: Dict[str, Any]) -> None:
        """Ingests a single packet dict into active flow state."""
        src_ip = pkt.get("src_ip", "0.0.0.0")
        src_port = pkt.get("src_port", 0)
        dst_ip = pkt.get("dst_ip", "0.0.0.0")
        dst_port = pkt.get("dst_port", 0)
        proto = pkt.get("protocol", "TCP")
        ts = pkt.get("timestamp", time.time())
        length = pkt.get("length", 0)
        flags = pkt.get("tcp_flags", "")

        key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port, proto)

        if key not in self.active_flows:
            self.active_flows[key] = FlowRecord(src_ip, src_port, dst_ip, dst_port, proto, ts)

        self.active_flows[key].add_packet(src_ip, length, ts, flags)

    def process_queue_batch(self, packet_queue: queue.Queue, max_batch: int = 500) -> int:
        """Drains up to max_batch packets from the sniffer queue and updates flow tables."""
        count = 0
        while count < max_batch:
            try:
                pkt = packet_queue.get_nowait()
                self.process_packet(pkt)
                count += 1
            except queue.Empty:
                break
        return count

    def should_flush(self) -> bool:
        """Determines if the time window has elapsed."""
        return (time.time() - self.last_flush_time) >= self.window_duration

    def flush_window(self, force_all: bool = False) -> Tuple[pd.DataFrame, int]:
        """
        Flushes expired or completed flows from the active table into a canonical DataFrame.
        
        Args:
            force_all: If True, flushes all active flows regardless of timeout.
            
        Returns:
            Tuple of (canonical_flow_df, count_flushed_flows)
        """
        now = time.time()
        self.last_flush_time = now
        flushed_records: List[Dict[str, Any]] = []
        keys_to_remove = []

        for key, flow in self.active_flows.items():
            is_expired = (now - flow.last_time) >= self.flow_timeout
            
            if force_all or flow.is_closed or is_expired:
                flushed_records.append(flow.to_canonical_dict())
                keys_to_remove.append(key)
            elif (now - flow.start_time) >= self.window_duration and flow.fwd_packets > 0:
                # Long-running flow: emit a window snapshot
                flushed_records.append(flow.to_canonical_dict())

        for k in keys_to_remove:
            del self.active_flows[k]

        if not flushed_records:
            empty_df = pd.DataFrame(columns=SchemaNormalizer.CANONICAL_COLUMNS)
            return empty_df, 0

        df = pd.DataFrame(flushed_records)
        return df, len(flushed_records)
