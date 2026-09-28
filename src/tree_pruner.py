import math
from typing import Any


class DynamicTreePruner:
    """
    Dynamic Tree Pruner for TreeIDS vectorless hierarchical indexes.
    
    Supports two modes:
    1. 'adaptive' (Default): Data-driven statistical pruning. Computes global and host-level
       traffic dispersion metrics (IQR, packet quantiles, session fan-out degree).
       - Automatically identifies high-volume DoS/floods and scales retention thresholds.
       - Preserves high-entropy horizontal/vertical port scans (even with 1-packet flows).
       - Retains all sensitive service ports.
    2. 'static': Fixed baseline thresholds (min_flow_count, min_forward_packets).
    """

    def __init__(self, config: dict):
        self.config = config.get("tree_pruning", {})
        self.enabled = self.config.get("enabled", True)
        self.mode = self.config.get("mode", "adaptive").lower()
        
        # Static baseline parameters
        self.min_flow_count = int(self.config.get("min_flow_count", 2))
        self.min_forward_packets = int(self.config.get("min_forward_packets", 50))
        
        # Adaptive tuning parameters
        self.packet_quantile = float(self.config.get("adaptive_packet_quantile", 0.50))
        self.scan_fanout_threshold = int(self.config.get("scan_fanout_threshold", 5))
        
        # Sensitive service ports preserved across all modes
        self.sensitive_ports = {
            int(port) for port in self.config.get(
                "retain_ports", [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
            )
        }

    def prune(self, tree_index: dict) -> dict:
        if not self.enabled:
            tree_index["pruning"] = {"enabled": False, "mode": self.mode}
            return tree_index

        before_sessions = 0
        retained_sessions = 0
        removed_sessions = 0
        removed_flow_samples = 0

        # Pre-compute distribution metrics if running in adaptive mode
        adaptive_thresholds = {}
        if self.mode == "adaptive":
            adaptive_thresholds = self._compute_adaptive_thresholds(tree_index)

        for src_ip, host_node in tree_index.get("hosts", {}).items():
            sessions = host_node.get("sessions", {})
            before_sessions += len(sessions)
            retained = {}

            # Host-level context for adaptive heuristics
            host_session_count = len(sessions)
            unique_dest_ports = len({s.get("destination_port", 0) for s in sessions.values()})
            is_scanning_suspect = (
                host_session_count >= self.scan_fanout_threshold
                or unique_dest_ports >= self.scan_fanout_threshold
            )

            for session_key, session_node in sessions.items():
                if self.mode == "adaptive":
                    retain = self._retain_adaptive(
                        session_node,
                        adaptive_thresholds,
                        is_scanning_suspect=is_scanning_suspect,
                    )
                else:
                    retain = self._retain_static(session_node)

                if retain:
                    retained[session_key] = session_node
                    retained_sessions += 1
                else:
                    removed_sessions += 1
                    removed_flow_samples += len(session_node.get("sampled_flows", []))

            host_node["sessions"] = retained

        tree_index["pruning"] = {
            "enabled": True,
            "mode": self.mode,
            "sessions_before": before_sessions,
            "sessions_after": retained_sessions,
            "sessions_removed": removed_sessions,
            "flow_samples_removed": removed_flow_samples,
            "adaptive_thresholds": adaptive_thresholds if self.mode == "adaptive" else None,
        }
        return tree_index

    def _compute_adaptive_thresholds(self, tree_index: dict) -> dict[str, Any]:
        """Calculates nonparametric statistics across all session nodes in the tree."""
        all_pkt_counts = []
        all_flow_counts = []

        for host_node in tree_index.get("hosts", {}).values():
            for session_node in host_node.get("sessions", {}).values():
                all_pkt_counts.append(int(session_node.get("total_fwd_packets", 0) or 0))
                all_flow_counts.append(int(session_node.get("flow_count", 0) or 0))

        if not all_pkt_counts:
            return {
                "dynamic_packet_threshold": self.min_forward_packets,
                "dynamic_flow_threshold": self.min_flow_count,
            }

        all_pkt_counts.sort()
        all_flow_counts.sort()
        n = len(all_pkt_counts)

        # Quantile index calculation
        q_idx = min(n - 1, max(0, int(math.floor(self.packet_quantile * n))))
        packet_quantile_val = all_pkt_counts[q_idx]

        # Interquartile Range (IQR) for dispersion
        q25_idx = int(0.25 * n)
        q75_idx = min(n - 1, int(0.75 * n))
        iqr_packets = all_pkt_counts[q75_idx] - all_pkt_counts[q25_idx]

        # Dynamic packet threshold bounded between 10 and 200
        # If network traffic has high volume dispersion, scale cutoff appropriately
        dynamic_packet_threshold = max(10, min(200, int(packet_quantile_val + 0.25 * iqr_packets)))

        # Dynamic flow threshold: median flow count, bounded between 2 and 5
        median_flows = all_flow_counts[int(0.5 * n)]
        dynamic_flow_threshold = max(2, min(5, int(median_flows)))

        return {
            "total_evaluated_sessions": n,
            "packet_median": all_pkt_counts[int(0.5 * n)],
            "packet_iqr": iqr_packets,
            "dynamic_packet_threshold": dynamic_packet_threshold,
            "dynamic_flow_threshold": dynamic_flow_threshold,
        }

    def _retain_adaptive(
        self,
        session_node: dict[str, Any],
        thresholds: dict[str, Any],
        is_scanning_suspect: bool = False,
    ) -> bool:
        """
        Adaptive retention decisions:
        1. Always retain designated sensitive/standard service ports (web, ssh, ftp, rpc, etc.).
        2. Always retain sessions belonging to potential port scan fan-out patterns,
           ensuring low-packet reconnaissance probes are never discarded.
        3. For remaining background traffic, dynamically prune sessions falling below
           the data-driven packet and flow dispersion thresholds.
        """
        destination_port = int(session_node.get("destination_port", 0) or 0)
        if destination_port in self.sensitive_ports:
            return True

        if is_scanning_suspect:
            # Preserve reconnaissance/probe sessions even if single-packet
            return True

        flow_count = int(session_node.get("flow_count", 0) or 0)
        forward_packets = int(session_node.get("total_fwd_packets", 0) or 0)

        dyn_pkt_thresh = thresholds.get("dynamic_packet_threshold", self.min_forward_packets)
        dyn_flow_thresh = thresholds.get("dynamic_flow_threshold", self.min_flow_count)

        return flow_count >= dyn_flow_thresh or forward_packets >= dyn_pkt_thresh

    def _retain_static(self, session_node: dict[str, Any]) -> bool:
        """Static rule-based retention decision."""
        flow_count = int(session_node.get("flow_count", 0) or 0)
        forward_packets = int(session_node.get("total_fwd_packets", 0) or 0)
        destination_port = int(session_node.get("destination_port", 0) or 0)
        return (
            flow_count >= self.min_flow_count
            or forward_packets >= self.min_forward_packets
            or destination_port in self.sensitive_ports
        )