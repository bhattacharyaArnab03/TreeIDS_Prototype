from typing import Any


class DynamicTreePruner:
    """Removes low-signal session leaves while retaining likely attack evidence."""

    def __init__(self, config: dict):
        self.config = config.get("tree_pruning", {})
        self.enabled = self.config.get("enabled", True)
        self.min_flow_count = int(self.config.get("min_flow_count", 2))
        self.min_forward_packets = int(self.config.get("min_forward_packets", 50))
        self.sensitive_ports = {
            int(port) for port in self.config.get(
                "retain_ports", [21, 22, 23, 25, 53, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
            )
        }

    def prune(self, tree_index: dict) -> dict:
        if not self.enabled:
            tree_index["pruning"] = {"enabled": False}
            return tree_index

        before_sessions = 0
        retained_sessions = 0
        removed_sessions = 0
        removed_flow_samples = 0

        for host_node in tree_index.get("hosts", {}).values():
            sessions = host_node.get("sessions", {})
            before_sessions += len(sessions)
            retained = {}

            for session_key, session_node in sessions.items():
                if self._retain_session(session_node):
                    retained[session_key] = session_node
                    retained_sessions += 1
                else:
                    removed_sessions += 1
                    removed_flow_samples += len(session_node.get("sampled_flows", []))

            host_node["sessions"] = retained

        tree_index["pruning"] = {
            "enabled": True,
            "sessions_before": before_sessions,
            "sessions_after": retained_sessions,
            "sessions_removed": removed_sessions,
            "flow_samples_removed": removed_flow_samples,
        }
        return tree_index

    def _retain_session(self, session_node: dict[str, Any]) -> bool:
        flow_count = int(session_node.get("flow_count", 0) or 0)
        forward_packets = int(session_node.get("total_fwd_packets", 0) or 0)
        destination_port = int(session_node.get("destination_port", 0) or 0)
        return (
            flow_count >= self.min_flow_count
            or forward_packets >= self.min_forward_packets
            or destination_port in self.sensitive_ports
        )