import time
import queue
import logging
import threading
from typing import Optional, Dict, Any

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Packet, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class LivePacketSniffer:
    """
    Asynchronous Scapy-based Packet Sniffer Engine for TreeIDS Phase 2.
    Captures live network telemetry on a dedicated background worker thread and
    pushes structured packet metadata into a bounded, thread-safe queue.Queue.
    
    Prevents packet dropping and blocking during LLM inference traversals.
    """

    def __init__(self, config: Optional[dict] = None, packet_queue: Optional[queue.Queue] = None):
        self.config = config or {}
        live_cfg = self.config.get("live_capture", {})
        
        self.interface = live_cfg.get("interface", None)  # None = default interface
        self.bpf_filter = live_cfg.get("bpf_filter", "ip and (tcp or udp or icmp)")
        self.max_queue_size = live_cfg.get("max_queue_size", 10000)
        
        self.packet_queue = packet_queue if packet_queue is not None else queue.Queue(maxsize=self.max_queue_size)
        self._stop_event = threading.Event()
        self._sniffer_thread: Optional[threading.Thread] = None
        
        # Performance metrics
        self.total_captured = 0
        self.total_dropped = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.is_running = False

    def _packet_callback(self, pkt: Any) -> None:
        """Callback invoked by Scapy for every captured packet."""
        if self._stop_event.is_set():
            return

        if not pkt.haslayer(IP):
            return

        try:
            ip_layer = pkt.getlayer(IP)
            timestamp = float(pkt.time) if hasattr(pkt, "time") else time.time()
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            proto_name = "OTHER"
            src_port = 0
            dst_port = 0
            tcp_flags = ""
            payload_len = len(pkt)

            if pkt.haslayer(TCP):
                proto_name = "TCP"
                tcp_layer = pkt.getlayer(TCP)
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = str(tcp_layer.flags)
                self.tcp_count += 1
            elif pkt.haslayer(UDP):
                proto_name = "UDP"
                udp_layer = pkt.getlayer(UDP)
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                self.udp_count += 1
            elif pkt.haslayer(ICMP):
                proto_name = "ICMP"
                self.icmp_count += 1

            packet_data = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto_name,
                "length": payload_len,
                "tcp_flags": tcp_flags
            }

            try:
                self.packet_queue.put_nowait(packet_data)
                self.total_captured += 1
            except queue.Full:
                self.total_dropped += 1

        except Exception:
            pass

    def _sniff_worker(self) -> None:
        """Worker thread function executing Scapy packet capture loop."""
        if not SCAPY_AVAILABLE:
            logging.error("Scapy is not installed. Live packet sniffing is unavailable.")
            return

        try:
            # Sniff with stop_filter checking stop_event
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False
            )
        except Exception as e:
            logging.error(f"Live sniffing encountered an error: {e}")
        finally:
            self.is_running = False

    def start(self) -> None:
        """Starts asynchronous packet capture on a background thread."""
        if self.is_running:
            return

        self._stop_event.clear()
        self.is_running = True
        self._sniffer_thread = threading.Thread(
            target=self._sniff_worker,
            name="TreeIDS-PacketSniffer",
            daemon=True
        )
        self._sniffer_thread.start()
        print(f"[+] LivePacketSniffer started (filter: '{self.bpf_filter}', iface: {self.interface or 'default'}).")

    def stop(self) -> None:
        """Signals the sniffer thread to stop and waits for termination."""
        if not self.is_running:
            return

        print("[+] Stopping LivePacketSniffer...")
        self._stop_event.set()
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)
        self.is_running = False
        print(f"[+] Sniffer stopped. Total Captured: {self.total_captured:,} | Dropped: {self.total_dropped:,}")

    def get_packet(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        """Retrieves next packet from the buffer queue with timeout."""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Returns runtime telemetry statistics of the sniffer engine."""
        return {
            "is_running": self.is_running,
            "queue_size": self.packet_queue.qsize(),
            "total_captured": self.total_captured,
            "total_dropped": self.total_dropped,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "icmp_count": self.icmp_count
        }
