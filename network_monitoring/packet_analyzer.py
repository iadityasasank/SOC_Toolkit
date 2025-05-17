#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, DNS
import yaml
import logging
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    def __init__(self, config_path: str = "../config.yaml"):
        """Initialize the packet analyzer with configuration."""
        self.config = self._load_config(config_path)
        self.stats = defaultdict(int)
        self.connections = defaultdict(list)
        self.dns_queries = defaultdict(list)
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}

    def packet_callback(self, packet):
        """Process each captured packet."""
        try:
            # Update packet count
            self.stats['total_packets'] += 1

            # Process IP packets
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                self.stats['ip_packets'] += 1

                # TCP analysis
                if TCP in packet:
                    self._analyze_tcp(packet, src_ip, dst_ip)

                # UDP analysis
                elif UDP in packet:
                    self._analyze_udp(packet, src_ip, dst_ip)

                # Store connection
                connection = f"{src_ip}:{dst_ip}"
                self.connections[connection].append({
                    'timestamp': datetime.now().isoformat(),
                    'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
                })

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _analyze_tcp(self, packet, src_ip: str, dst_ip: str):
        """Analyze TCP packets."""
        self.stats['tcp_packets'] += 1
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Track common services
        if dst_port == 80:
            self.stats['http_requests'] += 1
        elif dst_port == 443:
            self.stats['https_requests'] += 1
        elif dst_port == 22:
            self.stats['ssh_connections'] += 1

        # Track TCP flags
        if packet[TCP].flags.S:  # SYN
            self.stats['tcp_syn'] += 1
        if packet[TCP].flags.F:  # FIN
            self.stats['tcp_fin'] += 1
        if packet[TCP].flags.R:  # RST
            self.stats['tcp_rst'] += 1

    def _analyze_udp(self, packet, src_ip: str, dst_ip: str):
        """Analyze UDP packets."""
        self.stats['udp_packets'] += 1
        
        # DNS analysis
        if DNS in packet:
            self._analyze_dns(packet)

    def _analyze_dns(self, packet):
        """Analyze DNS packets."""
        self.stats['dns_queries'] += 1
        
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
            query = packet[DNS].qd.qname.decode('utf-8')
            self.dns_queries[query].append({
                'timestamp': datetime.now().isoformat(),
                'source': packet[IP].src
            })

    def start_capture(self, interface: str = None, timeout: int = None):
        """Start packet capture."""
        try:
            logger.info(f"Starting packet capture on interface: {interface}")
            
            # Get interface from config if not specified
            if not interface and self.config.get('network', {}).get('interface'):
                interface = self.config['network']['interface']

            # Start capturing
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                timeout=timeout
            )

        except Exception as e:
            logger.error(f"Error in packet capture: {e}")

    def generate_report(self, output_file: str):
        """Generate a report of the captured traffic."""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'statistics': dict(self.stats),
                'top_connections': self._get_top_connections(10),
                'top_dns_queries': self._get_top_dns_queries(10)
            }

            # Ensure directory exists
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)

            # Write report
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)

            logger.info(f"Report generated successfully: {output_file}")

        except Exception as e:
            logger.error(f"Error generating report: {e}")

    def _get_top_connections(self, limit: int) -> List[Dict[str, Any]]:
        """Get the top N most frequent connections."""
        connections_list = [
            {
                'connection': conn,
                'count': len(details)
            }
            for conn, details in self.connections.items()
        ]
        return sorted(connections_list, key=lambda x: x['count'], reverse=True)[:limit]

    def _get_top_dns_queries(self, limit: int) -> List[Dict[str, Any]]:
        """Get the top N most frequent DNS queries."""
        queries_list = [
            {
                'query': query,
                'count': len(details)
            }
            for query, details in self.dns_queries.items()
        ]
        return sorted(queries_list, key=lambda x: x['count'], reverse=True)[:limit]

def main():
    """Main function to demonstrate usage."""
    analyzer = PacketAnalyzer()
    
    # Start capture for 60 seconds
    analyzer.start_capture(timeout=60)
    
    # Generate report
    report_path = "../reports/network_analysis_report.json"
    analyzer.generate_report(report_path)

if __name__ == "__main__":
    main() 