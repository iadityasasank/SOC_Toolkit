#!/usr/bin/env python3

import os
import json
import psutil
import datetime
import magic
import hashlib
from collections import defaultdict
import logging
from ..utils.common import calculate_hash, get_timestamp, setup_logging

class IncidentResponseHandler:
    def __init__(self, case_id=None):
        self.case_id = case_id or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.evidence = []
        self.timeline = []
        self.system_info = {}
        self.network_connections = []
        self.running_processes = []
        self.logger = setup_logging(f"ir_case_{self.case_id}.log")
    
    def collect_system_info(self):
        """Collect basic system information"""
        self.system_info = {
            'hostname': os.uname().nodename if hasattr(os, 'uname') else os.environ.get('COMPUTERNAME'),
            'platform': os.uname().sysname if hasattr(os, 'uname') else os.name,
            'architecture': os.uname().machine if hasattr(os, 'uname') else platform.machine(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_partitions': [partition.device for partition in psutil.disk_partitions()],
            'collection_time': get_timestamp()
        }
        self.logger.info(f"System information collected for case {self.case_id}")
        return self.system_info

    def collect_running_processes(self):
        """Collect information about running processes"""
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'connections']):
            try:
                pinfo = proc.info
                pinfo['create_time'] = datetime.datetime.fromtimestamp(
                    proc.create_time()
                ).isoformat()
                self.running_processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        self.logger.info(f"Collected information for {len(self.running_processes)} running processes")
        return self.running_processes

    def collect_network_connections(self):
        """Collect active network connections"""
        connections = psutil.net_connections()
        for conn in connections:
            if conn.laddr and conn.raddr:  # Only get established connections
                connection_info = {
                    'local_ip': conn.laddr.ip,
                    'local_port': conn.laddr.port,
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'status': conn.status,
                    'pid': conn.pid
                }
                self.network_connections.append(connection_info)
        self.logger.info(f"Collected {len(self.network_connections)} active network connections")
        return self.network_connections

    def add_evidence(self, file_path, evidence_type, description):
        """Add a file to evidence collection with metadata"""
        if not os.path.exists(file_path):
            self.logger.error(f"Evidence file not found: {file_path}")
            return None

        evidence = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'file_type': magic.from_file(file_path),
            'file_hash': calculate_hash(file_path),
            'collection_time': get_timestamp(),
            'evidence_type': evidence_type,
            'description': description
        }
        self.evidence.append(evidence)
        self.logger.info(f"Added evidence: {evidence['file_name']} ({evidence['evidence_type']})")
        return evidence

    def add_timeline_event(self, timestamp, event_type, description, source):
        """Add an event to the investigation timeline"""
        event = {
            'timestamp': timestamp,
            'event_type': event_type,
            'description': description,
            'source': source
        }
        self.timeline.append(event)
        self.logger.info(f"Added timeline event: {event_type} from {source}")
        return event

    def export_case_data(self, output_dir):
        """Export all collected data to JSON files"""
        os.makedirs(output_dir, exist_ok=True)
        case_data = {
            'case_id': self.case_id,
            'system_info': self.system_info,
            'evidence': self.evidence,
            'timeline': self.timeline,
            'network_connections': self.network_connections,
            'running_processes': self.running_processes,
            'export_time': get_timestamp()
        }
        
        output_file = os.path.join(output_dir, f"case_{self.case_id}.json")
        with open(output_file, 'w') as f:
            json.dump(case_data, f, indent=4)
        self.logger.info(f"Case data exported to {output_file}")
        return output_file

if __name__ == "__main__":
    # Example usage
    ir_handler = IncidentResponseHandler()
    
    # Collect system information
    ir_handler.collect_system_info()
    
    # Collect process and network information
    ir_handler.collect_running_processes()
    ir_handler.collect_network_connections()
    
    # Add some evidence
    ir_handler.add_evidence(
        "suspicious_file.exe",
        "malware_sample",
        "Suspicious executable found in downloads folder"
    )
    
    # Add timeline event
    ir_handler.add_timeline_event(
        get_timestamp(),
        "initial_detection",
        "Suspicious process activity detected",
        "EDR Alert"
    )
    
    # Export case data
    ir_handler.export_case_data("case_evidence") 