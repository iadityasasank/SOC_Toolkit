#!/usr/bin/env python3

import requests
import json
import datetime
import os

class ThreatIntelCollector:
    def __init__(self):
        self.intel_data = {
            'timestamp': '',
            'sources': [],
            'indicators': []
        }
    
    def add_indicator(self, indicator_type, value, source, confidence_score):
        indicator = {
            'type': indicator_type,  # e.g., 'ip', 'domain', 'hash'
            'value': value,
            'source': source,
            'confidence_score': confidence_score,
            'timestamp': datetime.datetime.now().isoformat()
        }
        self.intel_data['indicators'].append(indicator)
    
    def fetch_from_source(self, source_name, api_url, api_key=None):
        """
        Template method for fetching threat intel from various sources
        Implement specific API integrations as needed
        """
        headers = {'Authorization': f'Bearer {api_key}'} if api_key else {}
        try:
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                self.intel_data['sources'].append({
                    'name': source_name,
                    'last_updated': datetime.datetime.now().isoformat(),
                    'status': 'success'
                })
                return response.json()
            else:
                self.intel_data['sources'].append({
                    'name': source_name,
                    'last_updated': datetime.datetime.now().isoformat(),
                    'status': 'failed',
                    'error': f'HTTP {response.status_code}'
                })
                return None
        except Exception as e:
            self.intel_data['sources'].append({
                'name': source_name,
                'last_updated': datetime.datetime.now().isoformat(),
                'status': 'failed',
                'error': str(e)
            })
            return None
    
    def export_intel(self, output_file):
        self.intel_data['timestamp'] = datetime.datetime.now().isoformat()
        with open(output_file, 'w') as f:
            json.dump(self.intel_data, f, indent=4)

if __name__ == "__main__":
    # Example usage
    collector = ThreatIntelCollector()
    collector.add_indicator(
        "ip",
        "192.168.1.100",
        "internal_blocklist",
        0.95
    )
    collector.export_intel("threat_intel.json") 