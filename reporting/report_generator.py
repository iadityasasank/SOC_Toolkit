#!/usr/bin/env python3

import datetime
import json
import os

class ReportGenerator:
    def __init__(self):
        self.report_data = {
            'timestamp': '',
            'incidents': [],
            'summary': '',
            'recommendations': []
        }
    
    def add_incident(self, incident_type, description, severity):
        incident = {
            'type': incident_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.datetime.now().isoformat()
        }
        self.report_data['incidents'].append(incident)
    
    def generate_summary(self):
        incident_count = len(self.report_data['incidents'])
        severity_counts = {}
        for incident in self.report_data['incidents']:
            severity = incident['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary = f"Total Incidents: {incident_count}\n"
        for severity, count in severity_counts.items():
            summary += f"{severity} severity incidents: {count}\n"
        
        self.report_data['summary'] = summary
    
    def export_report(self, output_file):
        self.report_data['timestamp'] = datetime.datetime.now().isoformat()
        with open(output_file, 'w') as f:
            json.dump(self.report_data, f, indent=4)

if __name__ == "__main__":
    # Example usage
    generator = ReportGenerator()
    generator.add_incident(
        "Suspicious Login",
        "Multiple failed login attempts from IP 192.168.1.100",
        "HIGH"
    )
    generator.generate_summary()
    generator.export_report("incident_report.json") 