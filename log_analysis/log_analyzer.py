#!/usr/bin/env python3

import yaml
import pandas as pd
import datetime
import re
from pathlib import Path
from typing import List, Dict, Any
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LogAnalyzer:
    def __init__(self, config_path: str = "../config.yaml"):
        """Initialize the log analyzer with configuration."""
        self.config = self._load_config(config_path)
        self.patterns = {
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'timestamp': r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'
        }

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}

    def parse_log_file(self, log_path: str) -> pd.DataFrame:
        """Parse a log file and return a DataFrame with structured data."""
        try:
            # Read the log file
            with open(log_path, 'r') as f:
                lines = f.readlines()

            # Extract data from each line
            parsed_data = []
            for line in lines:
                entry = self._parse_log_line(line)
                if entry:
                    parsed_data.append(entry)

            # Create DataFrame
            df = pd.DataFrame(parsed_data)
            return df

        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {e}")
            return pd.DataFrame()

    def _parse_log_line(self, line: str) -> Dict[str, Any]:
        """Parse a single log line and extract relevant information."""
        entry = {
            'raw_log': line.strip(),
            'timestamp': None,
            'ip_addresses': [],
            'emails': [],
        }

        # Extract timestamp
        timestamp_match = re.search(self.patterns['timestamp'], line)
        if timestamp_match:
            entry['timestamp'] = timestamp_match.group()

        # Extract IP addresses
        ip_matches = re.findall(self.patterns['ip_address'], line)
        if ip_matches:
            entry['ip_addresses'] = ip_matches

        # Extract email addresses
        email_matches = re.findall(self.patterns['email'], line)
        if email_matches:
            entry['emails'] = email_matches

        return entry

    def analyze_logs(self, log_directory: str) -> Dict[str, Any]:
        """Analyze all logs in the specified directory."""
        results = {
            'total_entries': 0,
            'unique_ips': set(),
            'unique_emails': set(),
            'entries_by_date': {},
        }

        try:
            # Process each log file
            log_files = Path(log_directory).glob('*.log')
            for log_file in log_files:
                df = self.parse_log_file(str(log_file))
                if not df.empty:
                    # Update statistics
                    results['total_entries'] += len(df)
                    
                    # Extract unique IPs and emails
                    for ips in df['ip_addresses']:
                        results['unique_ips'].update(ips)
                    for emails in df['emails']:
                        results['unique_emails'].update(emails)

                    # Group by date
                    if 'timestamp' in df.columns:
                        df['date'] = pd.to_datetime(df['timestamp']).dt.date
                        date_counts = df['date'].value_counts()
                        for date, count in date_counts.items():
                            date_str = str(date)
                            if date_str in results['entries_by_date']:
                                results['entries_by_date'][date_str] += count
                            else:
                                results['entries_by_date'][date_str] = count

            # Convert sets to lists for JSON serialization
            results['unique_ips'] = list(results['unique_ips'])
            results['unique_emails'] = list(results['unique_emails'])

            return results

        except Exception as e:
            logger.error(f"Error analyzing logs: {e}")
            return results

    def generate_report(self, analysis_results: Dict[str, Any], output_file: str):
        """Generate a report from the analysis results."""
        try:
            with open(output_file, 'w') as f:
                f.write("Log Analysis Report\n")
                f.write("==================\n\n")
                
                f.write(f"Total Log Entries: {analysis_results['total_entries']}\n")
                f.write(f"Unique IP Addresses: {len(analysis_results['unique_ips'])}\n")
                f.write(f"Unique Email Addresses: {len(analysis_results['unique_emails'])}\n\n")
                
                f.write("Entries by Date:\n")
                for date, count in sorted(analysis_results['entries_by_date'].items()):
                    f.write(f"  {date}: {count} entries\n")
                
                f.write("\nDetected IP Addresses:\n")
                for ip in sorted(analysis_results['unique_ips']):
                    f.write(f"  - {ip}\n")
                
                f.write("\nDetected Email Addresses:\n")
                for email in sorted(analysis_results['unique_emails']):
                    f.write(f"  - {email}\n")

            logger.info(f"Report generated successfully: {output_file}")

        except Exception as e:
            logger.error(f"Error generating report: {e}")

def main():
    """Main function to demonstrate usage."""
    analyzer = LogAnalyzer()
    
    # Example usage
    log_dir = "../logs"  # Update this path as needed
    results = analyzer.analyze_logs(log_dir)
    
    # Generate report
    report_path = "../reports/log_analysis_report.txt"
    analyzer.generate_report(results, report_path)

if __name__ == "__main__":
    main() 