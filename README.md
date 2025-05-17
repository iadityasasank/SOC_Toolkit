# SOC Toolkit

A comprehensive collection of tools and scripts for Security Operations Center (SOC) Analysts and Engineers.

## Project Structure

```
SOC_Toolkit/
├── log_analysis/          # Log parsing and analysis tools
├── threat_intel/         # Threat Intelligence integration scripts
├── incident_response/    # Incident Response automation tools
├── network_monitoring/   # Network traffic analysis scripts
├── malware_analysis/    # Basic malware analysis utilities
├── reporting/           # Automated report generation tools
└── utils/              # Common utilities and helper functions
```

## Features

### Log Analysis
- Log parsing and normalization
- Pattern matching and anomaly detection
- Alert correlation engine
- Log enrichment with threat intel

### Threat Intelligence
- IOC (Indicators of Compromise) collection
- Threat feed integration
- MISP integration
- Automated IOC extraction

### Incident Response
- Automated incident triage
- Evidence collection scripts
- Timeline generation
- System analysis tools

### Network Monitoring
- Packet analysis utilities
- Network traffic baseline tools
- Protocol analyzers
- Network IOC detection

### Malware Analysis
- Basic static analysis tools
- Sandbox integration
- IOC extraction
- Hash checking and verification

### Reporting
- Automated incident reports
- Dashboard generation
- Metrics collection
- Alert summary generation

## Setup and Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/SOC_Toolkit.git
cd SOC_Toolkit
```

2. Install required dependencies
```bash
pip install -r requirements.txt
```

3. Configure settings in `config.yaml`

## Usage

Each tool directory contains its own README with specific usage instructions.

## Requirements

- Python 3.8+
- Required Python packages listed in requirements.txt
- Access to necessary APIs and services

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 