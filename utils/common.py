#!/usr/bin/env python3

import re
import ipaddress
import hashlib
import datetime
import yaml
import os

def load_config(config_file):
    """Load configuration from YAML file"""
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def is_valid_ip(ip_str):
    """Validate if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """Validate if a string is a valid domain name"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.datetime.now().isoformat()

def setup_logging(log_file):
    """Setup basic logging configuration"""
    import logging
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

if __name__ == "__main__":
    # Example usage
    print(f"Current timestamp: {get_timestamp()}")
    print(f"Is valid IP? 192.168.1.1: {is_valid_ip('192.168.1.1')}")
    print(f"Is valid domain? example.com: {is_valid_domain('example.com')}") 