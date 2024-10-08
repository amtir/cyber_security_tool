#!/bin/bash
# Install Python dependencies
pip install -r requirements.txt

# Ensure external tools are installed (this is optional and depends on your system configuration)
sudo apt-get install -y whois nmap gobuster

echo "All dependencies installed!"
