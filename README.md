# HTTP/2 Flood Attack Tool - Premium Edition (GUI ONLY/WSL)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![PyQt5](https://img.shields.io/badge/PyQt5-5.15.9-green)
![License](https://img.shields.io/badge/License-MIT-orange)

A sophisticated HTTP/2 flood attack tool with a modern GUI interface, designed for network security testing and educational purposes.

## Features

- **HTTP/2 Protocol Attack**: Leverages HTTP/2 for high-performance flooding
- **Real-time Statistics**: Live monitoring of requests, responses, and errors
- **Graphical Interface**: Modern dark-themed GUI with real-time graphs
- **Proxy Support**: Rotate through proxy lists for enhanced anonymity
- **Target Monitoring**: Continuous target status checking with latency measurement
- **JavaScript Attack Methods**: Support for custom JS-based attack scripts
- **Multi-threaded**: High concurrency with configurable thread counts

## Prerequisites (NOT SUPPORT CLI) 

- **Linux/Debian** based system (GUI ONLY/WSL)
- **Python 3.8+**
- **Node.js** (for JS attack methods)
- **Git**

## Installation

### Method 1: Quick Install with requirements.txt

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3 python3-pip python3-venv git nodejs npm

# Clone the repository
git clone https://github.com/hmei7-id/gui-ddos.git
cd gui-ddos

#OPTIONAL  Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies from requirements.txt
pip install -r requirements.txt

# IF ERROR
pip install -r requirements.txt --break-system-packages

# RUN SCRIPT
python3 gui_dos.py

---------------------------------------------------------------
# Prepare necessary files
echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" > ua.txt
touch proxies.txt

# Add your proxies to proxies.txt (format: ip:port)
# Example: echo "127.0.0.1:8080" >> proxies.txt
