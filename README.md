# Spynet

A simple and efficient Python script to scan live hosts and open ports on your home network. This script uses ARP scanning to detect live hosts and asyncio for faster port scanning.

## Requirements

- Python 3.7+
- netifaces==0.11.0
- scapy==2.4.5

## Installation

1. Clone this repository or download the script files.
2. Install the required libraries: 
```
pip install -r requirements.txt
```


## Usage

By default, the script scans the local network and the first 10,000 ports:
```
python spynet.py
```


To scan a specific IP or IP range, use the `-i` or `--ip` option:
```
python spynet.py -i 192.168.1.1
```


To scan a specific port or port range, use the `-p` or `--port` option:
```
python spynet.py -p 80-100
```


To save the results in a specific file, use the `-o` or `--output` option:
```
python spynet.py -o results.json
```


The script will display live hosts and their open ports on the console and save the results in a JSON file.
