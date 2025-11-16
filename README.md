# Advanced Personal Firewall Using Python

A lightweight personal firewall written in Python that:
- Monitors network traffic using **Scapy**
- Applies **rule-based allow/block** decisions
- Optionally integrates with **iptables / nftables**
- Provides a simple **Tkinter GUI** and **logging**

---

## Features

- Packet sniffing (live or from PCAP files)  
- Rule engine (IP, port, protocol, direction, ICMP type, TCP flags)  
- Rule priority + match counters  
- Temporary (TTL) block rules  
- Optional iptables / nftables backend for real blocking  
- File + SQLite logging (`pfw.log`, `pfw_logs.db`)  
- Tkinter GUI: view/add/remove rules, live logs, help window  
- PCAP capture on suspicious rule matches  
- Basic SYN flood / port scan detection with adaptive blocking  
- Optional REST API (Flask) for rule management  

---

## Requirements

- Python 3  
- `pip install scapy flask requests`  
- Linux (for iptables / nftables backend)  

---

## Quick Start

```bash
# Monitor-only, no real blocking
sudo python3 personal_firewall_full.py --backend none --rules rules.json

# Real firewall mode using nftables
sudo python3 personal_firewall_full.py --backend nft --rules rules.json

# GUI mode
sudo python3 personal_firewall_full.py --backend none --rules rules.json --gui

# Simulation using PCAP
python3 personal_firewall_full.py --simulate sample.pcap --rules rules.json
```

For detailed usage:
```bash
python3 personal_firewall_full.py --help
python3 personal_firewall_full.py --help-usage
```
