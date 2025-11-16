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
# Running as a Systemd Daemon (Firewall Service)

Follow these steps to run the firewall automatically at system startup.

---

## 1. Move the firewall to a fixed location
```bash
sudo mkdir -p /opt/pfw
sudo cp personal_firewall_full.py /opt/pfw/
sudo cp rules.json /opt/pfw/
```

---

## 2. Create a systemd service file  
Create file:
```bash
sudo nano /etc/systemd/system/pfw.service
```

Paste this:
```
[Unit]
Description=Python Personal Firewall Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/pfw/personal_firewall_full.py --backend nft --rules /opt/pfw/rules.json --no-gui
Restart=on-failure
WorkingDirectory=/opt/pfw
User=root

[Install]
WantedBy=multi-user.target
```

---

## 3. Reload systemd and enable service
```bash
sudo systemctl daemon-reload
sudo systemctl enable pfw
sudo systemctl start pfw
```

---

## 4. Check firewall logs
```bash
sudo journalctl -u pfw -f
```

---

## 5. Stop or disable the firewall
```bash
sudo systemctl stop pfw
sudo systemctl disable pfw
```

---

## 6. Edit the service configuration
```bash
sudo nano /etc/systemd/system/pfw.service
sudo systemctl daemon-reload
sudo systemctl restart pfw
```

---

## 7. Recommended: Create a dedicated log directory
```bash
sudo mkdir -p /var/log/pfw
sudo chmod 777 /var/log/pfw
```

You may edit `pfw.service` to redirect logs there.

---

# Simulation Mode
Test firewall rules without live traffic:

```bash
python3 personal_firewall_full.py --simulate sample.pcap --rules rules.json
```

---

# REST API Mode
Start API:
```bash
python3 personal_firewall_full.py --api
```

List rules:
```bash
curl http://127.0.0.1:8080/rules
```

---

# Help Commands
```bash
python3 personal_firewall_full.py --help
python3 personal_firewall_full.py --help-usage
```

---
