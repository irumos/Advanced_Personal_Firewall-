#!/usr/bin/env python3
"""
personal_firewall_full.py

Advanced Personal Firewall (All-in-One):

Core:
- Live packet sniffing (Scapy) and PCAP simulation mode
- Rule engine with priorities, counters, direction, ICMP, TCP flags
- TTL-based temporary block rules
- Auto-rollback safety framework for backend rules (logging only for now)
- nftables / iptables / monitor-only backend

Monitoring:
- File + SQLite logging
- Tkinter GUI for rules and logs (optional)
- PCAP capture on suspicious rule match

Control & Integration:
- Simple Flask REST API & Web dashboard (optional)
- Threat-feed IP auto-block (optional, from URL or file)
- Basic adaptive blocking / SYN flood / rudimentary port-scan detection
- Rules backup before save

Run as:
- CLI program
- GUI tool
- Systemd daemon (no GUI, no TTY)

NOTE:
- For live sniffing + firewall backend, run as root (Linux).
- For REST / GUI features, install Tkinter + Flask.
"""

import argparse
import json
import logging
import os
import queue
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import deque
from argparse import RawDescriptionHelpFormatter

# Scapy
try:
    from scapy.all import (
        sniff,
        rdpcap,
        wrpcap,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
    )
except Exception as e:
    print("ERROR: scapy import failed. Install with: pip install scapy")
    raise

# Optional GUI
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, simpledialog
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

# Optional Flask REST API / dashboard
try:
    from flask import Flask, jsonify, request
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

# ----------------- Config -----------------
DEFAULT_RULES_FILE = "rules.json"
LOGFILE = "pfw.log"
SQLITE_DB = "pfw_logs.db"
CAPTURE_PCAP = "pfw_alert_capture.pcap"
RULES_BACKUP_DIR = "rules_backups"

# Heuristic thresholds
SYN_FLOOD_THRESHOLD = 100   # SYN packets per window
SYN_WINDOW_SECONDS = 10
PORTSCAN_PORTS_THRESHOLD = 20
ADAPTIVE_BLOCK_DURATION = 300  # seconds

FIREWALL_USAGE_TEXT = r"""
USAGE EXAMPLES
==============

Basic monitor-only mode (no real blocking):
  sudo python3 personal_firewall_full.py --backend none --rules rules.json

Full firewall mode using nftables (real DROP rules in kernel):
  sudo python3 personal_firewall_full.py --backend nft --rules rules.json

Run with GUI (to add/remove rules and see logs):
  sudo python3 personal_firewall_full.py --backend none --rules rules.json --gui

Run with REST API + mini web dashboard:
  sudo python3 personal_firewall_full.py --backend none --rules rules.json --api

Simulation mode using PCAP file (offline testing):
  python3 personal_firewall_full.py --simulate sample.pcap --rules rules.json

Use a threat feed file to auto-block IPs:
  sudo python3 personal_firewall_full.py --backend nft --rules rules.json --threat-feed bad_ips.txt


MAIN OPTIONS
============

--backend {none,iptables,nft}
  none      : monitor only, no actual system-level blocking
  iptables  : insert DROP/ACCEPT rules using iptables
  nft       : insert DROP/ACCEPT rules using nftables (recommended on modern Linux)

--rules PATH
  Path to rules.json file. Contains all firewall rules (block/allow, priorities, TTL, etc.).

--iface IFACE
  Interface to sniff on (e.g., eth0, wlan0). If omitted, listens on all interfaces.

--filter "BPF"
  BPF filter for Scapy sniffing, for example:
    --filter "tcp"
    --filter "port 80"
    --filter "tcp and port 443"

--gui / --no-gui
  --gui    : Start Tkinter GUI (if available) for managing rules and viewing logs.
  --no-gui : Force CLI mode only.

--simulate FILE.pcap
  Instead of live sniffing, read packets from a PCAP file and run them through the rules.

--api
  Start a simple REST API and mini web page at:
    http://<host>:<port>  (default: http://127.0.0.1:8080)

SPECIAL MODES
=============

Self-test:
  python3 personal_firewall_full.py --self-test

  Runs a small internal check to verify rule matching logic (SYN/ACK flags, etc.).

Daemon / systemd usage:
  Put the script in a fixed path (e.g. /opt/pfw/personal_firewall_full.py)
  and create a systemd unit that runs:

    ExecStart=/usr/bin/python3 /opt/pfw/personal_firewall_full.py \
        --rules /opt/pfw/rules.json \
        --backend nft \
        --no-gui

For a detailed usage guide at runtime:
  python3 personal_firewall_full.py --help-usage
"""

# ----------------- Logging Setup -----------------
logger = logging.getLogger("personal_firewall")
logger.setLevel(logging.DEBUG)

_file_handler = logging.FileHandler(LOGFILE)
_file_formatter = logging.Formatter(
    "%(asctime)s %(levelname)s [%(rule_id)s %(action)s]: %(message)s"
)
_file_handler.setFormatter(_file_formatter)
_file_handler.setLevel(logging.DEBUG)
logger.addHandler(_file_handler)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_file_formatter)
_console_handler.setLevel(logging.INFO)
logger.addHandler(_console_handler)


class SQLiteHandler(logging.Handler):
    """Log handler that writes log entries into a SQLite DB."""

    def __init__(self, db_path=SQLITE_DB):
        super().__init__()
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                level TEXT,
                rule_id TEXT,
                action TEXT,
                message TEXT
            )
            """
        )
        self._conn.commit()

    def emit(self, record: logging.LogRecord):
        msg = self.format(record)
        rule_id = getattr(record, "rule_id", None)
        action = getattr(record, "action", None)
        when = datetime.utcfromtimestamp(record.created).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO logs (time, level, rule_id, action, message) VALUES (?, ?, ?, ?, ?)",
                (when, record.levelname, rule_id, action, msg),
            )
            self._conn.commit()


_sql_handler = SQLiteHandler()
_sql_handler.setLevel(logging.INFO)
_sql_handler.setFormatter(_file_formatter)
logger.addHandler(_sql_handler)


class RuleAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("rule_id", "-")
        extra.setdefault("action", "-")
        return msg, kwargs


log = RuleAdapter(logger, {})

# ----------------- Helpers -----------------
def which(cmd: str) -> Optional[str]:
    from shutil import which as _which
    return _which(cmd)


# ----------------- Data Model -----------------
@dataclass
class Rule:
    id: str
    action: str  # "allow" or "block"
    priority: int = 100
    match_count: int = 0

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # "tcp","udp","icmp","ip","ipv6"
    direction: Optional[str] = "both"  # "in","out","both"

    icmp_type: Optional[int] = None
    tcp_flags: List[str] = field(default_factory=list)

    comment: Optional[str] = None

    # TTL support (temporary rules)
    ttl_seconds: Optional[int] = None  # if set, rule auto-expires
    created_at: Optional[str] = None   # ISO timestamp (string) for persistence

    # PCAP capture trigger
    capture_on_match: bool = False

    # Internal
    backend_applied: bool = False
    auto_rollback: bool = False  # if True, rule will be rolled back
    rollback_deadline: Optional[datetime] = None

    def is_expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        if not self.created_at:
            return False
        try:
            created = datetime.fromisoformat(self.created_at)
        except ValueError:
            return False
        return datetime.utcnow() > created + timedelta(seconds=self.ttl_seconds)

    def matches_packet(self, pkt_info: Dict[str, Any]) -> bool:
        """Return True if this rule matches the packet info dict."""
        if self.is_expired():
            return False

        if self.protocol and self.protocol.lower() != pkt_info.get("protocol", "").lower():
            return False

        if self.src_ip and self.src_ip != pkt_info.get("src_ip"):
            return False
        if self.dst_ip and self.dst_ip != pkt_info.get("dst_ip"):
            return False

        if self.src_port and self.src_port != pkt_info.get("src_port"):
            return False
        if self.dst_port and self.dst_port != pkt_info.get("dst_port"):
            return False

        if self.direction and self.direction.lower() != "both":
            if pkt_info.get("direction") != self.direction.lower():
                return False

        if self.icmp_type is not None:
            if pkt_info.get("icmp_type") != self.icmp_type:
                return False

        if self.tcp_flags:
            pkt_flags = pkt_info.get("tcp_flags", [])
            for f in self.tcp_flags:
                if f.upper() not in pkt_flags:
                    return False

        return True


# ----------------- Rule Engine -----------------
class RuleEngine:
    def __init__(self, rules: List[Rule]):
        self.rules: List[Rule] = rules
        self.lock = threading.Lock()

    @classmethod
    def load_from_file(cls, path: str) -> "RuleEngine":
        if not os.path.exists(path):
            log.info("Rules file %s not found, using empty rules set.", path,
                     extra={"rule_id": "-", "action": "load_rules"})
            return cls([])
        with open(path, "r") as f:
            data = json.load(f)
        rules: List[Rule] = []
        for r in data.get("rules", []):
            tcp_flags = r.get("tcp_flags") or []
            if isinstance(tcp_flags, str):
                tcp_flags = [tcp_flags]
            rule = Rule(
                id=r.get("id", f"r{len(rules)+1}"),
                action=r.get("action", "block"),
                priority=int(r.get("priority", 100)),
                match_count=int(r.get("match_count", 0)),
                src_ip=r.get("src_ip"),
                dst_ip=r.get("dst_ip"),
                src_port=int(r["src_port"]) if r.get("src_port") else None,
                dst_port=int(r["dst_port"]) if r.get("dst_port") else None,
                protocol=r.get("protocol"),
                direction=r.get("direction", "both"),
                icmp_type=int(r["icmp_type"]) if r.get("icmp_type") is not None else None,
                tcp_flags=[f.upper() for f in tcp_flags],
                comment=r.get("comment"),
                ttl_seconds=r.get("ttl_seconds"),
                created_at=r.get("created_at"),
                capture_on_match=r.get("capture_on_match", False),
            )
            rules.append(rule)
        return cls(rules)

    def backup_rules(self, path: str):
        os.makedirs(RULES_BACKUP_DIR, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(RULES_BACKUP_DIR, f"{os.path.basename(path)}.{ts}.bak")
        if os.path.exists(path):
            with open(path, "rb") as src, open(backup_path, "wb") as dst:
                dst.write(src.read())
            log.info("Rules backup created at %s", backup_path,
                     extra={"rule_id": "-", "action": "backup"})

    def save_to_file(self, path: str):
        self.backup_rules(path)
        with self.lock:
            out = {"rules": [self._rule_to_dict(r) for r in self.rules]}
        with open(path, "w") as f:
            json.dump(out, f, indent=2)
        log.info("Rules saved to %s", path, extra={"rule_id": "-", "action": "save_rules"})

    @staticmethod
    def _rule_to_dict(r: Rule) -> Dict[str, Any]:
        return {
            "id": r.id,
            "action": r.action,
            "priority": r.priority,
            "match_count": r.match_count,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "src_port": r.src_port,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "direction": r.direction,
            "icmp_type": r.icmp_type,
            "tcp_flags": r.tcp_flags,
            "comment": r.comment,
            "ttl_seconds": r.ttl_seconds,
            "created_at": r.created_at,
            "capture_on_match": r.capture_on_match,
        }

    def evaluate(self, pkt_info: Dict[str, Any]) -> Optional[Rule]:
        """Return the first matching non-expired rule by priority, incrementing its counter."""
        now = datetime.utcnow()
        with self.lock:
            # Remove expired rules in-place
            for r in self.rules:
                if r.is_expired() and not r.backend_applied:
                    log.info("Rule expired: %s", r.id, extra={"rule_id": r.id, "action": "ttl_expired"})
            self.rules = [r for r in self.rules if not r.is_expired()]

            for r in sorted(self.rules, key=lambda rr: rr.priority):
                if r.matches_packet(pkt_info):
                    r.match_count += 1
                    # ensure created_at is set
                    if r.created_at is None:
                        r.created_at = now.isoformat()
                    return r
        return None

    def add_rule(self, rule: Rule):
        with self.lock:
            if rule.created_at is None:
                rule.created_at = datetime.utcnow().isoformat()
            self.rules.append(rule)

    def remove_rule_by_id(self, rule_id: str):
        with self.lock:
            self.rules = [r for r in self.rules if r.id != rule_id]

    def get_rules_snapshot(self) -> List[Rule]:
        with self.lock:
            return list(self.rules)


# ----------------- Packet Info & Direction -----------------
_local_ips_cache: Optional[List[str]] = None


def get_local_ips() -> List[str]:
    global _local_ips_cache
    if _local_ips_cache is not None:
        return _local_ips_cache
    ips = set()
    try:
        import socket
        hostname = socket.gethostname()
        try:
            addrs = socket.gethostbyname_ex(hostname)[2]
            for a in addrs:
                if a and not a.startswith("127."):
                    ips.add(a)
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    except Exception:
        pass
    _local_ips_cache = list(ips)
    return _local_ips_cache


def detect_direction(pkt_info: Dict[str, Any]) -> str:
    local_ips = get_local_ips()
    dst = pkt_info.get("dst_ip")
    src = pkt_info.get("src_ip")
    if dst and dst in local_ips:
        return "in"
    if src and src in local_ips:
        return "out"
    if dst and (dst.startswith("10.") or dst.startswith("192.168.") or dst.startswith("172.")):
        return "in"
    return "in"


def extract_packet_info(pkt) -> Dict[str, Any]:
    pkt_info: Dict[str, Any] = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "ip",
        "direction": "in",
        "icmp_type": None,
        "tcp_flags": [],
    }

    if IP in pkt:
        ip = pkt[IP]
        pkt_info["src_ip"] = ip.src
        pkt_info["dst_ip"] = ip.dst
        pkt_info["protocol"] = "ip"
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        pkt_info["src_ip"] = ip6.src
        pkt_info["dst_ip"] = ip6.dst
        pkt_info["protocol"] = "ipv6"

    if TCP in pkt:
        t = pkt[TCP]
        pkt_info["protocol"] = "tcp"
        pkt_info["src_port"] = int(t.sport)
        pkt_info["dst_port"] = int(t.dport)
        flags_str = pkt.sprintf("%TCP.flags%")
        name_map = {
            "S": "SYN",
            "A": "ACK",
            "F": "FIN",
            "R": "RST",
            "P": "PSH",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }
        pkt_info["tcp_flags"] = [name_map.get(ch, ch) for ch in flags_str]
    elif UDP in pkt:
        u = pkt[UDP]
        pkt_info["protocol"] = "udp"
        pkt_info["src_port"] = int(u.sport)
        pkt_info["dst_port"] = int(u.dport)
    elif ICMP in pkt:
        ic = pkt[ICMP]
        pkt_info["protocol"] = "icmp"
        pkt_info["icmp_type"] = int(ic.type)

    return pkt_info


# ----------------- Backend (iptables / nftables / none) -----------------
def apply_backend_rule(rule: Rule, backend: str = "none") -> bool:
    if backend == "none":
        return False

    if backend == "iptables":
        if not sys.platform.startswith("linux") or which("iptables") is None:
            return False
        chain = "INPUT" if rule.direction == "in" else ("OUTPUT" if rule.direction == "out" else "INPUT")
        cmd = ["iptables", "-I", chain, "1"]
        if rule.protocol and rule.protocol.lower() in ("tcp", "udp", "icmp"):
            cmd += ["-p", rule.protocol.lower()]
        if rule.src_ip:
            cmd += ["-s", rule.src_ip]
        if rule.dst_ip:
            cmd += ["-d", rule.dst_ip]
        if rule.src_port and rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
            cmd += ["--sport", str(rule.src_port)]
        if rule.dst_port and rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
            cmd += ["--dport", str(rule.dst_port)]
        cmd += ["-j", "DROP" if rule.action == "block" else "ACCEPT"]

    elif backend == "nft":
        if not sys.platform.startswith("linux") or which("nft") is None:
            return False
        chain = "input" if rule.direction == "in" else ("output" if rule.direction == "out" else "input")
        cmd = ["nft", "add", "rule", "inet", "filter", chain]
        if rule.protocol:
            proto = rule.protocol.lower()
            if proto in ("tcp", "udp", "icmp"):
                cmd += [proto]
        if rule.src_ip:
            cmd += ["ip", "saddr", rule.src_ip]
        if rule.dst_ip:
            cmd += ["ip", "daddr", rule.dst_ip]
        if rule.src_port and rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
            cmd += ["sport", str(rule.src_port)]
        if rule.dst_port and rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
            cmd += ["dport", str(rule.dst_port)]
        cmd += ["counter"]
        cmd += ["drop" if rule.action == "block" else "accept"]
    else:
        return False

    try:
        log.debug("Applying backend rule: %s", " ".join(shlex.quote(x) for x in cmd),
                  extra={"rule_id": rule.id, "action": f"{backend}_apply"})
        subprocess.check_call(cmd)
        rule.backend_applied = True
        return True
    except Exception as e:
        log.error("Backend rule apply failed: %s", e,
                  extra={"rule_id": rule.id, "action": backend})
        return False


# ----------------- Notification Stub -----------------
def send_notification(subject: str, body: str):
    """
    Stub for notifications. Right now just logs.
    You can extend with SMTP or Telegram API.
    """
    log.info("NOTIFY: %s - %s", subject, body,
             extra={"rule_id": "-", "action": "notify"})


# ----------------- Packet Processor with Heuristics -----------------
class PacketProcessor:
    def __init__(self, engine: RuleEngine, backend: str = "none",
                 auto_rollback_seconds: Optional[int] = None,
                 queue_max=2000):
        self.engine = engine
        self.backend = backend
        self.q: queue.Queue = queue.Queue(maxsize=queue_max)
        self.running = False
        self.thread = threading.Thread(target=self._worker, daemon=True)

        # for PCAP capture
        self.recent_packets = deque(maxlen=200)

        # Auto-rollback
        self.auto_rollback_seconds = auto_rollback_seconds
        self.rollback_thread = threading.Thread(target=self._rollback_worker, daemon=True)

        # Heuristic / adaptive data
        self.syn_counts = {}       # ip -> [timestamps]
        self.portscan_ports = {}   # ip -> set(dst ports)

    def start(self):
        self.running = True
        self.thread.start()
        if self.auto_rollback_seconds:
            self.rollback_thread.start()
        log.info("Packet processor started", extra={"rule_id": "-", "action": "processor_start"})

    def stop(self):
        self.running = False
        log.info("Packet processor stopped", extra={"rule_id": "-", "action": "processor_stop"})

    def enqueue(self, pkt):
        try:
            self.recent_packets.append(pkt)
            self.q.put_nowait(pkt)
        except queue.Full:
            log.warning("Packet queue full, dropping packet",
                        extra={"rule_id": "-", "action": "drop_queue"})

    def _record_syn(self, info: Dict[str, Any]):
        if info.get("protocol") != "tcp":
            return
        flags = info.get("tcp_flags", [])
        if "SYN" in flags and "ACK" not in flags:
            src = info.get("src_ip")
            if not src:
                return
            now = time.time()
            arr = self.syn_counts.setdefault(src, [])
            arr.append(now)
            # trim old
            cutoff = now - SYN_WINDOW_SECONDS
            self.syn_counts[src] = [t for t in arr if t >= cutoff]

            # portscan detection
            dport = info.get("dst_port")
            if dport is not None:
                ports = self.portscan_ports.setdefault(src, set())
                ports.add(dport)

    def _check_heuristics(self):
        now = time.time()
        for ip, times in list(self.syn_counts.items()):
            if len(times) > SYN_FLOOD_THRESHOLD:
                send_notification("SYN flood suspected", f"Source IP: {ip}")
                # adaptive block
                self._adaptive_block_ip(ip, "syn_flood")

        for ip, ports in list(self.portscan_ports.items()):
            if len(ports) > PORTSCAN_PORTS_THRESHOLD:
                send_notification("Port scan suspected", f"Source IP: {ip}, ports: {len(ports)}")
                self._adaptive_block_ip(ip, "port_scan")

    def _adaptive_block_ip(self, ip: str, reason: str):
        rule_id = f"adapt_{reason}_{ip}"
        rule = Rule(
            id=rule_id,
            action="block",
            priority=5,
            src_ip=ip,
            direction="both",
            comment=f"adaptive_{reason}",
            ttl_seconds=ADAPTIVE_BLOCK_DURATION,
            capture_on_match=True,
        )
        self.engine.add_rule(rule)
        log.warning("Adaptive block created for %s (%s)", ip, reason,
                    extra={"rule_id": rule.id, "action": "adaptive_block"})

    def _apply_rule_backend_maybe(self, rule: Rule):
        if self.backend == "none" or rule.backend_applied:
            return
        if apply_backend_rule(rule, backend=self.backend) and self.auto_rollback_seconds:
            # Mark for auto rollback
            rule.auto_rollback = True
            rule.rollback_deadline = datetime.utcnow() + timedelta(seconds=self.auto_rollback_seconds)

    def _capture_pcap(self):
        try:
            if self.recent_packets:
                wrpcap(CAPTURE_PCAP, list(self.recent_packets), append=True)
                log.info("PCAP capture saved to %s", CAPTURE_PCAP,
                         extra={"rule_id": "-", "action": "pcap_capture"})
        except Exception as e:
            log.error("PCAP capture failed: %s", e,
                      extra={"rule_id": "-", "action": "pcap_error"})

    def _worker(self):
        while self.running:
            try:
                pkt = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                info = extract_packet_info(pkt)
                info["direction"] = detect_direction(info)

                # Heuristics
                self._record_syn(info)
                self._check_heuristics()

                rule = self.engine.evaluate(info)
                if rule:
                    msg = f"Rule {rule.id} ({rule.action}) matched pkt={info} count={rule.match_count}"
                    if rule.action == "block":
                        log.warning(msg, extra={"rule_id": rule.id, "action": "block"})
                        self._apply_rule_backend_maybe(rule)
                        if rule.capture_on_match:
                            self._capture_pcap()
                    else:
                        log.info(msg, extra={"rule_id": rule.id, "action": "allow"})
                else:
                    log.debug("No rule matched: %s", info,
                              extra={"rule_id": "-", "action": "none"})
            except Exception as e:
                log.error("Error processing packet: %s", e,
                          extra={"rule_id": "-", "action": "error"})

    def _rollback_worker(self):
        """Periodically check for rules that need auto-rollback backend removal (logging only)."""
        while self.running:
            time.sleep(2)
            now = datetime.utcnow()
            snapshot = self.engine.get_rules_snapshot()
            for r in snapshot:
                if r.auto_rollback and r.rollback_deadline and now > r.rollback_deadline:
                    log.warning(
                        "Auto-rollback window expired for rule %s (backend rules should be cleaned manually)",
                        r.id,
                        extra={"rule_id": r.id, "action": "auto_rollback"},
                    )
                    r.auto_rollback = False
                    r.rollback_deadline = None


# ----------------- Sniffing / Simulation -----------------
def start_sniffing(processor: PacketProcessor, iface: Optional[str], bpf_filter: Optional[str], count: int = 0):
    def _prn(pkt):
        processor.enqueue(pkt)
    log.info("Starting sniffing iface=%s filter=%s count=%s", iface, bpf_filter, count,
             extra={"rule_id": "-", "action": "sniff"})
    sniff(iface=iface, filter=bpf_filter, prn=_prn, store=False, count=count)


def run_simulation(processor: PacketProcessor, pcap_path: str):
    log.info("Simulation mode using PCAP: %s", pcap_path,
             extra={"rule_id": "-", "action": "simulate"})
    packets = rdpcap(pcap_path)
    processor.start()
    for pkt in packets:
        processor.enqueue(pkt)
    time.sleep(1)
    processor.stop()


# ----------------- Threat Feed Auto-Block -----------------
def apply_threat_feed(engine: RuleEngine, source: str):
    """
    Load IPs from a URL or file (simple one-IP-per-line format) and create block rules.
    Requires 'requests' if source is URL.
    """
    ips = []
    if source.startswith("http://") or source.startswith("https://"):
        try:
            import requests
            resp = requests.get(source, timeout=10)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "/" in line:
                    continue
                ips.append(line)
        except Exception as e:
            log.error("Threat feed download failed: %s", e,
                      extra={"rule_id": "-", "action": "threat_feed"})
            return
    else:
        if not os.path.exists(source):
            log.error("Threat feed file not found: %s", source,
                      extra={"rule_id": "-", "action": "threat_feed"})
            return
        with open(source, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "/" in line:
                    continue
                ips.append(line)
    for ip in ips:
        rid = f"threat_{ip}"
        rule = Rule(
            id=rid,
            action="block",
            priority=8,
            src_ip=ip,
            direction="both",
            comment="threat_feed_block",
            ttl_seconds=None,
        )
        engine.add_rule(rule)
    log.info("Threat feed: added %d IP block rules", len(ips),
             extra={"rule_id": "-", "action": "threat_feed"})


# ----------------- Tkinter GUI -----------------
if GUI_AVAILABLE:
    class FirewallGUI:
        def __init__(self, engine: RuleEngine, processor: PacketProcessor, rules_path: str):
            self.engine = engine
            self.processor = processor
            self.rules_path = rules_path
            self.root = tk.Tk()
            self.root.title("Python Personal Firewall (Advanced)")

            self._last_log_pos = 0

            self._build_ui()
            self._refresh_rules()
            self._update_logs_periodically()
            self._update_rules_periodically()

        def _build_ui(self):
            self.root.rowconfigure(0, weight=1)
            self.root.columnconfigure(0, weight=1)
            frame = ttk.Frame(self.root, padding=8)
            frame.grid(row=0, column=0, sticky="nsew")

            # Top buttons
            btn_frame = ttk.Frame(frame)
            btn_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
            ttk.Button(btn_frame, text="Start Processor", command=self._start_proc).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Stop Processor", command=self._stop_proc).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Save Rules", command=self._save_rules).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Add Rule", command=self._add_rule_dialog).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Remove Selected Rule", command=self._remove_selected_rule).pack(side="left", padx=4)
            ttk.Button(btn_frame, text="Help", command=self._show_help).pack(side="left", padx=4)

            # Rules list
            rules_frame = ttk.LabelFrame(frame, text="Rules")
            rules_frame.grid(row=1, column=0, sticky="nsew")
            frame.rowconfigure(1, weight=1)

            cols = ("id", "priority", "action", "matches", "ttl", "spec")
            self.tree = ttk.Treeview(rules_frame, columns=cols, show="headings", height=8)
            for c in cols:
                self.tree.heading(c, text=c.capitalize())
                self.tree.column(c, width=100 if c != "spec" else 400, anchor="w")
            self.tree.pack(fill="both", expand=True)

            # Logs
            logs_frame = ttk.LabelFrame(frame, text="Logs")
            logs_frame.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
            frame.rowconfigure(2, weight=1)
            self.log_text = scrolledtext.ScrolledText(logs_frame, height=10, state="disabled")
            self.log_text.pack(fill="both", expand=True)

        def _start_proc(self):
            if not self.processor.running:
                self.processor.start()
                messagebox.showinfo("Info", "Packet processor started.")

        def _stop_proc(self):
            if self.processor.running:
                self.processor.stop()
                messagebox.showinfo("Info", "Packet processor stopped.")

        def _save_rules(self):
            self.engine.save_to_file(self.rules_path)
            messagebox.showinfo("Rules", f"Rules saved to {self.rules_path}")

        def _refresh_rules(self):
            for i in self.tree.get_children():
                self.tree.delete(i)
            snapshot = self.engine.get_rules_snapshot()
            for r in sorted(snapshot, key=lambda rr: rr.priority):
                spec = (f"{r.protocol or 'ip'} {r.src_ip or '*'}:{r.src_port or '*'}"
                        f" -> {r.dst_ip or '*'}:{r.dst_port or '*'} {r.direction} "
                        f"ICMP:{r.icmp_type} FLAGS:{','.join(r.tcp_flags)} "
                        f"CAP:{r.capture_on_match}")
                ttl = r.ttl_seconds if r.ttl_seconds is not None else "-"
                self.tree.insert(
                    "",
                    "end",
                    iid=r.id,
                    values=(r.id, r.priority, r.action, r.match_count, ttl, spec),
                )

        def _update_rules_periodically(self):
            self._refresh_rules()
            self.root.after(1000, self._update_rules_periodically)

        def _update_logs_periodically(self):
            try:
                with open(LOGFILE, "r") as f:
                    f.seek(self._last_log_pos)
                    new = f.read()
                    if new:
                        self.log_text.configure(state="normal")
                        self.log_text.insert("end", new)
                        self.log_text.see("end")
                        self.log_text.configure(state="disabled")
                        self._last_log_pos = f.tell()
            except Exception:
                pass
            self.root.after(1000, self._update_logs_periodically)

        def _add_rule_dialog(self):
            rid = simpledialog.askstring("Rule ID", "Enter rule ID:")
            if not rid:
                return
            action = simpledialog.askstring("Action", "Action (allow/block):", initialvalue="block")
            priority = simpledialog.askinteger("Priority", "Priority (lower = higher priority):", initialvalue=100)
            src_ip = simpledialog.askstring("Source IP", "Source IP (blank=any):")
            dst_ip = simpledialog.askstring("Dest IP", "Destination IP (blank=any):")
            src_port = simpledialog.askinteger("Source port", "Source port (blank=any):")
            dst_port = simpledialog.askinteger("Dest port", "Dest port (blank=any):")
            protocol = simpledialog.askstring("Protocol", "Protocol (tcp/udp/icmp/ip):")
            direction = simpledialog.askstring("Direction", "Direction (in/out/both):", initialvalue="both")
            icmp_type = simpledialog.askinteger("ICMP Type", "ICMP Type (blank=any):")
            tcp_flags_str = simpledialog.askstring("TCP Flags", "TCP Flags (comma-separated, e.g. SYN,ACK):")
            ttl = simpledialog.askinteger("TTL (sec)", "TTL seconds (blank=permanent):")
            capture = messagebox.askyesno("Capture", "Capture PCAP on match?")

            tcp_flags = []
            if tcp_flags_str:
                tcp_flags = [f.strip().upper() for f in tcp_flags_str.split(",") if f.strip()]

            rule = Rule(
                id=rid,
                action=(action or "block").lower(),
                priority=priority or 100,
                src_ip=src_ip or None,
                dst_ip=dst_ip or None,
                src_port=src_port or None,
                dst_port=dst_port or None,
                protocol=(protocol or None),
                direction=(direction or "both").lower(),
                icmp_type=icmp_type if icmp_type is not None else None,
                tcp_flags=tcp_flags,
                comment="added_via_gui",
                ttl_seconds=ttl,
                capture_on_match=capture,
            )
            self.engine.add_rule(rule)
            self._refresh_rules()

        def _remove_selected_rule(self):
            sel = self.tree.selection()
            if not sel:
                return
            rid = sel[0]
            self.engine.remove_rule_by_id(rid)
            self._refresh_rules()

        def _show_help(self):
            # show a shorter version of FIREWALL_USAGE_TEXT in a separate window
            help_win = tk.Toplevel(self.root)
            help_win.title("Firewall Usage Help")
            txt = scrolledtext.ScrolledText(help_win, wrap="word", width=100, height=30)
            txt.pack(fill="both", expand=True)
            txt.insert("1.0", FIREWALL_USAGE_TEXT)
            txt.configure(state="disabled")

        def run(self):
            self.root.mainloop()


# ----------------- Flask REST API & Web Dashboard -----------------
def start_rest_api(engine: RuleEngine, host="127.0.0.1", port=8080):
    if not FLASK_AVAILABLE:
        log.error("Flask not available; REST API disabled",
                  extra={"rule_id": "-", "action": "api"})
        return
    app = Flask(__name__)

    @app.get("/rules")
    def api_rules():
        rules = [RuleEngine._rule_to_dict(r) for r in engine.get_rules_snapshot()]
        return jsonify(rules)

    @app.post("/rules")
    def api_add_rule():
        data = request.json or {}
        rid = data.get("id", f"api_{int(time.time())}")
        rule = Rule(
            id=rid,
            action=data.get("action", "block"),
            priority=int(data.get("priority", 100)),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            direction=data.get("direction", "both"),
            icmp_type=data.get("icmp_type"),
            tcp_flags=[f.upper() for f in (data.get("tcp_flags") or [])],
            ttl_seconds=data.get("ttl_seconds"),
            comment="added_via_api",
        )
        engine.add_rule(rule)
        return jsonify({"status": "ok", "id": rid})

    @app.delete("/rules/<rid>")
    def api_delete_rule(rid):
        engine.remove_rule_by_id(rid)
        return jsonify({"status": "deleted", "id": rid})

    @app.get("/")
    def index():
        # very minimal HTML dashboard
        return """
        <html>
        <head><title>Python Firewall</title></head>
        <body>
        <h1>Python Personal Firewall</h1>
        <p>Use <code>/rules</code> (GET/POST/DELETE) for API access.</p>
        </body>
        </html>
        """

    log.info("Starting REST API on %s:%s", host, port,
             extra={"rule_id": "-", "action": "api"})
    app.run(host=host, port=port, debug=False, use_reloader=False)


# ----------------- Self-test -----------------
def self_test():
    from scapy.all import IP, TCP
    rule = Rule(
        id="test",
        action="block",
        priority=10,
        protocol="tcp",
        dst_port=80,
        tcp_flags=["SYN"],
    )
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=12345, dport=80, flags="S")
    info = extract_packet_info(pkt)
    info["direction"] = "in"
    assert rule.matches_packet(info), "Rule should match SYN to port 80"
    pkt2 = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=12345, dport=80, flags="A")
    info2 = extract_packet_info(pkt2)
    info2["direction"] = "in"
    assert not rule.matches_packet(info2), "Rule should not match ACK"
    print("Self-test OK.")


# ----------------- CLI & main -----------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Advanced Python Personal Firewall (full version)",
        epilog=FIREWALL_USAGE_TEXT,
        formatter_class=RawDescriptionHelpFormatter,
    )

    p.add_argument("--rules", "-r", default=DEFAULT_RULES_FILE, help="Rules JSON file")
    p.add_argument("--iface", "-i", default=None, help="Interface to sniff on (default: all)")
    p.add_argument("--filter", "-f", default=None, help="BPF filter string (optional)")
    p.add_argument("--count", type=int, default=0, help="Number of packets to sniff (0=infinite)")

    p.add_argument(
        "--backend",
        choices=["none", "iptables", "nft"],
        default="none",
        help="Firewall backend (iptables/nft/none)",
    )
    p.add_argument(
        "--auto-rollback",
        type=int,
        default=None,
        help="Seconds for backend auto-rollback window (optional, logs only framework)",
    )

    p.add_argument("--gui", action="store_true", help="Start Tkinter GUI (if available)")
    p.add_argument("--no-gui", action="store_true", help="Force CLI mode")
    p.add_argument("--debug", action="store_true", help="Enable debug logging to console")
    p.add_argument("--simulate", metavar="PCAP", help="Simulation mode: read packets from PCAP")
    p.add_argument("--self-test", action="store_true", help="Run simple self-tests and exit")

    p.add_argument("--api", action="store_true", help="Start REST API + mini dashboard")
    p.add_argument("--api-host", default="127.0.0.1", help="REST API host")
    p.add_argument("--api-port", type=int, default=8080, help="REST API port")

    p.add_argument("--threat-feed", help="Threat-feed URL or file with IPs to auto-block")

    # Extended help
    p.add_argument(
        "--help-usage",
        action="store_true",
        help="Show extended usage examples and exit (firewall usage guide).",
    )

    return p.parse_args()


def main():
    args = parse_args()

    # If user only wants extended help, print it and exit
    if args.help_usage:
        print(FIREWALL_USAGE_TEXT)
        return

    if args.debug:
        _console_handler.setLevel(logging.DEBUG)

    if args.self_test:
        self_test()
        return

    log.info("Starting firewall rules=%s backend=%s", args.rules, args.backend,
             extra={"rule_id": "-", "action": "start"})

    engine = RuleEngine.load_from_file(args.rules)

    if args.threat_feed:
        apply_threat_feed(engine, args.threat_feed)

    processor = PacketProcessor(engine, backend=args.backend,
                                auto_rollback_seconds=args.auto_rollback)

    # REST API (in background thread)
    if args.api and FLASK_AVAILABLE:
        api_thread = threading.Thread(target=start_rest_api,
                                      args=(engine, args.api_host, args.api_port),
                                      daemon=True)
        api_thread.start()

    # Simulation mode
    if args.simulate:
        run_simulation(processor, args.simulate)
        engine.save_to_file(args.rules)
        return

    # Live mode
    processor.start()

    use_gui = args.gui and GUI_AVAILABLE and not args.no_gui
    if use_gui:
        gui = FirewallGUI(engine, processor, args.rules)
        sniff_thread = threading.Thread(
            target=start_sniffing,
            args=(processor, args.iface, args.filter, args.count),
            daemon=True,
        )
        sniff_thread.start()
        gui.run()
    else:
        try:
            start_sniffing(processor, args.iface, args.filter, args.count)
        except KeyboardInterrupt:
            log.info("KeyboardInterrupt, exiting",
                     extra={"rule_id": "-", "action": "interrupt"})
        finally:
            processor.stop()
            engine.save_to_file(args.rules)


if __name__ == "__main__":
    main()
