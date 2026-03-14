#!/usr/bin/env python3
"""
PHANTOM SHIFT — Real Laptop Agent
Team: SecureX | JSS Eclipse Hackathon 2025

Run this on each teammate's laptop.
It reads REAL system metrics and sends them to the server.
Press Ctrl+C then type 'attack' to manually trigger an attack simulation.

Usage:
    python agent.py --server http://192.168.x.x:8000 --name Preksha --type HMI
"""
import os, sys, time, socket, random, argparse, logging, threading
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [AGENT] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Try to import psutil (real metrics) ──────────────────
try:
    import psutil
    HAS_PSUTIL = True
    log.info("✅ psutil found — using REAL system metrics")
except ImportError:
    HAS_PSUTIL = False
    log.warning("⚠ psutil not found — using simulated metrics. Run: pip install psutil")

# ── Attack mode (toggled by keyboard input thread) ───────
ATTACK_MODE   = False
ATTACK_TYPE   = None
ATTACK_TICKS  = 0

ATTACK_PROFILES = {
    "port_scan": {
        "description": "Scanning ports 1-1024 rapidly",
        "port_range":  (1, 1024),
        "interval_ms": 5,         # very fast
        "volume_mul":  2.0,
        "ext_ip":      False,
        "protocol":    "tcp",
        "cpu_boost":   20,
        "duration":    30,
    },
    "data_exfil": {
        "description": "Sending large data to external IP",
        "port_range":  (443, 443),
        "interval_ms": 200,
        "volume_mul":  15.0,       # huge volume spike
        "ext_ip":      True,
        "protocol":    "https",
        "cpu_boost":   30,
        "duration":    40,
    },
    "lateral_move": {
        "description": "Spreading to internal devices via SMB",
        "port_range":  (445, 445),
        "interval_ms": 50,
        "volume_mul":  3.0,
        "ext_ip":      False,
        "protocol":    "smb",
        "cpu_boost":   15,
        "duration":    35,
    },
    "c2_beacon": {
        "description": "Beaconing to C2 server every 30s",
        "port_range":  (4444, 4444),
        "interval_ms": 30000,      # exactly 30 seconds — very suspicious
        "volume_mul":  0.5,
        "ext_ip":      True,
        "protocol":    "raw_tcp",
        "cpu_boost":   5,
        "duration":    60,
    },
    "firmware_tamper": {
        "description": "Firmware hash changed — device identity compromised",
        "port_range":  (8080, 8080),
        "interval_ms": 100,
        "volume_mul":  1.5,
        "ext_ip":      True,
        "protocol":    "http",
        "cpu_boost":   40,
        "duration":    45,
        "tamper_fw":   True,
    },
}

EXTERNAL_IPS = [
    "185.220.101.45",   # known Tor exit node
    "194.165.16.72",    # known C2 IP
    "45.142.212.100",   # suspicious ASN
    "198.251.83.12",
]


class LaptopAgent:
    def __init__(self, server_url, device_name, device_type, emit_interval):
        self.server      = server_url.rstrip("/")
        self.name        = device_name
        self.dtype       = device_type.upper()
        self.interval    = emit_interval
        self.my_ip       = self._get_my_ip()
        self.session     = requests.Session()
        self.events      = 0
        self.fw_hash     = f"fw_{self.name}_{random.randint(1000,9999)}"
        self.fw_original = self.fw_hash
        self.peer_list   = []

        # Build onboarding fingerprint from baseline system state
        self.baseline_cpu = self._read_cpu()
        self.baseline_mem = self._read_mem()
        log.info(f"Agent ready: {self.name} ({self.dtype}) @ {self.my_ip}")
        log.info(f"Server: {self.server}")
        log.info(f"Baseline — CPU: {self.baseline_cpu:.1f}%  MEM: {self.baseline_mem:.1f}%")

    def _get_my_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _read_cpu(self):
        if HAS_PSUTIL:
            return psutil.cpu_percent(interval=0.1)
        return random.uniform(5, 25)

    def _read_mem(self):
        if HAS_PSUTIL:
            return psutil.virtual_memory().percent
        return random.uniform(30, 60)

    def _read_net(self):
        """Get real network connections count and bytes sent."""
        if not HAS_PSUTIL:
            return 10, 1024
        try:
            conns = len(psutil.net_connections())
            stats = psutil.net_io_counters()
            return conns, stats.bytes_sent
        except Exception:
            return 10, 1024

    def _normal_payload(self):
        """Build a normal (healthy) telemetry payload from real metrics."""
        cpu  = self._read_cpu()
        mem  = self._read_mem()
        conns, bytes_sent = self._read_net()

        # Normal traffic pattern for this device type
        normal_ports = {
            "HMI":     [80, 443, 3389],
            "SENSOR":  [1883, 8883],
            "GATEWAY": [80, 443, 22, 8883],
            "PLC":     [102, 502],
            "SCADA":   [502, 4840, 443],
            "ROBOT":   [11311, 502],
        }
        port  = random.choice(normal_ports.get(self.dtype, [443, 80]))
        proto = "https" if port == 443 else "http" if port == 80 else "tcp"

        # Internal peer devices (other laptops on the network)
        if self.peer_list:
            dst = random.choice(self.peer_list) if random.random() > 0.3 else self.my_ip
        else:
            dst = f"192.168.1.{random.randint(1,20)}"

        return {
            "device_id":    self.name,
            "device_type":  self.dtype,
            "timestamp":    datetime.utcnow().isoformat(),
            "src_ip":       self.my_ip,
            "dst_ip":       dst,
            "port":         port,
            "protocol":     proto,
            "packet_size":  random.randint(128, 512),
            "interval_ms":  random.randint(80, 200),
            "volume_mb":    round(bytes_sent / 1e6 * 0.001 + random.uniform(0, 0.001), 6),
            "cpu_usage":    round(cpu, 2),
            "mem_usage":    round(mem, 2),
            "peer_list":    self.peer_list[-5:],
            "firmware_hash":self.fw_hash,
            "uptime_sec":   self.events * int(self.interval),
            "attack_type":  None,
        }

    def _attack_payload(self, atk_name, profile):
        """Overlay attack characteristics on top of real metrics."""
        base = self._normal_payload()
        cpu  = self._read_cpu()
        mem  = self._read_mem()

        port_lo, port_hi = profile["port_range"]
        port = random.randint(port_lo, port_hi)

        dst = random.choice(EXTERNAL_IPS) if profile["ext_ip"] \
              else f"192.168.1.{random.randint(1,254)}"

        # Firmware tamper — change the hash
        if profile.get("tamper_fw") and self.fw_hash == self.fw_original:
            self.fw_hash = f"TAMPERED_{random.randint(10000,99999)}"
            log.warning(f"🔐 Firmware hash changed! {self.fw_original} → {self.fw_hash}")

        base.update({
            "dst_ip":       dst,
            "port":         port,
            "protocol":     profile["protocol"],
            "packet_size":  random.randint(512, 4096),
            "interval_ms":  profile["interval_ms"],
            "volume_mb":    round(base["volume_mb"] * profile["volume_mul"], 6),
            "cpu_usage":    round(min(100, cpu + profile["cpu_boost"] + random.uniform(0,10)), 2),
            "mem_usage":    round(min(100, mem + random.uniform(0, 8)), 2),
            "firmware_hash":self.fw_hash,
            "attack_type":  atk_name,
        })
        return base

    def add_peer(self, ip):
        if ip not in self.peer_list:
            self.peer_list.append(ip)
            log.info(f"Added peer: {ip}")

    def run(self):
        global ATTACK_MODE, ATTACK_TYPE, ATTACK_TICKS

        # Wait for server
        log.info("Waiting for server...")
        for _ in range(30):
            try:
                r = self.session.get(f"{self.server}/health", timeout=3)
                if r.status_code == 200:
                    log.info(f"✅ Server reachable! Starting telemetry stream...")
                    break
            except Exception:
                pass
            time.sleep(2)

        log.info("─" * 50)
        log.info("RUNNING — Press Enter, then type attack name to trigger:")
        log.info("  port_scan | data_exfil | lateral_move | c2_beacon | firmware_tamper")
        log.info("  or 'stop' to end attack | 'quit' to exit")
        log.info("─" * 50)

        while True:
            self.events += 1

            # Build payload
            if ATTACK_MODE and ATTACK_TYPE in ATTACK_PROFILES:
                profile = ATTACK_PROFILES[ATTACK_TYPE]
                payload = self._attack_payload(ATTACK_TYPE, profile)
                ATTACK_TICKS -= 1
                if ATTACK_TICKS <= 0:
                    log.info(f"✅ Attack [{ATTACK_TYPE}] ended naturally")
                    ATTACK_MODE  = False
                    ATTACK_TYPE  = None
                    self.fw_hash = self.fw_original  # restore firmware
            else:
                payload = self._normal_payload()
                ATTACK_MODE = False

            # Send to server
            try:
                resp = self.session.post(
                    f"{self.server}/telemetry",
                    json=payload, timeout=3
                )
                score = resp.json().get("score", "?") if resp.status_code == 200 else "ERR"
                status = "🔴 ATTACK" if payload["attack_type"] else "🟢 normal"
                log.info(f"[{self.name}] {status} | score={score} | "
                         f"cpu={payload['cpu_usage']}% mem={payload['mem_usage']}%")
            except Exception as e:
                log.warning(f"Send failed: {e}")

            time.sleep(self.interval)


def input_thread(agent):
    """Runs in background — listens for attack commands."""
    global ATTACK_MODE, ATTACK_TYPE, ATTACK_TICKS
    while True:
        try:
            cmd = input().strip().lower()
            if cmd in ATTACK_PROFILES:
                profile = ATTACK_PROFILES[cmd]
                ATTACK_TYPE  = cmd
                ATTACK_MODE  = True
                ATTACK_TICKS = profile["duration"]
                print(f"\n🔴 ATTACK STARTED: {cmd}")
                print(f"   {profile['description']}")
                print(f"   Duration: ~{profile['duration']} seconds\n")
            elif cmd == "stop":
                ATTACK_MODE = False
                ATTACK_TYPE = None
                agent.fw_hash = agent.fw_original
                print("\n✅ Attack stopped — back to normal\n")
            elif cmd == "status":
                print(f"\nAttacking: {ATTACK_MODE} | Type: {ATTACK_TYPE} | Ticks left: {ATTACK_TICKS}\n")
            elif cmd in ("quit", "exit"):
                print("Exiting...")
                os._exit(0)
            elif cmd.startswith("peer "):
                ip = cmd.split(" ")[1]
                agent.add_peer(ip)
            else:
                print(f"Unknown: '{cmd}'. Options: port_scan, data_exfil, lateral_move, c2_beacon, firmware_tamper, stop, status, peer <ip>")
        except (EOFError, KeyboardInterrupt):
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PHANTOM SHIFT — Laptop IoT Agent")
    parser.add_argument("--server",   default="http://localhost:8000",
                        help="Server URL e.g. http://192.168.1.100:8000")
    parser.add_argument("--name",     default=f"LAPTOP_{socket.gethostname()[:8].upper()}",
                        help="Device name e.g. Preksha_Laptop")
    parser.add_argument("--type",     default="HMI",
                        choices=["HMI","SENSOR","GATEWAY","PLC","SCADA","ROBOT"],
                        help="Device type")
    parser.add_argument("--interval", default=2.0, type=float,
                        help="Seconds between events (default: 2)")
    parser.add_argument("--peers",    default="",
                        help="Comma-separated peer IPs e.g. 192.168.1.5,192.168.1.6")
    args = parser.parse_args()

    agent = LaptopAgent(args.server, args.name, args.type, args.interval)

    # Add peers from command line
    if args.peers:
        for ip in args.peers.split(","):
            agent.add_peer(ip.strip())

    # Start keyboard input thread
    t = threading.Thread(target=input_thread, args=(agent,), daemon=True)
    t.start()

    agent.run()
