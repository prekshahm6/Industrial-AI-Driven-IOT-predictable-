#!/usr/bin/env python3
"""
PHANTOM SHIFT — Industrial IoT Telemetry Simulator
Team: SecureX | JSS Eclipse Hackathon 2025
Simulates 6 device types: PLC, SCADA, HMI, Sensor, Gateway, Robot
Injects 5 attack types at configurable probability
"""
import os, time, random, logging, requests
from datetime import datetime

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [SIMULATOR] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

API_URL       = os.getenv("API_URL", "http://api:8000")
EMIT_INTERVAL = float(os.getenv("EMIT_INTERVAL_SEC", "1.0"))
ATTACK_PROB   = float(os.getenv("ATTACK_PROBABILITY", "0.05"))

DEVICE_PROFILES = {
    "PLC":     {"ports":[102,502,44818],"protocols":["modbus","s7comm","ethernet_ip"],"subnet":"10.0.1.","packet":(64,256),  "interval":(10,50),  "count":3},
    "SCADA":   {"ports":[502,4840,443], "protocols":["modbus","opc_ua","http"],       "subnet":"10.0.2.","packet":(128,512), "interval":(50,200), "count":2},
    "HMI":     {"ports":[80,443,3389],  "protocols":["http","https","rdp"],           "subnet":"10.0.2.","packet":(256,1024),"interval":(100,500),"count":2},
    "Sensor":  {"ports":[1883,8883,5683],"protocols":["mqtt","coap"],                 "subnet":"10.0.3.","packet":(32,128),  "interval":(500,2000),"count":3},
    "Gateway": {"ports":[80,443,8883,22],"protocols":["http","mqtt","ssh"],           "subnet":"10.0.0.","packet":(512,2048),"interval":(20,100), "count":1},
    "Robot":   {"ports":[11311,502],    "protocols":["ros","modbus"],                 "subnet":"10.0.2.","packet":(128,512), "interval":(20,80),  "count":1},
}

ATTACK_TYPES = {
    "reconnaissance":    {"vol":2.0, "ext_ip":False,"bad_port":True, "bad_proto":False},
    "data_exfiltration": {"vol":5.0, "ext_ip":True, "bad_port":False,"bad_proto":False},
    "firmware_tamper":   {"vol":1.5, "ext_ip":True, "bad_port":True, "bad_proto":True},
    "lateral_movement":  {"vol":3.0, "ext_ip":False,"bad_port":True, "bad_proto":True},
    "dos_attack":        {"vol":10.0,"ext_ip":False,"bad_port":False,"bad_proto":False},
}
EXTERNAL_IPS = ["185.220.101.45","194.165.16.72","45.142.212.100","198.251.83.12"]


class Device:
    def __init__(self, did, dtype, idx):
        self.did, self.dtype = did, dtype
        p = DEVICE_PROFILES[dtype]
        self.ip         = f"{p['subnet']}{10+idx}"
        self.base_port  = random.choice(p["ports"])
        self.base_proto = random.choice(p["protocols"])
        self.base_pkt   = random.uniform(*p["packet"])
        self.base_ms    = random.uniform(*p["interval"])
        self.fingerprint = [
            round(self.base_pkt/2048, 4),
            round(self.base_ms/2000, 4),
            round(self.base_port/65535, 4),
            round(random.uniform(0.85, 0.99), 4),
            round(random.uniform(0.80, 0.99), 4),
            round(random.uniform(0.75, 0.99), 4),
            round(len(p["ports"])/10, 4),
            round(len(p["protocols"])/5, 4),
        ]
        self.attacking  = False
        self.atk_type   = None
        self.atk_ctr    = 0
        self.events     = 0
        self.peers      = []

    def tick(self):
        self.events += 1
        if not self.attacking and random.random() < ATTACK_PROB:
            self.attacking = True
            self.atk_type  = random.choice(list(ATTACK_TYPES.keys()))
            self.atk_ctr   = random.randint(15, 60)
            log.warning(f"ATTACK [{self.atk_type}] → {self.did}")
        if self.attacking:
            self.atk_ctr -= 1
            if self.atk_ctr <= 0:
                self.attacking = False
                self.atk_type  = None

        atk = ATTACK_TYPES.get(self.atk_type, {}) if self.attacking else {}
        p   = DEVICE_PROFILES[self.dtype]

        port  = random.randint(1024, 65535) if atk.get("bad_port")  else self.base_port
        proto = random.choice(["telnet","ftp","raw_tcp"]) if atk.get("bad_proto") else self.base_proto
        dst   = random.choice(EXTERNAL_IPS) if atk.get("ext_ip") else f"{p['subnet']}{random.randint(1,20)}"
        pkt   = max(32, int(self.base_pkt * atk.get("vol", 1.0) * random.uniform(0.8, 1.2)))
        ms    = max(1,  int(self.base_ms  * random.uniform(0.7, 1.3)))

        if dst not in self.peers:
            self.peers.append(dst)
        if len(self.peers) > 10:
            self.peers = self.peers[-10:]

        return {
            "device_id":   self.did,
            "device_type": self.dtype,
            "timestamp":   datetime.utcnow().isoformat(),
            "src_ip":      self.ip,
            "dst_ip":      dst,
            "port":        port,
            "protocol":    proto,
            "packet_size": pkt,
            "interval_ms": ms,
            "peer_list":   self.peers[-5:],
            "fingerprint": self.fingerprint,
            "is_attack":   self.attacking,
            "attack_type": self.atk_type,
            "event_count": self.events,
        }


def main():
    devices = []
    for dtype, prof in DEVICE_PROFILES.items():
        for i in range(prof["count"]):
            devices.append(Device(f"{dtype.upper()}_{i+1:02d}", dtype, i))
    log.info(f"{len(devices)} devices ready. Connecting to API at {API_URL}...")

    for _ in range(40):
        try:
            if requests.get(f"{API_URL}/health", timeout=2).status_code == 200:
                log.info("API ready — simulation starting!")
                break
        except Exception:
            pass
        time.sleep(3)

    while True:
        for d in devices:
            try:
                requests.post(f"{API_URL}/telemetry", json=d.tick(), timeout=2)
            except Exception:
                pass
        time.sleep(EMIT_INTERVAL)


if __name__ == "__main__":
    main()
