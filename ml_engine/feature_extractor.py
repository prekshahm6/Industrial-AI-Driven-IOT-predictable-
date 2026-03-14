#!/usr/bin/env python3
"""Feature Extractor — 12 behavioural features per device per 5-min window."""
import math, time
from collections import defaultdict, deque
from typing import Dict, List

FEATURE_NAMES = [
    "ip_diversity","port_entropy","protocol_entropy",
    "interval_mean","interval_std","volume_trend",
    "packet_size_mean","port_anomaly_score","external_ip_ratio",
    "cpu_mean","mem_mean","peer_diversity",
]

BASELINE_PORTS = {
    "PLC":{"102","502","44818"}, "SCADA":{"4840","102","443"},
    "HMI":{"80","443","3389"},   "SENSOR":{"1883","8883","5683"},
    "GATEWAY":{"80","443","22","8080"}, "ROBOT":{"9090","11311","102"},
}
INTERNAL = ("10.","192.168.","172.16.","172.17.","172.18.","172.19.",
            "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
            "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.")

def _entropy(counts):
    total = sum(counts.values())
    if not total: return 0.0
    return -sum((v/total)*math.log2(v/total+1e-10) for v in counts.values())

def _is_external(ip): return not ip.startswith(INTERNAL)


class DeviceWindow:
    def __init__(self, did, dtype, window=300):
        self.did, self.dtype, self.window = did, dtype, window
        self.events: deque = deque()
        self._vol_hist: deque = deque(maxlen=12)
        self._baseline_vol = 0.0

    def add(self, ev):
        self.events.append({**ev, "_ts": time.time()})
        self._evict()

    def _evict(self):
        cutoff = time.time() - self.window
        while self.events and self.events[0]["_ts"] < cutoff:
            self.events.popleft()

    def extract(self) -> List[float]:
        if not self.events: return [0.0]*12
        evs = list(self.events); n = len(evs)

        ip_div   = len(set(e["dst_ip"] for e in evs)) / max(n,1)
        pc = defaultdict(int)
        for e in evs: pc[e["dst_port"]] += 1
        port_ent = _entropy(pc)
        protoC = defaultdict(int)
        for e in evs: protoC[e.get("protocol","tcp")] += 1
        proto_ent = _entropy(protoC)

        ivs = [e["interval_ms"] for e in evs if "interval_ms" in e]
        iv_mean = sum(ivs)/len(ivs) if ivs else 0.0
        iv_std  = math.sqrt(sum((x-iv_mean)**2 for x in ivs)/len(ivs)) if ivs else 0.0

        cur_vol = sum(e.get("volume_mb",0) for e in evs)
        vol_trend = (cur_vol-self._baseline_vol)/(self._baseline_vol+1e-6) if self._baseline_vol else 0.0
        self._vol_hist.append(cur_vol)
        self._baseline_vol = sum(self._vol_hist)/len(self._vol_hist)

        sz_mean   = sum(e.get("packet_size",0) for e in evs) / n
        base_ports= BASELINE_PORTS.get(self.dtype, set())
        port_anom = sum(1 for e in evs if str(e["dst_port"]) not in base_ports)/n if base_ports else 0.0
        ext_ratio = sum(1 for e in evs if _is_external(e.get("dst_ip","10.0.0.1")))/n

        cpu_mean  = sum(e.get("cpu_usage",0) for e in evs)/n
        mem_mean  = sum(e.get("mem_usage",0) for e in evs)/n

        peers = set()
        for e in evs: peers.update(e.get("peer_list",[]))
        peer_div  = len(peers)/max(5,1)

        return [round(x,4) for x in [
            ip_div, port_ent, proto_ent, iv_mean, iv_std,
            vol_trend, sz_mean, port_anom, ext_ratio,
            cpu_mean, mem_mean, peer_div
        ]]


class FeatureExtractorEngine:
    def __init__(self): self._wins: Dict[str, DeviceWindow] = {}
    def process(self, ev: dict) -> dict:
        did, dtype = ev["device_id"], ev.get("device_type","SENSOR")
        if did not in self._wins: self._wins[did] = DeviceWindow(did, dtype)
        self._wins[did].add(ev)
        return {
            "device_id":    did, "device_type": dtype,
            "timestamp":    ev["timestamp"],
            "features":     self._wins[did].extract(),
            "feature_names":FEATURE_NAMES,
            "firmware_hash":ev.get("firmware_hash",""),
            "attack_type":  ev.get("attack_type"),
        }
