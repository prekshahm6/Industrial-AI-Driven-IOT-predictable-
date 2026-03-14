#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  PHANTOM SHIFT — Fleet Contagion Intelligence               ║
║  NetworkX directed graph of device communication edges      ║
║  BFS from drifting node → blast radius in hops             ║
║  Fleet conspiracy: correlated drift across 2+ devices       ║
║  Team: SecureX | JSS Eclipse Hackathon 2025                  ║
╚══════════════════════════════════════════════════════════════╝
"""
import logging, time
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional
import networkx as nx

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [FLEET-GRAPH] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

CONSPIRACY_WINDOW_SEC = 300   # 5 min window for fleet conspiracy detection
CONSPIRACY_MIN_DEVICES = 2    # min drifting devices for conspiracy alert
BLAST_MAX_HOPS = 4            # max BFS depth for blast radius


class FleetContagionEngine:
    """
    Maintains a directed communication graph of all IoT devices.
    Calculates blast radius when a device is compromised.
    Detects fleet-level conspiracy (coordinated drift).
    """

    def __init__(self):
        self.graph: nx.DiGraph = nx.DiGraph()
        self._device_types: Dict[str, str] = {}
        self._device_scores: Dict[str, float] = {}
        self._recent_alerts: deque = deque()  # (timestamp, device_id, score)
        self._peer_map: Dict[str, Set[str]] = defaultdict(set)
        log.info("Fleet Contagion Engine initialized")

    def update_device(self, device_id: str, device_type: str,
                      trust_score: float, event: dict):
        """Update graph with latest device state and connections."""
        self._device_types[device_id] = device_type
        self._device_scores[device_id] = trust_score

        # Add node with attributes
        self.graph.add_node(device_id,
                            device_type=device_type,
                            trust_score=trust_score,
                            last_seen=time.time())

        # Add communication edges from peer list
        peers = event.get("peer_list", [])
        dst_ip = event.get("dst_ip", "")

        # Find device IDs for peer IPs (match by subnet prefix)
        for peer_ip in peers:
            peer_id = self._ip_to_device(peer_ip)
            if peer_id and peer_id != device_id:
                self._peer_map[device_id].add(peer_id)
                self.graph.add_edge(device_id, peer_id,
                                    weight=1,
                                    last_seen=time.time())

        # Track alerts for conspiracy detection
        if trust_score < 50:
            self._recent_alerts.append((time.time(), device_id, trust_score))
        self._evict_old_alerts()

    def _ip_to_device(self, ip: str) -> Optional[str]:
        """Approximate: match IP prefix to known device subnets."""
        subnet_map = {
            "10.0.1": "plc", "10.0.2": "scada", "10.0.3": "hmi",
            "10.0.4": "sensor", "10.0.5": "gateway", "10.0.6": "robot",
        }
        prefix = ".".join(ip.split(".")[:3])
        dtype  = subnet_map.get(prefix)
        if dtype:
            # Return a plausible device ID
            return f"{dtype}-01"
        return None

    def _evict_old_alerts(self):
        cutoff = time.time() - CONSPIRACY_WINDOW_SEC
        while self._recent_alerts and self._recent_alerts[0][0] < cutoff:
            self._recent_alerts.popleft()

    def blast_radius(self, compromised_device: str) -> dict:
        """
        BFS from compromised_device up to BLAST_MAX_HOPS.
        Returns affected devices with hop distance and risk level.
        """
        if compromised_device not in self.graph:
            return {"source": compromised_device, "affected": [], "total_at_risk": 0}

        visited: Dict[str, int] = {}  # device_id → hop distance
        queue   = deque([(compromised_device, 0)])

        while queue:
            node, hop = queue.popleft()
            if node in visited or hop > BLAST_MAX_HOPS:
                continue
            visited[node] = hop

            for neighbor in self.graph.successors(node):
                if neighbor not in visited:
                    queue.append((neighbor, hop + 1))

        # Build affected list (exclude source)
        affected = []
        for dev_id, hop in sorted(visited.items(), key=lambda x: x[1]):
            if dev_id == compromised_device:
                continue
            score = self._device_scores.get(dev_id, 100)
            risk  = self._hop_risk(hop, score)
            affected.append({
                "device_id":   dev_id,
                "device_type": self._device_types.get(dev_id, "unknown"),
                "hop_distance": hop,
                "current_score": score,
                "infection_risk": risk,
                "risk_label":   "HIGH" if risk > 0.6 else "MEDIUM" if risk > 0.3 else "LOW",
            })

        return {
            "source":        compromised_device,
            "source_score":  self._device_scores.get(compromised_device, 0),
            "affected":      affected,
            "total_at_risk": len(affected),
            "max_hops":      max((a["hop_distance"] for a in affected), default=0),
        }

    def _hop_risk(self, hop: int, current_score: float) -> float:
        """Risk decreases with hop distance, increases if target already weak."""
        base_risk = max(0, 1.0 - (hop * 0.25))
        weakness  = max(0, (100 - current_score) / 100)
        return round(min(1.0, base_risk * (1 + weakness * 0.3)), 3)

    def detect_conspiracy(self) -> Optional[dict]:
        """
        Fleet conspiracy: 2+ devices drifting in the same time window.
        Even if each individual score looks borderline, combined = fleet alert.
        """
        alerts = list(self._recent_alerts)
        if len(set(a[1] for a in alerts)) < CONSPIRACY_MIN_DEVICES:
            return None

        # Group by 60-second buckets
        buckets: Dict[int, List] = defaultdict(list)
        for ts, did, score in alerts:
            bucket = int(ts // 60)
            buckets[bucket].append((did, score))

        # Find buckets with 2+ unique devices
        for bucket, devs in buckets.items():
            unique_devs = list({d[0]: d for d in devs}.values())
            if len(unique_devs) >= CONSPIRACY_MIN_DEVICES:
                avg_score = sum(d[1] for d in unique_devs) / len(unique_devs)
                return {
                    "conspiracy_detected": True,
                    "involved_devices":    [d[0] for d in unique_devs],
                    "device_count":        len(unique_devs),
                    "avg_trust_score":     round(avg_score, 2),
                    "time_window_sec":     CONSPIRACY_WINDOW_SEC,
                    "severity":            "FLEET_CRITICAL" if avg_score < 30 else "FLEET_ALERT",
                    "message":             (
                        f"⚠ FLEET CONSPIRACY: {len(unique_devs)} devices drifting "
                        f"simultaneously (avg score: {avg_score:.0f}). "
                        f"Possible coordinated attack."
                    ),
                }
        return None

    def get_graph_data(self) -> dict:
        """Serialise graph for React dashboard visualisation."""
        nodes = []
        for node in self.graph.nodes(data=True):
            did, attrs = node
            score = self._device_scores.get(did, 100)
            nodes.append({
                "id":          did,
                "device_type": self._device_types.get(did, "unknown"),
                "trust_score": score,
                "color":       self._score_to_color(score),
                "size":        20 + (100 - score) * 0.3,
            })

        edges = []
        for src, dst, data in self.graph.edges(data=True):
            edges.append({
                "source": src,
                "target": dst,
                "age":    int(time.time() - data.get("last_seen", time.time())),
            })

        conspiracy = self.detect_conspiracy()
        return {
            "nodes":      nodes,
            "edges":      edges,
            "conspiracy": conspiracy,
            "total_devices": len(nodes),
            "at_risk":    sum(1 for n in nodes if n["trust_score"] < 50),
        }

    def _score_to_color(self, score: float) -> str:
        if score <= 19:  return "#ef4444"   # red
        if score <= 49:  return "#f97316"   # orange
        if score <= 79:  return "#eab308"   # yellow
        return "#22c55e"                    # green
