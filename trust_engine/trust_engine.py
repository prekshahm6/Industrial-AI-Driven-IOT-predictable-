#!/usr/bin/env python3
"""
PHANTOM SHIFT — Dual Trust Engine
Security Trust  = 0.4×Behavioral + 0.35×Policy + 0.25×Historical
Identity Conf   = cosine_similarity(current, onboarding_fingerprint)
Severity: 80-100=GREEN, 50-79=YELLOW, 20-49=ORANGE, 0-19=RED
Team: SecureX | JSS Eclipse Hackathon 2025
"""
import math, time, logging
from collections import deque
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [TRUST] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

BEHAVIORAL_W = 0.40
POLICY_W     = 0.35
HISTORY_W    = 0.25

SEVERITY_BANDS = [(80,100,"GREEN","Safe"),(50,79,"YELLOW","Watch"),(20,49,"ORANGE","Alert"),(0,19,"RED","Critical")]

HARD_POLICY = {
    "PLC":     {"banned_ports":{23,21,3389,4444}, "banned_proto":{"http","ftp","telnet"}, "max_ext":0.05},
    "SCADA":   {"banned_ports":{23,21,4444},       "banned_proto":{"ftp","telnet"},        "max_ext":0.10},
    "HMI":     {"banned_ports":{23,21,4444},       "banned_proto":{"ftp","telnet"},        "max_ext":0.20},
    "SENSOR":  {"banned_ports":{23,21,80,443,22},  "banned_proto":{"http","https","ssh"},  "max_ext":0.02},
    "GATEWAY": {"banned_ports":{23,21,4444},       "banned_proto":{"telnet"},              "max_ext":0.50},
    "ROBOT":   {"banned_ports":{23,21,4444,3389},  "banned_proto":{"ftp","telnet","rdp"},  "max_ext":0.05},
}


def severity(score: float) -> Tuple[str, str]:
    for lo, hi, color, label in SEVERITY_BANDS:
        if lo <= score <= hi:
            return color, label
    return "RED", "Critical"


def cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b): return 1.0
    dot = sum(x*y for x,y in zip(a,b))
    na  = math.sqrt(sum(x**2 for x in a))
    nb  = math.sqrt(sum(x**2 for x in b))
    if na==0 or nb==0: return 1.0
    return max(0.0, min(1.0, dot/(na*nb)))


class DeviceTrustState:
    def __init__(self, did: str, dtype: str):
        self.did, self.dtype = did, dtype
        self.score_history: deque = deque(maxlen=1440)
        self.fingerprint: Optional[List[float]] = None
        self.baseline: List[deque] = [deque(maxlen=288) for _ in range(12)]
        self.consecutive_alerts = 0
        self.last_score = 100.0
        # Enhancement 4 — Multi-factor Identity Verification
        # Combines: firmware hash + MAC address + certificate fingerprint + vendor signature
        self.identity_factors = {
            "firmware_hash":  None,   # SHA256 of device firmware image
            "mac_address":    None,   # Hardware MAC (spoofable but adds layer)
            "cert_fingerprint": None, # TLS client cert SHA1 fingerprint
            "vendor_signature": None, # Vendor-specific device model string
        }
        self.identity_factor_count = 0  # how many factors are enrolled
        self.identity_violations: List[str] = []  # which factors changed

    def lock_fingerprint(self, features):
        if self.fingerprint is None:
            self.fingerprint = features.copy()

    def update_baseline(self, features):
        for i, v in enumerate(features):
            if i < len(self.baseline):
                self.baseline[i].append(v)

    def baseline_stats(self, i) -> Tuple[float, float]:
        vals = list(self.baseline[i])
        if len(vals) < 5: return 0.0, 1.0
        mean = sum(vals)/len(vals)
        std  = math.sqrt(sum((v-mean)**2 for v in vals)/len(vals)) + 1e-6
        return mean, std


class DualTrustEngine:
    def __init__(self):
        self._states: Dict[str, DeviceTrustState] = {}

    def _get(self, did, dtype) -> DeviceTrustState:
        if did not in self._states:
            self._states[did] = DeviceTrustState(did, dtype)
        return self._states[did]

    def _behavioral(self, state, features, anomaly_score) -> float:
        state.update_baseline(features)
        drift = sum(1 for i,v in enumerate(features)
                    if abs(v - state.baseline_stats(i)[0]) / state.baseline_stats(i)[1] > 2.0)
        return max(0, 100 - drift/len(features)*40 - anomaly_score*50)

    def _policy(self, state, event, features) -> Tuple[float, List[str]]:
        p = HARD_POLICY.get(state.dtype, {})
        vio = []
        if event.get("dst_port",0) in p.get("banned_ports", set()):
            vio.append(f"BANNED_PORT:{event['dst_port']}")
        if event.get("protocol","").lower() in p.get("banned_proto", set()):
            vio.append(f"BANNED_PROTOCOL:{event.get('protocol')}")
        ext = features[8] if len(features) > 8 else 0
        if ext > p.get("max_ext", 1.0):
            vio.append(f"EXCESS_EXTERNAL:{ext:.2f}")
        if event.get("attack_type"):
            vio.append(f"KNOWN_ATTACK:{event['attack_type']}")
        penalty = min(len(vio)*25, 90)
        return max(0, 100-penalty), vio

    def _historical(self, state) -> float:
        if len(state.score_history) < 3: return 100.0
        recent = list(state.score_history)[-10:]
        trend  = recent[-1] - recent[0]
        if trend < -20: return max(0, 100+trend)
        if all(s < 50 for s in recent): return max(0, recent[-1]-10)
        return min(100, sum(recent)/len(recent))

    def _identity(self, state, features, fw_changes) -> float:
        """Enhancement 4 — Multi-factor Identity Verification.
        
        Checks 4 independent identity factors:
          1. Behavioural fingerprint (cosine similarity vs onboarding)
          2. Firmware hash            (changed = possible tamper)
          3. MAC address              (changed = possible device swap)
          4. Certificate fingerprint  (changed = possible MITM)
          5. Vendor signature         (changed = possible spoofing)
        
        Each factor contributes 20 points. Penalty applied per changed factor.
        This catches: firmware tamper, device substitution, MITM, spoofing.
        """
        if state.fingerprint is None:
            state.lock_fingerprint(features)
            return 100.0
        sim = cosine_similarity(features, state.fingerprint)
        base = sim * 100
        # Each firmware change costs 20 points (max 60 penalty from firmware alone)
        fw_penalty = min(fw_changes * 20, 60)
        # Multi-factor penalty: each changed identity factor costs 15 more points
        mf_penalty = len(state.identity_violations) * 15
        return max(0, base - fw_penalty - mf_penalty)

    def _check_identity_factors(self, state: DeviceTrustState, event: dict):
        """Enrol identity factors on first seen; detect changes on subsequent events."""
        state.identity_violations = []
        factors = {
            "firmware_hash":    event.get("firmware_hash", ""),
            "mac_address":      event.get("mac_address", ""),
            "cert_fingerprint": event.get("cert_fingerprint", ""),
            "vendor_signature": event.get("vendor_signature", ""),
        }
        for k, v in factors.items():
            if not v:
                continue  # factor not supplied — skip
            if state.identity_factors[k] is None:
                state.identity_factors[k] = v
                state.identity_factor_count += 1
            elif state.identity_factors[k] != v:
                state.identity_violations.append(k.upper().replace("_", " ") + " CHANGED")

    def score(self, ml_result: dict, event: dict) -> dict:
        did      = ml_result["device_id"]
        dtype    = ml_result["device_type"]
        features = ml_result["features"]
        state    = self._get(did, dtype)

        behavioral          = self._behavioral(state, features, ml_result["anomaly_score"])
        policy_score, vio   = self._policy(state, event, features)
        historical          = self._historical(state)
        self._check_identity_factors(state, event)  # Enhancement 4: multi-factor identity

        security_trust = round(max(0, min(100,
            BEHAVIORAL_W*behavioral + POLICY_W*policy_score + HISTORY_W*historical)), 2)

        identity_conf = round(self._identity(state, features, ml_result.get("firmware_changes",0)), 2)

        if security_trust < 50: state.consecutive_alerts += 1
        else: state.consecutive_alerts = max(0, state.consecutive_alerts-1)

        state.score_history.append(security_trust)
        state.last_score = security_trust

        sec_color, sec_label = severity(security_trust)
        id_color,  id_label  = severity(identity_conf)
        combined = round(min(security_trust, identity_conf), 2)
        comb_color, comb_label = severity(combined)

        alert_card = self._alert_card(did, dtype, security_trust, identity_conf, vio,
                                      ml_result["shap"], ml_result.get("pre_alert_level"),
                                      ml_result.get("predicted_score"), ml_result.get("lstm_confidence"))
        return {
            "device_id":          did,
            "device_type":        dtype,
            "timestamp":          ml_result["timestamp"],
            "security_trust":     security_trust,
            "identity_confidence":identity_conf,
            "combined_score":     combined,
            "behavioral_score":   round(behavioral,2),
            "policy_score":       round(policy_score,2),
            "historical_score":   round(historical,2),
            "severity_color":     comb_color,
            "severity_label":     comb_label,
            "sec_color":          sec_color,
            "id_color":           id_color,
            "policy_violations":  vio,
            "identity_violations": state.identity_violations,  # Enhancement 4
            "identity_factors_enrolled": state.identity_factor_count,  # Enhancement 4
            "predicted_score":    ml_result.get("predicted_score", security_trust),
            "lstm_confidence":    ml_result.get("lstm_confidence", 0),
            "pre_alert":          ml_result.get("pre_alert", False),
            "pre_alert_level":    ml_result.get("pre_alert_level"),
            "shap":               ml_result["shap"],
            "alert_card":         alert_card,
            "consecutive_alerts": state.consecutive_alerts,
            "anomaly_score":      ml_result["anomaly_score"],
        }

    def _alert_card(self, did, dtype, sec, idc, vio, shap,
                    pre_level, predicted, confidence) -> dict:
        lines = []
        if sec < 20:   lines.append(f"⛔ CRITICAL: {did} ({dtype}) is highly compromised.")
        elif sec < 50: lines.append(f"🔴 ALERT: {did} ({dtype}) shows active threat indicators.")
        elif sec < 80: lines.append(f"🟡 WATCH: {did} ({dtype}) behaviour drifting from baseline.")
        else:          lines.append(f"✅ {did} ({dtype}) operating normally.")
        if idc < 60:
            lines.append(f"🔐 Identity confidence low ({idc:.0f}/100) — possible firmware tampering.")
        for v in vio[:2]:
            lines.append(f"⚠ Policy violation: {v.replace('_',' ').replace(':',' ')}")
        for exp in shap.get("plain_english",[])[:2]:
            lines.append(f"📊 {exp.capitalize()}")
        if pre_level and predicted and confidence:
            lines.append(f"🔮 Predicted score: {predicted:.0f} in ~30 min ({confidence*100:.0f}% confidence)")
        return {"summary": lines[0] if lines else "No data", "details": lines[1:], "full_text": " | ".join(lines)}

    def get_all_scores(self) -> list:
        return [{"device_id":did,"last_score":s.last_score,"alerts":s.consecutive_alerts}
                for did,s in self._states.items()]
