#!/usr/bin/env python3
"""
Test Suite — PHANTOM SHIFT | Team SecureX
Run: python tests/test_securex.py
No external dependencies needed.
"""
import sys, math, time
sys.path.insert(0, "ml_engine")
sys.path.insert(0, "trust_engine")
sys.path.insert(0, "fleet_graph")

print("=" * 55)
print("  PHANTOM SHIFT — SecureX Test Suite")
print("  JSS Eclipse Hackathon 2025")
print("=" * 55)

passed = 0
failed = 0

def test(name, condition):
    global passed, failed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name}")
        failed += 1

# ── Test 1: Feature Extractor ────────────────────────────────
print("\n[1] Feature Extractor")
from feature_extractor import FeatureExtractorEngine, FEATURE_NAMES

eng = FeatureExtractorEngine()
ev  = {
    "device_id":"plc-01","device_type":"PLC","timestamp":time.time(),
    "src_ip":"10.0.1.10","dst_ip":"10.0.1.20","src_port":50000,"dst_port":502,
    "protocol":"modbus","packet_size":256,"interval_ms":100.0,
    "volume_mb":0.001,"peer_list":["10.0.1.1"],"firmware_hash":"abc123",
    "cpu_usage":15.0,"mem_usage":30.0,"attack_type":None,
}
result = eng.process(ev)
test("Returns device_id",     result["device_id"] == "plc-01")
test("Returns 12 features",   len(result["features"]) == 12)
test("All features are floats", all(isinstance(f, float) for f in result["features"]))
test("Feature names match",   result["feature_names"] == FEATURE_NAMES)

# ── Test 2: LSTM ─────────────────────────────────────────────
print("\n[2] LSTM Neural Network")
from ml_engine import NumpyLSTM
import numpy as np

lstm = NumpyLSTM(input_size=12, hidden_size=32)
seq  = np.random.randn(30, 12)
pred = lstm.forward(seq)
test("LSTM output is float",        isinstance(pred, float))
test("LSTM output in 0-100",        0 <= pred <= 100)
lstm.update_with_truth(seq, 85.0)
test("LSTM trains without error",   lstm._trained_steps == 1)
pred2 = lstm.forward(seq)
test("LSTM output still valid",     0 <= pred2 <= 100)

# ── Test 3: Isolation Forest ─────────────────────────────────
print("\n[3] Isolation Forest Anomaly Detection")
from ml_engine import DeviceMLState

state = DeviceMLState("plc-01", "PLC")
# Feed 60 normal events
normal_feat = [0.1, 0.5, 0.3, 100.0, 10.0, 0.0, 256.0, 0.0, 0.05, 15.0, 30.0, 1.0]
for _ in range(60):
    f = [v + np.random.randn()*0.01 for v in normal_feat]
    state.add_features(f, "fw-abc")

test("IsoForest fitted after 50 samples", state.iso_fitted)
normal_score = state.get_anomaly_score(normal_feat)
attack_feat  = [0.9, 3.5, 2.8, 15.0, 40.0, 8.0, 64.0, 0.9, 0.95, 85.0, 90.0, 5.0]
attack_score = state.get_anomaly_score(attack_feat)
test("Normal traffic low anomaly",   normal_score < 0.4)
test("Attack traffic higher anomaly", attack_score > normal_score)

# ── Test 4: SHAP ─────────────────────────────────────────────
print("\n[4] SHAP Explainability")
shap = state.get_shap_explanation(attack_feat)
test("SHAP returns top_features",   len(shap["top_features"]) > 0)
test("SHAP returns plain_english",  len(shap["plain_english"]) > 0)
test("SHAP anomaly_score present",  "anomaly_score" in shap)

# ── Test 5: Dual Trust Engine ────────────────────────────────
print("\n[5] Dual Trust Engine")
from trust_engine import DualTrustEngine, severity, cosine_similarity

engine = DualTrustEngine()
ml_res = {
    "device_id":"plc-01","device_type":"PLC","timestamp":time.time(),
    "features":normal_feat,"anomaly_score":0.05,
    "firmware_changes":0,"predicted_score":90.0,
    "lstm_confidence":0.8,"pre_alert":False,"pre_alert_level":None,
    "shap":{"top_features":[],"impacts":{},"plain_english":[],"anomaly_score":0.05},
}
ev_clean = {"dst_port":502,"protocol":"modbus","attack_type":None,"peer_list":[]}
score = engine.score(ml_res, ev_clean)

test("Score has security_trust",     "security_trust" in score)
test("Score has identity_confidence","identity_confidence" in score)
test("Score has combined_score",     "combined_score" in score)
test("Normal device score > 60",     score["security_trust"] > 60)
test("Alert card generated",         bool(score["alert_card"]["summary"]))

# ── Test 6: Severity mapping ─────────────────────────────────
print("\n[6] Severity Mapping")
test("Score 95 → GREEN",   severity(95)[0] == "GREEN")
test("Score 65 → YELLOW",  severity(65)[0] == "YELLOW")
test("Score 35 → ORANGE",  severity(35)[0] == "ORANGE")
test("Score 10 → RED",     severity(10)[0] == "RED")

# ── Test 7: Cosine Similarity ────────────────────────────────
print("\n[7] Identity Confidence")
a = [1.0, 0.5, 0.3, 100.0]
b = [1.0, 0.5, 0.3, 100.0]
c = [9.0, 8.0, 7.0, 1.0]
test("Identical vectors → sim=1.0",  abs(cosine_similarity(a,b) - 1.0) < 0.01)
test("Different vectors → sim<0.9",  cosine_similarity(a,c) < 0.9)

# ── Test 8: Fleet Contagion ──────────────────────────────────
print("\n[8] Fleet Contagion Graph")
from fleet_graph import FleetContagionEngine

fleet = FleetContagionEngine()
for i in range(5):
    fleet.update_device(f"plc-0{i+1}", "PLC", 90.0-i*5, {"peer_list":[f"10.0.1.{i+2}"]})
fleet.update_device("plc-01", "PLC", 10.0, {"peer_list":["10.0.1.2","10.0.1.3"]})
blast = fleet.blast_radius("plc-01")

test("Blast radius has source",      blast["source"] == "plc-01")
test("Blast radius has affected",    "affected" in blast)
test("Graph data has nodes",         len(fleet.get_graph_data()["nodes"]) > 0)

# Conspiracy detection
from collections import deque
fleet._recent_alerts = deque()
now = time.time()
fleet._recent_alerts.append((now, "plc-01", 25.0))
fleet._recent_alerts.append((now, "scada-01", 30.0))
conspiracy = fleet.detect_conspiracy()
test("Conspiracy detected for 2 drifting devices", conspiracy is not None)

# ── Results ──────────────────────────────────────────────────
print()
print("=" * 55)
print(f"  Results: {passed} passed, {failed} failed")
if failed == 0:
    print("  🎉 ALL TESTS PASSED — SecureX is ready!")
else:
    print(f"  ⚠  {failed} test(s) need attention")
print("=" * 55)
