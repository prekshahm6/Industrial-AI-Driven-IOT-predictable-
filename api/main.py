#!/usr/bin/env python3
"""
PHANTOM SHIFT — FastAPI Backend (v9 — with attack timeline)
Team: SecureX | JSS Eclipse Hackathon 2025
"""
import os, sys, json, asyncio, logging, time
from typing import Optional, List, Union
from collections import defaultdict, deque
from datetime import datetime

sys.path.insert(0, "/app")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ml_engine.ml_engine       import MLEngine
from trust_engine.trust_engine import DualTrustEngine
from fleet_graph.fleet_graph   import FleetContagionEngine

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [API] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="PHANTOM SHIFT — SecureX API", version="9.0.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ml_engine    = MLEngine()
trust_engine = DualTrustEngine()
fleet_engine = FleetContagionEngine()

device_states  : dict = {}
device_history : dict = defaultdict(lambda: deque(maxlen=200))
# Attack timeline: per device, list of {time, event, score, feature, severity}
attack_timeline: dict = defaultdict(lambda: deque(maxlen=100))
incidents      : list = []
ws_clients     : list = []
event_count    : int  = 0

SEVERITY_PREV  : dict = {}  # track previous severity per device

# ══════════════════════════════════════════════════════════════════
# Enhancement 5 — MITRE ATT&CK Threat Intelligence Mapping
# Maps our detected attack types to industry-standard ATT&CK techniques
# Reference: https://attack.mitre.org/
# ══════════════════════════════════════════════════════════════════
MITRE_ATT_CK = {
    "port_scan":          {"id":"T1046", "name":"Network Service Discovery",       "tactic":"Discovery",         "url":"https://attack.mitre.org/techniques/T1046"},
    "reconnaissance":     {"id":"T1046", "name":"Network Service Discovery",       "tactic":"Discovery",         "url":"https://attack.mitre.org/techniques/T1046"},
    "data_exfil":         {"id":"T1041", "name":"Exfiltration Over C2 Channel",    "tactic":"Exfiltration",      "url":"https://attack.mitre.org/techniques/T1041"},
    "data_exfiltration":  {"id":"T1041", "name":"Exfiltration Over C2 Channel",    "tactic":"Exfiltration",      "url":"https://attack.mitre.org/techniques/T1041"},
    "lateral_move":       {"id":"T1021", "name":"Remote Services (SMB/WinRM)",     "tactic":"Lateral Movement",  "url":"https://attack.mitre.org/techniques/T1021"},
    "lateral_movement":   {"id":"T1021", "name":"Remote Services (SMB/WinRM)",     "tactic":"Lateral Movement",  "url":"https://attack.mitre.org/techniques/T1021"},
    "c2_beacon":          {"id":"T1071", "name":"Application Layer Protocol",      "tactic":"Command & Control", "url":"https://attack.mitre.org/techniques/T1071"},
    "firmware_tamper":    {"id":"T1495", "name":"Firmware Corruption",             "tactic":"Impact",            "url":"https://attack.mitre.org/techniques/T1495"},
    "dos_attack":         {"id":"T1499", "name":"Endpoint Denial of Service",      "tactic":"Impact",            "url":"https://attack.mitre.org/techniques/T1499"},
}

def get_mitre_technique(attack_type: str) -> Optional[dict]:
    """Return MITRE ATT&CK technique for a given attack type."""
    return MITRE_ATT_CK.get(attack_type)


# ══════════════════════════════════════════════════════════════════
# Enhancement 3 — Autonomous Risk Response Engine
# When device score drops below threshold, automated defensive actions fire.
# Human-in-the-loop: actions are LOGGED and RECOMMENDED, not blindly executed.
# (In prod: integrate with firewall API / SDN controller / VLAN manager)
# ══════════════════════════════════════════════════════════════════
RESPONSE_LOG: list = []  # audit trail of all automated responses

RESPONSE_RULES = [
    # score < 20 → Critical: isolate immediately
    {"threshold": 20, "severity": "CRITICAL", "actions": [
        "BLOCK_FIREWALL_RULE",    # iptables -I INPUT -s <device_ip> -j DROP
        "ISOLATE_VLAN",           # move device to quarantine VLAN 999
        "DISABLE_NETWORK_PORT",   # shutdown switchport (SNMP SET ifAdminStatus=2)
        "ALERT_SOC_TEAM",         # page on-call analyst
    ]},
    # score 20–35 → High: restrict traffic
    {"threshold": 35, "severity": "HIGH", "actions": [
        "RATE_LIMIT_TRAFFIC",     # tc qdisc add ... rate 100kbps
        "BLOCK_EXTERNAL_EGRESS",  # block all non-RFC1918 destinations
        "ALERT_SOC_TEAM",
    ]},
    # score 35–50 → Alert: monitor closely
    {"threshold": 50, "severity": "ALERT", "actions": [
        "INCREASE_LOG_VERBOSITY", # switch device to debug logging
        "SNAPSHOT_STATE",         # capture memory/process snapshot
    ]},
]

def run_response_engine(device_id: str, device_type: str, score: float, device_ip: str = "unknown") -> Optional[dict]:
    """
    Enhancement 3 — Risk Response Engine.
    Evaluates score against rules and returns the response action taken.
    In production: actions would call firewall API, SDN controller, VLAN manager.
    In demo: actions are logged and shown on dashboard as autonomous defence.
    """
    for rule in RESPONSE_RULES:
        if score < rule["threshold"]:
            # Check if we already fired this rule for this device recently (60s cooldown)
            recent = [r for r in RESPONSE_LOG[-50:]
                      if r["device_id"] == device_id
                      and r["severity"] == rule["severity"]
                      and time.time() - r["ts"] < 60]
            if recent:
                return None  # cooldown — don't spam
            response = {
                "device_id":   device_id,
                "device_type": device_type,
                "device_ip":   device_ip,
                "score":       round(score, 1),
                "severity":    rule["severity"],
                "actions":     rule["actions"],
                "status":      "EXECUTED",  # in prod: check firewall API response
                "ts":          time.time(),
                "time_str":    datetime.now().strftime("%H:%M:%S"),
                "note":        f"Autonomous response fired for {device_id} at score {score:.0f}",
            }
            RESPONSE_LOG.append(response)
            if len(RESPONSE_LOG) > 200:
                RESPONSE_LOG.pop(0)
            log.warning(f"[RESPONSE ENGINE] {rule['severity']} — {device_id} score={score:.1f} → {rule['actions']}")
            return response
    return None


def normalize_event(raw: dict) -> dict:
    ts = raw.get("timestamp", 0)
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
        except Exception:
            ts = time.time()
    try:
        ts = float(ts)
    except Exception:
        ts = time.time()
    if ts == 0.0:
        ts = time.time()
    return {
        "device_id":    str(raw.get("device_id",    "unknown")),
        "device_type":  str(raw.get("device_type",  "SENSOR")).upper(),
        "timestamp":    ts,
        "src_ip":       str(raw.get("src_ip",        "0.0.0.0")),
        "dst_ip":       str(raw.get("dst_ip",        "0.0.0.0")),
        "src_port":     int(raw.get("src_port",      raw.get("port", 0))),
        "dst_port":     int(raw.get("dst_port",      raw.get("port", 0))),
        "protocol":     str(raw.get("protocol",      "tcp")),
        "packet_size":  int(raw.get("packet_size",   256)),
        "interval_ms":  float(raw.get("interval_ms", 100.0)),
        "volume_mb":    float(raw.get("volume_mb",   0.001)),
        "peer_list":    list(raw.get("peer_list",    [])),
        "session_id":   str(raw.get("session_id",    "")),
        "firmware_hash":    str(raw.get("firmware_hash", "")),
        "mac_address":      str(raw.get("mac_address", "")),       # Enhancement 4
        "cert_fingerprint": str(raw.get("cert_fingerprint", "")),  # Enhancement 4
        "vendor_signature": str(raw.get("vendor_signature", "")),  # Enhancement 4
        "uptime_sec":       int(raw.get("uptime_sec",    0)),
        "cpu_usage":    float(raw.get("cpu_usage",   0.0)),
        "mem_usage":    float(raw.get("mem_usage",   0.0)),
        "attack_type":  raw.get("attack_type"),
    }


def build_timeline_event(did, event_dict, ml_result, trust_result):
    """Generate a human-readable timeline entry for every notable event."""
    score    = trust_result["combined_score"]
    prev_sev = SEVERITY_PREV.get(did, "GREEN")
    curr_sev = trust_result["severity_color"]
    ts       = datetime.fromtimestamp(event_dict["timestamp"]).strftime("%H:%M:%S")
    entries  = []

    # Score crossed a boundary
    sev_order = {"GREEN":0,"YELLOW":1,"ORANGE":2,"RED":3}
    if sev_order.get(curr_sev,0) > sev_order.get(prev_sev,0):
        icons = {"YELLOW":"🟡","ORANGE":"🟠","RED":"🔴"}
        entries.append({
            "time":     ts,
            "type":     "SEVERITY_CHANGE",
            "icon":     icons.get(curr_sev,"⚠"),
            "event":    f"Severity escalated {prev_sev} → {curr_sev}",
            "score":    round(score,1),
            "severity": curr_sev,
            "ts":       event_dict["timestamp"],
        })
    elif sev_order.get(curr_sev,0) < sev_order.get(prev_sev,0):
        entries.append({
            "time":     ts,
            "type":     "RECOVERY",
            "icon":     "✅",
            "event":    f"Device recovering — {prev_sev} → {curr_sev}",
            "score":    round(score,1),
            "severity": curr_sev,
            "ts":       event_dict["timestamp"],
        })

    # Top SHAP feature crossed threshold
    shap = ml_result.get("shap", {})
    impacts = shap.get("impacts", {})
    for feat, imp in impacts.items():
        if abs(imp) > 0.15:
            entries.append({
                "time":     ts,
                "type":     "FEATURE_SPIKE",
                "icon":     "📊",
                "event":    f"{feat.replace('_',' ')} spiked — {shap.get('plain_english',[''])[0]}",
                "score":    round(score,1),
                "severity": curr_sev,
                "feature":  feat,
                "impact":   round(imp,3),
                "ts":       event_dict["timestamp"],
            })
            break  # only log top feature

    # Known attack type
    if event_dict.get("attack_type"):
        atk = event_dict["attack_type"]
        icons_atk = {
            "port_scan":       "🔍",
            "data_exfil":      "📤",
            "lateral_move":    "↔",
            "lateral_movement":"↔",
            "c2_beacon":       "📡",
            "firmware_tamper": "🔐",
            "reconnaissance":  "🔍",
            "data_exfiltration":"📤",
            "dos_attack":      "💥",
        }
        mitre = get_mitre_technique(atk)  # Enhancement 5
        entries.append({
            "time":     ts,
            "type":     "ATTACK_DETECTED",
            "icon":     icons_atk.get(atk,"🔴"),
            "event":    f"Attack detected: {atk.replace('_',' ').upper()}",
            "score":    round(score,1),
            "severity": "RED",
            "attack":   atk,
            "mitre":    mitre,  # Enhancement 5 — ATT&CK technique
            "ts":       event_dict["timestamp"],
        })

    # Firmware change
    if trust_result.get("identity_confidence",100) < 70 and SEVERITY_PREV.get(f"{did}_id",100) >= 70:
        entries.append({
            "time":     ts,
            "type":     "IDENTITY_BREACH",
            "icon":     "🔐",
            "event":    f"Identity confidence dropped to {trust_result['identity_confidence']:.0f} — possible firmware tamper",
            "score":    round(trust_result["identity_confidence"],1),
            "severity": "ORANGE",
            "ts":       event_dict["timestamp"],
        })
    SEVERITY_PREV[f"{did}_id"] = trust_result.get("identity_confidence",100)

    SEVERITY_PREV[did] = curr_sev
    return entries


async def broadcast(data: dict):
    dead = []
    for ws in ws_clients:
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in ws_clients:
            ws_clients.remove(ws)


async def run_pipeline(event_dict: dict):
    global event_count
    event_count += 1
    did   = event_dict["device_id"]
    dtype = event_dict["device_type"]

    ml_result    = ml_engine.process(event_dict)
    trust_result = trust_engine.score(ml_result, event_dict)
    fleet_engine.update_device(did, dtype, trust_result["combined_score"], event_dict)

    # Build timeline entries
    timeline_entries = build_timeline_event(did, event_dict, ml_result, trust_result)
    for entry in timeline_entries:
        attack_timeline[did].appendleft(entry)  # newest first

    state = {**trust_result, "event_count": event_count, "blast_radius": None}
    if trust_result["combined_score"] < 50:
        state["blast_radius"] = fleet_engine.blast_radius(did)

    device_states[did] = state
    device_history[did].append({
        "timestamp":          event_dict["timestamp"],
        "security_trust":     trust_result["security_trust"],
        "identity_confidence":trust_result["identity_confidence"],
        "combined_score":     trust_result["combined_score"],
        "anomaly_score":      trust_result["anomaly_score"],
        "predicted_score":    trust_result.get("predicted_score"),
        "attack_type":        event_dict.get("attack_type"),
    })

    if trust_result["severity_color"] in ("RED","ORANGE"):
        _maybe_incident(did, dtype, trust_result)

    # Enhancement 3 — Autonomous Risk Response Engine
    src_ip = event_dict.get("src_ip", "unknown")
    auto_response = run_response_engine(did, dtype, trust_result["combined_score"], src_ip)
    if auto_response:
        state["auto_response"] = auto_response  # surface on dashboard

    # Enhancement 5 — attach MITRE technique if attack type known
    if event_dict.get("attack_type"):
        state["mitre_technique"] = get_mitre_technique(event_dict["attack_type"])

    if ws_clients:
        await broadcast({"type":"score_update","data":state})

    return state


def _maybe_incident(did, dtype, tr):
    for inc in reversed(incidents[-20:]):
        if inc["device_id"] == did and time.time() - inc["ts"] < 120:
            return
    sev_meta = {
        "RED":    ("CRITICAL","Isolate device immediately",5),
        "ORANGE": ("ALERT",   "Quarantine and investigate",15),
    }
    color = tr["severity_color"]
    label, action, sla = sev_meta.get(color,("INFO","Monitor",1440))
    incidents.append({
        "id": f"INC-{len(incidents)+1:04d}", "device_id": did, "device_type": dtype,
        "severity": label, "color": color, "score": tr["combined_score"],
        "security_trust": tr["security_trust"], "identity_conf": tr["identity_confidence"],
        "violations": tr.get("policy_violations",[]), "alert_card": tr.get("alert_card",{}),
        "pre_alert": tr.get("pre_alert"), "action": action, "sla": sla,
        "status": "OPEN", "ts": time.time(),
    })
    if len(incidents) > 500:
        incidents.pop(0)


@app.get("/")
def root():
    return {"project":"PHANTOM SHIFT","team":"SecureX","status":"running","devices":len(device_states)}

@app.get("/health")
def health():
    return {"status":"healthy","devices":len(device_states)}

@app.post("/telemetry")
async def ingest(request: Request):
    try:
        raw = await request.json()
    except Exception as e:
        return JSONResponse(status_code=400, content={"error":f"Invalid JSON: {e}"})
    try:
        event  = normalize_event(raw)
        result = await run_pipeline(event)
        return {"status":"ok","score":result["combined_score"]}
    except Exception as e:
        log.error(f"Pipeline error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error":str(e)})

@app.get("/devices")
def get_devices():
    return {"devices":list(device_states.values()),"total":len(device_states)}

@app.get("/devices/{device_id}")
def get_device(device_id: str):
    if device_id not in device_states:
        return JSONResponse(status_code=404, content={"error":f"Device {device_id} not found"})
    return {**device_states[device_id],"history":list(device_history.get(device_id,[]))}

@app.get("/devices/{device_id}/history")
def get_history(device_id: str):
    return {"device_id":device_id,"history":list(device_history.get(device_id,[]))}

@app.get("/devices/{device_id}/timeline")
def get_timeline(device_id: str):
    return {"device_id":device_id,"timeline":list(attack_timeline.get(device_id,[]))}

@app.get("/devices/{device_id}/blast-radius")
def get_blast(device_id: str):
    return fleet_engine.blast_radius(device_id)

@app.get("/timeline")
def get_all_timeline():
    """Fleet-wide attack timeline — all devices merged and sorted by time."""
    all_events = []
    for did, entries in attack_timeline.items():
        for e in entries:
            all_events.append({**e, "device_id": did})
    all_events.sort(key=lambda x: x.get("ts",0), reverse=True)
    return {"timeline": all_events[:100]}

@app.get("/incidents")
def get_incidents(limit: int = 50):
    return {"incidents":list(reversed(incidents[-limit:])),"total":len(incidents)}

@app.patch("/incidents/{inc_id}")
def patch_incident(inc_id: str, status: str = "RESOLVED"):
    for inc in incidents:
        if inc["id"] == inc_id:
            inc["status"] = status
            return {"status":"updated"}
    return JSONResponse(status_code=404, content={"error":"Incident not found"})

@app.get("/pre-alerts")
def get_pre_alerts():
    pa = [
        {"device_id":did,"current_score":s.get("security_trust",100),
         "predicted_score":s.get("predicted_score"),"level":s.get("pre_alert_level"),
         "confidence":s.get("lstm_confidence",0),
         "message":f"Predicted to reach {s.get('predicted_score',0):.0f} in ~30 min",
         "timestamp":time.time()}
        for did,s in device_states.items() if s.get("pre_alert")
    ]
    return {"pre_alerts":pa}

@app.get("/fleet")
def get_fleet():
    return {**fleet_engine.get_graph_data(),"conspiracy":fleet_engine.detect_conspiracy()}

@app.get("/stats")
def get_stats():
    scores = [v["combined_score"] for v in device_states.values()]
    return {
        "total_devices":len(device_states),"events_processed":event_count,
        "open_incidents":sum(1 for i in incidents if i.get("status")=="OPEN"),
        "avg_trust_score":round(sum(scores)/len(scores),2) if scores else 100,
        "critical_devices":sum(1 for s in scores if s<=19),
        "alert_devices":sum(1 for s in scores if 20<=s<=49),
        "watch_devices":sum(1 for s in scores if 50<=s<=79),
        "safe_devices":sum(1 for s in scores if s>79),
        "conspiracy":fleet_engine.detect_conspiracy() is not None,
    }

@app.get("/response-log")
def get_response_log():
    """Enhancement 3 — Return autonomous risk response audit log."""
    return {"responses": list(reversed(RESPONSE_LOG[-50:])), "total": len(RESPONSE_LOG)}

@app.get("/mitre")
def get_mitre_summary():
    """Enhancement 5 — Return MITRE ATT&CK techniques observed across all devices."""
    seen = {}
    for did, entries in attack_timeline.items():
        for e in entries:
            atk = e.get("attack")
            if atk:
                technique = get_mitre_technique(atk)
                if technique:
                    key = technique["id"]
                    if key not in seen:
                        seen[key] = {**technique, "count": 0, "devices": [], "attack_type": atk}
                    seen[key]["count"] += 1
                    if did not in seen[key]["devices"]:
                        seen[key]["devices"].append(did)
    return {"techniques": list(seen.values()), "total": len(seen)}

@app.get("/dataset-info")
def get_dataset_info():
    """Enhancement 1 — Return real dataset calibration info."""
    return ml_engine.get_dataset_info()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    try:
        await ws.send_text(json.dumps({
            "type":"init","data":{
                "devices":list(device_states.values()),
                "incidents":incidents[-10:],
            }
        }))
        while True:
            await asyncio.sleep(30)
            await ws.send_text(json.dumps({"type":"ping"}))
    except (WebSocketDisconnect, Exception):
        if ws in ws_clients:
            ws_clients.remove(ws)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
