# PHANTOM SHIFT — SecureX

**Team SecureX | JSS Eclipse Hackathon 2025**

| Member | USN |
|--------|-----|
| Preksha H M   | 1RX24CS183 |
| Pragathi G    | 1RN24CS171 |
| Poojitha P    | 1RN24CS165 |
| Pranathi K P  | 1RX24CS174 |

## Quick Start

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| React Dashboard | http://localhost:3000 |
| FastAPI + Docs  | http://localhost:8000/docs |

## Three Pillars

1. **Predictive Threat Horizon** — LSTM predicts trust score 30 min ahead
2. **Dual Trust Scoring** — Security Trust + Identity Confidence
3. **Fleet Contagion Intelligence** — NetworkX blast radius calculation

## Architecture

```
Simulator (6 device types: PLC, SCADA, HMI, Sensor, Gateway, Robot)
    ↓ HTTP POST /api/telemetry
FastAPI Backend
    ├── ML Engine (Isolation Forest + LSTM trend + SHAP)
    ├── Dual Trust Engine (Security 0.6 × Identity 0.4)
    └── Fleet Contagion Engine (NetworkX BFS blast radius)
    ↓ WebSocket /ws/live
React Dashboard
    ├── Live trust score rings per device
    ├── SHAP plain-English alert cards
    ├── Blast radius visualization
    └── Pre-alert 30-min predictions
```

## Trust Score Formula

```
Security Trust  = 0.40×Behavioral + 0.35×Policy + 0.25×History
Identity Score  = cosine_similarity(current_behavior, onboarding_fingerprint)
Combined Trust  = 0.60×Security + 0.40×Identity

Severity: 80-100 🟢 SAFE | 50-79 🟡 WATCH | 20-49 🟠 ALERT | 0-19 🔴 CRITICAL
```
