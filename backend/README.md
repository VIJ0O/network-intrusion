# Network Intrusion Detection & Response System (NIDS/NDR) — Backend API

FastAPI-based backend engine providing real-time Scapy packet capture, PyTorch Autoencoder anomaly detection, LSTM threat forecasting, and **PPO Reinforcement Learning Adaptive Defense** with WebSocket streaming.

---

## 🧠 Reinforcement Learning Adaptive Response Architecture

The RL Subsystem forms the intelligent decision-making layer that selects the most appropriate mitigation action given the live security state:

```
REAL NETWORK
      ↓
PACKET CAPTURE (Scapy)
      ↓
FEATURE EXTRACTION
      ↓
AUTOENCODER (Reconstruction Anomaly Detection)
      ↓
LSTM (Threat Horizon Forecasting)
      ↓
THREAT ENGINE (Correlator)
      ↓
RL RESPONSE AGENT (PPO Actor-Critic Policy)
      ↓
VALIDATED RESPONSE ENGINE (Netsh / IPtables / Throttling)
      ↓
OBSERVED OUTCOME (Telemetry Delta & Disruption Metrics)
      ↓
REWARD CALCULATION & CONTROLLED LEARNING
```

---

## ⚙️ RL State Space (18 Normalized Dimensions)

Observations are normalized in the range $[0.0, 1.0]$:
1. `anomaly_score`: Autoencoder reconstruction error normalized against baseline threshold
2. `threat_probability`: AI Engine predicted threat probability ($0.0 - 1.0$)
3. `pps`: Packets per second (normalized against $5000\text{ pps}$)
4. `bps`: Bytes per second (normalized against $20\text{ MB/s}$)
5. `tcp_ratio`: Ratio of TCP packets in current window ($0.0 - 1.0$)
6. `udp_ratio`: Ratio of UDP packets in current window ($0.0 - 1.0$)
7. `icmp_ratio`: Ratio of ICMP packets in current window ($0.0 - 1.0$)
8. `syn_ratio`: Ratio of SYN flags (indicator of SYN Floods) ($0.0 - 1.0$)
9. `distinct_ports`: Number of destination ports probed (normalized against $200$)
10. `unique_ips`: Distinct active source/destination IP addresses ($0.0 - 1.0$)
11. `attack_confidence`: AI confidence score ($0.0 - 1.0$)
12. `attack_severity_num`: Numeric severity ($0.0=\text{None}, 0.25=\text{Low}, 0.5=\text{Medium}, 0.75=\text{High}, 1.0=\text{Critical}$)
13. `attack_duration`: Incident duration in seconds (normalized against $300\text{s}$)
14. `num_attackers`: Distinct adversary count ($0.0 - 1.0$)
15. `num_victims`: Distinct target count ($0.0 - 1.0$)
16. `victim_risk_score`: Asset criticality score ($0.0 - 1.0$)
17. `current_defense_status`: Active mitigation state ($0.0=\text{None}, 0.25=\text{Monitored}, 0.5=\text{RateLimited}, 0.75=\text{Blocked}, 1.0=\text{Quarantined}$)
18. `forecast_trend`: LSTM horizon slope ($0.0=\text{falling}, 0.5=\text{stable}, 1.0=\text{rising}$)

---

## 🎯 Action Space (6 Discrete Actions)

- `0: CONTINUE_MONITORING` — Zero disruption passive observation
- `1: GENERATE_ALERT` — SOC alert dispatch for analyst review
- `2: INCREASE_MONITORING` — Elevated inspection rate & deep packet capture
- `3: RATE_LIMIT` — Dynamic bandwidth/PPS throttling to suppress floods
- `4: BLOCK_SOURCE` — Firewall rule dropping all adversary packets
- `5: QUARANTINE_DEVICE` — Network segment isolation of compromised host

---

## 💎 Configurable Reward Function

Designed to maximize threat suppression while minimizing false-positive operational disruption:
- Mitigated Attack Reward: `+10.0`
- Normal Traffic Monitored Reward: `+5.0`
- Successful Incident Recovery: `+8.0`
- False Positive Warning Penalty: `-8.0`
- Unnecessary Host Blocking Penalty: `-15.0`
- Unnecessary Quarantine Penalty: `-20.0`
- Service Disruption Penalty: `-15.0`
- Unmitigated Attack Escalation Penalty: `-10.0`

> **Heavy Traffic Distinction**: The environment distinguishes high-bandwidth benign transfers (e.g. backups/streaming) from DoS attacks via multi-feature correlation (reconstruction error, SYN ratio, port distributions).

---

## 🛡️ Multi-Layer Safety Architecture

- `RL_DRY_RUN=true` (Enabled by default): The RL agent calculates and recommends decisions on live telemetry, but does **not** modify OS firewall rules without analyst approval.
- `RL_AUTO_RESPONSE_ENABLED=false` (Disabled by default): Automatic blocking requires explicit runtime authorization.
- **Allowlist Action Enforcement**: Only validated safe actions in the allowlist are executed.
- **Failsafe Fallback**: If the RL model is missing, corrupt, or untrained, the system smoothly falls back to rule-based monitoring without service interruption.

---

## 🚀 Setup & Execution

```bash
cd backend
pip install -r requirements.txt

# Run PPO training & benchmark
python -m rl.train --timesteps 25000

# Run automated test suite
python -m unittest tests/test_rl.py

# Start Backend Server
uvicorn main:app --reload --port 8000
```

---

## 📡 API Endpoints

- `GET /api/rl/status` — RL policy status, latest decision, and safety configuration
- `GET /api/rl/decisions` — Historical decision log with explainability factors
- `GET /api/rl/evaluation` — Latest comparative benchmark (RL vs Rule-Based)
- `POST /api/rl/train` — Trigger background PPO training
- `POST /api/rl/evaluate` — Trigger benchmark evaluation
- `POST /api/rl/config` — Update safety gates (Dry-Run, Auto-Response, Allowed Actions)
- `POST /api/rl/infer-now` — Force immediate inference on live network state
- `WS /ws/rl` — Real-time WebSocket decision stream
