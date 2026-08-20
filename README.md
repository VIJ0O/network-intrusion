# Real-Time AI & Reinforcement Learning Network Intrusion Detection and Adaptive Response System (NIDS/NDR)

An industrial-grade cybersecurity platform that combines real-time network discovery, live Scapy packet sniffing, deep learning Autoencoder anomaly detection, LSTM threat forecasting, and **PPO Reinforcement Learning Adaptive Defense** to detect, forecast, and proactively mitigate cyber threats.

---

## 🌟 Key Architecture Layers

1. **Live Network Telemetry & Device Discovery**: Real-time packet parsing via Scapy, active ARP/ICMP sweeps, and device fingerprinting.
2. **Deep Learning Anomaly Detection (PyTorch Autoencoder)**: Baseline network profiling and reconstruction error anomaly classification.
3. **Threat Forecasting (PyTorch LSTM)**: Temporal threat trajectory forecasting across $10\text{s}$, $30\text{s}$, and $60\text{s}$ windows.
4. **Adaptive Response Engine (PPO Reinforcement Learning)**: Deep Actor-Critic agent trained via Proximal Policy Optimization to choose proportional defensive actions without disrupting legitimate high-volume traffic.
5. **Multi-Layer Safety Gates**: Native Dry-Run mode (`RL_DRY_RUN=true`), explicit controlled auto-response authorization (`RL_AUTO_RESPONSE_ENABLED=false`), allowlisted action validation, and rule-based failsafe fallbacks.
6. **SOC Operations Dashboard (Next.js & TypeScript)**: Real-time 3D topology canvas with device risk indicators, live attack timelines, telemetry stream visualizers, and interactive RL Explainability inspector.

---

## 🚀 Quick Start

### 1. Backend Service (FastAPI & PyTorch RL)

```bash
cd backend
pip install -r requirements.txt

# Run automated tests
python -m unittest tests/test_rl.py

# Launch Backend Server
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

- REST API: `http://127.0.0.1:8000`
- Interactive API Docs: `http://127.0.0.1:8000/docs`

### 2. Frontend Operations Dashboard (Next.js)

```bash
cd frontend
npm install
npm run dev
```

- Dashboard UI: `http://localhost:3000`
- RL Adaptive Defense Center: `http://localhost:3000/rl`
- 3D Network Topology: `http://localhost:3000/topology`
