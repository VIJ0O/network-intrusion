# Network Intrusion Detection System — Backend API

A FastAPI-based backend that provides REST API + WebSocket streaming for the NIDS dashboard.

## Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## API Docs

Once running, visit `http://localhost:8000/docs` for interactive Swagger UI.

## Endpoints

- `GET /api/dashboard` — System overview stats
- `GET /api/devices` — Connected devices list
- `GET /api/devices/{id}` — Device detail
- `GET /api/alerts` — Alert notifications
- `GET /api/predictions` — AI forecast
- `GET /api/attacks` — Attack history
- `GET /api/attacks/current` — Active attack
- `GET /api/reports/export` — CSV export
- `WS /ws/live` — Real-time traffic stream
