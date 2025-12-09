# OpenRouter Enclave Verifier

Lightweight verification service for OpenRouter stations. Designed for enclave deployment with in-memory-only storage.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python verifier.py
# or
uvicorn verifier:app --host 0.0.0.0 --port 8000
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/station/register` | POST | Register station with cookie data |
| `/challenge` | POST | Verify privacy toggles off + generation exists |
| `/station/{station_id}` | GET | Check registration status |
| `/broadcast` | GET | Get all verified stations |

### Register Station

```bash
curl -X POST http://localhost:8000/station/register \
  -H "Content-Type: application/json" \
  -d '{"station_id": "my-station", "cookie_data": {"cookies": [...]}}'
```

### Challenge Station

```bash
curl -X POST http://localhost:8000/challenge \
  -H "Content-Type: application/json" \
  -d '{"station_id": "my-station", "generation_id": "gen-xxx"}'
```

### Check Registration

```bash
curl http://localhost:8000/station/my-station
```

### Broadcast

```bash
curl http://localhost:8000/broadcast
```

## Security

- All cookie data stored in memory only (never persisted)
- Failed challenges mark stations as untrustworthy
- Designed for TEE/enclave deployment







