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
| `/register` | POST | Register station with Ed25519 public key and cookie |
| `/station/{public_key}` | GET | Get station info |
| `/broadcast` | GET | Get all verified stations and banned list |
| `/add-invitation` | POST | Add invitation code for Privacy Pass tickets |
| `/tickets` | GET | Get ticket usage statistics |
| `/banned-stations` | GET | Get list of banned stations |
| `/reload-config` | POST | Hot-reload config from .env (requires auth) |

## Module Structure

| File | Purpose |
|------|---------|
| `verifier.py` | FastAPI routes, main entry point |
| `config.py` | Hot-reloadable configuration (reads from .env on each access) |
| `models.py` | Pydantic/dataclass models |
| `openrouter_api.py` | OpenRouter auth & API interactions |
| `tickets.py` | Privacy Pass ticket management |
| `banned.py` | Banned station tracking |
| `challenge.py` | Station verification challenges |
| `registry.py` | Station registry fetch |
| `logging_config.py` | Loguru setup |

## Security

- Three-way binding: station_id (registry) <-> email (cookie) <-> public_key (station)
- Cookie data stored in memory only (never persisted)
- Background verification loop randomly challenges stations
- Designed for TEE/enclave deployment
