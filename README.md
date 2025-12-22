# OpenRouter Enclave Verifier

Lightweight verification service for OpenRouter stations. Designed for enclave deployment with in-memory-only storage.

## Build & Run

```bash
go build -o verifier ./cmd/verifier
./verifier

# Or directly
go run ./cmd/verifier
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register station with Ed25519 public key and cookie |
| `/submit_key` | POST | Submit double-signed API key for ownership verification |
| `/station/{public_key}` | GET | Get station info |
| `/broadcast` | GET | Get all verified stations and banned list |
| `/banned-stations` | GET | Get list of banned stations |
| `/reload-config` | POST | Hot-reload config from .env (requires auth) |

## Module Structure

| Path | Purpose |
|------|---------|
| `cmd/verifier/main.go` | Entry point |
| `internal/server/` | HTTP server, handlers, verification loop |
| `internal/config/` | Hot-reloadable configuration |
| `internal/models/` | Data models |
| `internal/openrouter/` | OpenRouter auth & API interactions |
| `internal/banned/` | Banned station tracking |
| `internal/challenge/` | Privacy toggle verification |
| `internal/registry/` | Station registry fetch |

## Security

- Three-way binding: station_id (registry) <-> email (cookie) <-> public_key (station)
- Cookie data stored in memory only (never persisted)
- Background verification loop randomly challenges stations
- Designed for TEE/enclave deployment
