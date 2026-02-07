// Package registry handles station registry interactions.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/netretry"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// FetchStations fetches authorized stations from registry.
func FetchStations() ([]map[string]any, error) {
	registryURL := config.RegistryURL()
	registrySecret := config.RegistrySecret()

	if registryURL == "" || registrySecret == "" {
		slog.Warn("registry not configured (STATION_REGISTRY_URL or STATION_REGISTRY_SECRET missing)")
		return nil, nil
	}

	cfg := netretry.DefaultConfig(3)
	var lastErr error
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		req, _ := http.NewRequest("GET", registryURL+"/verifier/registered_stations", nil)
		req.Header.Set("Authorization", "Bearer "+registrySecret)

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			slog.Error("registry fetch error", "attempt", attempt, "error", err)
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Error("registry fetch failed", "attempt", attempt, "status", resp.StatusCode)
			lastErr = fmt.Errorf("registry fetch failed: status %d", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return nil, nil
		}

		var result struct {
			Stations []map[string]any `json:"stations"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			slog.Error("registry parse error", "attempt", attempt, "error", err)
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return nil, err
		}

		slog.Info("fetched stations from registry", "count", len(result.Stations))
		for _, s := range result.Stations {
			slog.Info("  station", "data", s)
		}

		return result.Stations, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}
