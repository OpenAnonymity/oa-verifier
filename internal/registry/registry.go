// Package registry handles station registry interactions.
package registry

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/oa-verifier/internal/config"
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

	req, _ := http.NewRequest("GET", registryURL+"/verifier/registered_stations", nil)
	req.Header.Set("Authorization", "Bearer "+registrySecret)

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Error("registry fetch error", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Error("registry fetch failed", "status", resp.StatusCode)
		return nil, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Stations []map[string]any `json:"stations"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		slog.Error("registry parse error", "error", err)
		return nil, err
	}

	slog.Info("fetched stations from registry", "count", len(result.Stations))
	for _, s := range result.Stations {
		slog.Info("  station", "data", s)
	}

	return result.Stations, nil
}
