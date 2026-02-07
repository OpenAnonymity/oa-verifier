package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/netretry"
)

const (
	maxRetries = 5

	managementKeysRouterState = "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22settings%22%2C%7B%22children%22%3A%5B%22management-keys%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
)

var retryCfg = netretry.DefaultConfig(maxRetries)

var (
	escapedObjectRe = regexp.MustCompile(`\{[^{}]*\\"hash\\":\\"[0-9a-f]{64}\\"[^{}]*\}`)
	escapedHashRe   = regexp.MustCompile(`\\"hash\\":\\"([0-9a-f]{64})\\"`)
	escapedNameRe   = regexp.MustCompile(`\\"name\\":\\"([^"\\]+)\\"`)
	escapedProvRe   = regexp.MustCompile(`\\"is_provisioning_key\\":(true|false)`)

	plainObjectRe = regexp.MustCompile(`\{[^{}]*"hash":"[0-9a-f]{64}"[^{}]*\}`)
	plainHashRe   = regexp.MustCompile(`"hash":"([0-9a-f]{64})"`)
	plainNameRe   = regexp.MustCompile(`"name":"([^"]+)"`)
	plainProvRe   = regexp.MustCompile(`"is_provisioning_key":(true|false)`)
)

// Shared HTTP client with connection pooling
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

// FetchActivityData fetches user data including email and privacy toggles.
func FetchActivityData(auth *Auth) (map[string]any, error) {
	actionHash := auth.GetActionHash("activity")
	if actionHash == "" {
		return nil, fmt.Errorf("no activity hash found, available: %v", auth.GetAllActionHashes())
	}

	cookies := auth.GetCookies()
	routerState := "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22activity%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("POST", config.BaseURL+"/activity", strings.NewReader("[]"))
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		req.Header.Set("Accept", "text/x-component")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Next-Action", actionHash)
		req.Header.Set("Next-Router-State-Tree", routerState)
		req.Header.Set("Origin", config.BaseURL)
		req.Header.Set("Referer", config.BaseURL+"/activity")

		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("fetch_activity_data error", "attempt", attempt, "error", err)
			if attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return nil, err
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("fetch_activity_data failed", "attempt", attempt, "status", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return nil, fmt.Errorf("fetch_activity_data failed: status %d", resp.StatusCode)
		}

		// Parse response
		for _, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, `{"__kind":"OK"`) || strings.Contains(line, `"email"`) {
				idx := strings.Index(line, "{")
				if idx >= 0 {
					var obj map[string]any
					if err := json.Unmarshal([]byte(line[idx:]), &obj); err == nil {
						if obj["__kind"] == "OK" {
							if data, ok := obj["data"].(map[string]any); ok {
								return data, nil
							}
						}
						if _, hasEmail := obj["email"]; hasEmail {
							return obj, nil
						}
					}
				}
			}
		}

		slog.Warn("fetch_activity_data could not parse response", "attempt", attempt)
		if attempt < maxRetries {
			_ = netretry.Sleep(context.Background(), attempt, retryCfg)
			continue
		}
	}

	return nil, fmt.Errorf("fetch_activity_data failed after %d attempts", maxRetries)
}

// FetchProvisioningKeys fetches all provisioning keys.
func FetchProvisioningKeys(auth *Auth) ([]map[string]string, error) {
	cookies := auth.GetCookies()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("GET", config.BaseURL+managementKeysPagePath, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("fetch_provisioning_keys error", "attempt", attempt, "path", managementKeysPagePath, "error", err)
			if attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return nil, err
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("fetch_provisioning_keys failed", "attempt", attempt, "path", managementKeysPagePath, "status", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return nil, fmt.Errorf("fetch_provisioning_keys failed: status %d", resp.StatusCode)
		}

		return parseProvisioningKeysResponse(string(body)), nil
	}

	return nil, fmt.Errorf("fetch_provisioning_keys failed after %d attempts", maxRetries)
}

func parseProvisioningKeysResponse(body string) []map[string]string {
	candidates := parseProvisioningKeyCandidates(body, escapedObjectRe, escapedHashRe, escapedNameRe, escapedProvRe)

	normalized := strings.ReplaceAll(body, `\"`, `"`)
	candidates = append(candidates, parseProvisioningKeyCandidates(normalized, plainObjectRe, plainHashRe, plainNameRe, plainProvRe)...)

	keys := make([]map[string]string, 0, len(candidates))
	seen := make(map[string]struct{})
	for _, key := range candidates {
		hash := key["hash"]
		if hash == "" {
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		keys = append(keys, key)
	}

	return keys
}

func parseProvisioningKeyCandidates(body string, objectRe, hashRe, nameRe, provisioningRe *regexp.Regexp) []map[string]string {
	objects := objectRe.FindAllString(body, -1)
	keys := make([]map[string]string, 0, len(objects))

	for _, obj := range objects {
		hashMatch := hashRe.FindStringSubmatch(obj)
		if len(hashMatch) < 2 || hashMatch[1] == "" {
			continue
		}

		nameMatch := nameRe.FindStringSubmatch(obj)
		if len(nameMatch) < 2 || nameMatch[1] == "" {
			continue
		}

		provisioningMatch := provisioningRe.FindStringSubmatch(obj)
		if len(provisioningMatch) >= 2 && provisioningMatch[1] != "true" {
			continue
		}

		keys = append(keys, map[string]string{
			"name": nameMatch[1],
			"hash": hashMatch[1],
		})
	}

	return keys
}

// DeleteProvisioningKey deletes a provisioning key by hash.
func DeleteProvisioningKey(auth *Auth, keyHash string) error {
	actionHash := auth.GetActionHash("provisioning_keys_delete")
	if actionHash == "" {
		return fmt.Errorf("could not get delete action hash")
	}

	cookies := auth.GetCookies()
	payload := fmt.Sprintf(`[%q,{"deleted":true},{"isProvisioningKey":true}]`, keyHash)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("POST", config.BaseURL+managementKeysPagePath, strings.NewReader(payload))
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		req.Header.Set("Accept", "text/x-component")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Next-Action", actionHash)
		req.Header.Set("Next-Router-State-Tree", managementKeysRouterState)
		req.Header.Set("Origin", config.BaseURL)
		req.Header.Set("Referer", config.BaseURL+managementKeysPagePath)

		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("delete_provisioning_key error", "attempt", attempt, "error", err)
			if attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return err
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("delete_provisioning_key failed", "attempt", attempt, "status", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return fmt.Errorf("delete_provisioning_key failed: status %d", resp.StatusCode)
		}

		if strings.Contains(string(body), `"deleted":true`) || strings.Contains(string(body), `"__kind":"OK"`) {
			slog.Info("deleted provisioning key", "hash", keyHash[:min(16, len(keyHash))])
			return nil
		}

		slog.Warn("delete_provisioning_key unexpected response", "attempt", attempt)
		if attempt < maxRetries {
			_ = netretry.Sleep(context.Background(), attempt, retryCfg)
			continue
		}
	}

	return fmt.Errorf("delete_provisioning_key failed after %d attempts", maxRetries)
}

// CleanupProvisioningKeys deletes all provisioning keys matching the label.
func CleanupProvisioningKeys(auth *Auth, label string) (int, error) {
	keys, err := FetchProvisioningKeys(auth)
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}

	var matching []map[string]string
	for _, k := range keys {
		if k["name"] == label {
			matching = append(matching, k)
		}
	}

	if len(matching) == 0 {
		return 0, nil
	}

	slog.Info("cleaning up provisioning keys", "label", label, "count", len(matching))
	deleted := 0
	for _, k := range matching {
		if err := DeleteProvisioningKey(auth, k["hash"]); err == nil {
			deleted++
		}
	}

	slog.Info("cleaned up provisioning keys", "label", label, "deleted", deleted, "total", len(matching))
	return deleted, nil
}

// CreateProvisioningKey creates a new provisioning key and returns it.
func CreateProvisioningKey(auth *Auth, label string) (string, error) {
	actionHash := auth.GetActionHash("provisioning_keys_create")
	if actionHash == "" {
		return "", fmt.Errorf("could not get create action hash, available: %v", auth.GetAllActionHashes())
	}

	cookies := auth.GetCookies()
	payload := fmt.Sprintf(`[{"name":%q}]`, label)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("POST", config.BaseURL+managementKeysPagePath, strings.NewReader(payload))
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		req.Header.Set("Accept", "text/x-component")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Next-Action", actionHash)
		req.Header.Set("Next-Router-State-Tree", managementKeysRouterState)
		req.Header.Set("Origin", config.BaseURL)
		req.Header.Set("Referer", config.BaseURL+managementKeysPagePath)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("create_provisioning_key error", "attempt", attempt, "error", err)
			if attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return "", err
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("create_provisioning_key failed", "attempt", attempt, "status", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < maxRetries {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return "", fmt.Errorf("create_provisioning_key failed: status %d", resp.StatusCode)
		}

		for _, line := range strings.Split(string(body), "\n") {
			idx := strings.Index(line, "{")
			if idx >= 0 {
				var obj map[string]any
				if err := json.Unmarshal([]byte(line[idx:]), &obj); err == nil {
					if obj["__kind"] == "OK" {
						if data, ok := obj["data"].(map[string]any); ok {
							if key, ok := data["key"].(string); ok && strings.HasPrefix(key, "sk-or-") {
								slog.Info("created provisioning key", "key", key[:20])
								return key, nil
							}
						}
					}
				}
			}
		}

		slog.Warn("create_provisioning_key could not parse key from response", "attempt", attempt)
		if attempt < maxRetries {
			_ = netretry.Sleep(context.Background(), attempt, retryCfg)
			continue
		}
	}

	return "", fmt.Errorf("create_provisioning_key failed after %d attempts", maxRetries)
}

// OwnershipCheckResult describes the ownership check outcome.
type OwnershipCheckResult struct {
	Owned      bool
	NotOwned   bool
	StatusCode int
	Body       string
}

// VerifyKeyOwnership verifies that a key belongs to the station's account.
func VerifyKeyOwnership(provisioningKey, keyHash string) (OwnershipCheckResult, error) {
	reqURL := config.OpenRouterAPIURL + "/keys/" + url.PathEscape(keyHash)
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("Authorization", "Bearer "+provisioningKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return OwnershipCheckResult{}, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	result := OwnershipCheckResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}

	if resp.StatusCode == 404 {
		slog.Warn("key not found", "hash", keyHash[:16])
		result.NotOwned = true
		return result, nil
	}

	if resp.StatusCode != 200 {
		return result, nil
	}

	var resultJSON struct {
		Data struct {
			Hash string `json:"hash"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resultJSON); err != nil {
		return result, err
	}

	if resultJSON.Data.Hash == keyHash {
		slog.Debug("key ownership verified", "hash", keyHash[:16])
		result.Owned = true
		return result, nil
	}

	slog.Warn("key hash mismatch", "expected", keyHash[:16])
	result.NotOwned = true
	return result, nil
}

// FetchOrgPublicKey fetches the org's public key from registry.
func FetchOrgPublicKey() (string, error) {
	registryURL := config.RegistryURL()
	if registryURL == "" {
		return "", fmt.Errorf("REGISTRY_URL not configured")
	}

	cfg := netretry.DefaultConfig(3)
	var lastErr error
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		req, _ := http.NewRequest("GET", registryURL+"/api/public_key", nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return "", err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("failed to fetch org public key: status %d", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return "", lastErr
		}

		var result struct {
			PublicKey string `json:"public_key"`
			Algorithm string `json:"algorithm"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return "", err
		}

		if result.PublicKey != "" {
			slog.Info("fetched org public key", "key", result.PublicKey[:16], "algorithm", result.Algorithm)
			return result.PublicKey, nil
		}

		lastErr = fmt.Errorf("empty public key in response")
		if attempt < cfg.Attempts {
			_ = netretry.Sleep(context.Background(), attempt, cfg)
			continue
		}
		return "", lastErr
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("failed to fetch org public key")
}

// NotifyOrgBanned notifies org about a banned station.
func NotifyOrgBanned(stationID, reason string) error {
	registryURL := config.RegistryURL()
	registrySecret := config.RegistrySecret()
	if registryURL == "" || registrySecret == "" {
		return nil // Not configured, skip
	}

	payload, _ := json.Marshal(map[string]string{
		"station_id": stationID,
		"reason":     reason,
	})

	cfg := netretry.DefaultConfig(3)
	var lastErr error
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		req, _ := http.NewRequest("POST", registryURL+"/verifier/ban_station", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+registrySecret)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			slog.Warn("failed to notify org about ban", "error", err)
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			slog.Info("notified org about banned station", "station_id", stationID)
			return nil
		}

		lastErr = fmt.Errorf("notify failed: status %d", resp.StatusCode)
		if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < cfg.Attempts {
			_ = netretry.Sleep(context.Background(), attempt, cfg)
			continue
		}

		slog.Warn("failed to notify org about ban", "status", resp.StatusCode, "body", string(body))
		return lastErr
	}
	return lastErr
}

// OrgUpdate represents a station update payload sent to the registry.
type OrgUpdate struct {
	StationID   string `json:"station_id"`
	PublicKey   string `json:"public_key"`
	Email       string `json:"email"`
	Reason      string `json:"reason"`
	StatusCode  int    `json:"status_code"`
	ErrorDetail string `json:"error_detail"`
	Event       string `json:"event"`
	OccurredAt  string `json:"occurred_at"`
	Source      string `json:"source"`
}

// NotifyOrgUpdate notifies org about station status changes.
func NotifyOrgUpdate(update OrgUpdate) error {
	registryURL := config.RegistryURL()
	registrySecret := config.RegistrySecret()
	if registryURL == "" || registrySecret == "" {
		return nil // Not configured, skip
	}

	payload, _ := json.Marshal(update)

	cfg := netretry.DefaultConfig(3)
	var lastErr error
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		req, _ := http.NewRequest("POST", registryURL+"/verifier/update", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+registrySecret)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			slog.Warn("failed to notify org update", "error", err)
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			slog.Info("notified org update", "station_id", update.StationID, "event", update.Event)
			return nil
		}

		lastErr = fmt.Errorf("update notify failed: status %d", resp.StatusCode)
		if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < cfg.Attempts {
			_ = netretry.Sleep(context.Background(), attempt, cfg)
			continue
		}

		slog.Warn("failed to notify org update", "status", resp.StatusCode, "body", string(body))
		return lastErr
	}
	return lastErr
}
