package openrouter

import (
	"bytes"
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
)

const (
	maxRetries = 5
	retryDelay = 2 * time.Second
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
				time.Sleep(retryDelay)
			}
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("fetch_activity_data failed", "attempt", attempt, "status", resp.StatusCode)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
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
			time.Sleep(retryDelay)
		}
	}

	return nil, fmt.Errorf("fetch_activity_data failed after %d attempts", maxRetries)
}

// FetchProvisioningKeys fetches all provisioning keys.
func FetchProvisioningKeys(auth *Auth) ([]map[string]string, error) {
	cookies := auth.GetCookies()

	keyRe := regexp.MustCompile(`\\"label\\":\\"([^"\\]+)\\",\\"name\\":\\"([0-9a-f]{16})\\".+?\\"hash\\":\\"([0-9a-f]{64})\\"`)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("GET", config.BaseURL+"/settings/provisioning-keys?page=1", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("fetch_provisioning_keys error", "attempt", attempt, "error", err)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("fetch_provisioning_keys failed", "attempt", attempt, "status", resp.StatusCode)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
		}

		matches := keyRe.FindAllStringSubmatch(string(body), -1)
		var keys []map[string]string
		for _, m := range matches {
			keys = append(keys, map[string]string{
				"label": m[1],
				"name":  m[2],
				"hash":  m[3],
			})
		}
		return keys, nil
	}

	return nil, fmt.Errorf("fetch_provisioning_keys failed after %d attempts", maxRetries)
}

// DeleteProvisioningKey deletes a provisioning key by hash.
func DeleteProvisioningKey(auth *Auth, keyHash string) error {
	actionHash := auth.GetActionHash("provisioning_keys_delete")
	if actionHash == "" {
		return fmt.Errorf("could not get delete action hash")
	}

	cookies := auth.GetCookies()
	routerState := "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22settings%22%2C%7B%22children%22%3A%5B%22provisioning-keys%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
	payload := fmt.Sprintf(`[%q,{"deleted":true},{"isProvisioningKey":true}]`, keyHash)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("POST", config.BaseURL+"/settings/provisioning-keys?page=1", strings.NewReader(payload))
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		req.Header.Set("Accept", "text/x-component")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Next-Action", actionHash)
		req.Header.Set("Next-Router-State-Tree", routerState)
		req.Header.Set("Origin", config.BaseURL)
		req.Header.Set("Referer", config.BaseURL+"/settings/provisioning-keys?page=1")

		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("delete_provisioning_key error", "attempt", attempt, "error", err)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("delete_provisioning_key failed", "attempt", attempt, "status", resp.StatusCode)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
		}

		if strings.Contains(string(body), `"deleted":true`) || strings.Contains(string(body), `"__kind":"OK"`) {
			slog.Info("deleted provisioning key", "hash", keyHash[:16])
			return nil
		}

		slog.Warn("delete_provisioning_key unexpected response", "attempt", attempt)
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	return fmt.Errorf("delete_provisioning_key failed after %d attempts", maxRetries)
}

// CleanupProvisioningKeys deletes all provisioning keys matching the label.
func CleanupProvisioningKeys(auth *Auth, label string) (int, error) {
	keys, err := FetchProvisioningKeys(auth)
	if err != nil || len(keys) == 0 {
		return 0, err
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
	routerState := "%5B%22%22%2C%7B%22children%22%3A%5B%22(user)%22%2C%7B%22children%22%3A%5B%22settings%22%2C%7B%22children%22%3A%5B%22provisioning-keys%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
	payload := fmt.Sprintf(`[{"name":%q}]`, label)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, _ := http.NewRequest("POST", config.BaseURL+"/settings/provisioning-keys", strings.NewReader(payload))
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
		req.Header.Set("Accept", "text/x-component")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Next-Action", actionHash)
		req.Header.Set("Next-Router-State-Tree", routerState)
		req.Header.Set("Origin", config.BaseURL)
		req.Header.Set("Referer", config.BaseURL+"/settings/provisioning-keys")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			slog.Warn("create_provisioning_key error", "attempt", attempt, "error", err)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			slog.Warn("create_provisioning_key failed", "attempt", attempt, "status", resp.StatusCode)
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
			continue
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
			time.Sleep(retryDelay)
		}
	}

	return "", fmt.Errorf("create_provisioning_key failed after %d attempts", maxRetries)
}

// VerifyKeyOwnership verifies that a key belongs to the station's account.
func VerifyKeyOwnership(provisioningKey, keyHash string) (bool, error) {
	reqURL := config.OpenRouterAPIURL + "/keys/" + url.PathEscape(keyHash)
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("Authorization", "Bearer "+provisioningKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		slog.Warn("key not found", "hash", keyHash[:16])
		return false, nil
	}

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("key verification failed: status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Hash string `json:"hash"`
		} `json:"data"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	if result.Data.Hash == keyHash {
		slog.Debug("key ownership verified", "hash", keyHash[:16])
		return true, nil
	}

	slog.Warn("key hash mismatch", "expected", keyHash[:16])
	return false, nil
}

// FetchOrgPublicKey fetches the org's public key from registry.
func FetchOrgPublicKey() (string, error) {
	registryURL := config.RegistryURL()
	if registryURL == "" {
		return "", fmt.Errorf("REGISTRY_URL not configured")
	}

	req, _ := http.NewRequest("GET", registryURL+"/api/public_key", nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to fetch org public key: status %d", resp.StatusCode)
	}

	var result struct {
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if result.PublicKey != "" {
		slog.Info("fetched org public key", "key", result.PublicKey[:16], "algorithm", result.Algorithm)
		return result.PublicKey, nil
	}

	return "", fmt.Errorf("empty public key in response")
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

	req, _ := http.NewRequest("POST", registryURL+"/verifier/ban_station", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+registrySecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Warn("failed to notify org about ban", "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		slog.Info("notified org about banned station", "station_id", stationID)
		return nil
	}

	slog.Warn("failed to notify org about ban", "status", resp.StatusCode)
	return fmt.Errorf("notify failed: status %d", resp.StatusCode)
}


