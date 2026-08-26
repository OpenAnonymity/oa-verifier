package openrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openanonymity/oa-verifier/internal/config"
	"github.com/openanonymity/oa-verifier/internal/netretry"
)

const (
	currentUserAPIPath        = "/api/frontend/v1/private/users/current"
	userWorkspacesAPIPath     = "/api/frontend/v1/private/user/workspaces"
	managementKeysAPIPath     = "/api/frontend/v1/private/management-keys"
	workspaceAPIKeysAPIPath   = "/api/frontend/v1/private/workspace-api-keys"
	privacySettingsPagePath   = "/settings/privacy"
	managementKeysPagePath    = "/settings/management-keys"
	workspaceSettingsPagePath = "/workspaces/default/settings"
	maxFrontendResponseBytes  = 4 << 20
	maxManagementKeyPages     = 200
)

const maxRetries = 5

var retryCfg = netretry.DefaultConfig(maxRetries)

// RequestResponseError captures OpenRouter request/response metadata for failures.
// Context deliberately summarizes bodies and redacts credential-bearing headers.
type RequestResponseError struct {
	Operation       string
	Method          string
	URL             string
	RequestHeaders  map[string]string
	RequestBody     string
	ResponseStatus  int
	ResponseHeaders map[string]string
	ResponseBody    string
	Err             error
}

func (e *RequestResponseError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("%s failed: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("%s failed", e.Operation)
}

func (e *RequestResponseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *RequestResponseError) Context() map[string]any {
	if e == nil {
		return nil
	}
	return map[string]any{
		"openrouter_operation": e.Operation,
		"openrouter_request": map[string]any{
			"method":  e.Method,
			"url":     e.URL,
			"headers": e.RequestHeaders,
			"body":    safeBodySummary(e.RequestBody),
		},
		"openrouter_response": map[string]any{
			"status_code": e.ResponseStatus,
			"headers":     e.ResponseHeaders,
			"body":        safeBodySummary(e.ResponseBody),
		},
	}
}

// ErrorContext extracts OpenRouter request/response context from wrapped errors.
func ErrorContext(err error) map[string]any {
	type contextErr interface {
		Context() map[string]any
	}
	for err != nil {
		if ce, ok := err.(contextErr); ok {
			return ce.Context()
		}
		err = errors.Unwrap(err)
	}
	return nil
}

// IsSessionAuthError reports whether OpenRouter explicitly rejected the
// refreshed browser session. Callers can distinguish this from endpoint/schema
// drift and upstream failures instead of reporting every verifier error as a
// bad cookie.
func IsSessionAuthError(err error) bool {
	var requestErr *RequestResponseError
	if !errors.As(err, &requestErr) {
		return false
	}
	return requestErr.ResponseStatus == http.StatusUnauthorized ||
		requestErr.ResponseStatus == http.StatusForbidden
}

func flattenHeaders(h http.Header) map[string]string {
	if h == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(h))
	for k, vals := range h {
		switch strings.ToLower(k) {
		case "authorization", "cookie", "proxy-authorization", "set-cookie":
			out[k] = "[REDACTED]"
		default:
			out[k] = strings.Join(vals, ", ")
		}
	}
	return out
}

func safeBodySummary(body string) string {
	if body == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("[REDACTED: %d bytes, sha256:%x]", len(body), sum)
}

// Shared HTTP client with connection pooling
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

// frontendBaseURL is replaceable by package tests. Production always uses the
// attested OpenRouter origin from config.
var frontendBaseURL = config.BaseURL

// doFrontendJSON calls one of OpenRouter's cookie-authenticated frontend APIs.
// GET and PATCH requests retry transient failures. POST is deliberately attempted
// once because retrying an ambiguous management-key creation can orphan keys.
func doFrontendJSON(auth *Auth, operation, method, path, refererPath string, payload any) ([]byte, error) {
	var requestBody []byte
	var err error
	if payload != nil {
		requestBody, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("%s: encode request: %w", operation, err)
		}
	}

	attempts := maxRetries
	if method == http.MethodPost {
		attempts = 1
	}

	client := auth.client
	if client == nil {
		client = httpClient
	}

	requestURL := strings.TrimRight(frontendBaseURL, "/") + path
	for attempt := 1; attempt <= attempts; attempt++ {
		var bodyReader io.Reader
		if requestBody != nil {
			bodyReader = bytes.NewReader(requestBody)
		}

		req, err := http.NewRequest(method, requestURL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("%s: build request: %w", operation, err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Origin", strings.TrimRight(frontendBaseURL, "/"))
		if refererPath != "" {
			req.Header.Set("Referer", strings.TrimRight(frontendBaseURL, "/")+refererPath)
		}
		if requestBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, cookie := range auth.GetCookies() {
			req.AddCookie(cookie)
		}

		resp, err := client.Do(req)
		if err != nil {
			slog.Warn(operation+" request failed", "attempt", attempt, "error", err)
			if attempt < attempts {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return nil, &RequestResponseError{
				Operation:      operation,
				Method:         req.Method,
				URL:            req.URL.String(),
				RequestHeaders: flattenHeaders(req.Header),
				RequestBody:    string(requestBody),
				Err:            err,
			}
		}

		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxFrontendResponseBytes+1))
		resp.Body.Close()
		finalURL := req.URL.String()
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}

		if readErr != nil {
			return nil, &RequestResponseError{
				Operation:       operation,
				Method:          req.Method,
				URL:             finalURL,
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     string(requestBody),
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				Err:             fmt.Errorf("read response: %w", readErr),
			}
		}
		if len(responseBody) > maxFrontendResponseBytes {
			return nil, &RequestResponseError{
				Operation:       operation,
				Method:          req.Method,
				URL:             finalURL,
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     string(requestBody),
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				ResponseBody:    string(responseBody[:maxFrontendResponseBytes]),
				Err:             fmt.Errorf("response exceeds %d bytes", maxFrontendResponseBytes),
			}
		}

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			var statusErr error
			switch resp.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden:
				statusErr = fmt.Errorf("OpenRouter session rejected with status %d", resp.StatusCode)
			case http.StatusNotFound:
				statusErr = fmt.Errorf("OpenRouter frontend API contract missing (status 404)")
			default:
				statusErr = fmt.Errorf("OpenRouter frontend API returned status %d", resp.StatusCode)
			}
			if method != http.MethodPost && netretry.ShouldRetry(resp.StatusCode, nil) && attempt < attempts {
				_ = netretry.Sleep(context.Background(), attempt, retryCfg)
				continue
			}
			return nil, &RequestResponseError{
				Operation:       operation,
				Method:          req.Method,
				URL:             finalURL,
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     string(requestBody),
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				ResponseBody:    string(responseBody),
				Err:             statusErr,
			}
		}

		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if len(bytes.TrimSpace(responseBody)) > 0 && !strings.Contains(contentType, "application/json") {
			return nil, &RequestResponseError{
				Operation:       operation,
				Method:          req.Method,
				URL:             finalURL,
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     string(requestBody),
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				ResponseBody:    string(responseBody),
				Err:             fmt.Errorf("unexpected content type %q", resp.Header.Get("Content-Type")),
			}
		}

		return responseBody, nil
	}

	return nil, fmt.Errorf("%s failed after %d attempts", operation, attempts)
}

func decodeDataObject(body []byte, operation string) (map[string]any, error) {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%s: decode response: %w", operation, err)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, fmt.Errorf("%s: response missing data object", operation)
	}

	var data map[string]any
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return nil, fmt.Errorf("%s: decode data object: %w", operation, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: response data is empty or not an object", operation)
	}
	return data, nil
}

// FetchActivityData fetches account identity and privacy toggles from the
// current-user JSON endpoint. It does not depend on Next.js bundle internals.
func FetchActivityData(auth *Auth) (map[string]any, error) {
	body, err := doFrontendJSON(
		auth,
		"fetch_activity_data",
		http.MethodGet,
		currentUserAPIPath,
		privacySettingsPagePath,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return decodeDataObject(body, "fetch_activity_data")
}

// FetchWorkspaceData fetches the station account's default workspace settings.
func FetchWorkspaceData(auth *Auth) (map[string]any, error) {
	query := url.Values{"scope": []string{"member"}}
	body, err := doFrontendJSON(
		auth,
		"fetch_workspace_data",
		http.MethodGet,
		userWorkspacesAPIPath+"?"+query.Encode(),
		workspaceSettingsPagePath,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Data               []map[string]any `json:"data"`
		ActiveWorkspaceID  string           `json:"active_workspace_id"`
		DefaultWorkspaceID string           `json:"default_workspace_id"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("fetch_workspace_data: decode response: %w", err)
	}
	if envelope.DefaultWorkspaceID == "" {
		return nil, fmt.Errorf("fetch_workspace_data: response missing default_workspace_id")
	}

	for _, workspace := range envelope.Data {
		if id, _ := workspace["id"].(string); id == envelope.DefaultWorkspaceID {
			return workspace, nil
		}
	}

	return nil, fmt.Errorf(
		"fetch_workspace_data: default workspace %q absent from %d memberships",
		envelope.DefaultWorkspaceID,
		len(envelope.Data),
	)
}

type managementKeyMetadata struct {
	Hash    string `json:"hash"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

func parseManagementKeysPage(body []byte) ([]managementKeyMetadata, int, error) {
	var envelope struct {
		Data *struct {
			Keys       *[]managementKeyMetadata `json:"keys"`
			TotalCount *int                     `json:"total_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, 0, fmt.Errorf("fetch_provisioning_keys: decode response: %w", err)
	}
	if envelope.Data == nil || envelope.Data.Keys == nil || envelope.Data.TotalCount == nil {
		return nil, 0, fmt.Errorf("fetch_provisioning_keys: response missing data.keys or data.total_count")
	}
	if *envelope.Data.TotalCount < 0 {
		return nil, 0, fmt.Errorf("fetch_provisioning_keys: response has negative data.total_count")
	}
	return *envelope.Data.Keys, *envelope.Data.TotalCount, nil
}

// FetchProvisioningKeys fetches every account management/provisioning key.
// OpenRouter paginates this endpoint, so cleanup must follow all pages or it can
// silently leave an older same-label verifier key behind.
func FetchProvisioningKeys(auth *Auth) ([]map[string]string, error) {
	keys := make([]map[string]string, 0)
	seen := make(map[string]struct{})

	for page := 1; page <= maxManagementKeyPages; page++ {
		query := url.Values{"page": []string{strconv.Itoa(page)}}
		body, err := doFrontendJSON(
			auth,
			"fetch_provisioning_keys",
			http.MethodGet,
			managementKeysAPIPath+"?"+query.Encode(),
			managementKeysPagePath,
			nil,
		)
		if err != nil {
			return nil, err
		}

		pageKeys, totalCount, err := parseManagementKeysPage(body)
		if err != nil {
			return nil, err
		}
		if len(pageKeys) == 0 {
			if len(seen) >= totalCount {
				return keys, nil
			}
			return nil, fmt.Errorf(
				"fetch_provisioning_keys: pagination ended after %d of %d keys",
				len(seen),
				totalCount,
			)
		}

		added := 0
		for _, key := range pageKeys {
			if key.Hash == "" {
				continue
			}
			if _, exists := seen[key.Hash]; exists {
				continue
			}
			seen[key.Hash] = struct{}{}
			added++
			if key.Deleted || key.Name == "" {
				continue
			}
			keys = append(keys, map[string]string{
				"name": key.Name,
				"hash": key.Hash,
			})
		}
		if len(seen) >= totalCount {
			return keys, nil
		}
		if added == 0 {
			return nil, fmt.Errorf(
				"fetch_provisioning_keys: page %d made no progress after %d of %d keys",
				page,
				len(seen),
				totalCount,
			)
		}
	}

	return nil, fmt.Errorf("fetch_provisioning_keys: exceeded %d pages", maxManagementKeyPages)
}

var managementKeyHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DeleteProvisioningKey deletes a management/provisioning key by hash.
func DeleteProvisioningKey(auth *Auth, keyHash string) error {
	if !managementKeyHashRe.MatchString(keyHash) {
		return fmt.Errorf("delete_provisioning_key: invalid key hash")
	}

	payload := map[string]any{
		"payload": map[string]bool{"deleted": true},
		"opts":    map[string]bool{"is_provisioning_key": true},
	}
	body, err := doFrontendJSON(
		auth,
		"delete_provisioning_key",
		http.MethodPatch,
		workspaceAPIKeysAPIPath+"/"+url.PathEscape(keyHash),
		managementKeysPagePath,
		payload,
	)
	if err != nil {
		return err
	}

	var envelope struct {
		Data *struct {
			Deleted *bool `json:"deleted"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("delete_provisioning_key: decode response: %w", err)
	}
	if envelope.Data == nil || envelope.Data.Deleted == nil || !*envelope.Data.Deleted {
		return fmt.Errorf("delete_provisioning_key: response did not confirm deletion")
	}
	slog.Info("deleted provisioning key")
	return nil
}

// CleanupOperationError identifies the failing operation in provisioning-key cleanup.
type CleanupOperationError struct {
	Operation string
	Err       error
}

func (e *CleanupOperationError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s failed: %v", e.Operation, e.Err)
}

func (e *CleanupOperationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// CleanupProvisioningKeys deletes all provisioning keys matching the label.
func CleanupProvisioningKeys(auth *Auth, label string) (int, error) {
	keys, err := FetchProvisioningKeys(auth)
	if err != nil {
		return 0, &CleanupOperationError{
			Operation: "management_key_list",
			Err:       err,
		}
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
	deleteFailures := 0
	var firstErr error
	for _, k := range matching {
		if err := DeleteProvisioningKey(auth, k["hash"]); err == nil {
			deleted++
		} else {
			deleteFailures++
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	slog.Info("cleaned up provisioning keys", "label", label, "deleted", deleted, "total", len(matching))
	if deleteFailures > 0 {
		err := fmt.Errorf("failed to delete %d of %d matching keys", deleteFailures, len(matching))
		if firstErr != nil {
			err = fmt.Errorf("failed to delete %d of %d matching keys: %w", deleteFailures, len(matching), firstErr)
		}
		return deleted, &CleanupOperationError{
			Operation: "management_key_cleanup",
			Err:       err,
		}
	}
	return deleted, nil
}

// CreateProvisioningKey creates a new management/provisioning key and returns
// its plaintext value. OpenRouter only returns the plaintext once.
func CreateProvisioningKey(auth *Auth, label string) (string, error) {
	if strings.TrimSpace(label) == "" {
		return "", fmt.Errorf("create_provisioning_key: label is required")
	}

	body, err := doFrontendJSON(
		auth,
		"create_provisioning_key",
		http.MethodPost,
		workspaceAPIKeysAPIPath+"/management",
		managementKeysPagePath,
		map[string]string{"name": label},
	)
	if err != nil {
		var requestErr *RequestResponseError
		if errors.As(err, &requestErr) &&
			requestErr.ResponseStatus >= http.StatusBadRequest &&
			requestErr.ResponseStatus < http.StatusInternalServerError {
			return "", err
		}
		return "", reconcileAmbiguousCreate(auth, label, err)
	}

	var envelope struct {
		Data *struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", reconcileAmbiguousCreate(
			auth,
			label,
			fmt.Errorf("create_provisioning_key: decode response: %w", err),
		)
	}
	if envelope.Data == nil || !strings.HasPrefix(envelope.Data.Key, "sk-or-") {
		return "", reconcileAmbiguousCreate(
			auth,
			label,
			fmt.Errorf("create_provisioning_key: response missing a valid key"),
		)
	}

	return envelope.Data.Key, nil
}

// reconcileAmbiguousCreate removes a same-label key that may have been created
// when OpenRouter accepted the POST but the response was lost or malformed.
func reconcileAmbiguousCreate(auth *Auth, label string, createErr error) error {
	deleted, cleanupErr := CleanupProvisioningKeys(auth, label)
	if cleanupErr != nil {
		return fmt.Errorf(
			"create_provisioning_key was ambiguous and orphan cleanup failed: %v: %w",
			cleanupErr,
			createErr,
		)
	}
	if deleted > 0 {
		return fmt.Errorf(
			"create_provisioning_key response was ambiguous; cleaned up %d possible orphan(s): %w",
			deleted,
			createErr,
		)
	}
	return createErr
}

// OwnershipCheckResult describes the ownership check outcome.
type OwnershipCheckResult struct {
	Owned           bool
	NotOwned        bool
	StatusCode      int
	Body            string
	RequestMethod   string
	RequestURL      string
	RequestHeaders  map[string]string
	RequestBody     string
	ResponseHeaders map[string]string
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
		StatusCode:      resp.StatusCode,
		Body:            string(body),
		RequestMethod:   req.Method,
		RequestURL:      req.URL.String(),
		RequestHeaders:  flattenHeaders(req.Header),
		RequestBody:     "",
		ResponseHeaders: flattenHeaders(resp.Header),
	}

	if resp.StatusCode == 404 {
		// OpenRouter returns {"error":{"message":"API key not found","code":404}}
		// when a key genuinely doesn't belong to the authenticated account.
		// A transient infrastructure 404 would have a different body (or none).
		//
		// We set NotOwned only when the body confirms genuine non-ownership.
		// The caller still retries all 404s (transient or not) before acting
		// on this flag — see handleSubmitKey in handlers.go.
		var errResp struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil &&
			strings.EqualFold(errResp.Error.Message, "API key not found") {
			slog.Warn("key not found (definitive)", "hash", keyHash[:16])
			result.NotOwned = true
		} else {
			slog.Warn("key lookup 404 with unexpected body", "hash", keyHash[:16],
				"body", string(body))
		}
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
		return "", fmt.Errorf("STATION_REGISTRY_URL not configured")
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
	SchemaVersion int            `json:"schema_version"`
	EventID       string         `json:"event_id"`
	Event         string         `json:"event"`
	Source        string         `json:"source"`
	OccurredAt    string         `json:"occurred_at"`
	Severity      string         `json:"severity,omitempty"`
	StationID     string         `json:"station_id,omitempty"`
	Message       string         `json:"message,omitempty"`
	Operation     string         `json:"operation,omitempty"`
	StatusCode    int            `json:"status_code,omitempty"`
	Details       map[string]any `json:"details"`
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
