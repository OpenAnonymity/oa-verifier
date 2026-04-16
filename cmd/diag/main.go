// Diagnostic tool: test privacy toggle verification with raw cookies.
//
// Usage:
//   OR_COOKIES='<raw Cookie header>' go run cmd/diag/main.go
//
// The cookie header can be copied from browser DevTools Network tab.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/openanonymity/oa-verifier/internal/challenge"
	"github.com/openanonymity/oa-verifier/internal/config"
	"github.com/openanonymity/oa-verifier/internal/openrouter"
)

func main() {
	rawCookies := os.Getenv("OR_COOKIES")
	jsonCreds := os.Getenv("OR_CREDS")
	if rawCookies == "" && jsonCreds == "" {
		fmt.Println("Usage:")
		fmt.Println("  OR_COOKIES='<raw Cookie header>' go run cmd/diag/main.go")
		fmt.Println("  OR_CREDS='{\"client_token\":\"...\",\"session_id\":\"...\",\"client_uat\":\"...\"}' go run cmd/diag/main.go")
		os.Exit(1)
	}

	fmt.Println("=== Step 1: Authenticate ===")
	var auth *openrouter.Auth
	var err error

	if jsonCreds != "" {
		// Parse structured JSON credentials
		var creds struct {
			ClientToken string `json:"client_token"`
			ClientUAT   string `json:"client_uat"`
			SessionID   string `json:"session_id"`
		}
		if e := json.Unmarshal([]byte(jsonCreds), &creds); e != nil {
			fmt.Printf("Failed to parse OR_CREDS JSON: %v\n", e)
			os.Exit(1)
		}
		fmt.Printf("Session ID: %s\n", creds.SessionID)
		fmt.Printf("Client token: %s...\n", creds.ClientToken[:min(30, len(creds.ClientToken))])

		// Build structured cookie data for NewAuthFromCookieData
		cookieData := map[string]any{
			"cookies": []any{
				map[string]any{"name": "__client", "value": creds.ClientToken, "domain": "clerk.openrouter.ai"},
				map[string]any{"name": "__client_uat", "value": creds.ClientUAT, "domain": "openrouter.ai"},
				map[string]any{"name": "clerk_active_context", "value": creds.SessionID + ":", "domain": "openrouter.ai"},
			},
		}
		auth, err = openrouter.NewAuthFromCookieData(cookieData)
	} else {
		auth, err = openrouter.NewAuthFromRawCookieHeader(rawCookies)
	}

	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		if ctx := openrouter.ErrorContext(err); ctx != nil {
			pretty, _ := json.MarshalIndent(ctx, "", "  ")
			fmt.Printf("\nError context:\n%s\n", string(pretty))
		}
		os.Exit(1)
	}
	fmt.Println("Authentication successful!")
	fmt.Printf("Action hashes: %v\n", auth.GetAllActionHashes())

	fmt.Println("\n=== Step 2: Fetch Activity Data ===")
	data, err := openrouter.FetchActivityData(auth)
	if err != nil {
		fmt.Printf("Failed to fetch activity data: %v\n", err)

		// Show error context if available
		if ctx := openrouter.ErrorContext(err); ctx != nil {
			pretty, _ := json.MarshalIndent(ctx, "", "  ")
			fmt.Printf("\nError context:\n%s\n", string(pretty))
		}
		os.Exit(1)
	}
	if data == nil {
		fmt.Println("Activity data is nil (empty response)")
		os.Exit(1)
	}

	fmt.Println("Activity data fetched successfully!")
	pretty, _ := json.MarshalIndent(data, "", "  ")
	fmt.Printf("\nUser data:\n%s\n", string(pretty))

	fmt.Println("\n=== Step 2b: Fetch Workspace Data ===")
	wsData, wsErr := openrouter.FetchWorkspaceData(auth)
	if wsErr != nil {
		fmt.Printf("Workspace data fetch failed: %v\n", wsErr)
	} else if wsData != nil {
		wsPretty, _ := json.MarshalIndent(wsData, "", "  ")
		fmt.Printf("Workspace data:\n%s\n", string(wsPretty))
	}

	// Merge user + workspace data for toggle checking
	merged := make(map[string]any)
	for k, v := range data {
		merged[k] = v
	}
	for k, v := range wsData {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}

	fmt.Println("\n=== Step 3: Check Privacy Toggles ===")
	result, details := challenge.CheckPrivacyToggles(merged)
	fmt.Printf("Result: %s\n", result)
	if len(details) > 0 {
		fmt.Printf("Details: %v\n", details)
	}

	// Show which toggles were found and their values
	fmt.Println("\n=== Step 4: Toggle Inventory ===")
	fmt.Println("Required toggles (all must be false):")
	for name, required := range config.OpenRouterRequiredToggles {
		val, found := findToggleValue(merged, name)
		source := ""
		if found {
			if _, inUser := findToggleValue(data, name); inUser {
				source = " [user]"
			} else {
				source = " [workspace]"
			}
		}
		status := "MISSING"
		if found {
			if val == required {
				status = fmt.Sprintf("OK (%v)%s", val, source)
			} else {
				status = fmt.Sprintf("INVALID (got %v, expected %v)%s", val, required, source)
			}
		}
		fmt.Printf("  %-40s %s\n", name, status)
	}

	// List all boolean-like fields in merged response
	fmt.Println("\nAll boolean fields (merged):")
	listBoolFields(merged, "")
}

func findToggleValue(data map[string]any, name string) (bool, bool) {
	nameLower := strings.ToLower(name)
	return searchMap(data, nameLower, "")
}

func searchMap(data map[string]any, target, prefix string) (bool, bool) {
	for k, v := range data {
		keyLower := strings.ToLower(k)
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		pathLower := strings.ToLower(path)

		if keyLower == target || pathLower == target || strings.HasSuffix(pathLower, "."+target) {
			if b, ok := v.(bool); ok {
				return b, true
			}
		}

		if nested, ok := v.(map[string]any); ok {
			if val, found := searchMap(nested, target, path); found {
				return val, true
			}
		}
		if arr, ok := v.([]any); ok {
			for _, item := range arr {
				if nested, ok := item.(map[string]any); ok {
					if val, found := searchMap(nested, target, path); found {
						return val, true
					}
				}
			}
		}
	}
	return false, false
}

func listBoolFields(data map[string]any, prefix string) {
	for k, v := range data {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch t := v.(type) {
		case bool:
			fmt.Printf("  %s = %v\n", path, t)
		case map[string]any:
			listBoolFields(t, path)
		case []any:
			for i, item := range t {
				if m, ok := item.(map[string]any); ok {
					listBoolFields(m, fmt.Sprintf("%s[%d]", path, i))
				}
			}
		}
	}
}
