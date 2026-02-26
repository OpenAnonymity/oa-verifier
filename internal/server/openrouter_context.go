package server

import "github.com/openanonymity/oa-verifier/internal/openrouter"

func openrouterErrorDetails(err error) map[string]any {
	ctx := openrouter.ErrorContext(err)
	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

func openrouterOwnershipDetails(result openrouter.OwnershipCheckResult) map[string]any {
	return map[string]any{
		"openrouter_operation": "ownership_check",
		"openrouter_request": map[string]any{
			"method":  result.RequestMethod,
			"url":     result.RequestURL,
			"headers": result.RequestHeaders,
			"body":    result.RequestBody,
		},
		"openrouter_response": map[string]any{
			"status_code": result.StatusCode,
			"headers":     result.ResponseHeaders,
			"body":        result.Body,
		},
	}
}
