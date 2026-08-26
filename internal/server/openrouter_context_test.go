package server

import (
	"errors"
	"net/http"
	"testing"

	"github.com/openanonymity/oa-verifier/internal/openrouter"
)

func TestClassifyOpenRouterReadFailure(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantMessage string
	}{
		{
			name: "session rejected",
			err: &openrouter.RequestResponseError{
				Operation:      "fetch_activity_data",
				ResponseStatus: http.StatusUnauthorized,
			},
			wantStatus:  http.StatusUnauthorized,
			wantMessage: "Failed to verify cookie",
		},
		{
			name: "frontend contract missing",
			err: &openrouter.RequestResponseError{
				Operation:      "fetch_activity_data",
				ResponseStatus: http.StatusNotFound,
			},
			wantStatus:  http.StatusBadGateway,
			wantMessage: "Unable to fetch OpenRouter verification data",
		},
		{
			name:        "schema drift",
			err:         errors.New("response missing data object"),
			wantStatus:  http.StatusBadGateway,
			wantMessage: "Unable to fetch OpenRouter verification data",
		},
		{
			name:        "empty response",
			err:         nil,
			wantStatus:  http.StatusBadGateway,
			wantMessage: "Unable to fetch OpenRouter verification data",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, message := classifyOpenRouterReadFailure(test.err)
			if status != test.wantStatus || message != test.wantMessage {
				t.Errorf("got (%d, %q), want (%d, %q)", status, message, test.wantStatus, test.wantMessage)
			}
		})
	}
}
