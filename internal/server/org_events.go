package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/openanonymity/oa-verifier/internal/openrouter"
)

type orgEvent struct {
	event                   string
	stationID               string
	publicKey               string
	email                   string
	reason                  string
	statusCode              int
	errorDetail             string
	operation               string
	consecutiveFailureCount int
	withinGrace             bool
	withinGraceSet          bool
	severity                string
	message                 string
	details                 map[string]any
}

func (s *Server) notifyOrgEvent(e orgEvent) {
	if e.event == "" {
		return
	}

	details := map[string]any{}
	if e.publicKey != "" {
		details["public_key"] = e.publicKey
	}
	if e.email != "" {
		details["email"] = e.email
	}
	if e.reason != "" {
		details["reason"] = e.reason
	}
	if e.errorDetail != "" {
		details["error_detail"] = e.errorDetail
	}
	if e.consecutiveFailureCount > 0 {
		details["consecutive_failure_count"] = e.consecutiveFailureCount
	}
	if e.withinGraceSet {
		details["within_grace"] = e.withinGrace
	}
	for k, v := range e.details {
		details[k] = v
	}
	severity := e.severity
	if severity == "" {
		severity = defaultSeverityForEvent(e.event)
	}
	message := e.message
	if message == "" {
		if e.reason != "" {
			message = e.reason
		} else {
			message = e.event
		}
	}

	update := openrouter.OrgUpdate{
		SchemaVersion: 1,
		EventID:       newEventID(),
		Event:         e.event,
		Source:        "oa-verifier",
		OccurredAt:    utcNow(),
		Severity:      severity,
		StationID:     e.stationID,
		Message:       message,
		Operation:     e.operation,
		StatusCode:    e.statusCode,
		Details:       details,
	}

	go func() {
		if err := openrouter.NotifyOrgUpdate(update); err != nil {
			slog.Warn("failed to notify org update", "event", e.event, "station_id", e.stationID, "error", err)
		}
	}()
}

func newEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "evt_fallback"
	}
	return "evt_" + hex.EncodeToString(b[:])
}

func defaultSeverityForEvent(event string) string {
	if _, ok := warningSeverityEvents[event]; ok {
		return "warning"
	}
	switch {
	case strings.Contains(event, "station_banned"), strings.Contains(event, "station_unregistered"):
		return "error"
	case strings.Contains(event, "failed"), strings.Contains(event, "forbidden"), strings.Contains(event, "rate_limited"):
		return "warning"
	default:
		return "info"
	}
}

var warningSeverityEvents = map[string]struct{}{
	"transient_failure_started":                {},
	"register_privacy_toggles_unverifiable":    {},
	"verification_no_cookie_data":              {},
	"verification_privacy_toggles_missing":     {},
	"verification_privacy_toggles_unparseable": {},
}

func normalizeOpFailureIdentity(stationID, publicKey string) string {
	if stationID != "" {
		return stationID
	}
	if publicKey != "" {
		return publicKey
	}
	return "unknown"
}

func opFailureKey(identity, operation string) string {
	if identity == "" {
		identity = "unknown"
	}
	if operation == "" {
		operation = "unknown"
	}
	return identity + "|" + operation
}

func (s *Server) incOpFailure(identity, operation string) int {
	key := opFailureKey(identity, operation)
	s.opFailureMu.Lock()
	defer s.opFailureMu.Unlock()
	s.opFailure[key]++
	return s.opFailure[key]
}

func (s *Server) clearOpFailure(identity, operation string) int {
	key := opFailureKey(identity, operation)
	s.opFailureMu.Lock()
	defer s.opFailureMu.Unlock()
	prev := s.opFailure[key]
	delete(s.opFailure, key)
	return prev
}
