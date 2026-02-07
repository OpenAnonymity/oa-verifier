package server

import (
	"time"

	"github.com/oa-verifier/internal/config"
)

func (s *Server) markTransientFailure(pk, reason string, statusCode int, detail string) bool {
	graceSeconds := config.StationFailureGraceSeconds()
	graceWindow := time.Duration(graceSeconds) * time.Second
	now := time.Now()

	s.mu.Lock()
	station, ok := s.stations[pk]
	if !ok {
		s.mu.Unlock()
		return false
	}

	if station.FailureFirstAt == nil {
		station.FailureFirstAt = &now
	}
	station.FailureLastAt = &now
	station.FailureReason = reason
	station.FailureDetail = detail
	station.FailureStatus = statusCode
	station.FailureCount++

	first := station.FailureFirstAt
	s.mu.Unlock()

	if graceWindow <= 0 || first == nil {
		return false
	}
	return now.Sub(*first) < graceWindow
}

func (s *Server) clearTransientFailure(pk string) {
	s.mu.Lock()
	if station, ok := s.stations[pk]; ok {
		station.FailureFirstAt = nil
		station.FailureLastAt = nil
		station.FailureReason = ""
		station.FailureDetail = ""
		station.FailureStatus = 0
		station.FailureCount = 0
	}
	s.mu.Unlock()
}

func (s *Server) getTransientFailure(pk string) (reason string, statusCode int, detail string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if station, ok := s.stations[pk]; ok {
		return station.FailureReason, station.FailureStatus, station.FailureDetail
	}
	return "", 0, ""
}
