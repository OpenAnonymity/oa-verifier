package server

import (
	"context"
	"testing"
	"time"

	"github.com/openanonymity/oa-verifier/internal/models"
)

func TestGraceDeadlineUsesLastApprovalAndRejectsMissingEvidence(t *testing.T) {
	t.Setenv("STATION_FAILURE_GRACE_SECONDS", "")
	now := time.Now().UTC().Truncate(time.Second)
	approved := now.Add(-6 * 24 * time.Hour).Format(time.RFC3339)
	station := &models.Station{LastVerified: &approved, FailureFirstAt: &now}
	deadline, ok := stationFailureDeadline(station, now)
	if !ok || !deadline.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("deadline = %v, approved = %v", deadline, ok)
	}
	for _, stamp := range []string{"", "invalid", now.Add(time.Second).Format(time.RFC3339)} {
		station.LastVerified = &stamp
		if _, ok := stationFailureDeadline(station, now); ok {
			t.Fatal("invalid approval gained grace")
		}
	}
	station.LastVerified = nil
	if _, ok := stationFailureDeadline(station, now); ok {
		t.Fatal("unapproved station gained grace")
	}
}

func TestProviderFailureKeepsApprovedStationAndRestartDoesNotRenew(t *testing.T) {
	t.Setenv("STATION_FAILURE_GRACE_SECONDS", "")
	t.Setenv("STATION_REGISTRY_URL", "")
	store := &memStore{}
	s := newTestServer(t, store)
	pk := addStation(s, "grace")
	approved := time.Now().Add(-6 * 24 * time.Hour).UTC().Format(time.RFC3339)
	s.stations[pk].LastVerified = &approved
	if !s.markTransientFailure(pk, "activity_fetch_failed", 408, "timeout") {
		t.Fatal("previously approved station removed before seven days")
	}
	rows := broadcastOf(t, s)["verified_stations"].([]any)
	if len(rows) != 1 {
		t.Fatal("station missing from broadcast during grace")
	}
	row := rows[0].(map[string]any)
	if row["verification_state"] != "grace" || row["last_verified_at"] != approved {
		t.Fatal("historical approval misrepresented as a fresh check")
	}
	deadline := row["grace_until"]
	if err := s.persistOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored := newTestServer(t, store)
	restored.loadStationState(context.Background())
	if !restored.markTransientFailure(pk, "activity_fetch_failed", 408, "timeout") {
		t.Fatal("restored approval lost its remaining grace")
	}
	row = broadcastOf(t, restored)["verified_stations"].([]any)[0].(map[string]any)
	if row["grace_until"] != deadline {
		t.Fatal("restart or retry extended grace")
	}
	// Expiry must affect broadcast immediately, before the next background check.
	expired := time.Now().Add(-7*24*time.Hour - time.Second).UTC().Format(time.RFC3339)
	restored.stations[pk].LastVerified = &expired
	if len(broadcastOf(t, restored)["verified_stations"].([]any)) != 0 {
		t.Fatal("expired grace still advertised as available")
	}
	if restored.markTransientFailure(pk, "activity_fetch_failed", 408, "timeout") {
		t.Fatal("retry revived expired grace")
	}
}

func TestTransientChallengeRetainsStationButExpiryUnregisters(t *testing.T) {
	t.Setenv("STATION_FAILURE_GRACE_SECONDS", "")
	t.Setenv("STATION_REGISTRY_URL", "")
	s := newTestServer(t, &memStore{})
	pk := addStation(s, "challenge")
	approved := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	s.stations[pk].LastVerified = &approved
	s.stations[pk].CookieData = nil // deterministic provider-state unavailability
	s.challengeOneStation(context.Background(), pk, *s.stations[pk])
	if s.stations[pk] == nil || s.wasRemoved("station-challenge") {
		t.Fatal("transient challenge failure removed approved station")
	}
	expired := time.Now().Add(-7*24*time.Hour - time.Second).UTC().Format(time.RFC3339)
	s.stations[pk].LastVerified = &expired
	s.challengeOneStation(context.Background(), pk, *s.stations[pk])
	if s.stations[pk] != nil || !s.wasRemoved("station-challenge") {
		t.Fatal("expired station was not unregistered")
	}
}

func TestGraceNeverOverridesBanOrExplicitRemoval(t *testing.T) {
	t.Setenv("STATION_FAILURE_GRACE_SECONDS", "")
	t.Setenv("STATION_REGISTRY_URL", "")
	s := newTestServer(t, &memStore{})
	pk := addStation(s, "banned")
	s.markTransientFailure(pk, "activity_fetch_failed", 408, "timeout")
	s.banned.Ban("station-banned", pk, "banned@example.com", "privacy_toggles_invalid")
	if len(broadcastOf(t, s)["verified_stations"].([]any)) != 0 {
		t.Fatal("banned station retained in approved list")
	}
	other := addStation(s, "removed")
	s.unregisterStation("station-removed", other, "removed@example.com", "operator_revocation", 403, "", "", 0, false)
	if len(broadcastOf(t, s)["verified_stations"].([]any)) != 0 {
		t.Fatal("explicitly removed station retained by grace")
	}
}
