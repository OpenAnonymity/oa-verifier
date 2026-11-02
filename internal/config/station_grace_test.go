package config

import "testing"

func TestStationFailureGraceIsBounded(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{
		{"", 604800}, {"invalid", 604800}, {"-1", 604800},
		{"0", 0}, {"600", 600}, {"604800", 604800}, {"604801", 604800},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("STATION_FAILURE_GRACE_SECONDS", tc.value)
			if got := StationFailureGraceSeconds(); got != tc.want {
				t.Fatalf("grace = %d, want %d", got, tc.want)
			}
		})
	}
}
