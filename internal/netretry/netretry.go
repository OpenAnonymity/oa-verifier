package netretry

import (
	"context"
	"math/rand"
	"net/http"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Config struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Jitter    time.Duration
}

func DefaultConfig(attempts int) Config {
	return Config{
		Attempts:  attempts,
		BaseDelay: 250 * time.Millisecond,
		MaxDelay:  2 * time.Second,
		Jitter:    200 * time.Millisecond,
	}
}

func ShouldRetry(status int, err error) bool {
	if err != nil {
		return true
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	return false
}

func BackoffDuration(attempt int, cfg Config) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := cfg.BaseDelay * time.Duration(1<<uint(attempt-1))
	if delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}
	if cfg.Jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(cfg.Jitter)))
	}
	return delay
}

func Sleep(ctx context.Context, attempt int, cfg Config) error {
	delay := BackoffDuration(attempt, cfg)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
