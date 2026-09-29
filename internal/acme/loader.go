package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/openanonymity/oa-verifier/internal/certstore"
)

// Source says where the certificate returned by LoadOrObtain came from.
type Source string

const (
	// SourcePersisted: the stored certificate was valid for more than
	// RenewBefore and matched the domain; the CA was not contacted.
	SourcePersisted Source = "persisted"
	// SourceObtained: a new certificate was issued (and saved).
	SourceObtained Source = "obtained"
	// SourcePersistedNearExpiry: issuing failed but the stored certificate is
	// still valid, so it is served and the renewal loop retries. This is the
	// path that must never degrade to self-signed.
	SourcePersistedNearExpiry Source = "persisted-near-expiry"
)

// Obtainer issues a new certificate. existing, when non-nil, carries a
// persisted ACME account (AccountKeyPEM / AccountURI) that should be reused
// instead of registering a new one.
type Obtainer func(ctx context.Context, existing *certstore.Bundle) (*certstore.Bundle, error)

// CheckBundle reports whether b can be served for domain at time now with at
// least minRemaining validity left, and was issued by the CA at caDirURL
// (an empty caDirURL in the bundle is accepted for forward compatibility).
func CheckBundle(b *certstore.Bundle, domain, caDirURL string, now time.Time, minRemaining time.Duration) error {
	if b == nil {
		return errors.New("no bundle")
	}
	if b.CADirURL != "" && caDirURL != "" && b.CADirURL != caDirURL {
		return fmt.Errorf("issued by %s, configured CA is %s", b.CADirURL, caDirURL)
	}
	cert, _, err := b.TLSCertificate()
	if err != nil {
		return err
	}
	leaf := cert.Leaf
	if err := leaf.VerifyHostname(domain); err != nil {
		return fmt.Errorf("certificate does not cover %q: %w", domain, err)
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("certificate not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	remaining := leaf.NotAfter.Sub(now)
	if remaining <= minRemaining {
		return fmt.Errorf("certificate expires in %s (need more than %s)", remaining.Round(time.Hour), minRemaining)
	}
	return nil
}

// LoadOrObtain implements the start-up decision:
//
//  1. Load from store. A valid bundle for cfg.Domain with more than RenewBefore
//     left is used as is; the CA is not contacted.
//  2. Otherwise obtain a new certificate, reusing the persisted ACME account
//     when the bundle came from the same CA, and Save the result.
//  3. If obtaining fails but the persisted certificate is still valid, serve
//     it anyway (the renewal loop keeps retrying) rather than failing.
//
// now may be nil (time.Now). Every path is logged with its Source.
func LoadOrObtain(ctx context.Context, cfg *Config, store certstore.Store, obtain Obtainer, now func() time.Time) (*certstore.Bundle, Source, error) {
	if store == nil {
		store = certstore.NoopStore{}
	}
	if now == nil {
		now = time.Now
	}
	caDir := cfg.CADirURL()

	stored, err := store.Load(ctx)
	switch {
	case err == nil:
		if cerr := CheckBundle(stored, cfg.Domain, caDir, now(), RenewBefore); cerr == nil {
			slog.Info("using persisted TLS certificate; skipping ACME issuance",
				"domain", cfg.Domain, "not_after", stored.NotAfter.UTC().Format(time.RFC3339),
				"account", stored.AccountURI)
			return stored, SourcePersisted, nil
		} else {
			slog.Info("persisted TLS certificate not reusable, obtaining a new one",
				"domain", cfg.Domain, "reason", cerr)
		}
	case errors.Is(err, certstore.ErrNotFound):
		slog.Info("no persisted TLS certificate, obtaining a new one", "domain", cfg.Domain)
	default:
		slog.Warn("failed to load persisted TLS certificate, obtaining a new one", "domain", cfg.Domain, "error", err)
	}

	// Only reuse the account if it belongs to the CA we are talking to.
	var existing *certstore.Bundle
	if stored != nil && len(stored.AccountKeyPEM) > 0 && (stored.CADirURL == "" || stored.CADirURL == caDir) {
		existing = stored
	}

	fresh, oerr := obtain(ctx, existing)
	if oerr == nil {
		if fresh == nil {
			oerr = errNoBundle
		} else if cerr := CheckBundle(fresh, cfg.Domain, caDir, now(), 0); cerr != nil {
			oerr = fmt.Errorf("obtained certificate is unusable: %w", cerr)
		}
	}
	if oerr == nil {
		if serr := store.Save(ctx, fresh); serr != nil {
			slog.Error("failed to persist TLS certificate; it will be re-issued on next restart", "domain", cfg.Domain, "error", serr)
		} else if _, noop := store.(certstore.NoopStore); !noop {
			slog.Info("TLS certificate persisted", "domain", cfg.Domain)
		}
		return fresh, SourceObtained, nil
	}

	// Issuance failed. Prefer a still-valid persisted certificate over anything else.
	if stored != nil {
		if cerr := CheckBundle(stored, cfg.Domain, caDir, now(), 0); cerr == nil {
			slog.Warn("ACME issuance failed; serving persisted certificate until renewal succeeds",
				"domain", cfg.Domain, "not_after", stored.NotAfter.UTC().Format(time.RFC3339), "error", oerr)
			return stored, SourcePersistedNearExpiry, nil
		}
	}
	return nil, "", oerr
}

// RetryPolicy controls NewRetryingObtainer.
type RetryPolicy struct {
	RegisterRetries int
	RegisterDelay   time.Duration
	ObtainRetries   int
	ObtainDelay     time.Duration
}

// DefaultRetryPolicy mirrors the historical start-up behaviour: registration
// is retried patiently (DNS provider / CA hiccups), issuance a few times.
var DefaultRetryPolicy = RetryPolicy{
	RegisterRetries: 10,
	RegisterDelay:   3 * time.Minute,
	ObtainRetries:   5,
	ObtainDelay:     15 * time.Second,
}

// bundleObtainer is the part of Client the retry helper needs.
type bundleObtainer interface {
	ObtainBundle(ctx context.Context) (*certstore.Bundle, error)
}

// NewRetryingObtainer returns an Obtainer that creates the ACME client
// (reusing the persisted account when given) with retries, then obtains the
// certificate with retries without re-registering. It returns ctx.Err() as
// soon as ctx is cancelled.
func NewRetryingObtainer(cfg *Config, p RetryPolicy) Obtainer {
	return func(ctx context.Context, existing *certstore.Bundle) (*certstore.Bundle, error) {
		return retryObtain(ctx, p, func() (bundleObtainer, error) {
			if existing != nil {
				return NewClientWithAccount(cfg, existing.AccountKeyPEM, existing.AccountURI)
			}
			return NewClient(cfg)
		})
	}
}

func retryObtain(ctx context.Context, p RetryPolicy, newClient func() (bundleObtainer, error)) (*certstore.Bundle, error) {
	if p.RegisterRetries < 1 {
		p.RegisterRetries = 1
	}
	if p.ObtainRetries < 1 {
		p.ObtainRetries = 1
	}

	var client bundleObtainer
	var err error
	for attempt := 1; ; attempt++ {
		client, err = newClient()
		if err == nil {
			break
		}
		if attempt >= p.RegisterRetries {
			slog.Error("ACME registration failed after all retries", "attempts", p.RegisterRetries, "error", err)
			return nil, err
		}
		slog.Warn("ACME registration failed, retrying", "attempt", attempt, "max_retries", p.RegisterRetries, "error", err)
		if werr := sleepCtx(ctx, p.RegisterDelay); werr != nil {
			return nil, werr
		}
	}

	for attempt := 1; ; attempt++ {
		b, oerr := client.ObtainBundle(ctx)
		if oerr == nil {
			return b, nil
		}
		err = oerr
		if attempt >= p.ObtainRetries {
			slog.Error("ACME certificate failed after all retries", "attempts", p.ObtainRetries, "error", err)
			return nil, err
		}
		slog.Warn("ACME certificate attempt failed, retrying", "attempt", attempt, "max_retries", p.ObtainRetries, "error", err)
		if werr := sleepCtx(ctx, p.ObtainDelay); werr != nil {
			return nil, werr
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
