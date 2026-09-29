package certstore

import (
	"fmt"
	"strings"
)

// Environment variables understood by FromEnv. Every one of them must be
// listed in the CCE policy's optional_env_vars (build-and-sign.yml, "Generate
// CCE policy" step) or the confidential container will refuse to start.
const (
	// EnvStore selects the backend: none (default) | file | file-sealed | keyvault-sealed.
	EnvStore = "TLS_CERT_STORE"
	// EnvStoreDir is the directory for file and file-sealed.
	EnvStoreDir = "TLS_CERT_STORE_DIR"
	// EnvKEKVault is the Key Vault / Managed HSM URL holding the release-policy key (sealed modes).
	EnvKEKVault = "TLS_CERT_KEK_VAULT"
	// EnvKEKName is the name of that key (sealed modes).
	EnvKEKName = "TLS_CERT_KEK_NAME"
	// EnvSKRURL overrides the sidecar release endpoint (default DefaultSKRReleaseURL).
	EnvSKRURL = "TLS_CERT_SKR_URL"
	// EnvSecretVault is the Key Vault URL holding the sealed bundle secret (keyvault-sealed).
	EnvSecretVault = "TLS_CERT_SECRET_VAULT"
	// EnvSecretName is that secret's name (keyvault-sealed; default DefaultSecretName).
	EnvSecretName = "TLS_CERT_SECRET_NAME"
	// EnvMSIClientID selects a user-assigned identity for Key Vault access (keyvault-sealed, optional).
	EnvMSIClientID = "TLS_CERT_MSI_CLIENT_ID"
	// EnvMAAProvider is the existing attestation authority variable reused as maa_endpoint.
	EnvMAAProvider = "MAA_PROVIDER_URL"
)

// DefaultSecretName is used when TLS_CERT_SECRET_NAME is unset.
const DefaultSecretName = "oa-verifier-tls-bundle"

// DefaultMAAProvider matches the value the deployment template sets.
const DefaultMAAProvider = "sharedeus.eus.attest.azure.net"

// FromEnv builds the Store selected by TLS_CERT_STORE. An empty or "none"
// value returns NoopStore, i.e. exactly the pre-persistence behaviour. The
// returned string describes the configuration for logging. Misconfiguration
// (a mode without its required variables) is an error so that it is caught at
// deploy time instead of silently burning certificate quota.
func FromEnv(getenv func(string) string) (Store, string, error) {
	mode := strings.ToLower(strings.TrimSpace(getenv(EnvStore)))
	switch mode {
	case "", "none":
		return NoopStore{}, "none", nil

	case "file":
		fs, err := NewFileStore(getenv(EnvStoreDir))
		if err != nil {
			return nil, "", fmt.Errorf("%s=file requires %s: %w", EnvStore, EnvStoreDir, err)
		}
		return fs, "file:" + fs.Dir, nil

	case "file-sealed":
		fs, err := NewFileStore(getenv(EnvStoreDir))
		if err != nil {
			return nil, "", fmt.Errorf("%s=file-sealed requires %s: %w", EnvStore, EnvStoreDir, err)
		}
		rel, err := releaserFromEnv(getenv)
		if err != nil {
			return nil, "", err
		}
		st, err := NewSealedStore(fs, rel)
		if err != nil {
			return nil, "", err
		}
		return st, fmt.Sprintf("file-sealed:%s kek=%s/%s", fs.Dir, rel.AKVEndpoint, rel.KID), nil

	case "keyvault-sealed":
		rel, err := releaserFromEnv(getenv)
		if err != nil {
			return nil, "", err
		}
		vault := getenv(EnvSecretVault)
		if vault == "" {
			return nil, "", fmt.Errorf("%s=keyvault-sealed requires %s", EnvStore, EnvSecretVault)
		}
		name := getenv(EnvSecretName)
		if name == "" {
			name = DefaultSecretName
		}
		tokens := NewMSITokenSourceFromEnv(getenv, getenv(EnvMSIClientID))
		kv, err := NewKeyVaultSecretStore(vault, name, tokens)
		if err != nil {
			return nil, "", err
		}
		st, err := NewSealedStore(kv, rel)
		if err != nil {
			return nil, "", err
		}
		return st, fmt.Sprintf("keyvault-sealed:%s/secrets/%s kek=%s/%s", kv.VaultURL, kv.SecretName, rel.AKVEndpoint, rel.KID), nil

	default:
		return nil, "", fmt.Errorf("unknown %s value %q (none|file|file-sealed|keyvault-sealed)", EnvStore, mode)
	}
}

func releaserFromEnv(getenv func(string) string) (*SKRReleaser, error) {
	vault := getenv(EnvKEKVault)
	name := getenv(EnvKEKName)
	if vault == "" || name == "" {
		return nil, fmt.Errorf("sealed %s modes require %s and %s", EnvStore, EnvKEKVault, EnvKEKName)
	}
	maa := getenv(EnvMAAProvider)
	if maa == "" {
		maa = DefaultMAAProvider
	}
	return &SKRReleaser{
		URL:         getenv(EnvSKRURL),
		MAAEndpoint: maa,
		AKVEndpoint: NormalizeVaultURL(vault),
		KID:         name,
	}, nil
}
