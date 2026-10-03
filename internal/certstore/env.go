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
		rel, err := ReleaserFromEnv(getenv, EnvStore)
		if err != nil {
			return nil, "", err
		}
		st, err := NewSealedStore(fs, rel)
		if err != nil {
			return nil, "", err
		}
		return st, fmt.Sprintf("file-sealed:%s kek=%s/%s", fs.Dir, rel.AKVEndpoint, rel.KID), nil

	case "keyvault-sealed":
		rel, err := ReleaserFromEnv(getenv, EnvStore)
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

// ReleaserFromEnv builds the SKR key releaser from the shared KEK variables
// (TLS_CERT_KEK_VAULT, TLS_CERT_KEK_NAME, TLS_CERT_SKR_URL, MAA_PROVIDER_URL).
// modeVar names the *_STORE variable being configured, for the error message.
func ReleaserFromEnv(getenv func(string) string, modeVar string) (*SKRReleaser, error) {
	vault := getenv(EnvKEKVault)
	name := getenv(EnvKEKName)
	if vault == "" || name == "" {
		return nil, fmt.Errorf("sealed %s modes require %s and %s", modeVar, EnvKEKVault, EnvKEKName)
	}
	maa := getenv(EnvMAAProvider)
	if maa == "" {
		maa = DefaultMAAProvider
	}
	rel := &SKRReleaser{
		URL:         getenv(EnvSKRURL),
		MAAEndpoint: maa,
		AKVEndpoint: NormalizeVaultURL(vault),
		KID:         name,
	}
	// With a user-assigned identity named explicitly, hand the sidecar a token
	// for that identity rather than letting it pick one itself.
	if clientID := getenv(EnvMSIClientID); clientID != "" {
		rel.Tokens = NewMSITokenSourceFromEnv(getenv, clientID)
	}
	return rel, nil
}

// BlobSpec describes one persisted object and the backend that stores it.
// It lets other packages (the station registry) reuse the same four backends
// and the same KEK as the certificate bundle while keeping their own file
// name, secret name and sealing purpose.
type BlobSpec struct {
	// ModeVar is the environment variable that selected Mode (for messages).
	ModeVar string
	// Mode is "", none, file, file-sealed or keyvault-sealed.
	Mode string
	// Dir is the directory for the file modes.
	Dir string
	// DirVar names the variable Dir came from (for messages).
	DirVar string
	// FileName is the file inside Dir for the file modes.
	FileName string
	// SecretName is the Key Vault secret for keyvault-sealed.
	SecretName string
	// Purpose is the sealing domain; "" is reserved for the TLS bundle.
	Purpose string
}

// BlobStoreFromEnv builds the BlobStore described by spec. The vault holding
// the secret, the KEK, the SKR endpoint and the managed identity come from the
// shared TLS_CERT_* variables, so one Key Vault setup serves every blob.
// Mode "" or none returns (nil, "none", nil): the caller decides what "off"
// means for its data. Misconfiguration is an error so it surfaces at start-up.
func BlobStoreFromEnv(getenv func(string) string, spec BlobSpec) (BlobStore, string, error) {
	mode := strings.ToLower(strings.TrimSpace(spec.Mode))
	switch mode {
	case "", "none":
		return nil, "none", nil

	case "file":
		fs, err := NewFileStoreNamed(spec.Dir, spec.FileName)
		if err != nil {
			return nil, "", fmt.Errorf("%s=file requires %s: %w", spec.ModeVar, spec.DirVar, err)
		}
		return fs, "file:" + fs.path(), nil

	case "file-sealed":
		fs, err := NewFileStoreNamed(spec.Dir, spec.FileName)
		if err != nil {
			return nil, "", fmt.Errorf("%s=file-sealed requires %s: %w", spec.ModeVar, spec.DirVar, err)
		}
		rel, err := ReleaserFromEnv(getenv, spec.ModeVar)
		if err != nil {
			return nil, "", err
		}
		st, err := NewSealedBlobStore(fs, rel, spec.Purpose)
		if err != nil {
			return nil, "", err
		}
		return st, fmt.Sprintf("file-sealed:%s kek=%s/%s", fs.path(), rel.AKVEndpoint, rel.KID), nil

	case "keyvault-sealed":
		rel, err := ReleaserFromEnv(getenv, spec.ModeVar)
		if err != nil {
			return nil, "", err
		}
		vault := getenv(EnvSecretVault)
		if vault == "" {
			return nil, "", fmt.Errorf("%s=keyvault-sealed requires %s", spec.ModeVar, EnvSecretVault)
		}
		if spec.SecretName == "" {
			return nil, "", fmt.Errorf("%s=keyvault-sealed requires a secret name", spec.ModeVar)
		}
		tokens := NewMSITokenSourceFromEnv(getenv, getenv(EnvMSIClientID))
		kv, err := NewKeyVaultSecretStore(vault, spec.SecretName, tokens)
		if err != nil {
			return nil, "", err
		}
		st, err := NewSealedBlobStore(kv, rel, spec.Purpose)
		if err != nil {
			return nil, "", err
		}
		return st, fmt.Sprintf("keyvault-sealed:%s/secrets/%s kek=%s/%s", kv.VaultURL, kv.SecretName, rel.AKVEndpoint, rel.KID), nil

	default:
		return nil, "", fmt.Errorf("unknown %s value %q (none|file|file-sealed|keyvault-sealed)", spec.ModeVar, spec.Mode)
	}
}
