package certstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Managed identity tokens (ACI MSI endpoint, IMDS fallback)
// ---------------------------------------------------------------------------

// IMDSTokenURL is the classic Azure Instance Metadata Service token endpoint.
const IMDSTokenURL = "http://169.254.169.254/metadata/identity/oauth2/token"

// TokenSource returns a bearer token for an Azure resource.
type TokenSource interface {
	Token(ctx context.Context, resource string) (string, error)
}

// MSITokenSource obtains tokens for the container group's managed identity.
//
// In Azure Container Instances the platform injects IDENTITY_ENDPOINT and
// IDENTITY_HEADER; the token request is
//
//	GET $IDENTITY_ENDPOINT?resource=<resource>&api-version=2019-08-01[&client_id=...]
//	X-IDENTITY-HEADER: $IDENTITY_HEADER
//
// When those variables are absent it falls back to IMDS
// (Metadata: true, api-version=2018-02-01), which is what the SKR sidecar
// itself uses (upstream pkg/common/token.go). Tokens are cached until five
// minutes before expiry.
type MSITokenSource struct {
	// Endpoint overrides the token endpoint (IDENTITY_ENDPOINT or IMDS).
	Endpoint string
	// Header is the value for X-IDENTITY-HEADER; empty means IMDS style.
	Header string
	// ClientID selects a user-assigned identity when the group has several.
	ClientID string
	// HTTPClient defaults to a client with a 20s timeout.
	HTTPClient *http.Client

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// NewMSITokenSourceFromEnv builds a token source from the process environment.
func NewMSITokenSourceFromEnv(getenv func(string) string, clientID string) *MSITokenSource {
	return &MSITokenSource{
		Endpoint: getenv("IDENTITY_ENDPOINT"),
		Header:   getenv("IDENTITY_HEADER"),
		ClientID: clientID,
	}
}

type msiTokenResponse struct {
	AccessToken string      `json:"access_token"`
	ExpiresOn   interface{} `json:"expires_on"`
	ExpiresIn   interface{} `json:"expires_in"`
}

// Token implements TokenSource.
func (m *MSITokenSource) Token(ctx context.Context, resource string) (string, error) {
	m.mu.Lock()
	if c, ok := m.cache[resource]; ok && time.Now().Before(c.expires) {
		m.mu.Unlock()
		return c.token, nil
	}
	m.mu.Unlock()

	// Header present => ACI/App Service identity endpoint (2019-08-01).
	// Otherwise IMDS style (Metadata: true, 2018-02-01), possibly at an
	// overridden endpoint in tests.
	endpoint := m.Endpoint
	apiVersion := "2019-08-01"
	if m.Header == "" {
		apiVersion = "2018-02-01"
		if endpoint == "" {
			endpoint = IMDSTokenURL
		}
	} else if endpoint == "" {
		return "", errors.New("certstore: IDENTITY_HEADER set without IDENTITY_ENDPOINT")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("certstore: msi endpoint: %w", err)
	}
	q := u.Query()
	q.Set("resource", resource)
	q.Set("api-version", apiVersion)
	if m.ClientID != "" {
		q.Set("client_id", m.ClientID)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if m.Header != "" {
		req.Header.Set("X-IDENTITY-HEADER", m.Header)
	} else {
		req.Header.Set("Metadata", "true")
	}
	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("certstore: msi token request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("certstore: read msi response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("certstore: msi token HTTP %d: %s", resp.StatusCode, firstLine(string(raw)))
	}
	var tr msiTokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", fmt.Errorf("certstore: decode msi response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("certstore: msi response has no access_token")
	}
	expires := time.Now().Add(55 * time.Minute)
	if v, ok := asInt64(tr.ExpiresOn); ok && v > 0 {
		expires = time.Unix(v, 0)
	} else if v, ok := asInt64(tr.ExpiresIn); ok && v > 0 {
		expires = time.Now().Add(time.Duration(v) * time.Second)
	}

	m.mu.Lock()
	if m.cache == nil {
		m.cache = make(map[string]cachedToken)
	}
	m.cache[resource] = cachedToken{token: tr.AccessToken, expires: expires.Add(-5 * time.Minute)}
	m.mu.Unlock()
	return tr.AccessToken, nil
}

// asInt64 accepts the number-or-string encodings Azure uses for expires_on.
func asInt64(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// ---------------------------------------------------------------------------
// Key Vault secret as blob storage
// ---------------------------------------------------------------------------

// KeyVaultResource is the token audience for Azure Key Vault (public cloud).
const KeyVaultResource = "https://vault.azure.net"

// KeyVaultSecretStore keeps the blob as the value of one Key Vault secret via
// the REST API (api-version 7.4), authenticated with a TokenSource. It stores
// ciphertext only when used underneath SealedStore; the vault, its access
// policies and Azure operators never see plaintext.
//
// Note: Key Vault secrets are capped at 25 KB, comfortably above the ~10 KB a
// sealed bundle needs.
type KeyVaultSecretStore struct {
	// VaultURL such as https://myvault.vault.azure.net (no trailing slash).
	VaultURL string
	// SecretName of the secret holding the bundle.
	SecretName string
	// Tokens supplies bearer tokens for Resource.
	Tokens TokenSource
	// Resource defaults to KeyVaultResource.
	Resource string
	// HTTPClient defaults to a client with a 30s timeout.
	HTTPClient *http.Client
}

const keyVaultAPIVersion = "7.4"

// NewKeyVaultSecretStore normalises vault ("name" or full URL) and returns a store.
func NewKeyVaultSecretStore(vault, secretName string, tokens TokenSource) (*KeyVaultSecretStore, error) {
	if vault == "" || secretName == "" {
		return nil, errors.New("certstore: key vault store needs a vault and a secret name")
	}
	if tokens == nil {
		return nil, errors.New("certstore: key vault store needs a token source")
	}
	return &KeyVaultSecretStore{VaultURL: NormalizeVaultURL(vault), SecretName: secretName, Tokens: tokens}, nil
}

// NormalizeVaultURL turns "myvault" into https://myvault.vault.azure.net and
// strips trailing slashes from full URLs.
func NormalizeVaultURL(v string) string {
	v = strings.TrimRight(strings.TrimSpace(v), "/")
	if !strings.Contains(v, "://") {
		if !strings.Contains(v, ".") {
			v += ".vault.azure.net"
		}
		v = "https://" + v
	}
	return v
}

func (s *KeyVaultSecretStore) secretURL() string {
	return fmt.Sprintf("%s/secrets/%s?api-version=%s", s.VaultURL, url.PathEscape(s.SecretName), keyVaultAPIVersion)
}

func (s *KeyVaultSecretStore) do(ctx context.Context, method string, body []byte) (int, []byte, error) {
	resource := s.Resource
	if resource == "" {
		resource = KeyVaultResource
	}
	token, err := s.Tokens.Token(ctx, resource)
	if err != nil {
		return 0, nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.secretURL(), rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("certstore: key vault %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("certstore: read key vault response: %w", err)
	}
	return resp.StatusCode, raw, nil
}

type kvSecret struct {
	Value       string `json:"value"`
	ContentType string `json:"contentType,omitempty"`
}

type kvError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func kvErrorMessage(status int, raw []byte) string {
	var e kvError
	if json.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
		return fmt.Sprintf("HTTP %d %s: %s", status, e.Error.Code, firstLine(e.Error.Message))
	}
	return fmt.Sprintf("HTTP %d: %s", status, firstLine(string(raw)))
}

// LoadBlob implements BlobStore. A missing secret maps to ErrNotFound.
func (s *KeyVaultSecretStore) LoadBlob(ctx context.Context) ([]byte, error) {
	status, raw, err := s.do(ctx, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("certstore: key vault get secret: %s", kvErrorMessage(status, raw))
	}
	var sec kvSecret
	if err := json.Unmarshal(raw, &sec); err != nil {
		return nil, fmt.Errorf("certstore: decode key vault secret: %w", err)
	}
	if sec.Value == "" {
		return nil, ErrNotFound
	}
	return []byte(sec.Value), nil
}

// SaveBlob implements BlobStore; each save creates a new secret version.
func (s *KeyVaultSecretStore) SaveBlob(ctx context.Context, data []byte) error {
	body, err := json.Marshal(kvSecret{Value: string(data), ContentType: "application/json"})
	if err != nil {
		return err
	}
	status, raw, err := s.do(ctx, http.MethodPut, body)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("certstore: key vault set secret: %s", kvErrorMessage(status, raw))
	}
	return nil
}
