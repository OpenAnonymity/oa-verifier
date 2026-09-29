# TLS Certificate Persistence

## Problem

TLS terminates inside the enclave: the verifier obtains its own Let's Encrypt
certificate (`internal/acme`, DNS-01 via Cloudflare) at start-up and serves it
from `RunTLS` (`internal/server/server.go`). Until this change nothing was
persisted, so every process start requested a brand-new certificate and
registered a brand-new ACME account.

Azure recreates the Confidential ACI group on every platform repair (observed
daily since 2026-09-25, see `investigation/`). Each recreation is a cold start,
so the verifier hit Let's Encrypt's *duplicate certificate* limit (5 per
registered domain per week) within days and fell back to a self-signed
certificate, which browsers and clients reject.

## Design

A new package `internal/certstore` persists a **bundle**:

| field | content |
|---|---|
| `certificate_pem` | full chain, leaf first |
| `private_key_pem` | certificate private key |
| `account_key_pem`, `account_uri`, `ca_dir_url` | ACME account (so the account is reused, not re-registered) |
| `domain`, `issued_at`, `not_after` | metadata for the start-up decision |

```go
type Store interface {
    Load(ctx) (*Bundle, error)   // certstore.ErrNotFound when nothing saved
    Save(ctx, *Bundle) error
}
```

### Start-up decision (`acme.LoadOrObtain`)

1. `store.Load`. If a bundle exists, was issued by the configured CA
   (production vs staging), its key pair parses, it covers `TLS_DOMAIN`
   (`VerifyHostname`) and has **more than 30 days** left, it is served and the
   CA is not contacted at all (`source=persisted`).
2. Otherwise a certificate is obtained. When the stored bundle belongs to the
   same CA its account key is reused (`registration.ResolveAccountByKey`);
   only if the CA does not know the key is a registration created. The result
   is `store.Save`d (`source=obtained`). Save failures are logged, never fatal.
3. If issuance fails but the stored certificate is still valid (any remaining
   validity, right domain, right CA) it is served and the renewal loop retries
   every 12 h (`source=persisted-near-expiry`). **A persisted valid certificate
   is never replaced by a self-signed one.** Self-signed remains only for the
   case where there is nothing valid at all, exactly as before.

The renewal loop (`acme.StartRenewalLoop`) creates its ACME client lazily from
the bundle's account key, saves the renewed bundle to the store and swaps the
live certificate under the existing mutex.

### Backends (`TLS_CERT_STORE`)

| value | Store | where the bundle lives | plaintext? |
|---|---|---|---|
| unset / `none` | `NoopStore` | nowhere; **identical to the previous behaviour** | – |
| `file` | `FileStore` | `TLS_CERT_STORE_DIR/tls-bundle.json`, dir 0700, file 0600, atomic temp-file + rename | yes — only for storage that never leaves the enclave (emptyDir/tmpfs, local dev) |
| `file-sealed` | `SealedStore(FileStore)` | same path, AES-256-GCM ciphertext | no |
| `keyvault-sealed` | `SealedStore(KeyVaultSecretStore)` | one Key Vault secret, AES-256-GCM ciphertext | no |

`SealedStore` wraps a `BlobStore` (raw bytes) rather than a `Store`, because
ciphertext is not a `Bundle`; `FileStore` and `KeyVaultSecretStore` implement
both interfaces.

### Sealing

* Envelope: `{"v":1,"alg":"A256GCM","kdf":"HKDF-SHA256","kid":…,"nonce":…,"ciphertext":…}`.
  The AAD binds `alg/v/kid`, so a blob cannot be re-labelled or replayed under a
  different key without detection. A kid mismatch between envelope and released
  key is refused before decryption (helps during KEK rotation).
* The key-encryption key is **released by the Microsoft SKR sidecar** already in
  the container group (`mcr.microsoft.com/aci/skr`, port 8080):

  ```
  POST http://localhost:8080/key/release
  {"maa_endpoint": "<MAA_PROVIDER_URL>", "akv_endpoint": "<TLS_CERT_KEK_VAULT>", "kid": "<TLS_CERT_KEK_NAME>"}
  → 200 {"key": "<JWK as a JSON string>"}      (4xx/5xx {"error": "..."})
  ```

  Request/response shapes are taken from the vendored upstream source
  (`internal/httpginendpoints/httpginendpoints.go`, `PostKeyRelease`). The
  sidecar attests the UVM with MAA and asks Key Vault to release the key; Key
  Vault only does so when the MAA token satisfies the key's *release policy*.
* The released JWK is an asymmetric key (`kty: RSA` — the only exportable type
  in Key Vault Premium; Managed HSM can also release `EC` and `oct-HSM`). Its
  private material (`d`, or `k` for `oct`) is not an AES key, so the 256-bit
  data key is derived with **HKDF-SHA256** (RFC 5869; implemented with
  `crypto/hmac` to stay on go 1.22 and stdlib):
  `salt = "oa-verifier/certstore/kek/v1"`, `info = "oa-verifier/certstore/aes-256-gcm/" + kid`.
  Public JWKs, unknown key types and material shorter than 256 bits are rejected.

### Key Vault secret backend

`KeyVaultSecretStore` talks REST directly (`GET/PUT https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4`),
authenticated with the container group's managed identity:
`GET $IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01`
with `X-IDENTITY-HEADER: $IDENTITY_HEADER` (ACI), falling back to IMDS
(`Metadata: true`, `api-version=2018-02-01`) when those variables are absent.
`TLS_CERT_MSI_CLIENT_ID` selects a user-assigned identity. Tokens are cached
until 5 minutes before expiry. No third-party dependency was added; `go.mod` is
unchanged. Each save creates a new secret version (Key Vault keeps history).

## Trust argument

`docs/TRUST_MODEL.md` and `docs/ATTESTATION.md` promise that TLS terminates in
the attested enclave and that `/attestation` binds the TLS public key hash to
the hardware report. Persistence must not weaken that:

* **The private key never leaves the enclave in plaintext.** Outside the
  enclave (Key Vault secret, Azure Files) only AES-256-GCM ciphertext exists.
* **Only an attested enclave can decrypt.** The data key derives from a Key
  Vault/MHSM key whose *release policy* requires an MAA token with the expected
  claims (`x-ms-attestation-type = sevsnpvm`, `x-ms-sevsnpvm-hostdata =
  <sha256 of the CCE policy>`, `x-ms-compliance-status = azure-compliant-uvm`,
  `x-ms-sevsnpvm-is-debuggable = false`). The `hostdata` claim is the same
  policy hash auditors verify in `docs/ATTESTATION.md`, so a modified image
  (different policy) cannot unseal the bundle. Azure operators, the subscription
  owner and anyone who dumps the Key Vault secret get ciphertext only.
* **Attestation binding is unchanged.** `tls_pubkey_hash` is computed from
  whatever leaf is served (persisted or fresh), so clients still bind the TLS
  channel to the enclave. Reusing a key across restarts means the hash is
  stable across platform repairs, which is a usability improvement, not a
  weakening; the key still only exists in plaintext inside attested memory.
* **Integrity.** GCM authentication plus AAD detects tampering and
  re-labelling. A tampered or foreign blob causes `Load` to fail and the
  verifier obtains a fresh certificate (the old behaviour), never a silent
  downgrade.
* **What this does not protect against:** a *new* image whose CCE policy hash
  is also allowed by the release policy (the operator controls the policy, as
  they always did), and Let's Encrypt's own trust. Both are outside the
  enclave's guarantees already.

The `file` (plaintext) mode is deliberately limited to storage inside the
enclave boundary. An `emptyDir` volume in a confidential ACI group is backed by
the UVM's encrypted memory/disk and disappears with the group, so it helps only
with container restarts inside one group, not with platform repairs; use a
sealed mode for that.

## Environment variables

All of them must be added to `optional_env_vars` in the *Generate CCE policy*
step of `.github/workflows/build-and-sign.yml` (values are regex-matched, not
captured) or the confidential container will not start.

| variable | modes | meaning |
|---|---|---|
| `TLS_CERT_STORE` | all | `none` (default) / `file` / `file-sealed` / `keyvault-sealed` |
| `TLS_CERT_STORE_DIR` | file, file-sealed | directory for `tls-bundle.json` |
| `TLS_CERT_KEK_VAULT` | sealed | Key Vault (Premium) or Managed HSM URL holding the KEK, e.g. `https://oa-verifier-kv.vault.azure.net` |
| `TLS_CERT_KEK_NAME` | sealed | KEK name (the `kid` sent to the sidecar) |
| `TLS_CERT_SKR_URL` | sealed, optional | sidecar endpoint, default `http://localhost:8080/key/release` |
| `TLS_CERT_SECRET_VAULT` | keyvault-sealed | Key Vault URL holding the sealed bundle secret (may be the same vault) |
| `TLS_CERT_SECRET_NAME` | keyvault-sealed, optional | default `oa-verifier-tls-bundle` |
| `TLS_CERT_MSI_CLIENT_ID` | keyvault-sealed, optional | client id of a user-assigned identity |
| `MAA_PROVIDER_URL` | sealed | already set by the deployment; used as `maa_endpoint` |
| `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` | keyvault-sealed | injected by ACI when an identity is assigned; confirm the generated policy allows them |

## Azure resources the operator must create (`keyvault-sealed`)

1. **Managed identity** on the container group (system- or user-assigned). The
   SKR sidecar uses it to call MAA/Key Vault; the verifier uses it for the secret.
2. **Key Vault Premium** (or Managed HSM) with an **exportable RSA-HSM key**
   created with a release policy, e.g.

   ```json
   {"version":"1.0.0","anyOf":[{"authority":"https://sharedeus.eus.attest.azure.net","allOf":[
     {"claim":"x-ms-attestation-type","equals":"sevsnpvm"},
     {"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},
     {"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"},
     {"claim":"x-ms-sevsnpvm-hostdata","equals":"<sha256 of the deployed CCE policy>"}]}]}
   ```
   `az keyvault key create --vault-name <kv> --name <TLS_CERT_KEK_NAME> --kty RSA-HSM --exportable --policy release-policy.json`.
   The `hostdata` value changes with every image, so the release policy (or an
   additional `anyOf` entry) must be updated as part of each deploy.
3. **Roles** for the group's identity: `Key Vault Crypto Service Release User`
   on the KEK (release), and `Key Vault Secrets Officer` (get + set) on the
   vault/secret that holds the bundle. With access-policy vaults: key `release`
   and secret `get`,`set`.
4. Deployment: set the env vars above on the `oa-verifier` container and add
   them to the CCE policy's `optional_env_vars`.

Local development: `TLS_CERT_STORE=file TLS_CERT_STORE_DIR=./.certs`.

## Tests

* `internal/certstore`: FileStore round-trip, permissions, atomic replace and
  cleanup on failed rename; SealedStore round-trip against a fake sidecar (RSA
  and oct JWKs), wrong key / tampering / kid mismatch; RFC 5869 HKDF vector;
  Key Vault store against an `httptest` server faking the MSI endpoint and the
  secrets API, token caching, IMDS fallback; `FromEnv` selection.
* `internal/acme`: `LoadOrObtain` with a fake obtainer and in-memory store
  covering every branch above, `CheckBundle`, and the retry helper.
