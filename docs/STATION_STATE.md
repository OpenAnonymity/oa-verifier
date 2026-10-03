# Station registry persistence (`STATION_STATE_STORE`)

## Problem

The verifier keeps its station registry — which stations are registered, each
one's OpenRouter session cookies, and the OpenRouter-issued *management key*
it uses for `/submit_key` ownership checks — in process memory
(`internal/server`: `stations`, `emailToPK`, `stationIDToPK`). Every container
start therefore began with zero stations, `/broadcast` answered with an empty
list, the org dropped the stations' public keys on its next sync, heartbeats
were rejected and every station re-registered.

Re-registration asks OpenRouter to issue a new management key on the station
operator's account. Since late September 2026 OpenRouter gates that endpoint
behind a *recent* multi-factor login (`strict_mfa`: a second factor within the
last ten minutes). An unattended restart — a platform repair of the container
group, a deploy, a crash — therefore ended with `register_management_key_create_failed`
(HTTP 403 from OpenRouter, HTTP 500 to the station) repeating every minute
until a person logged in on the station. `oa-verifier-2` sat at
`"stations": 0` for days for exactly this reason while the untouched
production group kept working only because it had never restarted.

Everything the verifier does with a management key it *already holds* is
unaffected by that gate: `/api/v1/keys` ownership checks and the periodic
privacy-toggle reads (the verifier refreshes the operator's Clerk session JWT
itself from the stored `__client` cookie, which needs no MFA). The only step
that needs a person is minting a key, and a key only has to be minted once
per station if the verifier stops forgetting it.

## Design

`internal/stationstore` persists a `Snapshot` of the registry through the same
storage backends as the TLS certificate bundle (`internal/certstore`):

| `STATION_STATE_STORE` | where | plaintext? | survives |
|---|---|---|---|
| unset / `none` | nowhere — **identical to the previous behaviour** | – | nothing |
| `file` | `STATION_STATE_STORE_DIR/station-state.json`, 0600, atomic replace | yes — only for storage that never leaves the enclave (local dev, emptyDir) | container restarts in one group |
| `file-sealed` | same path, sealed | no | same, plus a mounted volume if one is configured |
| `keyvault-sealed` | one Key Vault secret (`STATION_STATE_SECRET_NAME`, default `oa-verifier-station-state`), sealed | no | platform repairs, redeploys of the same image |

"Sealed" is `certstore.SealedBlobStore`: AES-256-GCM under a key derived (HKDF-
SHA256) from a Key Vault key that the SKR sidecar releases only to an enclave
whose attestation satisfies the key's *release policy* — the same mechanism
`docs/CERT_PERSISTENCE.md` describes. The station snapshot uses the sealing
**purpose** `stationstore`, which is mixed into the HKDF info string and the
AEAD associated data, so:

* the TLS bundle and the station snapshot are encrypted under *different*
  AES keys even though both derive from one Key Vault key, and
* a blob written by one store is rejected by the other before decryption
  (`envelope sealed for purpose "stationstore", this store is ""`).

### What is stored

One `Record` per registered station: public key, `StationID`, `Email`,
`DisplayName`, `CookieData` (the operator's OpenRouter session as the station
supplied it), `RegisteredAt`, `LastVerified`, `ProvisioningKey` (the
management key), `NextChallengeAt` and the transient-failure fields — i.e.
`models.Station` as the server holds it. This is station-operator governance
data only; end-user prompts, identities and API keys never enter the registry
and so never enter the snapshot.

Size: Key Vault secrets are capped at 25 KB. A trimmed record is well under
1 KB, and `stationstore.Marshal` refuses snapshots above 17 KB of plaintext
(`ErrTooLarge`) rather than let Key Vault reject them. That is plenty for the
handful of stations one verifier serves; sharding would be the next step if
it ever is not. An oversized snapshot is logged at error level and shows as
`save_error` on `/health`; the previous snapshot stays in place.

### Server behaviour (`internal/server/state.go`)

* **Start-up.** `InitStationState` builds the store from the environment (a
  misconfigured store is fatal: the process must not start half-configured),
  loads the snapshot — retrying six times ten seconds apart because the SKR
  sidecar can be slow after a cold start — and restores it. Banned stations
  are skipped. A live registration wins over a saved record for the same key,
  except that a saved management key fills an empty live one. Restored
  stations get `NextChallengeAt` within the next 60 seconds, so stale state is
  corrected by the normal verification loop almost immediately and the org is
  notified exactly as for a live station. `/broadcast` lists the restored,
  verified stations at once, so the org keeps their public keys and heartbeats
  never fail.
* **Writes.** Every code path that changes the registry (register,
  unregister, removal of a banned station, management-key refresh,
  verification outcome, failure bookkeeping) calls `requestPersist()`, which
  sets a one-slot flag. A single background goroutine coalesces flags (2 s
  debounce), snapshots the registry under the read lock, and writes **only
  when the durable content changed**: `stationstore.Digest` covers identity,
  cookies, the management key, and whether a station is verified or in a
  failure window, but not `NextChallengeAt`, timestamps or counters. Routine
  privacy checks therefore produce no writes; registrations and state
  transitions do. Failed writes are retried every 30 s. On shutdown
  (SIGTERM from a platform repair or a redeploy) the loop makes one last
  bounded write of any pending change and `main` waits for it, so a station
  that registered seconds before the stop is not lost.
* **What is written per station.** `stationstore.RecordFromStation` keeps
  only the cookies the verifier reads (`__client*`, `__client_uat*`,
  `clerk_active_context`, `__session*`, `__refresh*`), each reduced to name,
  value and domain. Other cookies a station may send are never persisted.
* **Never clobber what we could not read.** If the start-up load fails with
  anything other than "not found", the server starts empty but *refuses to
  write* until a later load succeeds; the late-loaded records are then merged
  into the live registry (same rules as at start-up) and the union is written.
  A sidecar that is slow for a minute can therefore never cause the snapshot
  to be replaced by a smaller one.
* **`/health`** gains `"registry_ready"` (see "Readiness signal") and `"persistence": {"store": "<mode>", "loaded": bool,
  "load_error": true?, "save_error": true?}`. Only the backend name is
  exposed, never the vault or key name. `save_error` appears when the last
  write failed (Key Vault unreachable, or the snapshot over its size budget)
  and clears on the next successful write.

Nothing about *what* the verifier verifies changes. A restored station that
fails its re-check is unregistered or banned exactly as before.

## Trust argument

`docs/TRUST_MODEL.md` promises that users need to trust only the attested
verifier code and OpenRouter's APIs. Persistence must not widen that:

* **Plaintext only inside attested memory.** Outside the enclave only
  AES-256-GCM ciphertext exists. Azure operators, the subscription owner and
  anyone who reads the Key Vault secret get ciphertext.
* **Only an attested enclave running an allowed image can decrypt.** The data
  key derives from a Key Vault key whose release policy requires an MAA token
  with `x-ms-attestation-type = sevsnpvm`, `x-ms-compliance-status =
  azure-compliant-uvm`, `x-ms-sevsnpvm-is-debuggable = false` and
  `x-ms-sevsnpvm-hostdata = <sha256 of the CCE policy>` — the same hash users
  verify through `/attestation`.
* **What persistence does add**, and the review the 2026-09-27 diagnosis asked
  for: the snapshot contains the station operators' OpenRouter sessions and the
  management keys, which previously existed only in enclave memory. Whoever can
  change the key's *release policy* (Key Vault Crypto Officer on the key) could
  allow a different image to release the key and unseal them. Mitigations in
  place: the release policy is maintained by the deploy pipeline from the build
  it is about to deploy (`build-and-sign.yml`, "Authorize this build's policy
  hash"), the window of allowed hashes is bounded (`KEK_RELEASE_KEEP_HASHES`,
  default 4), the vault has purge protection and RBAC, and the policy can be
  audited at any time with `az keyvault key show … --query releasePolicy`. The
  TLS private key accepted the same trade in PR #8. If the project wants to
  remove the operator from this loop later, the key's release policy can be
  made `immutable` with a fixed set of hashes, at the cost of a new key per
  image change.
* **Integrity.** GCM authentication with purpose-bound AAD detects tampering
  and re-labelling. A tampered or foreign blob fails to load and the verifier
  starts empty — the old behaviour — never with partial or forged state.
* **Freshness.** A restored "verified" flag can be at most as old as the
  outage; every restored station is re-checked within a minute and the org
  learns the outcome through the existing events.

## Environment variables

All of them are listed in `optional_env_vars` of the *Generate CCE policy*
step of `.github/workflows/build-and-sign.yml` (values are regex-matched, not
captured). The vault, key, sidecar endpoint and identity are the **shared**
`TLS_CERT_*` variables, so one Key Vault setup serves both blobs.

| variable | modes | meaning |
|---|---|---|
| `STATION_STATE_STORE` | all | `none` (default) / `file` / `file-sealed` / `keyvault-sealed` |
| `STATION_STATE_STORE_DIR` | file, file-sealed | directory for `station-state.json` |
| `STATION_STATE_SECRET_NAME` | keyvault-sealed, optional | default `oa-verifier-station-state` |
| `TLS_CERT_KEK_VAULT`, `TLS_CERT_KEK_NAME` | sealed | Key Vault (Premium) or Managed HSM URL and key name of the sealing key |
| `TLS_CERT_SECRET_VAULT` | keyvault-sealed | vault holding the sealed secret (may be the same vault) |
| `TLS_CERT_MSI_CLIENT_ID` | sealed modes, optional | client id of the group's user-assigned identity; when set, the verifier also hands the sidecar a token for that identity (`access_token`) instead of letting it pick one |
| `TLS_CERT_SKR_URL`, `MAA_PROVIDER_URL` | sealed | as for the TLS bundle |

Local development: `STATION_STATE_STORE=file STATION_STATE_STORE_DIR=./.state`.

## Rolling it out on the shared verifier (`oa-verifier-2`)

1. **Azure, once.** Run `scripts/setup-sealed-state.sh` in Azure Cloud Shell as
   an owner of the `oa-verifier` resource group. It creates a Premium, RBAC
   Key Vault with purge protection, an exportable RSA-HSM sealing key with a
   placeholder release policy, and the role assignments: the group's
   user-assigned identity may release the key and read/write the secrets, and
   the GitHub deploy principal may update the key's release policy. It prints
   the repository variables to set.
2. **GitHub repository variables** (not secrets — these are names):
   `STATION_STATE_STORE=keyvault-sealed`, `TLS_CERT_STORE=keyvault-sealed`,
   `SEALED_KEK_VAULT`, `SEALED_KEK_NAME`, `SEALED_SECRET_VAULT`,
   `SEALED_MSI_CLIENT_ID`, `ACI_PULL_IDENTITY_ID` (same identity),
   `KEK_RELEASE_KEEP_HASHES=4`. Leaving `STATION_STATE_STORE`/`TLS_CERT_STORE`
   unset keeps the old behaviour byte for byte.
3. **Merge to `main`.** The workflow generates the CCE policy, *then*
   authorizes its hash on the key's release policy (and verifies by reading it
   back) *before* deleting the old group. If Key Vault refuses, the running
   verifier is left alone and the deploy stops.
4. **One login per station, once.** The deploy is a restart, so the first
   build with persistence starts with an empty registry like every build before
   it. A person runs the station's login recovery on each station that uses
   this verifier (`sudo /opt/oa-station/auth-recovery-20260911/recover-login`
   on the staging station) so it registers and the verifier mints and now
   *keeps* its management key.
5. **Check.** `curl https://verifier2.openanonymity.ai/health` →
   `"stations": 1, "persistence": {"store": "keyvault-sealed", "loaded": true}`;
   `az keyvault secret list --vault-name <vault>` shows
   `oa-verifier-station-state` (and `oa-verifier-tls-bundle`). The next
   platform recycle or redeploy should come back with the same station count
   and without `register_management_key_create_failed` in the logs.

After that, a person is needed only for a brand-new station's first
registration, and for account-level events (the operator's OpenRouter login
revoked or expired, the management key deleted) that would need one today too.

## Readiness signal (`registry_ready`)

Persistence removes the usual cause of an empty registry, but not every one:
a store that cannot be read yet, a build whose policy hash was not authorised,
a verifier that has no persistence at all. In those cases the verifier used to
be *up and wrong*: it answered `/broadcast` with an empty list, which the org
took as authoritative and dropped every station key within 30 seconds, and it
answered `/submit_key` with `404 Station not registered`, a verdict. A verifier
that is *down* was handled more gracefully than one that had merely forgotten.

So the verifier now says when it cannot judge yet. `registryReadiness()`
(`internal/server/ready.go`) is **ready** when:

* a **complete** snapshot was restored — one saved while the verifier was
  itself ready (`Snapshot.Complete`). A snapshot saved *during* a warm-up holds
  only the stations that re-registered since, so restoring it does not make
  the verifier ready; or
* `REGISTRY_WARMUP_SECONDS` (default and maximum 7 days, capped in code
  because the variable is outside the measured policy; `0` = ready as soon as
  the state store is loaded) have passed since the warm-up began, and the
  state store is loaded. The warm-up begins at this start, or earlier if an
  incomplete snapshot carries an earlier `warmup_since`, so restarts during a
  warm-up cannot extend it. When it ends, a periodic check writes the snapshot
  again with `Complete: true`.

While not ready:

* `/broadcast` carries `"registry_ready": false`, a `registry` status block
  (`reason`, `started_at`, `warmup_since`, `uptime_seconds`, `warmup_seconds`)
  and `removed_stations`: stations this process deliberately unregistered
  (not banned), with the public key they had. The org
  (`station_manager/services/verifier_sync.py`) then **merges** the stations
  that are listed instead of replacing its set, drops the keys of removed
  stations, keeps the rest for its grace window (`VERIFIER_GRACE_PERIOD`), and
  applies the published bans at once.
* `/submit_key` for a station the verifier does not know answers
  `503 {"status":"unavailable","detail":"registry_warming"}` with
  `Retry-After` and the status block, which the client classifies as a
  verifier outage (bounded background retries, outage policy) rather than a
  verdict. A station banned by this verifier still gets `403 banned`, and a
  station it unregistered still gets `404`, whatever the readiness. Known
  stations are checked exactly as before.
* `/health` carries `"registry_ready"`.

The default of 7 days is deliberate: it gives the team days, not minutes, to
repair a verifier that lost its state, while the org's own grace window (set to
match) keeps stations online and the client's advisory policy keeps users
informed that verification is unavailable. The org measures its window from
the last time the verifier was *ready*, not from each restart, so repeated
restarts cannot stretch the time the org keeps unlisted stations past 7 days.
Stations the verifier does list while not ready are always kept, including
after the window. Nothing is marked verified without evidence during that time
— the verifier declines to answer, it does not say yes. Readers of the trust
model should note that this is the same bounded tolerance the client already
extended to a verifier that is unreachable, now applied consistently to one
that is reachable but not yet complete.

Limits worth knowing:

* The verifier's ban list (`BANNED_STATIONS_FILE`) and its removal tombstones
  live in the container and are lost on restart. The org's own ban record in
  Redis is what persists; a ban the org has already applied is not undone by a
  verifier restart.
* Without persistence (`STATION_STATE_STORE` unset), a verifier that restarts
  more often than every 7 days never becomes ready on its own: every restart
  starts a new warm-up with an empty registry. That configuration buys the
  team a 7-day window measured from the last time the verifier was ready, not
  a steady state; persistence is what makes restarts harmless.
* The org's live verifier health check ignores readiness, so certified
  stations get no shared-secret fallback while the verifier is merely not
  ready (stricter than during an outage).
* If saving stalls (`save_error`, e.g. an oversized snapshot), the last
  complete snapshot stays in place and a restart restores that older list.

### If the snapshot cannot be read

A `load_error` on `/health` that does not clear means the saved secret exists
but cannot be opened: the release policy does not allow the running build
(check the "Authorize" step of the last deploy and
`az keyvault key show --vault-name <vault> --name <kek> --query releasePolicy`),
the key was rotated or replaced (`kid` mismatch), or the blob is corrupt. The
verifier keeps running with whatever registers live but **refuses to write**
until a load succeeds, so the unreadable snapshot is preserved for diagnosis.
To start over deliberately, make the secret empty or delete it
(`az keyvault secret set --vault-name <vault> --name oa-verifier-station-state --value ""`,
or `az keyvault secret delete …`): an empty or missing secret reads as "not
found", writes resume, and each station needs one operator login again. The
TLS bundle secret (`oa-verifier-tls-bundle`) is independent and can be left
alone.

The shared deployment accepts only `none` and `keyvault-sealed`; the `file`
modes need a mounted directory the container group does not have.
## Tests

* `internal/stationstore`: snapshot round-trip (including the cookie-data
  shape `openrouter.NewAuthFromCookieData` expects), version and integrity
  checks, size budget, `Digest` stability across volatile fields and change on
  durable ones, file backend, sealed backend through a fake SKR sidecar with
  the certificate store refusing the station blob, `FromEnv` modes and
  misconfiguration.
* `internal/certstore`: `SealedBlobStore` round-trip and purpose separation
  (label mismatch refused before decryption; forged label fails AEAD), legacy
  certificate envelopes still open, `FileStoreNamed`, `BlobStoreFromEnv`,
  `access_token` pass-through to the sidecar.
* `internal/server`: writes only on durable change and coalesced bursts,
  retry after a failed write, full restart simulation (restore, index maps,
  prompt re-check, `/broadcast` and `/health`, no redundant rewrite), banned
  and superseded records skipped on restore, **failed start-up load never
  clobbers the snapshot** (late load merged), env-configured file backend,
  misconfiguration rejected at start-up.
* `tests/deployment/test_release_policy.py`: release-policy merge window,
  placeholder replacement, fixed claims, CLI, and workflow ordering (authorize
  before delete; sealed variables allow-listed and kept out of the measured
  policy template).
