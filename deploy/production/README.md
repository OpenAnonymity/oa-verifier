# Production verifier recovery

This automation targets only `oa-verifier-production-20260917` in Azure resource
group `oa-verifier`, preserving
`https://verifier-production-20260917.openanonymity.ai`. It does not deploy
`oa-verifier-2` or change DNS. The application source is pinned in the workflow
and rollout script; changing that pin requires another review and preparation.

## Prerequisites

1. Release the client outage policy for the exact production station public key.
   Explicit rejection, bad signatures, bans, expiry, and wrong verifier origins
   must remain hard failures. An outage fallback must say it is unverified.
2. Install production org grace and per-registration renewal first. Verify a
   fresh station heartbeat, retained station public key, unchanged ticket issuer,
   and the status/timer on org-live. The grace clock must never renew from a
   verifier restart, failed login, or repeated observation of a registration.
3. Run the reviewed `scripts/setup_production_encrypted_storage.sh` as the
   authorized Azure Owner. Production uses its own vault, key and identity.
   The staging variables and secrets must not be reused or replaced.
4. The existing GitHub environment `oa-production-20260917` supplies
   `PRODUCTION_REGISTRY_SECRET`. The separate
   `PRODUCTION_RESILIENCE_WORKER_SECRET` authenticates only the deployment worker.
   Org's production storage readiness stays off until this workflow is ready.

## Prepare before replacing the verifier

The `prepare` operation tests the application, reproducibly builds and signs an
immutable image, reads the live Azure configuration, validates fixed production
addresses and registry authorization, generates a confidential policy, and asks
Azure to validate **both** deployment and rollback templates. Preparation does
not restart a verifier or authorize a new key-release measurement.

Public policy and a sanitized production record are retained as artifacts.
Credential-bearing parameters are private, are never uploaded, and are removed
at job end. Public security configuration is bound to exact required values in
the measured policy. Only secret values and Azure's injected identity variables
use patterns. Application/sidecar stdout access is disabled.

## Guarded activation

Enable the dedicated worker credential and production readiness only after
preparation passes. Enable repository variable `PRODUCTION_DASHBOARD_CONTROLS`
after the dispatcher is on main. A storage change on the authenticated org-live
dashboard requires its current revision, same-origin request, production header,
and the typed confirmation `PRODUCTION`. Concurrent/pending changes are refused.

The dispatcher does not claim the request. The actual deployment run claims it
once, then checks the same revision and run ID again immediately before replacing
the container. Production grace must remain enabled. The Azure configuration is
also compared with the pre-build baseline; a concurrent change stops deployment.
Deployment requires an explicit workflow dispatch with `operation=deploy` and
the exact pending dashboard revision. Branch pushes can only prepare.

The new measured policy is authorized to release only the production sealing key;
recent policy measurements remain authorized for rollback. TLS certificate
persistence remains on even when the station-storage switch is off. Switching
off station storage does not delete saved blobs or keys.

Replacement necessarily interrupts the verifier briefly. It cannot recover
management keys that the old verifier never saved. The first activation may
therefore require one operator station login/MFA. Org grace and client outage
handling provide continuity for the already approved station; they do not make
an offline station work or manufacture fresh verification.

Mandatory post-deployment checks include trusted TLS, a fresh nonce, signed MAA
claims, the exact hardware policy measurement, TLS key binding, expected image,
unchanged public DNS identity, and persistence health. Failure restores the old
container template. A failure to report success to the dashboard does not roll
back a healthy verifier; reconcile that run's claim from its retained evidence.

## Acceptance test

1. After the first successful login, confirm the production station appears in
   the verifier broadcast with the same public key; persistence has no load/save
   error; org shows currently verified and online.
2. Confirm an existing chat and a new chat work in OA and zkAPI using an explicit
   test account or the operator's own test. Do not use personal wallets remotely.
3. Record the TLS certificate fingerprint, approval/registration time, and
   persistence health. Restart the **production** container only after these
   checks pass and the operator is available for recovery.
4. Without another station login, confirm the same certificate was restored,
   the station and its original registration time survived, verification works,
   and both existing and newly issued keys work. New successful registration
   may renew the grace deadline; the restart itself must not.
5. Keep TLS, org grace, station heartbeat, and issuance checks separate. A healthy
   homepage or `/health` alone does not prove recovery or inference.

If certificate issuance or restore fails, do not repeatedly restart and consume
the certificate authority's quota. Preserve the failed run evidence and use the
prepared rollback/recovery path. Never erase browser profiles, wallets, station
identities, or encrypted state as a troubleshooting step.
