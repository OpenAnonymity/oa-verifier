# Trust Model (Verifier Role Clarity)

## Purpose

This document defines what the verifier does, what it does not do, and how auditors
should interpret the unlinkable inference claim: users do not need to trust any OA
system for identity-unlinkability (blind signatures) and cross-unlinkability
(inference confidentiality and integrity).

For the full technical description of unlinkable inference, see the blog post:
[Unlinkable Inference as a User Privacy Architecture](https://openanonymity.ai/blog/unlinkable-inference/).

Core statement:

- Verifier is a station compliance enforcer.
- Verifier is not an end-user prompt/response transport path.

## Actors

1. Station operator: registers station credentials/material for governance checks.
2. End user (`oa-chat`): obtains ephemeral access credentials and sends prompts.
3. Verifier (`oa-verifier`): enforces station-policy and ownership checks.
4. OpenRouter: provider serving model inference and exposing account-state metadata.
5. Org/registry: governance inputs for station admission and key-signature validation.

## Data Flow Boundaries

```text
Station operator ---> oa-verifier (/register, cookies, pk, signatures)
                         |
                         | periodic compliance + ownership checks
                         v
                     OpenRouter account-state APIs

End user (oa-chat) ---------------------------> OpenRouter inference APIs
   (ephemeral key usage, prompts/responses)
```

Prompt/response path:

- End-user prompts/responses are in client -> provider flow.
- Verifier handlers do not carry prompt/response content.

Governance path:

- Station registration, signature checks, and policy enforcement occur via verifier APIs.
- Station operator credentials (cookies, email, public key) stored by the verifier are
  station governance data for compliance checks. They are not end-user data and have no
  bearing on user privacy or unlinkability. The verifier never receives, stores, or
  processes any end-user identity material.

## Verifier Role

1. Register and bind station governance identity/material.
2. Continuously enforce required provider toggle state.
3. Verify submitted key ownership and signatures.
4. Emit governance status (verified/unverified/banned/unregistered semantics).

## Required Anti-Forgery Verification Inputs

The following verification inputs are required for verifier decisions to prevent
forged/misattributed key submissions and unauthorized station admission that could
otherwise wrongly penalize a genuine station:

1. Registry station authorization records (`/register` gating).
2. Org signature/public-key path for `/submit_key` validation.
3. Provider-exposed account-state APIs (toggle/ownership checks).

These inputs are governance/control-path requirements. They are distinct from end-user
prompt/response transport.

## Runtime Trust Chain

```text
Attested runtime integrity
  -> verifier logic executes as audited
  -> required toggle checks + issued API key ownership checks run
  -> station trust state updated
  -> client accepts/rejects station key usage based on verifier outcomes
```

## Guarantees vs Non-Goals

| Category | Statement |
|---|---|
| Guarantee | Verifier enforces station governance checks for toggle compliance and key ownership/signatures. |
| Guarantee | Verifier does not transport end-user prompt/response content in handler paths. |
| Guarantee | Toggle checks are based on provider-exposed account-state data, not station self-report text. |
| Non-goal | Verifier alone proving blind-signature unlinkability of ticket issuance/redemption. |
| Non-goal | Verifier alone attesting provider-internal systems beyond exposed account-state signals. |
| Non-goal | Hiding governance telemetry from org/registry in this architecture. |

## Why This Is Zero-Trust for oa-chat Users

Stations are the entities that issue ephemeral API keys to oa-chat users.
The verifier audits that those stations are doing a genuine, privacy-compliant
job. It uses the provider's own systems as the sole source of truth and adds
zero proprietary verification data to the chain.

What the verifier checks (all using OpenRouter's own APIs):

1. Privacy toggles are correctly set on the station's OpenRouter account --
   user data is not being logged or trained on.
2. Submitted keys actually belong to the station's registered account -- not
   stolen keys, not fake keys, and not keys from a shadow account (a second
   account with logging/training enabled that would defeat privacy guarantees).
3. Station identity is verified via three-way binding (station_id <-> email <->
   public_key).

What this means for users:

- Prompts/responses go directly from oa-chat to OpenRouter. The verifier
  never sees or touches user data.
- The management key used for ownership checks is issued by OpenRouter on the
  station operator's account. The verifier requests it but does not create or
  host it.
- The verifier's broadcast endpoint tells oa-chat which stations are
  verified or banned, based entirely on evidence from OpenRouter's own APIs.
- Users only need to trust that: (1) the verifier code is what it claims
  (hardware attestation proves this), and (2) OpenRouter's APIs returned the
  data the verifier reports (the code is open-source and auditable).

## Zero-Trust Scope: OA Infrastructure

"Zero trust" means users do not need to trust any OA-operated component (org,
stations, verifier operators) for **unlinkable inference**, which consists of
two guarantees: (1) **identity-unlinkability** -- blind signatures ensure no
party can link ticket issuance to redemption, and sessions cannot be linked to
the user's identity, and (2) **cross-unlinkability** -- different sessions
cannot be linked to each other, and no party can link a user's prompts/responses
to their identity or across sessions. OA stations provide inference
**confidentiality** (no OA system can observe prompt/response content) and
**integrity** (no OA system can tamper with it). No OA system sees prompts or
responses.

OpenRouter is used by OA as the frontier model provider. Through OA's unlinkable
inference layer, even if OpenRouter is malicious, user prompts are still unlinkable to
the user's identity and unlinkable across sessions. Each session uses an ephemeral API
key issued via blind signatures with no identity binding -- OpenRouter has no way to know
who is behind any given key.

OA adds enforceable accountability on top of the provider relationship:

- Toggle verification ensures the station's OpenRouter account has logging/training
  disabled, using OpenRouter's own APIs as evidence.
- Shadow-account prevention ensures the station cannot issue keys from a second,
  logging-enabled account.

What zero-trust guarantees for users:

- No OA component (org, station, verifier operator) needs to be trusted. The verifier
  is hardware-attested (AMD SEV-SNP) and open-source. Even a compromised OA operator
  cannot alter the attested code or extract user identity from the system, because no
  OA component possesses user identity in the first place.
- The org being closed-source does not affect unlinkability. The security-critical
  cryptography (blinding/unblinding) runs client-side in open-source code. The org is
  an operational orchestrator whose worst case is denial of service, not privacy breach.
- Centralized OA components (registry, org backend) are an availability concern, not a
  trust concern. No centralized OA component can deanonymize users because none possess
  the identity-to-inference linkage. Future roadmap includes multiple verifier instances
  and stations operated by independent parties (universities, other organizations).

Defense-in-depth: even if every side-channel attack were to succeed and blind signature
unlinkability were somehow weakened, inference remains unlinkable -- no OA system sees
prompts or responses (direct browser-to-provider), and the provider sees anonymous
ephemeral keys. The worst case for the org is knowing "some user obtained an API key"
but never what was sent with it. See
[PRIVACY_MODEL.md](https://github.com/openanonymity/oa-fastchat/blob/main/docs/PRIVACY_MODEL.md)
for the full malicious-component analysis.

## System-Level Unlinkability Model

"Unlinkable inference" means: **no party in the OA system can link a specific user's
identity to their specific inference activity.** This property is achieved through
multiple complementary mechanisms (see blog post
[Section 1: Blind Signatures](https://openanonymity.ai/blog/unlinkable-inference/#1-blind-signatures),
[Section 2: Secure Inference Proxies](https://openanonymity.ai/blog/unlinkable-inference/#2-secure-inference-proxies),
and [Section 3: Putting It Together](https://openanonymity.ai/blog/unlinkable-inference/#3-putting-it-together)):

1. **Blind signatures** -- The org/station signs blinded token requests during
   ticket issuance. The user unblinds locally to produce a finalized ticket. At
   redemption, the finalized ticket is cryptographically unlinkable to the signing
   event. No party except the user has ever seen the finalized ticket before redemption.
   The org/station therefore cannot correlate "I signed blind request B" to "ticket T
   was redeemed for API key K." Even though the org handles both issuance
   (`/api/alpha-register`) and redemption (`/api/request_key`), it only sees blinded
   requests at issuance and finalized (unblinded) tickets at redemption -- these are
   cryptographically unlinkable. See blog post
   [Section 3.1.3: OA-Proxy Collusion](https://openanonymity.ai/blog/unlinkable-inference/#3-putting-it-together).

2. **Ephemeral key carries no user identity** -- The API key returned to the user has no
   binding to any user identity. OpenRouter sees inference from key K but has zero
   information about who holds key K. The key was issued by a station, but the station
   cannot link it back to any prior interaction or user identity (blind signatures).

3. **No OA system sees prompts/responses** -- Prompts and responses go directly from
   the user's browser to OpenRouter over HTTPS. The org, station, and verifier are
   architecturally excluded from the inference data path. The verifier's attested code
   proves this exclusion.

4. **Verifier processes keys transiently** -- `handleSubmitKey` uses the raw API key
   only for signature verification and immediately hashes it via SHA-256
   (`computeKeyHash`). The raw key is never stored in memory beyond the handler scope,
   never written to logs, and never included in org event payloads. Only a truncated
   hash prefix (16 hex chars) appears in structured logs.

5. **Centralized components cannot deanonymize** -- Even though the registry and org
   backend are centralized, they never possess the identity-to-inference linkage. The
   registry gates station admission (not user identity). The org backend receives
   governance events about stations (not about users). No centralized OA component can
   correlate a user to their inference activity.

Common audit mistake: confusing "component X can see data item Y" with "unlinkability
is broken." The correct question is: **can any party link a specific user's identity to
specific inference requests?** Seeing a finalized ticket or an API key is useless for
deanonymization because neither carries user identity.

## Wrong-Conclusion Traps

The following traps have occurred in prior audits. They stem from confusing
"component X can see data item Y" with "unlinkability is broken." The correct
question is always: **can any party link a specific user's identity to specific
inference requests?** For the formal threat model and security properties, see blog post
[Section 3.1: Threat Model & Security Properties](https://openanonymity.ai/blog/unlinkable-inference/#31-threat-model).

| Trap | Correct interpretation |
|---|---|
| "Verifier is where user prompts go." | False. Prompt transport is client -> provider path. |
| "No verification inputs are required." | False. Registry/org/provider account-state are required anti-forgery verification inputs. |
| "Decoded `/attestation` summary is full cryptographic proof." | False. JWT signature + freshness checks are required externally. |
| "Verifier alone proves ticket unlinkability." | False. That is a separate system-level property outside verifier-runtime-only claims. |
| "Station sees the finalized ticket and API key, so unlinkability is broken." | False. The finalized ticket is the output of blind signature unblinding -- cryptographically unlinkable to the blind-signing event. No party except the user has seen it before redemption. The station cannot correlate signing to redemption. |
| "OpenRouter sees the API key and inference, so zero-trust is violated." | False. OpenRouter is the frontier model provider used by OA. Even a malicious provider cannot link prompts to a user's identity or to each other. Each session uses an ephemeral key issued via blind signatures with no identity binding. The provider sees anonymous, unlinkable requests. OA additionally enforces accountability via toggle verification and shadow-account prevention. |
| "The verifier sees the API key in `/submit_key`, so it can track users." | False. The raw key is used transiently for signature verification, immediately hashed (SHA-256), and never stored, logged, or reported. Only a truncated hash prefix (16 hex chars) appears in structured logs. Even if retained, the key carries no user identity because it was issued through blind signatures. |
| "Centralized registry/org contradicts zero-trust." | False. Centralization is an availability concern, not a trust concern. No centralized OA component (registry, org backend) possesses the identity-to-inference linkage needed for deanonymization. The registry gates station admission. The org receives station governance events. Neither sees user identity or inference content. |
| "OA systems (org, station) could log user prompts." | False. No OA system (org, station, verifier) is in the inference data path. Prompts go directly from the user's browser to OpenRouter over HTTPS. The verifier's attested code proves this architectural exclusion. Station operator cookies are governance material for toggle/ownership checks, not prompt-transport credentials. |
| "The org handles both issuance and redemption, so it can correlate them." | False. At issuance the org sees blinded requests; at redemption it sees finalized (unblinded) tickets for the first time. These are cryptographically unlinkable -- that is the core guarantee of blind signatures. The org knows "credential X -> N blinded requests" but cannot determine which finalized tickets those became. |
| "The org knows the invitation code/email, so it knows who redeemed tickets." | False. The org knows identity -> credential -> N blinded requests. But it cannot link blinded requests to finalized tickets (blind signatures). The finalized tickets at redemption are unlinkable to any prior issuance step. |
| "The provider sees prompts, so zero-trust is violated." | False. OA's claim is unlinkable inference, not invisible inference. Prompts reach the provider (they must for inference to work), but they are unlinkable to the user's identity and to each other. The provider sees anonymous requests from ephemeral keys. |
| "Station operator cookies stored in verifier memory affect user privacy." | False. Station operator credentials are governance data for compliance checks on the operator's provider account. They are not end-user data. The verifier never receives or stores any end-user identity material. |
| "Side-channel attacks (timing, IP, batch size) break unlinkability." | IP is mitigated by the built-in in-browser VPN proxy (on by default), and users can additionally use their own VPN/Tor. Timing correlation is weakened by the large volume of tickets issued across many users -- individual redemption events are lost in the mix. Even if these side channels were somehow exploited, inference remains unlinkable: no OA system sees prompts/responses (direct browser-to-provider), the provider sees anonymous ephemeral keys, and the worst case is the org learning "some user obtained an API key" -- but never what was sent with it. |
| "The org is closed-source, so it's an unauditable trust anchor." | False. The org does not need to be trusted for unlinkability. Blinding/unblinding runs client-side using `@cloudflare/privacypass-ts` (open-source, Apache-2.0, pure JS). The org only sees blinded requests (issuance) and finalized tickets (redemption) which are cryptographically unlinkable. Its worst case is denial of service, not privacy breach. See [UNLINKABILITY_PROOF.md](https://github.com/openanonymity/oa-fastchat/blob/main/docs/UNLINKABILITY_PROOF.md) for the formal proof. |
| "The org could serve per-user public keys to break unlinkability." | Detectable. The public key endpoint is publicly accessible and unauthenticated. Any user or third party can call it at any time to record and compare keys. Since verification calls are independent and unpredictable, the org cannot serve per-user keys without detection. A single inconsistency reported by any observer exposes the attack. Future: automated transparency log. |
| "OpenRouter could perform traffic analysis on ephemeral keys to deanonymize users." | False. Each session uses a different ephemeral key with no user identity binding. There is no persistent pseudonym across sessions for the provider to build a longitudinal profile against. Content-based correlation has only plausible deniability -- the provider cannot distinguish Alice sending prompt X from Bob sending the same prompt. |
| "Toggle/ownership verification means trusting OpenRouter, violating zero trust." | False. Toggle and ownership checks enforce accountability on the station's provider account -- they are not about trusting the OA system. If OpenRouter lies about its own API state, it undermines itself, not OA. User prompts remain unlinkable regardless because blind signatures and ephemeral keys carry no user identity. |
