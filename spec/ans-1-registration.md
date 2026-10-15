# ANS-1: Registration & Lifecycle

Status: DRAFT v1.0
Spec: ANS-1 (Registration & Lifecycle)
Version: 0.2.0
Date: 2026-07-02
Audience: implementers building an ANS-conformant Registration Authority (RA)

## 1. Scope

ANS-1 defines how an agent's **primary anchor** — an FQDN proven through ANS-0's [fqdn profile](identity-profiles/fqdn.md) — binds to operational metadata (display name, description, endpoints) and how that binding moves through a lifecycle. ANS-1 specifies:

- The `RegistrationService` contract: register, verify-acme, verify-dns, revoke, plus the server-certificate renewal and identity-certificate rotation operations.
- The registration aggregate's data shape and identifier set.
- The lifecycle state machine (§4.4).
- The event set the RA emits to the Transparency Log (ANS-4).

ANS-1 reads the agent's primary anchor through the ANS-0 proof-of-control gate
([ANS-0 §3](ans-0-identity-anchor.md#3-the-proof-of-control-gate)) and does not re-implement
per-kind mechanics. The agent (the *what*) carries one FQDN primary anchor; operator identities
(the *who*) are **Verified Identities** proven and linked per ANS-0
([§4](ans-0-identity-anchor.md#4-the-verified-identity-object),
[§6](ans-0-identity-anchor.md#6-identity-links)), not registration anchor types.

ANS-1 does **not** specify the proof-of-control gate itself (ANS-0), the ANSName form or Identity Certificate binding (ANS-2), DNS emission (ANS-3), TL sealing (ANS-4), continuous verification (ANS-5), or trust scoring (the separate Trust Index specification).

## 2. Terminology

- **Registration**: an aggregate the RA owns, identified by `agentId`, carrying the ANSName (`agentHost` with an optional name-bound `version`), operational metadata, status, and lifecycle history.
- **AHP (Agent Hosting Platform)**: the operator that hosts the agent's code and manages its DNS and certificates. Submits the registration request.
- **Lifecycle event**: an event the RA emits to the TL when a registration changes state. The emitted set is `AGENT_REGISTERED` (activation), `AGENT_REVOKED` (revocation), `AGENT_RENEWED` (certificate changes) and `AGENT_UPDATED` (profile/endpoint changes). `AGENT_DEPRECATED` remains reserved (§6.3).
- **Identity Certificate**: an optional owner-authorized certificate binding, either RA-issued from a CSR or imported through the identity-certificate operation. The leaf must cover the registered FQDN; runtime possession follows ANS-6. A registration without one registers, activates, and operates on its Server Certificate alone (§7.2).

## 3. The `RegistrationService` interface

The `RegistrationService` is the protocol contract for ANS-1; conformant implementations expose `register`,
`verifyACME`, `verifyDNS`, `getRegistration`, `list`, and `revoke`, plus the server-certificate renewal family
identity-certificate rotation, and owner-scoped GET/PUT operations for profile and endpoints (§7.4). The stored `LifecycleStatus` set is `PENDING_VALIDATION`, `PENDING_DNS`,
`ACTIVE`, `DEPRECATED`, `REVOKED`, `FAILED`, and `EXPIRED`; the RA additionally surfaces `PENDING_CERTS` in
the pending-registration response as the derived phase while certificate issuance is in flight (it is not a
distinct stored state).

The `agentHost` field is the agent's operational FQDN: ANS-3 (DNS publication) consumes it for record generation, and an optional `version` derive the registration's ANSName.

## 4. Registration sequence

Registration is a three-step flow driven by the AHP: the RA accepts the request and returns the domain-control
challenges (`PENDING_VALIDATION`), verify-acme proves domain control and issues certificates (`PENDING_DNS`),
and verify-dns confirms the published records and activates the agent (`ACTIVE`). ANS never writes DNS on the
operator's behalf — every DNS step is the AHP publishing records the RA hands it.

### 4.1 Step 1 — pending registration

The AHP submits a registration request:

| Group | Field | Required | Description |
| --- | --- | --- | --- |
| **Identity** | `agentHost` | Yes | Operational FQDN (RFC 1123) |
| | `version` | No (V2); Yes (V1) | Optional bare semver (e.g., `1.0.0`); omission creates `ans://{agentHost}` |
| | `agentDisplayName` | Yes | Human-readable name (max 64 chars) |
| | `agentDescription` | No | Brief capability description (max 150 chars) |
| **Endpoints** | per-endpoint `protocol` | Yes | `A2A`, `MCP`, or `HTTP-API` (1–16 endpoint/location records) |
| | per-endpoint `agentUrl` | Yes | The endpoint URL; its hostname MUST equal `agentHost` (case-insensitive) |
| | per-endpoint `metaDataUrl` | No | Protocol metadata URL on the registered FQDN |
| | per-endpoint `metaDataHashes` | No | Accepted set of 0–8 unique `SHA256:<64 lowercase hex>` digests for this service/metadata location; a nonempty set requires `metaDataUrl` |
| | per-endpoint `metaDataHash` | No | Legacy singleton input; mutually exclusive with `metaDataHashes` |
| | per-endpoint `documentationUrl` | No | Developer documentation |
| | per-endpoint `functions` | No | Function declarations: `id`, `name`, optional `tags` |
| | per-endpoint `transports` | No | `STREAMABLE_HTTP`, `SSE`, `JSON_RPC`, `GRPC`, `REST`, `HTTP` |
| **Discovery** | `discoveryProfiles` | No | The DNS record families the RA emits for this registration, per [ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles). Defaults to `ANS_DNSAID` |
| **Certificates** | `identityCsrPEM` | No | Optional CSR for private identity issuance. A server-only registration may add an identity credential after activation (§7.2) |
| | `serverCsrPEM` | Conditional | CSR for the RA-issued Server Certificate |
| | `serverCertificatePEM` (+ optional `serverCertificateChainPEM`) | Conditional | BYOC Server Certificate. Exactly one of `serverCsrPEM` / `serverCertificatePEM` MUST be present |

Pending-stage validations:

1. `agentHost` MUST be a syntactically valid FQDN (RFC 1123).
2. Each endpoint's `agentUrl` MUST carry `agentHost` as its hostname (case-insensitive). The constraint keeps endpoint URLs reachable through the same TLS certificate that anchors the agent's identity.
3. Exactly one of `serverCsrPEM` and `serverCertificatePEM` MUST be present (CSR or BYOC, never both, never neither).
4. The endpoint set MUST contain 1–16 valid records keyed by `(protocol, agentUrl, metaDataUrl)`. Repeated protocols at distinct locations are permitted; duplicate tuples, duplicate/malformed digests and conflicting singular/plural hash inputs reject (422). Both service and metadata URL hosts MUST equal `agentHost`; existing URL safety rules apply.
5. `agentDisplayName` and `agentDescription` length limits apply (64 and 150 chars respectively).
6. The ANSName derived from `agentHost` and the optional `version` MUST be globally unique; a taken name is rejected with `ANS_NAME_TAKEN` (409).

If valid, the RA assigns an `agentId` (UUID v4), constructs the ANSName per [ANS-2 §2](ans-2-versioned-naming.md), opens a certificate order at the configured server-certificate issuer, and sets the registration to `PENDING_VALIDATION`. The response relays the order's domain-control challenges (DNS-01 TXT and/or HTTP-01) verbatim to the AHP.

### 4.2 Step 2 — verify-acme (domain control and certificate issuance)

After publishing a challenge artifact, the AHP calls `verifyACME(agentId)`. The challenge gate passes when either the DNS-01 TXT record or the HTTP-01 resource verifies. The gate is unconditional — it runs on every registration.

On a passing gate the RA:

1. Finalizes the server-certificate order (or validates the BYOC certificate). Asynchronous CAs (e.g. RFC 8555 ACME CAs) may return an order-pending result; re-POSTing verify-acme re-drives the order until the certificate issues.
2. Signs the Identity CSR at the private CA — **only when one was submitted at registration**. A registration without a pending Identity CSR is not an error; the agent advances without an Identity Certificate.
3. Transitions the registration to `PENDING_DNS`. The verify-acme response is a status body (status, phase, completed/pending steps, timestamps); the AHP fetches the production DNS record set it must publish from the registration detail response while `PENDING_DNS` (content per [ANS-3 §3](ans-3-dns-publication.md)), and the issued certificates from the `GET …/certificates/*` endpoints.

Conformant implementations MUST gate identity-certificate issuance on the presence of a pending Identity CSR, not unconditionally on lifecycle entry.

### 4.3 Step 3 — verify-dns (activation)

After publishing the production records, the AHP calls `verifyDNS(agentId)`. The RA checks the
ANS-managed discovery records under ANS-3 §4. SVCB and HTTPS lookups carry the resolver's DNSSEC Authenticated-Data
result into the sealed event as `dnsRecordsProvisioned[].dnssecVerified`; TXT lookups do not carry the flag.

When the records verify, the RA records the ACTIVE transition and its signed `AGENT_REGISTERED` publication under the durability and replay requirements in §6.3–§6.5.

### 4.4 The state machine

```text
                ┌────────────────────┐
                │ PENDING_VALIDATION │──────────────┐
                └──────────┬─────────┘              │
                           │ domain control proven, │ lapses to EXPIRED /
                           │ certificates issued    │ cancel to REVOKED
                           ▼                        ▼
                    ┌──────────────┐         ┌───────────────────┐
                    │ PENDING_DNS  │────────▶│ EXPIRED / REVOKED │
                    └──────┬───────┘         └───────────────────┘
                           │ published records verified
                           ▼
                    ┌──────────────┐         ┌──────────────┐
                    │    ACTIVE    │────────▶│  DEPRECATED  │
                    └──────┬───────┘         └──────┬───────┘
                           │ AHP or RA              │ AHP or RA
                           │ revokes                │ revokes
                           ▼                        ▼
                    ┌──────────────────────────────────────────┐
                    │                 REVOKED                  │
                    └──────────────────────────────────────────┘
```

`REVOKED`, `FAILED`, and `EXPIRED` are terminal. Revocation is idempotent. Cancelling a pending
registration transitions it to `REVOKED` without a TL event (no log entry exists for an agent that never
reached `ACTIVE`), revoking any already-issued Identity Certificates at the private CA — except a
`PENDING_VALIDATION` registration still awaiting its domain-control challenge, which is refused
(`CANNOT_CANCEL`) and lapses to `EXPIRED` on its own; the pre-activation expiry sweep likewise emits no TL
event.

`DEPRECATED` and `FAILED` are defined states (`ACTIVE → DEPRECATED` a valid transition, `FAILED` a
pending-side terminal), but no RA operation drives either today (§6.3).

Activation and revocation produce their lifecycle events. Eligible certificate and metadata mutations also publish complete snapshots (§6.3); they do not create a new registration or reactivate a terminal one. Everything before activation is RA-internal.

## 5. Identifiers

| Identifier | Format | Assigned by | Mutable | Scope | Purpose |
| --- | --- | --- | --- | --- | --- |
| **`agentId`** | UUID v4 | RA at registration | No | Issuing RA | Registration-instance key; used in the RA API paths (`/v2/ans/agents/{agentId}`, `/v1/agents/{agentId}`) |
| **`ansId`** | UUID | RA | No | Issuing RA | Carried in every sealed TL event payload. In the reference implementation it is the same value as `agentId` |
| **`logId`** | UUID v7 | TL at ingest | No | TL | The Transparency Log entry identifier, wrapped around the producer event when the TL seals it |
| **`agentHost`** | RFC 1123 FQDN | AHP submits | No | Global | Operational endpoint where the agent terminates TLS |
| **`ANSName`** | `ans://{host}` or `ans://v{ver}.{host}` | Derived at registration | No | Global | Stable identifier (see [ANS-2 §2](ans-2-versioned-naming.md)); the assigned name remains unchanged during updates |
| **`ownerId`** | RA-defined | RA from its authentication system | No | Issuing RA | The authenticated principal that owns the registration; scopes reads and lifecycle operations |

The TL wire envelopes carry an optional `providerId` field on agent events, but the agent lane leaves it empty; `providerId` is populated on identity-lane events only ([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)). Cross-RA correlation is by `agentHost`: an agent moves between RAs by updating DNS records, not by changing its name.

## 6. Event set

The RA emits the following events to the ANS-4 Transparency Log. Each event carries the RA instance ID (`raId`) and the RA's producer signature, and is sealed by the TL before becoming visible to consumers.

### 6.1 `AGENT_REGISTERED`

Emitted at activation (the verify-dns transition to `ACTIVE`). Publications follow the **V3 TL format**: `ansId`
(the RA-assigned agent id), `ansName`, a nested `agent` object (`host`, `name`, optional `version` and `description`), `attestations` —
`identityCerts[]` (when the registration carries Identity Certificates) and `serverCerts[]`, each entry
`{fingerprint, type, notAfter}`; `dnsRecordsProvisioned[]` as `{name, type, data}` records, each optionally
carrying `dnssecVerified: true` when the verifying resolver returned the DNSSEC Authenticated-Data bit;
`domainValidation`; and `endpointMetadata`, the complete list of
`{protocol, agentUrl, metaDataUrl, metaDataHashes}` records. An absent metadata URL is `""`; no commitment
is `[]`. A legacy `metadataHashes` entry is provided only for a protocol with one location and one digest.
The event also carries `expiresAt` calculated under §7.3, `issuedAt`, `raId`, and `timestamp`.

ANS-4 §4.1 defines historical payload formats; §6.5 defines publication compatibility.

A worked example payload appears in the [ANS-1 worked examples](examples/ans-1-examples.md).

### 6.2 `AGENT_REVOKED`

Emitted when the AHP or RA revokes a registration. Payload includes `revocationReasonCode` — an RFC 5280
revocation reason name token (`KEY_COMPROMISE`, `AFFILIATION_CHANGED`, `SUPERSEDED`, `CESSATION_OF_OPERATION`,
`CERTIFICATE_HOLD`, `PRIVILEGE_WITHDRAWN`, `AA_COMPROMISE`) — and `revokedAt`. AHP submissions use the
friendlier short field name `reason`; the sealed event canonicalizes to `revocationReasonCode`.

### 6.3 Renewal and metadata events

Certificate additions, renewals, rotations and binding removals publish `AGENT_RENEWED`; profile and
endpoint changes publish `AGENT_UPDATED`. Each event is a complete snapshot of the resulting certificate
families, profile, endpoints and applicable validation evidence. Metadata edits preserve certificate
expiry and domain-proof age. A delayed certificate completion MUST preserve newer metadata changes.

Before acknowledging acceptance, the RA MUST durably record both the mutation and the exact signed
publication so neither can be lost independently. Publication follows §6.5; responses follow §7.4.
`AGENT_DEPRECATED` remains reserved.

### 6.4 Identity events (V2)

These events exist only when the RA implements the **optional** Verified Identity surface
([ANS-0 §12.2](ans-0-identity-anchor.md#122-optional-capability-verified-identities)); an RA
without it emits none of them and is fully conformant.

The Verified-Identity event family — `IDENTITY_VERIFIED`, `IDENTITY_UPDATED`, `IDENTITY_REVOKED`,
`IDENTITY_LINKED`, `IDENTITY_UNLINKED` — is defined by
[ANS-0 §8.1](ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest) and sealed on the
**identity ingest lane** ([ANS-4 §5.3](ans-4-transparency.md#53-identity-surface)), not as part
of the agent event set above. These events are emitted by the identity API
(`/v2/ans/identities/*`), carry `SchemaVersion = "V2"`, and are indexed under `identityId` (and,
for link events, additionally under each named `ansId`). The V1 agent event lane is unaffected
and stays frozen.

A linked agent's badge reflects its who-identities by a **read-time join** over these events
([ANS-0 §8.2](ans-0-identity-anchor.md#82-computed-reads-and-the-visibility-predicate)) — an
identity rotation or revocation seals exactly one event regardless of how many agents are linked,
and **no identity operation writes to an agent's event history** (nor the reverse). The agent
detail response gains a computed, optional `identities[]` array (the current-links view) that is
never stored on the registration; the list response carries no identities field.

### 6.5 Publication compatibility

Newly constructed agent events use the V3 ingest route and envelope defined in ANS-4 §4.1, including
mutations of existing registrations through supported V1/V2 management routes. V1 registration requests
still require a version; the V2 management API permits omission.

A successful mutation preserves the registration ID, FQDN, assigned ANS name, name-bound version and
established discovery identifier. It adopts V3 for subsequent publications; failed writes and no-ops
do not commit adoption. Later events remain V3 across restart and configuration changes.

Already-signed queued events and prepared activation retries retain their exact bytes, signatures and
schema. The TL accepts exact historical retries under deduplication and rejects newly constructed
schema downgrades. Publications remain ordered per registration so an older snapshot cannot become
current after a newer one. Historical entries are immutable.

## 7. Lifecycle operations

| Operation | Trigger | AHP submits | RA processes | RA seals | DNS effect |
| --- | --- | --- | --- | --- | --- |
| **Additional versioned registration** | Operator needs a separate registration identity | A full new registration: new `version`, same `agentHost`, display name, endpoints, and exactly one of server CSR / BYOC (an Identity CSR MAY be included) | The new registration runs the full sequence — fresh domain-control proof, certificate issuance, DNS verification | `AGENT_REGISTERED` (for the new registration) | New per-version records published by the AHP; the prior version's records are untouched |
| **Renewal (Server Certificate)** | Certificate approaching expiration | A renewal submission (CSR or BYOC) on the renewal routes | Re-proves domain control at renewal verify-acme (DNS-01 TXT or HTTP-01), then finalizes the order and delivers the fresh certificate | `AGENT_RENEWED` with current certificate and metadata snapshots | None |
| **Identity credential addition/rotation/removal** | Owner authorizes or retires a credential | `csrPEM` or BYOC leaf on the identity route; DELETE an individual binding by fingerprint | Owner/ACTIVE/admission checks; retain valid overlap; removing an external binding does not revoke its CA certificate (§7.2) | `AGENT_RENEWED` with the resulting certificate families | No automatic DNS publication |
| **Profile/endpoint update** | Display text, metadata or endpoint changes | Complete replacement with the resource ETag in `If-Match` | Owner/lifecycle/precondition and full-result validation (§7.4) | `AGENT_UPDATED` | No DNS change for unmirrored display/hash edits; locator changes may require publication |
| **Revocation** | Agent shutdown or version retirement | `reason` (RFC 5280 reason name token) | Revokes Identity Certificates at the issuing private CA (Server Certificates are not revoked at their issuer) and transitions the registration | `AGENT_REVOKED` | The revocation response lists ANS-managed `dnsRecordsToRemove`; the AHP removes them under ANS-3 |

One exception to the renewal re-proof: a CSR renewal whose provider order arrives with no challenges (ACME
authorization reuse inside the provider's validity window) finalizes directly — the re-proof is the
provider's cached validation rather than a fresh RA-side check. Re-driven verify-acme calls on an
already-finalizing order likewise skip the artifact check by design.

### 7.1 Version coexistence

Separate versioned and versionless registrations have independent status, credentials and history,
as defined in ANS-2 §2.3. Updating an existing registration uses the compatibility rules in §6.5.

### 7.2 Identity credential management

An ACTIVE registration's owner may add an identity credential using
`POST /v2/ans/agents/{agentId}/certificates/identity`, including when no identity CSR was supplied at
registration. Supply exactly one of `csrPEM` or `identityCertificatePEM`; the certificate may include
`identityCertificateChainPEM`. A chain alone or a CSR combined with BYOC material rejects.

CSR submission returns `202 {csrId, message?}`. BYOC returns
`202 {status: "PENDING_PUBLICATION"}` under the durable-publication rule in §6.3. Admission follows
ANS-2 §3; no enrollment possession challenge is required. The resulting `AGENT_RENEWED` snapshot retains
valid overlap and current metadata. A renewed leaf needs a new fingerprint binding even when its key
is unchanged. Use begins when the verifier's authenticated evidence includes that binding (§7.4).

The owner retires a binding through
`DELETE /v2/ans/agents/{agentId}/certificates/identity/{fingerprint}`, using the 64 lowercase hex digest
without `SHA256:`. It requires ACTIVE state and returns 202 pending publication. Repeating removal of a
known retired binding is idempotent; an unknown fingerprint returns 404. This removes ANS authorization,
not the externally issued certificate at its CA. Fresh evidence excludes the binding; cached tokens
retain their existing acceptance window.

Retiring the final identity binding leaves a server-only registration and disables ANS caller
authentication. Credential removal preserves domain-proof age.

### 7.3 Expiry

For each complete certificate snapshot, the RA MUST calculate `expiresAt` from the latest expiry within
each required certificate group, then the earliest of those group expirations:

```text
serverExpiry   = max(server certificate notAfter values)
identityExpiry = max(identity certificate notAfter values)
expiresAt      = min(serverExpiry, identityExpiry)
```

Compare RFC 3339 timestamps as instants, normalizing offsets to UTC. Certificate validity includes
`notAfter` (RFC 5280 §4.1.2.5); a group has lapsed when the current instant is later than its latest
`notAfter`. “Latest” means furthest expiry, not most recent issuance.

Server Certificates are required. The identity group also participates while the registration carries
identity bindings. Explicit retirement of the final identity binding (§7.2) makes subsequent snapshots
server-only, with `expiresAt = serverExpiry`; expiry alone is not retirement. Every required group MUST
be nonempty at activation.
A new snapshot MUST retain expiry evidence for a lapsed required group rather than omit it or invent a
value for an undefined `max()`. Historical snapshots and their sealed `expiresAt` are immutable.

Expiry of another required group MUST NOT by itself block Server Certificate renewal on a registration
whose stored status is ACTIVE. Renewal publishes a new complete snapshot (§6.3); the TL evaluates its
`expiresAt` after publication. Replacing the server leaf alone does not recover an expired identity group.

An older certificate expiring during overlap does not expire the registration while every required
group has a usable replacement in the current evidence. Individual validity and revocation checks still
apply. See the [overlap example](examples/ans-1-examples.md#a4-certificate-expiry-during-overlap).
Certificate lapse itself does not change stored ACTIVE state or emit an event; the TL derives WARNING
and EXPIRED at read time. The pending-registration expiry sweep remains as specified in §4.4.

### 7.4 Updating registration data

Owners use these conditional replacement resources:

| Resource under `/v2/ans/agents/{agentId}` | GET body with strong ETag | PUT replacement |
| --- | --- | --- |
| `/profile` | `{agentDisplayName, agentDescription}` | Both non-null strings; nonempty name of at most 64 chars and description of at most 150; `""` clears description |
| `/endpoints` | `{endpoints: [...]}` | Complete collection of 1–16 endpoint/location records |

Only the listed fields are writable. Endpoint records reuse `protocol`, `agentUrl`, `metaDataUrl`,
`documentationUrl`, `functions` and `transports`; `(protocol, agentUrl, metaDataUrl)` identifies a record.
Service and metadata URLs stay on the registered FQDN and follow the certificate-coverage rules in
ANS-2 §3. Informational documentation links are not endpoints.

`metaDataHashes` contains up to eight unique `SHA256:<64 lowercase hex>` values. A nonempty set requires
`metaDataUrl`. Legacy `metaDataHash` is singleton input and MUST NOT be combined with the plural form.
Replacement removes omitted records and digests. Empty or missing commitments authorize no metadata bytes.

The request MUST supply the strong ETag returned by GET of the same resource in `If-Match`.
Missing tags return `428 PRECONDITION_REQUIRED`; stale tags return `412 PROFILE_CHANGED` or
`412 ENDPOINTS_CHANGED`. Weak/wildcard tags are not accepted. The RA MUST enforce ownership, ACTIVE
eligibility, usable certificate evidence and the precondition against the state being changed.
Unknown, immutable or invalid fields reject; metadata edits cannot recover a lapsed registration.

A changed result follows the durable-publication rule in §6.3. The response is
`202 {"status":"PENDING_PUBLICATION"}` with the resulting ETag. This confirms local acceptance; new
bindings are usable only after they appear in the verifier's authenticated evidence. An unchanged
representation returns the same ETag without another event. After an ambiguous response, read the
resource before retrying: the earlier write may have succeeded and made its precondition stale.

Metadata edits preserve domain-proof age. `discoveryProfiles` is not writable here. Endpoint, port or
locator changes may require operator DNS publication under ANS-3.

### 7.5 Discovery snapshots and stable identifiers

Public discovery reflects delivered evidence; management reads may include accepted edits still awaiting
publication. Feed entries MUST preserve event-time values and distinguish discovery annotations from
TL-attested fields. Historical entries must not acquire current mutable values.

Finder/catalog consumers process `AGENT_UPDATED`, support registrations without a version, and distinguish
same-protocol locations. An authoritative update with zero discoverable A2A/MCP endpoints clears prior
results; a failed projection does not. The registration still has at least one endpoint, possibly HTTP-only.

Keep established agent and child discovery identifiers stable across renames, hash changes, adoption and
index rebuild. Optional `discoveryIdentifier` carries the existing handle. Catalog `updatedAt` reflects
the published event time, and its ETag changes when emitted bytes change.

## 8. RA key management

| Principle | Rule |
| --- | --- |
| Agent keys | The RA never generates, handles, or accesses an agent's private keys. Registration intake is CSR- or BYOC-based; the AHP owns its key lifecycle |
| RA producer keys | Each RA instance MUST have at least one active public key registered with the ANS-4 TL before submitting events. Rotation uses an overlap window: new keys are registered with future `valid_from` dates; both old and new remain active during the transition. Producer private keys never leave the RA instance |

Producer-key expiry and revocation both gate **new** ingest — an expired or revoked key can no longer sign events the TL will accept. Already-sealed events are unaffected: the log is append-only, and verifiers check the TL's own attestations, receipts, and checkpoints against `/root-keys`, not producer keys.

Producer-key rotation procedure:

1. Generate the new producer key pair under the RA's key manager. The reference implementation ships a file-based ECDSA P-256 key manager; cloud-KMS adapters slot in at the port boundary.
2. Register the public key with the TL (`POST /internal/v1/producer-keys`, admin-gated). `valid_from` (set to the rotation cutover time) and `expires_at` are both required, and `valid_from` must precede `expires_at`.
3. Continue signing with the old key until cutover; the RA's signing identity is its configured `{keyId, raId}` attestation pair.
4. At cutover, switch the RA's configuration to the new key. The old key remains registered and inside its validity window, so pending events replaying their persisted signatures still verify at ingest.
5. Revoke the old key (`DELETE /internal/v1/producer-keys/{key_id}`) once no pending events reference it. Revocation stops the key from authorizing new ingest; previously-sealed events remain verifiable through the TL's own attestations and receipts.

## 9. Conformance

A conformant ANS-1 implementation:

1. Exposes a `RegistrationService` whose register operation accepts the registration request (§4.1) and returns the pending registration with its domain-control challenges.
2. Verifies domain control before certificate issuance on every registration and renewal — the challenge gate is unconditional, except a renewal order that arrives challenge-free under ACME authorization reuse (§7).
3. Gates Identity Certificate issuance on the presence of a pending Identity CSR (the verify-acme rule, §4.2), never unconditionally on lifecycle entry.
4. Enforces global ANSName uniqueness at registration (`ANS_NAME_TAKEN`, 409).
5. Never generates, holds, or accesses an agent's private keys, and does not persist proven public keys as live state (key transience per [ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)).
6. Emits the registration, revocation, certificate and metadata events defined in §6 to the ANS-4 TL, constructing and signing each event payload once and replaying the exact bytes and signature on retry.
7. Honors the lifecycle state machine (§4.4) and permits only the eligible mutations in §7; updates never reactivate terminal registrations.
8. Exposes an owner-scoped `list(filter)` operation that supports `agentHost` filtering.
9. Implements resource-scoped conditional updates and published discovery snapshots (§7.4–§7.5).

## 10. Security considerations

### 10.1 Reputation continuity and operator changes

When a domain transfers ownership, the FQDN persists but the operator does not. Reputation accumulated under
the old operator must not silently transfer to the new one. The registration model bounds the exposure through
re-proof: domain control is re-proven at every renewal and every new version registration (the challenge gate
is unconditional, subject to the ACME authorization-reuse window noted in §7), so a party that no longer
controls the domain cannot renew or extend the registration. A
failed re-proof fails that renewal — the registration is not auto-revoked — and the certificates lapse on
their own schedule, surfacing as the TL's read-time `WARNING`/`EXPIRED` derivation. Revoking a live
registration is an operator or RA action (`AGENT_REVOKED`); downstream consumers evaluate staleness from the
sealed event timestamps.

### 10.2 Failure modes

| Scenario | Consequence | RA response |
| --- | --- | --- |
| AHP unavailable for extended period | Certificates expire; TLS fails | The RA cannot auto-renew (the AHP owns its private keys). RA state is unchanged; the TL derives `WARNING` and then `EXPIRED` at read time from the sealed `expiresAt` |
| TL unavailable | Agent-lane event delivery is deferred | Agent-lane publications are retained durably and replayed byte-for-byte until accepted; local acceptance follows §6.3. Identity-lane writes (ANS-0) instead fail closed with `TL_UNAVAILABLE` |

## Appendix A: Worked examples (non-normative)

Non-normative worked examples (registration request, event payloads) live at [`examples/ans-1-examples.md`](examples/ans-1-examples.md).

## References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md) — the proof-of-control gate, the Verified Identity object, identity links, and the [identity profiles](identity-profiles/).
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md) — ANSName form, Identity Certificate binding.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md) — DNS record emission per registration.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md) — TL append, receipt.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md) — verification worker contract.
- [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123): Host requirements (FQDN syntax).
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339): Timestamp representation and ordering.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): X.509 (certificate validity and revocation reason codes).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS (signature envelope).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JWK (JSON Web Key).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME (FQDN domain-control proof).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
