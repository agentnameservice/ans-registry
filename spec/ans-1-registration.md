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

ANS-1 does **not** specify the proof-of-control gate itself (ANS-0), the ANSName form or PriCC (ANS-2), DNS emission (ANS-3), TL sealing (ANS-4), continuous verification (ANS-5), or trust scoring (the separate Trust Index specification).

## 2. Terminology

- **Registration**: an aggregate the RA owns, identified by `agentId`, carrying the ANSName (`version` + `agentHost`), operational metadata, status, and lifecycle history.
- **AHP (Agent Hosting Platform)**: the operator that hosts the agent's code and manages its DNS and certificates. Submits the registration request.
- **Lifecycle event**: an event the RA emits to the TL when a registration changes state. The emitted set is `AGENT_REGISTERED` (at activation) and `AGENT_REVOKED` (at revocation). `AGENT_RENEWED` and `AGENT_DEPRECATED` are reserved event types — defined in the TL event enums and accepted at ingest, but not emitted by the reference RA (§6.3).
- **Identity Certificate**: an optional certificate binding the registration's ANSName, issued from the RA's private CA against an operator-submitted CSR. A registration without one registers, activates, and operates on its Server Certificate alone (§7.2).

## 3. The `RegistrationService` interface

The `RegistrationService` is the protocol contract for ANS-1; conformant implementations expose `register`,
`verifyACME`, `verifyDNS`, `getRegistration`, `list`, and `revoke`, plus the server-certificate renewal family
and identity-certificate rotation. The stored `LifecycleStatus` set is `PENDING_VALIDATION`, `PENDING_DNS`,
`ACTIVE`, `DEPRECATED`, `REVOKED`, `FAILED`, and `EXPIRED`; the RA additionally surfaces `PENDING_CERTS` in
the pending-registration response as the derived phase while certificate issuance is in flight (it is not a
distinct stored state).

The `agentHost` field is the agent's operational FQDN: ANS-3 (DNS publication) consumes it for record generation, and together with `version` it derives the registration's ANSName.

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
| | `version` | Yes | Semantic version, bare semver (e.g., `1.0.0`) |
| | `agentDisplayName` | Yes | Human-readable name (max 64 chars) |
| | `agentDescription` | No | Brief capability description (max 150 chars) |
| **Endpoints** | per-endpoint `protocol` | Yes | `A2A`, `MCP`, or `HTTP_API` (minimum 1 endpoint) |
| | per-endpoint `agentUrl` | Yes | The endpoint URL; its hostname MUST equal `agentHost` (case-insensitive) |
| | per-endpoint `metaDataUrl` | No | Protocol metadata location |
| | per-endpoint `metaDataHash` | No | `SHA256:`-prefixed SHA-256 of the document at `metaDataUrl`, computed and declared by the AHP (format-validated by the RA, not re-fetched). Sealed into the TL `attestations.metadataHashes` map keyed by the protocol token |
| | per-endpoint `documentationUrl` | No | Developer documentation |
| | per-endpoint `functions` | No | Function declarations: `id`, `name`, optional `tags` |
| | per-endpoint `transports` | No | `STREAMABLE_HTTP`, `SSE`, `JSON_RPC`, `GRPC`, `REST`, `HTTP` |
| **Discovery** | `discoveryProfiles` | No | The DNS record families the RA emits for this registration, per [ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles). Defaults to `ANS_TXT` |
| **Certificates** | `identityCsrPEM` | No | CSR for the Identity Certificate. When omitted, the agent registers without one and cannot add one later (§7.2) |
| | `serverCsrPEM` | Conditional | CSR for the RA-issued Server Certificate |
| | `serverCertificatePEM` (+ optional `serverCertificateChainPEM`) | Conditional | BYOC Server Certificate. Exactly one of `serverCsrPEM` / `serverCertificatePEM` MUST be present |

Pending-stage validations:

1. `agentHost` MUST be a syntactically valid FQDN (RFC 1123).
2. Each endpoint's `agentUrl` MUST carry `agentHost` as its hostname (case-insensitive). The constraint keeps endpoint URLs reachable through the same TLS certificate that anchors the agent's identity.
3. Exactly one of `serverCsrPEM` and `serverCertificatePEM` MUST be present (CSR or BYOC, never both, never neither).
4. The endpoint set MUST contain at least one endpoint with valid `protocol` and `agentUrl`, and at most one endpoint per protocol (`DUPLICATE_PROTOCOL`, 422).
5. `agentDisplayName` and `agentDescription` length limits apply (64 and 150 chars respectively).
6. The ANSName derived from `version` + `agentHost` MUST be globally unique; a taken name is rejected with `ANS_NAME_TAKEN` (409).

If valid, the RA assigns an `agentId` (UUID v4), constructs the ANSName per [ANS-2 §2](ans-2-versioned-naming.md), opens a certificate order at the configured server-certificate issuer, and sets the registration to `PENDING_VALIDATION`. The response relays the order's domain-control challenges (DNS-01 TXT and/or HTTP-01) verbatim to the AHP.

### 4.2 Step 2 — verify-acme (domain control and certificate issuance)

After publishing a challenge artifact, the AHP calls `verifyACME(agentId)`. The challenge gate passes when either the DNS-01 TXT record or the HTTP-01 resource verifies. The gate is unconditional — it runs on every registration.

On a passing gate the RA:

1. Finalizes the server-certificate order (or validates the BYOC certificate). Asynchronous CAs (e.g. RFC 8555 ACME CAs) may return an order-pending result; re-POSTing verify-acme re-drives the order until the certificate issues.
2. Signs the Identity CSR at the private CA — **only when one was submitted at registration**. A registration without a pending Identity CSR is not an error; the agent advances without an Identity Certificate.
3. Transitions the registration to `PENDING_DNS`. The verify-acme response is a status body (status, phase, completed/pending steps, timestamps); the AHP fetches the production DNS record set it must publish from the registration detail response while `PENDING_DNS` (content per [ANS-3 §3](ans-3-dns-publication.md)), and the issued certificates from the `GET …/certificates/*` endpoints.

Conformant implementations MUST gate identity-certificate issuance on the presence of a pending Identity CSR, not unconditionally on lifecycle entry.

### 4.3 Step 3 — verify-dns (activation)

After publishing the production records, the AHP calls `verifyDNS(agentId)`. The RA queries the records live; a DNSSEC-authenticated mismatch blocks activation. TLSA, SVCB, and HTTPS lookups carry the resolver's DNSSEC Authenticated-Data result into the sealed event as `dnsRecordsProvisioned[].dnssecVerified`; TXT lookups do not carry the flag.

When the records verify, the RA transitions the registration to `ACTIVE` and enqueues the `AGENT_REGISTERED` event to the ANS-4 TL in the same transaction. The event payload is constructed and signed once; retries replay the exact same bytes and signature (the TL dedupes by content hash).

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

TL events fire only on the `ACTIVE` and `REVOKED` transitions. Everything before activation is RA-internal.

## 5. Identifiers

| Identifier | Format | Assigned by | Mutable | Scope | Purpose |
| --- | --- | --- | --- | --- | --- |
| **`agentId`** | UUID v4 | RA at registration | No | Issuing RA | Registration-instance key; used in the RA API paths (`/v2/ans/agents/{agentId}`, `/v1/agents/{agentId}`) |
| **`ansId`** | UUID | RA | No | Issuing RA | Carried in every sealed TL event payload. In the reference implementation it is the same value as `agentId` |
| **`logId`** | UUID v7 | TL at ingest | No | TL | The Transparency Log entry identifier, wrapped around the producer event when the TL seals it |
| **`agentHost`** | RFC 1123 FQDN | AHP submits | No | Global | Operational endpoint where the agent terminates TLS |
| **`ANSName`** | `ans://v{ver}.{host}` | Derived from `version` + `agentHost` | No | Global | Versioned identifier (see [ANS-2 §2](ans-2-versioned-naming.md)); globally unique per registration |
| **`ownerId`** | RA-defined | RA from its authentication system | No | Issuing RA | The authenticated principal that owns the registration; scopes reads and lifecycle operations |

The TL wire envelopes carry an optional `providerId` field on agent events, but the agent lane leaves it empty; `providerId` is populated on identity-lane events only ([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)). Cross-RA correlation is by `agentHost`: an agent moves between RAs by updating DNS records, not by changing its name.

## 6. Event set

The RA emits the following events to the ANS-4 Transparency Log. Each event carries the RA instance ID (`raId`) and the RA's producer signature, and is sealed by the TL before becoming visible to consumers.

### 6.1 `AGENT_REGISTERED`

Emitted at activation (the verify-dns transition to `ACTIVE`). Payload follows the **V2 TL format**: `ansId`
(the RA-assigned agent id), `ansName`, a nested `agent` object (`host`, `name`, `version`), `attestations` —
`identityCerts[]` (when the registration carries Identity Certificates) and `serverCerts[]`, each entry
`{fingerprint, type, notAfter}`; `dnsRecordsProvisioned[]` as `{name, type, data}` records, each optionally
carrying `dnssecVerified: true` when the verifying resolver returned the DNSSEC Authenticated-Data bit;
`domainValidation` (the constant `ACME-DNS-01`); an optional `metadataHashes` map
keyed by protocol token — plus `expiresAt` (the earliest `notAfter` across the attested certificates),
`issuedAt`, `raId`, and `timestamp`.

Registrations driven through the V1 paths (`/v1/agents/*`) seal **V1-format** payloads instead: a map-typed
`dnsRecordsProvisioned` with no `dnssecVerified`, and `validIdentityCerts[]` / `validServerCerts[]`
rotation arrays (§6.4's "V1 lane stays frozen" covers identity events; the V1 agent lane remains live).

A worked example payload appears in the [ANS-1 worked examples](examples/ans-1-examples.md).

### 6.2 `AGENT_REVOKED`

Emitted when the AHP or RA revokes a registration. Payload includes `revocationReasonCode` — an RFC 5280
revocation reason name token (`KEY_COMPROMISE`, `AFFILIATION_CHANGED`, `SUPERSEDED`, `CESSATION_OF_OPERATION`,
`CERTIFICATE_HOLD`, `PRIVILEGE_WITHDRAWN`, `AA_COMPROMISE`) — and `revokedAt`. AHP submissions use the
friendlier short field name `reason`; the sealed event canonicalizes to `revocationReasonCode`.

### 6.3 Reserved event types

`AGENT_RENEWED` and `AGENT_DEPRECATED` are defined in both the V1 and V2 TL event enums, accepted at TL
ingest, and mapped by the TL's read-time badge and status-token derivations (`AGENT_DEPRECATED` →
`DEPRECATED`). The reference RA emits neither today: the renewal lifecycle completes without a TL event, and
no operation drives the `DEPRECATED` transition. The tokens are part of the wire contract and reserved for
those flows.

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

## 7. Lifecycle operations

| Operation | Trigger | AHP submits | RA processes | RA seals | DNS effect |
| --- | --- | --- | --- | --- | --- |
| **Version bump** | Code or config change | A full new registration: new `version`, same `agentHost`, display name, endpoints, and exactly one of server CSR / BYOC (an Identity CSR MAY be included) | The new registration runs the full sequence — fresh domain-control proof, certificate issuance, DNS verification | `AGENT_REGISTERED` (for the new registration) | New per-version records published by the AHP; the prior version's records are untouched |
| **Renewal (Server Certificate)** | Certificate approaching expiration | A renewal submission (CSR or BYOC) on the renewal routes | Re-proves domain control at renewal verify-acme (DNS-01 TXT or HTTP-01), then finalizes the order and delivers the fresh certificate | Nothing today (`AGENT_RENEWED` reserved — §6.3) | None |
| **Identity-certificate rotation** | Key roll on an identity-bearing registration | A fresh `identityCsrPEM` | Issues a new Identity Certificate at the private CA. Additive: the prior certificate remains valid until it expires. No fresh domain-control proof. `ACTIVE` registrations only; a registration created without an Identity CSR is refused (`IDENTITY_CSR_NOT_PERMITTED`, 409) | Nothing | AHP updates any published fingerprint records per ANS-3 |
| **Revocation** | Agent shutdown or version retirement | `reason` (RFC 5280 reason name token) | Revokes Identity Certificates at the issuing private CA (Server Certificates are not revoked at their issuer) and transitions the registration | `AGENT_REVOKED` | The revocation response lists `dnsRecordsToRemove`; the AHP removes them |

One exception to the renewal re-proof: a CSR renewal whose provider order arrives with no challenges (ACME
authorization reuse inside the provider's validity window) finalizes directly — the re-proof is the
provider's cached validation rather than a fresh RA-side check. Re-driven verify-acme calls on an
already-finalizing order likewise skip the artifact check by design.

### 7.1 Version coexistence

Versions are independent registrations: uniqueness is on the full ANSName, so `v1.0.0` and `v2.0.0` of the
same host are unrelated rows with independent statuses. During a bump both old and new versions are `ACTIVE`;
a patch bump may coexist for hours, a major version for months. The RA imposes no retirement timeline, keeps
no linkage between versions, and a failed new registration leaves the old version untouched.

### 7.2 Registrations without an Identity Certificate

`identityCsrPEM` is optional. When omitted, the agent registers, activates, and operates on its Server
Certificate alone: verify-acme succeeds with no identity issuance, renewal covers the Server Certificate
exactly as for any other registration, and revocation finds no Identity Certificates to revoke. The choice is
permanent for that registration — the rotation operation refuses agents that registered without an Identity
CSR (§7 table); the path to an Identity Certificate is a new versioned registration.

### 7.3 Expiry

A registration's sealed `AGENT_REGISTERED` event carries `expiresAt` — the earliest `notAfter` across its
attested certificates. Certificate lapse does not change RA state on an `ACTIVE` registration and emits no
event; the TL derives `WARNING` and `EXPIRED` at read time from the attested expiry (ANS-4). The RA's expiry
sweep applies only to pending registrations: a lapsed `PENDING_VALIDATION` row is retired to `EXPIRED` without
a TL event.

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
4. At cutover, switch the RA's configuration to the new key. The old key remains registered and inside its validity window, so in-flight outbox events replaying their persisted signatures still verify at ingest.
5. Revoke the old key (`DELETE /internal/v1/producer-keys/{key_id}`) once no in-flight events reference it. Revocation stops the key from authorizing new ingest; previously-sealed events remain verifiable through the TL's own attestations and receipts.

## 9. Conformance

A conformant ANS-1 implementation:

1. Exposes a `RegistrationService` whose register operation accepts the registration request (§4.1) and returns the pending registration with its domain-control challenges.
2. Verifies domain control before certificate issuance on every registration and renewal — the challenge gate is unconditional, except a renewal order that arrives challenge-free under ACME authorization reuse (§7).
3. Gates Identity Certificate issuance on the presence of a pending Identity CSR (the verify-acme rule, §4.2), never unconditionally on lifecycle entry.
4. Enforces global ANSName uniqueness at registration (`ANS_NAME_TAKEN`, 409).
5. Never generates, holds, or accesses an agent's private keys, and does not persist proven public keys as live state (key transience per [ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)).
6. Emits `AGENT_REGISTERED` at activation and `AGENT_REVOKED` at revocation to the ANS-4 TL, constructing and signing each event payload once and replaying the exact bytes and signature on retry.
7. Honors the lifecycle state machine (§4.4) and produces TL events only on the `ACTIVE` and `REVOKED` transitions.
8. Exposes an owner-scoped `list(filter)` operation that supports `agentHost` filtering.

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
| AHP unavailable for extended period | Certificates expire; TLS fails | The RA cannot auto-renew (the AHP owns its private keys). RA state is unchanged; the TL derives `WARNING` and then `EXPIRED` at read time from the attested certificate expiry |
| TL unavailable | Agent-lane event delivery is deferred | Agent-lane events queue in the transactional outbox and replay byte-for-byte until the TL accepts them; activation commits locally with the event enqueued. Identity-lane writes (ANS-0) instead fail closed with `TL_UNAVAILABLE` |

## Appendix A: Worked examples (non-normative)

Non-normative worked examples (registration request, event payloads) live at [`examples/ans-1-examples.md`](examples/ans-1-examples.md).

## References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md) — the proof-of-control gate, the Verified Identity object, identity links, and the [identity profiles](identity-profiles/).
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md) — ANSName form, Identity Certificate, PriCC.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md) — DNS record emission per registration.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md) — TL append, receipt, witness profiles.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md) — verification worker contract.
- [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123): Host requirements (FQDN syntax).
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): X.509 (revocation reason codes).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS (signature envelope).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JWK (JSON Web Key).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME (FQDN domain-control proof).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
