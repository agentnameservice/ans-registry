# ANS-1: Registration & Lifecycle

Status: DRAFT v1.0
Spec: ANS-1 (Registration & Lifecycle)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building an ANS-conformant Registration Authority (RA)

## 1. Scope

ANS-1 defines how an anchor proven through ANS-0 binds to operational metadata (display name, description, endpoints, optional Trust Card body) and how that binding moves through a lifecycle. ANS-1 specifies:

- The `RegistrationService` code-interface contract: register, verify-acme, verify-dns, deprecate, revoke.
- The registration aggregate's data shape and identifier set.
- The lifecycle state machine (PENDING_VALIDATION → PENDING_CERTS → PENDING_DNS → ACTIVE → DEPRECATED → REVOKED, plus EXPIRED and FAILED).
- The event set the RA emits to the Transparency Log (ANS-4) and event stream consumers.
- The cross-anchor `EquivalenceLink` event shape.
- Base-only registration handling, including the special-case rules around verification and uniqueness.
- The skill registration sub-profile, where artifacts register as catalog entries under a parent agent.
- Capability token discipline for ANS-registered agents issuing verifiable credentials to verifiers.

ANS-1 is **anchor-agnostic**: it reads identity through `IdentityClaim` only and never branches on the anchor type. A `RegistrationService` composes with any ANS-0 profile by configuration alone.

ANS-1 does **not** specify the anchor proof itself (ANS-0), the ANSName form or PriCC (ANS-2), DNS emission (ANS-3), TL sealing (ANS-4), continuous verification (ANS-5), or trust scoring (separate `ti-*` layer set, out of scope here).

## 2. Terminology

- **Registration**: an aggregate the RA owns, identified by `agentId`, carrying one `IdentityClaim` plus operational metadata, status, and lifecycle history.
- **AHP (Agent Hosting Platform)**: the operator that hosts the agent's code and manages its DNS and certificates. Submits the registration request.
- **Lifecycle event**: a `RegistrationEvent` the RA emits when a registration changes state (`AGENT_REGISTERED`, `AGENT_RENEWED`, `AGENT_REVOKED`, `EQUIVALENCE_LINK`, `INTEGRITY_WARNING`, `INTEGRITY_RESOLVED`, `IDENTITY_CERT_UPDATED`).
- **Base-only registration**: a registration with no `version` and no Identity CSR. The agent's identity is the ANS-0 anchor alone; there is no ANSName.
- **Versioned registration**: a registration with a `version` and an Identity CSR. The ANSName form (ANS-2) names the version; an Identity Certificate binds it.
- **`EquivalenceLink`**: a TL event recording that two registrations share an operator and refer to the same agent through different anchor types (defined in the event-set section).
- **Capability token**: a JWT issued by an ANS-registered agent to an ANS-registered verifier, carrying claims that bind the token's use to specific audiences and constrain its lifetime.

## 3. The `RegistrationService` interface

The `RegistrationService` interface is the protocol contract for ANS-1; conformant implementations expose `register`, `verifyACME`, `getRegistration`, and the lifecycle event surface. ANS-1 carries the `LifecycleStatus` enum (`PENDING_VALIDATION`, `PENDING_DNS`, `ACTIVE`, `DEPRECATED`, `REVOKED`, `EXPIRED`; the RA also surfaces `PENDING_CERTS` and `FAILED`) and the registration fields
`agentDescription`, `serverCsrPEM`, `serverCertificatePEM`, and `echConfigList` on `RegisterInput`.

`RegistrationService` reads identity through `IdentityClaim` only (ANS-0). The `agentHost` field is stored alongside the claim because ANS-0 separates operational endpoint from identity anchor; ANS-3 (DNS publication) consumes `agentHost`, while ANS-5 (verification) consumes both `agentHost` and `claim.resolvedId`.

## 4. Registration sequence

Registration has two stages: the RA accepts the request and sets the registration to `PENDING_VALIDATION` (reserving the ANSName when one was submitted), then activates the agent once all validations pass.

### 4.1 Stage 1 — pending registration

The AHP submits a registration request. The payload structure mirrors `RegisterInput` defined above plus a few fields the RA derives or fills in:

| Group | Field | Required | Description |
| --- | --- | --- | --- |
| **Anchor** | `claim` (an `IdentityClaim` from an ANS-0 resolver) | Yes | Carries `anchorType`, `resolvedId`, `publicKey`, optional `metadataUrl`, `issuedAt`, `expiresAt` |
| **Identity** | `agentHost` | Yes | Operational FQDN; equals `claim.resolvedId` for FQDN anchors |
| | `version` | Conditional | Semantic version (e.g., `1.0.0`). Required when the registrant is declaring a versioned identifier; absent for base-only registrations |
| | `agentDisplayName` | Yes | Human-readable name (max 64 chars) |
| | `agentDescription` | No | Brief capability description (max 150 chars) |
| **Endpoints** | per-endpoint `protocol` | Yes | `A2A`, `MCP`, `HTTP-API`, or `PAYMENT` (minimum 1 endpoint) |
| | per-endpoint `agentUrl` | Yes | The endpoint URL (authority portion MUST be `agentHost` per RFC 3986 §3) |
| | per-endpoint `metaDataUrl` | No | Protocol metadata location |
| | per-endpoint `metaDataHash` | No | `SHA256:`-prefixed SHA-256 of the document at `metaDataUrl`, computed by the AHP. The RA seals it into the TL `attestations.metadataHashes` map keyed by the uppercase protocol token |
| | per-endpoint `documentationUrl` | No | Developer documentation |
| | per-endpoint `functions` | No | Function declarations: `id`, `name`, optional `tags` |
| | per-endpoint `transports` | No | `STREAMABLE-HTTP`, `SSE`, `JSON-RPC`, `GRPC`, `REST`, `HTTP` |
| **Certificates** | `identityCsrPEM` | Conditional | CSR for Identity Certificate. Required when `version` is submitted; absent otherwise. A payload with `version` and no `identityCsrPEM` (or the reverse) is rejected |
| | `serverCsrPEM` | No | CSR for RA-issued Server Certificate |
| | `serverCertificatePEM` | No | BYOC Server Certificate (alternative to CSR) |
| **Trust Card** | `trustCardContent` | No | Full Trust Card JSON. Hashed and sealed into the TL at activation, enabling content integrity verification |
| **Privacy** | `echConfigList` | No | Base64-encoded ECHConfigList (RFC 9849) |
| **On-chain (optional cross-anchor signal)** | `onChainId`, `ensName` | No | Persistent ledger identifiers, verified post-activation by ANS-5 |
| **Discovery (optional)** | `ansUrn` | No | URN alias for Agent Finder catalog entries (e.g., `urn:acme:agent:support`); not an identity anchor |

When `trustCardContent` is provided, the RA hashes it (SHA-256 over JCS-canonical bytes per ANS-4 §canonicalization) and seals the hash into the TL at activation. When omitted and the AHP hosts a Trust Card, ANS-5 computes the baseline hash on first successful fetch.

Pending-stage validations:

1. The `claim` MUST be a fresh `IdentityClaim` from a configured `AnchorResolver` whose `supportedProfiles()` returns `claim.anchorType`.
2. `agentHost` MUST be a syntactically valid FQDN (RFC 1123). For FQDN anchors, `agentHost` MUST equal `claim.resolvedId` (with the ANS-0 dot tie-breaker rule having already applied at the dispatcher).
3. Each endpoint's `agentUrl` MUST use `agentHost` as its scheme + authority portion (RFC 3986 §3). The constraint keeps endpoint URLs reachable through the same TLS certificate that anchors the agent's identity.
4. Conditional cert rule: `version` and `identityCsrPEM` are jointly present or jointly absent. A payload with one and not the other is rejected with `ANS1_VERSIONED_CSR_MISMATCH`.
5. **Base-only uniqueness predicate.** The `(agentHost, claim.anchorType)` pair MUST NOT collide with any existing ACTIVE base-only registration. Each pair admits at most one base-only registration; an FQDN already carrying an FQDN-anchored row MAY accept a DID-anchored or LEI-anchored base-only row under the same `agentHost`, because the anchor type differs. A registration whose pair already
   exists is rejected with `BASE_ONLY_PAIR_TAKEN`.
6. Endpoint set MUST contain at least one endpoint with valid `protocol` and `agentUrl`.
7. `agentDisplayName` and `agentDescription` length limits apply (64 and 150 chars respectively).

If valid, the RA assigns an `agentId` (UUID v4), constructs the ANSName (only when `version` is present) per [ANS-2 §2](ans-2-versioned-naming.md), and sets the registration to `PENDING_VALIDATION`.

### 4.2 Stage 2 — activation

Activation requires four validations (all MUST pass):

| Validation | Method |
| --- | --- |
| Anchor proof | The anchor type's domain-control-equivalent proof per the relevant ANS-0 subsection. For FQDN: ACME DNS-01 (RFC 8555 §8.4) or HTTP-01 (RFC 8555 §8.3). For `did:web`: the `.well-known/ans-did-web-challenge.txt` flow per [ANS-0 DID](ans-0-identity-anchor.md#52-did-status-active). For LEI: the entity-control proof plus cross-anchor binding per [ANS-0 LEI](ans-0-identity-anchor.md#53-lei-status-active) |
| Schema integrity | Fetch each endpoint's `metaDataUrl`, hash, compare against the value the AHP submitted (when one was submitted) |
| DNSSEC presence | Query for DNSKEY at the agent's zone. Advisory: warn if absent; do not block. The RA records the result as a `dnssecStatus` field in the TL event payload, with one of three values: `fully_validated`, `not_signed`, or `signed_broken` |
| `(host, anchor_type)` uniqueness | Re-check at activation that the uniqueness predicate from the registration-sequence section still holds (a concurrent registration may have taken the slot during the pending window) |

The activation sequence is irreversible once step (d) completes:

| Step | Action |
| --- | --- |
| (a) Certificate issuance | RA obtains the Server Certificate from a Public CA (if CSR) or validates the BYOC certificate. **Conditional on `version` being present**, the RA also obtains the Identity Certificate from the Private CA per [ANS-2 §3](ans-2-versioned-naming.md). For base-only registrations, the Identity Certificate branch does not run |
| (b) DNS record generation | RA generates record set content per [ANS-3 §3](ans-3-dns-publication.md) |
| (c) Event payload | RA hashes Trust Card content (if submitted) and assembles the event payload |
| (d) Log sealing | RA submits signed event to ANS-4 TL. Point of no return |
| (e) Artifact delivery | RA delivers certificates and DNS record content to AHP |
| (f) Notification | TL publishes sealed event to message bus |

DNS provisioning happens after step (e) and is the AHP's responsibility; it falls outside the RA's activation SLA.

### 4.3 The `verifyACME` rule for base-only registrations

The `verifyACME(agentId)` operation runs the ACME challenge validation step and gates the activation sequence. For a versioned registration it also gates Identity Certificate issuance (step a). For a **base-only registration**, the operation MUST skip the Identity Certificate path entirely; `verifyACME` succeeds when the ACME challenge validates and the Server Certificate (or BYOC cert) is in
place, with no requirement for a pending Identity CSR.

Conformant ANS-1 implementations MUST gate identity-cert issuance on the presence of an Identity CSR, not unconditionally on lifecycle entry. An implementation that requires a pending Identity CSR for every `verifyACME` call rejects all base-only DID and LEI registrations and is non-conformant.

### 4.4 The state machine

```text
                ┌────────────────────┐
                │ PENDING_VALIDATION │
                └──────────┬─────────┘
                           │ anchor proven, certs ready
                           ▼
                    ┌──────────────┐
                    │ PENDING_DNS  │  (external domains; internal domains skip directly to ACTIVE)
                    └──────┬───────┘
                           │ all DNS verified
                           ▼
                    ┌──────────────┐         ┌──────────────┐
                    │    ACTIVE    │────────▶│  DEPRECATED  │  (signals consumers to migrate)
                    └──────┬───────┘         └──────┬───────┘
                           │                        │
              cert validity│                        │
                expired    │   AHP or RA            │ AHP or RA
                           ▼   revokes              ▼ revokes
                    ┌──────────────┐         ┌──────────────┐
                    │   EXPIRED    │         │   REVOKED    │
                    └──────────────┘         └──────────────┘
```

`REVOKED` and `EXPIRED` are terminal. The pending states (`PENDING_VALIDATION`, `PENDING_CERTS`, `PENDING_DNS`) MAY be cancelled, removing partial artifacts without a TL event because the log-sealing step has not yet occurred. Revocation is idempotent.

Only transitions to `ACTIVE`, `DEPRECATED`, `REVOKED`, `RENEWED`, and `EXPIRED` produce TL events. Transitions before activation are RA-internal.

## 5. Identifiers

| Identifier | Format | Assigned by | Mutable | Scope | Purpose |
| --- | --- | --- | --- | --- | --- |
| **`agentId`** | UUID | RA at registration | No | Issuing RA | RA registration-instance key; used in the RA API paths (`/v1/agents/{agentId}`) |
| **`ansId`** | UUID v7 | ANS, at registration | No | Global | Identifier of the ANS entry, carried in the sealed TL event payload (ANS-4). Distinct from the RA's `agentId` **by design** |
| **`agentHost`** | RFC 1035 FQDN | AHP submits | No | Global | Operational endpoint where the agent terminates TLS |
| **`claim.resolvedId`** | Anchor-type specific (FQDN, DID URI, or LEI) | ANS-0 resolver | No | Global | Identity anchor; coincides with `agentHost` for FQDN anchors |
| **`ANSName`** | `ans://v{ver}.{host}` | Derived from `version` + `agentHost` | No | Global | Versioned identifier; absent for base-only registrations (see [ANS-2 §2](ans-2-versioned-naming.md)) |
| **`providerId`** (legacy: `ProviderID`) | RA-defined | RA from authentication system | No | Issuing RA | Names the entity that controls the anchor, not the entity that authored the software |
| **`supersededBy`** | `agentId` reference | RA when a new version registers | No | Issuing RA | Previous version's registration record |

`providerId` constraints: stable (the same entity always receives the same `providerId` from a given RA, regardless of credential), scoped to the issuing RA. In a federated ecosystem, consumers scope `providerId` by the issuing RA's identifier to avoid collisions.

`providerId` does not span RAs. `agentHost` does. An agent moves between RAs by updating DNS records, not by changing its name. For cross-RA correlation, the optional `lei` field on the registration (carried as a cross-anchor link per [ANS-0 §5.3](ans-0-identity-anchor.md#53-lei-status-active)) gives a globally-unique organizational identifier.

When the agent has an ERC-8004 registration, the on-chain `agentId` (ERC-721 tokenId, scoped to the registered chain) provides an additional cross-RA correlation identifier. The Trust Card's `registrations` array supports multiple entries across chains and registries; ANS-1 stores the array as opaque metadata and ANS-5 verifies cross-references post-activation.

### 5.1 Hosted-platform delegation

When a platform registers an agent on behalf of a tenant, `providerId` and the optional `lei` field identify the platform and the tenant respectively. These are identity assertions, not delegation proofs. The tenant closes this gap by issuing a W3C Verifiable Credential (`ANS_DELEGATION` claim type) authorizing the platform to register on its behalf; the platform includes the VC in the Trust
Card's `verifiableClaims` array.

## 6. Event set

The RA emits the following events to the ANS-4 Transparency Log. Each event carries the RA instance ID (`raId`), the RA's producer signature, and is sealed by the TL before becoming visible to consumers.

### 6.1 `AGENT_REGISTERED`

Emitted at activation. Payload follows the **V2 TL response format**: `ansId` (the TL entry id, UUIDv7), `ansName` if versioned, a nested `agent` object (`host`, `name`, `version`, `providerId`), `attestations` (`identityCerts[]` when versioned and `serverCerts[]` — each entry `{fingerprint, type, notAfter}`; `dnsRecordsProvisioned[]` as `{name, type, data}` objects; `domainValidation` method;
`dnssecStatus`), `expiresAt`, `issuedAt`, `raId`, `timestamp`. The `claim` summary and optional `lei` are forward-looking ANS additions carried alongside the V2 fields.

A worked example payload appears in the [ANS-1 worked examples](examples/ans-1-examples.md).

### 6.2 `AGENT_RENEWED`

Emitted when the Identity Certificate (versioned registrations) or Server Certificate (base-only) is reissued without a code change. Payload mirrors `AGENT_REGISTERED` with a new `expiresAt` and a `previousExpiresAt`.

### 6.3 `AGENT_REVOKED`

Emitted when the AHP or RA revokes a registration. Payload includes `revocationReasonCode` (an RFC 5280 reason code; AHP submissions use the friendlier short field name `reason` and the sealed event canonicalizes to `revocationReasonCode`) and `revokedAt`.

### 6.4 `EQUIVALENCE_LINK`

Emitted when an operator links two registrations as referring to the same agent through different anchor types (per the ANS-0 cross-anchor identity equivalence section). Both registrations' active keys MUST authorize the link.

- **Single-RA case (current).** When both registrations live on the same RA, the RA's authentication system verifies that the caller controls both registrations before accepting the link request, and the RA's producer key signs the resulting envelope. Caller-side ownership of both registrations is the authorization signal.
- **Federated multi-RA case (future amendment).** When the registrations live on different RAs, the cryptographic co-signature requirement applies: the inner-event JCS bytes are signed by the primary registration's anchor key, and the producer envelope carries a co-signature from the equivalent registration's anchor key. The envelope schema admitting the co-signer block is a future amendment.

The wire shape:

```json
{
  "eventType": "EQUIVALENCE_LINK",
  "linkedAnsId": "f3c2d4e5-...-1234",
  "linkedAnsName": "ans://v1.0.0.invoicing.acme.com",
  "linkedAnchorType": "lei",
  "linkedAnchorResolvedId": "549300EXAMPLE00LEI17",
  "rationale": "Cross-anchor binding: same agent, dual identity assertion (FQDN + LEI).",
  "raId": "id-A",
  "timestamp": "2026-05-17T18:00:00Z"
}
```

Field semantics:

- `linkedAnsId`: the `agentId` of the equivalent (linked-to) registration. The event itself is sealed under the primary registration's `agentId`.
- `linkedAnsName`: the equivalent registration's ANSName, when versioned. Absent for base-only equivalents.
- `linkedAnchorType`: the equivalent registration's `claim.anchorType` (`fqdn`, `did`, or `lei`).
- `linkedAnchorResolvedId`: the equivalent registration's `claim.resolvedId`.
- `rationale`: free-form operator note explaining the equivalence, surfaced to verifiers.
- `raId`, `timestamp`: standard event headers.

### 6.5 `INTEGRITY_WARNING` and `INTEGRITY_RESOLVED`

Emitted when the AIM (ANS-5) reports a confirmed mismatch and when the discrepancy clears. Both events leave the registration `ACTIVE`.

### 6.6 `IDENTITY_CERT_UPDATED`

Emitted when the operator adds, removes, or rolls the Identity Certificate on an existing registration without otherwise changing the agent's identity. The registration's `agentId`, `agentHost`, ANSName (when present), and anchor binding are unchanged across the event.

The wire shape:

```json
{
  "eventType": "IDENTITY_CERT_UPDATED",
  "ansId": "f3c2d4e5-...-1234",
  "previousState": "absent",
  "newState": "present",
  "previousIdentityCertFingerprint": null,
  "newIdentityCertFingerprint": "SHA256:...",
  "raId": "id-A",
  "timestamp": "2026-05-17T18:00:00Z"
}
```

Field semantics:

- `previousState`, `newState`: each is `present` (the registration carried an Identity Certificate at that point) or `absent` (it did not).
- `previousIdentityCertFingerprint`: the SHA-256 of the prior Identity Certificate's DER-encoded bytes when `previousState` is `present`; `null` when `previousState` is `absent`.
- `newIdentityCertFingerprint`: the SHA-256 of the new Identity Certificate when `newState` is `present`; `null` when `newState` is `absent`.

Three state transitions a single event can carry:

1. `absent` to `present`: the operator submitted a new Identity CSR plus PriCC. The RA issued the certificate at the Private CA and seals the new fingerprint. ANSName is allocated at this point if it was not present before.
2. `present` to `absent`: the operator requested removal. The RA revoked the Identity Certificate at the Private CA and seals the prior fingerprint with a `null` new fingerprint. The registration continues to operate on its Server Certificate.
3. `present` to `present`: the operator submitted a fresh Identity CSR (key roll, e.g., on a regulator-driven cadence) without changing the registration's version. The RA issued a new certificate and seals both fingerprints. Distinct from `AGENT_RENEWED`, which reissues without a key change.

The `absent` to `absent` transition is not a valid event; the RA rejects the operation.

## 7. Lifecycle operations

| Operation | Trigger | AHP submits | RA processes | RA seals | DNS effect |
| --- | --- | --- | --- | --- | --- |
| **Version bump** (versioned only) | Code or config change | new `version` + fresh `identityCsrPEM` | Re-validates anchor proof, issues new Identity Certificate | `AGENT_REGISTERED` | New per-version records added (`_ans`, `_ans-badge`); shared records unchanged. AHP updates `_ans-identity._tls` for the new Identity Certificate |
| **Renewal** | Cert approaching expiration, code unchanged | new CSR, same `version` (or none for base-only) | Re-runs anchor proof, issues fresh certificate | `AGENT_RENEWED` | None |
| **Revocation** | Agent shutdown or version retirement | RFC 5280 reason code | Revokes certificates at issuing CA(s) | `AGENT_REVOKED` | Per-version records removed immediately; shared records removed when last ACTIVE version is gone |
| **Equivalence link** | Operator binds two registrations as one agent | Co-signed link payload (defined in the event-set section) | Verifies both anchor signatures, records the link | `EQUIVALENCE_LINK` | None |
| **Integrity warning** | AIM finding confirmed by RA re-verification | (AIM-initiated) | Re-verifies against TL sealed records | `INTEGRITY_WARNING` | None. Agent stays `ACTIVE` |
| **Integrity resolved** | Discrepancy clears | (AIM-initiated) | Confirms live state matches TL | `INTEGRITY_RESOLVED` | None |
| **Identity-cert toggle** | Operator adds, removes, or rolls the Identity Certificate without changing the registration's version | new `identityCsrPEM` plus PriCC (add or roll), or removal request (remove) | Validates anchor proof; issues or revokes the Identity Certificate at the Private CA | `IDENTITY_CERT_UPDATED` | AHP updates `_ans-identity._tls` to publish the new fingerprint, or removes the record on a remove |

### 7.1 Version coexistence (versioned registrations only)

During a version bump, both old and new versions are `ACTIVE`. The Server Certificate stays active (tied to `agentHost`, not to the version). A patch bump may coexist for hours; a major version change may coexist for months. The RA does not impose a retirement timeline. If the new registration fails validation, the old version remains `ACTIVE`.

### 7.2 Base-only registrations

A base-only registration has no ANSName, no Identity Certificate, and no version-bump flow. The lifecycle table above applies with these substitutions:

- **Renewal** covers the Server Certificate and re-runs the ANS-0 anchor proof. No Identity Certificate renewal step runs (per the `verifyACME` rule in the registration-sequence section).
- **Version bump** does not apply. A base-only registrant seeking version discipline uses the migration flow described in the lifecycle section.
- **Revocation** targets the registration itself and the Server Certificate. There is no Identity Certificate to revoke at the Private CA.
- **Integrity warnings** and **integrity resolutions** apply unchanged; ANS-5 verifies live DNS and Server Certificate state against the sealed TL values.

### 7.3 Migration: base-only to versioned

A base-only registration that later wants version discipline submits a new registration with a `version` and `identityCsrPEM`. The RA validates and seals the new versioned registration; the AHP then atomically swaps DNS records by removing the base-only `_ans` and `_ans-badge` records as it publishes the new per-version records, so the "MUST NOT mix versioned and unversioned" constraint in [ANS-3
§6.2](ans-3-dns-publication.md#62-legacy-_ans-txt-family-status-active) is preserved. A brief discovery gap during the DNS swap is expected and is bounded by the zone's DNS TTL.

After the swap, the AHP submits `AGENT_REVOKED` for the base-only registration. The TL records both the new versioned registration and the base-only revocation, in order.

The reverse direction (versioned to base-only) is not a protocol operation. A registrant that no longer wants version discipline revokes all versioned registrations and registers fresh at the base-only floor.

### 7.4 Registration expiry under toggleable Identity Certificates

A registration's expiry tracks the earlier of its Server Certificate expiry and its Identity Certificate expiry, but only while the Identity Certificate is present. A registration in the `present` state expires on whichever certificate lapses first; the same registration after `IDENTITY_CERT_UPDATED` to `absent` tracks Server Certificate expiry alone.

This makes Identity-cert toggling an operational option rather than a forced re-registration. An operator who lets the Identity Certificate lapse without renewing it triggers `IDENTITY_CERT_UPDATED` with `newState: absent`. The registration continues on the Server Certificate's expiry and remains discoverable; counterparties who require a versioned identity see the toggle and adjust per their own
policy.

### 7.5 Private-CA compromise

When the RA's Private CA loses control of its signing key, every Identity Certificate issued by that Private CA becomes untrusted.

Two recovery paths are available:

- **Re-anchor to a new CA.** Switch to a different Private CA (or different RA), revoke all Identity Certificates from the compromised Private CA, and reissue under the new CA. The agent registration retains its `agentId`. Each affected registration emits an `IDENTITY_CERT_UPDATED` event flow: each old certificate goes `present` to `absent`, and the new one comes back `absent` to `present`.
- **Drop to base-only.** Emit `IDENTITY_CERT_UPDATED` with `newState: absent` and continue operating on the Server Certificate alone. The agent loses its versioned identity but retains its `agentId` and behavior history.

The choice between re-anchor and drop-to-base-only is operator policy; ANS-1 does not force one path.

## 8. Skill registration sub-profile

Skills (validation routines, retrieval handlers, tool implementations) are files, not services, and change faster than the agent's declared version. A per-skill FQDN with its own ACME-validated certificate does not fit that cadence. Skills register as artifacts under a parent agent's record.

Each skill appears in the parent's Trust Card catalog as an entry with:

- a stable identifier scoped to the parent (for example, `domain-dns-ssl-troubleshooting`);
- a location URL pointing at an immutable, content-addressed artifact (a raw blob or archive at a specific commit SHA, an object-storage URL whose path includes the content hash, or a path under the parent's FQDN serving a single immutable file);
- an integrity commitment over the canonical byte stream retrieved from that location URL.

Each skill's commitment lives as its own ANS-4 TL entry indexed by `parent_ansname + skill_id` (or `parent_fqdn + skill_id` for base-only parents). The receipt's hash covers the canonical byte stream retrieved from the location URL at commitment time. The parent's Trust Card carries the catalog (the list of skill IDs with their location URLs) but not per-skill receipts. Adding or removing a skill
is a Trust Card change and bumps the parent's integrity commitment; updating an existing skill is a skill-level TL event that does not modify the parent's Trust Card hash.

A browsable page (a GitHub `tree/...` URL, a directory index) is not an acceptable location URL; different retrievers see different renderings, and different verifiers would hash different bytes for the same skill.

Two sub-profiles:

- **Skill (internal).** Same principal as the parent. Per-skill integrity commitment required. Principal binding inherits from the parent.
- **Skill (external).** The skill crosses a trust boundary. Per-skill integrity commitment required. Per-skill principal binding required (NOT inherited). Authorization is carried by a W3C Verifiable Credential of claim type `ANS_SKILL_DELEGATION` from the parent's principal to the skill, verified per W3C VC Data Model 2.0. Implementations MUST NOT infer external-skill authorization from the
  parent binding alone.

## 9. Capability token discipline

ANS-registered agents issue verifiable credentials (capability tokens) to ANS-registered verifiers for high-value operations (payment authorization, configuration changes, resource provisioning). These tokens carry claims that bind each token to specific audiences, constrain its lifetime, and optionally require proof of possession.

### 9.1 Capability token claims

Every capability token an ANS-registered agent issues MUST carry:

- An `aud` (audience) claim naming the intended verifier as a single JSON string. The value is the verifier's ANSName (with the `ans://` scheme prefix, lowercased) or the verifier's FQDN (lowercased, no trailing dot). RFC 7519 §4.1.3 permits `aud` to be a string or an array; this specification restricts it to a single string so verifiers can match byte-for-byte without array-membership logic.
- An `iat` (issued-at) claim carrying the POSIX seconds at which the agent signed the token. Verifiers use this to measure a token's age against the operator's declared freshness ceiling.
- An `exp` (expiration) claim. A token SHOULD be issued with `exp - iat` no longer than the freshness ceiling declared for its usage class in the Trust Card's token-discipline policy (transactional or discovery).
- A `jti` (JWT ID) claim suitable for one-time-use enforcement at the verifier.

For capabilities the Trust Card marks `high_value: true`, the caller MUST additionally attach a Demonstration of Proof-of-Possession (DPoP) proof per RFC 9449 (September 2023): a JWT signed over the current HTTP method, URL, and timestamp. The DPoP proof JWT's header carries the full public key in `jwk`; the capability token binds that key by its SHA-256 JWK thumbprint (RFC 7638) in the `cnf.jkt`
claim. The verifier recomputes the thumbprint from the DPoP header's `jwk` and compares against `cnf.jkt`.

### 9.2 Verifier MUST-checks

A verifier receiving a capability token rejects the token when any of the following hold:

- The `aud` claim is absent, is not a single JSON string, or does not byte-for-byte equal the verifier's own ANSName or FQDN in the canonical form above.
- `now()` is past `exp`, or `now() - iat` exceeds the operator's declared freshness ceiling for the capability's usage class.
- The `jti` has been seen within the declared freshness window.
- On a high-value capability, the DPoP proof is absent, stale, or signed by a key whose SHA-256 JWK thumbprint does not match `cnf.jkt`.

A rejection surfaces as HTTP 401 with `WWW-Authenticate: DPoP` or `WWW-Authenticate: Bearer error="invalid_token"` per RFC 9449 §7.

### 9.3 Token-discipline policy

Operators declare their freshness ceilings and acceptable signing algorithms in the Trust Card. These values are operator-configurable knobs, not switches on the MUST requirements above:

```json
{
  "token_discipline": {
    "freshness_seconds_transactional": 60,
    "freshness_seconds_discovery": 300,
    "algorithms": ["ES256", "EdDSA"]
  }
}
```

A verifier MUST reject tokens whose signature algorithm is absent from the declared list. The freshness ceiling applies at verification time through the `now() - iat` check above, so tokens issued with long `exp` values remain usable only within the ceiling's window. The integrity commitment's hash covers this policy alongside the rest of the Trust Card; a change to the policy bumps the integrity
commitment.



**Related standards.** RFC 7519 (JWT) for claim formats. RFC 9449 (DPoP) for proof of possession. RFC 9700 (OAuth 2.0 Security BCP, January 2025) for audience-binding guidance at scale.

## 10. RA key management

| Principle | Rule |
| --- | --- |
| Agent keys | The RA never generates, handles, or accesses an agent's private keys. The AHP owns its key lifecycle |
| RA producer keys | Each RA instance MUST register at least one active public key with the ANS-4 TL before submitting events. Rotation uses an overlap window: new keys are registered with future `validFrom` dates; both old and new remain active during the transition. Producer private keys never leave the RA instance. Historical signatures remain valid after key expiration but not after revocation |
| External-service credentials | Separate credentials per external service integration (DNS provider, public CA account, private CA, KMS), rotated on schedule |

Producer-key rotation procedure:

1. Generate the new producer key pair inside a secure key store the RA instance controls. The store MUST keep the private key inaccessible to any process outside the RA.
2. Register the public key with the TL (`POST /producer-keys`) with `validFrom` set to the rotation cutover time.
3. Continue signing with the old key until cutover.
4. At cutover, switch to the new key. The old key's `validFrom` window remains; existing signatures verify against the still-published key.
5. Revoke the old key when the operator is confident no in-flight events still reference it. Revocation invalidates the key's authority for new signatures; previously-sealed events remain verifiable through the TL's preserved key history.

## 11. Conformance

A conformant ANS-1 implementation:

1. Exposes a `RegistrationService` whose `register` operation accepts `RegisterInput` and returns a `Registration` matching the data type defined above.
2. Reads identity through `IdentityClaim` only and does not branch on `claim.anchorType`.
3. Implements the conditional Identity Certificate gate (the `verifyACME` rule).
4. Implements the `(agentHost, claim.anchorType)` uniqueness predicate.
5. Stores `anchor_type` and `anchor_resolved_id` as nullable columns and treats nil as FQDN-implicit per ANS-0.
6. Does not persist `IdentityClaim.publicKey` on the registration row per ANS-0.
7. Emits the event set above to the ANS-4 TL with the `EQUIVALENCE_LINK` schema.
8. Honors the lifecycle state machine and produces TL events only on transitions to `ACTIVE`, `DEPRECATED`, `REVOKED`, `RENEWED`, and `EXPIRED`.
9. Exposes a `list(filter)` operation that supports `agentHost` filtering as the transitional cross-anchor join.
10. Passes the conformance test vectors at `docs/tests/conformance/ans-1/`.

## 12. Security considerations

### 12.1 Reputation continuity and operator changes

When a domain transfers ownership, the FQDN persists but the operator does not. Reputation accumulated under the old operator must not transfer to the new one. Three mechanisms detect the change:

- **Anchor proof re-validation.** The RA re-runs the ANS-0 anchor proof at each renewal and version bump. When the original operator no longer controls the anchor (DNS, DID document, LEI registration), the proof fails and the RA revokes the registration.
- **RDAP monitoring.** ANS-5 monitors the registrant entity in the registrar's RDAP response (FQDN anchors). A change in the registrant entity handle or a fresh `last changed` timestamp signals a transfer.
- **`providerId` mismatch.** The RA assigns `providerId` from its authentication system at registration. When a new operator registers under an `agentHost` that already has an ACTIVE registration under a different `providerId`, the RA detects the conflict and MUST revoke the prior registration.

Upon detection of a control change via any of these mechanisms, the RA MUST emit `AGENT_REVOKED` to the TL. Between a transfer and detection, stale reputation remains attached to `agentHost`. Downstream consumers evaluate staleness from the sealed event timestamps.

### 12.2 Unstable payload fields

Some payload fields (`onChainId`, `ensName`, `ansUrn`) are advisory metadata at registration and verified post-activation by ANS-5. ANS-1 stores them but does not gate registration on their validity; an attacker who lies about an unrelated `onChainId` cannot prevent registration but produces a verification failure once ANS-5 catches up.

### 12.3 Failure modes

| Scenario | Consequence | RA response |
| --- | --- | --- |
| AHP unavailable for extended period | Identity Certificate expires (versioned) or Server Certificate expires (base-only); mTLS or TLS fails | RA detects expired status and emits `EXPIRED`. Cannot auto-renew (AHP controls its private keys) |
| Anchor expires (FQDN domain expires; LEI lapses to inactive; DID document removed) | Endpoint unreachable; subsequent re-validation fails | RA treats the anchor-proof failure as a security event and MUST emit `AGENT_REVOKED` |
| TL unavailable | New registrations queue; in-flight registrations retain `PENDING_VALIDATION` status | RA MUST NOT activate without a sealed event (step (d) is the point of no return) |

## Appendix A: Trust Card and metadata (normative)

### A.1 Scope and unique content

The Trust Card is the JSON document an AHP hosts at `/.well-known/ans/trust-card.json`. The AHP submits the same bytes as `trustCardContent` at registration. The RA hashes the JCS-canonical bytes (RFC 8785) and seals `SHA-256(JCS(trustCardContent))` into the `AGENT_REGISTERED` event under `attestations.metadataHashes.capabilitiesHash`. The same digest, base64url-encoded, populates the SVCB
`card-sha256` SvcParam at `agentHost` (per [ANS-3 consolidated SVCB](ans-3-dns-publication.md#61-consolidated-svcb-status-active-default)). A verifier holding any one of those three values can confirm the other two without trusting the channel that delivered each one.

The Trust Card carries content that no protocol-native metadata file holds:

- the ANSName-to-anchor binding (or, for base-only registrations, the anchor binding alone);
- the agent's catalog of registered skills (skill registration sub-profile) with their content-addressed location URLs;
- the `verifiableClaims` array carrying third-party attestations: `ANS_DELEGATION` for hosted-platform tenants, `ANS_SKILL_DELEGATION` for external skills, and operator-published claims like SOC 2 reports, SBOMs, and GLEIF-signed LEI proofs;
- an optional `principalBinding` block tying the agent to an off-DNS principal (ENS, DID, LEI);
- the token-discipline policy declaring freshness ceilings and acceptable signing algorithms (capability token discipline section);
- an optional stapled SCITT receipt (`transparencyReceipt`) for offline TL verification.

### A.2 Document landscape and hash topology

| Document | Path | Hash field path in `AGENT_REGISTERED` (`SHA256:`-prefixed hex) | DNS SvcParam (base64url) | Carries |
| --- | --- | --- | --- | --- |
| Trust Card body | `/.well-known/ans/trust-card.json` | `attestations.metadataHashes.capabilitiesHash` | `card-sha256` at `wk` on the 3.B SVCB row at `agentHost` | ANSName + anchor binding, endpoints, skill catalog, verifiable claims, token discipline, optional principal binding, optional SCITT staple |
| A2A AgentCard | `/.well-known/agent-card.json` | `attestations.metadataHashes.A2A` | Not directly in DNS; referenced from the Trust Card body's `endpoints[].metaDataUrl`. Hash sealed only in TL | A2A endpoint metadata (skills, modalities, transports) |
| MCP ServerCard | per-server published path | `attestations.metadataHashes.MCP` | Not directly in DNS; referenced from the Trust Card body's `endpoints[].metaDataUrl`. Hash sealed only in TL | MCP endpoint metadata (tools, prompts, resources) |
| DNS-AID capability descriptor | operator-defined `cap` SvcParam target | (DNS-AID does not seal a TL) | `cap-sha256` on a DNS-AID SVCB row | Per-service capability descriptor under the DNS-AID layout, distinct from the agent card |

The TL stores each digest `SHA256:`-prefixed (uppercase `SHA256:` + lowercase hex, per the V2 TL `metadataHashes` schema); the SVCB SvcParam stores the same digest bytes as base64url per RFC 9460. A verifier comparing the two MUST strip the `SHA256:` prefix and decode both to raw bytes (or re-encode to a common form) before equality check.

ANS does not publish DNS-AID's `cap-sha256` SvcParam. Capability content lives in the Trust Card body's `verifiableClaims` and `endpoints[].functions` fields, which `card-sha256` already covers.

### A.3 Body schema

Top-level fields:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `ansName` | string (`ans://v{ver}.{host}`) | Versioned only | Versioned identifier per [ANS-2 §2](ans-2-versioned-naming.md). Absent for base-only registrations |
| `agentHost` | string (RFC 1123 FQDN) | Yes | Operational endpoint where the agent terminates TLS |
| `anchorType` | enum (`fqdn`, `did`, `lei`) | Yes | Anchor profile per [ANS-0](ans-0-identity-anchor.md) |
| `anchorResolvedId` | string | Yes | Anchor-resolved identifier (FQDN, DID URI, or LEI string) |
| `agentDisplayName` | string (≤64 chars) | No | Human-readable name. Same `agentDisplayName` field as the registration request |
| `agentDescription` | string (≤150 chars) | No | Brief capability description. Same `agentDescription` field as the registration request |
| `version` | string (semver, no `v` prefix) | No | Same as the version segment of `ansName`, hoisted for direct access |
| `releaseChannel` | string | No | Release-track label (`stable`, `beta`, `alpha`, …). Free-form; consumers MAY use it as a discovery signal |
| `endpoints` | array of endpoint objects | Yes | One entry per protocol the agent speaks. See per-endpoint table below |
| `securitySchemes` | object | No | Connection-time auth declarations (mTLS, OAuth, API key) |
| `principalBinding` | object | No | Off-DNS principal binding; types include `ENS_ENSIP25`, `DID_WEB`, `LEI`, `BIOMETRIC_HASH` |
| `verifiableClaims` | array of W3C VC 2.0 objects | No | Third-party attestations per W3C VC Data Model 2.0 |
| `skillCatalog` | array of skill catalog entries | Conditional | Required when the agent registers skills under the skill-registration sub-profile. Each entry: `id`, `locationUrl`, `integrityCommitment` |
| `token_discipline` | object | No | Operator's freshness ceilings and acceptable signing algorithms per the capability-token-discipline section |
| `transparencyReceipt` | string (base64) | No | Stapled SCITT receipt for the most recent `AGENT_REGISTERED` or `AGENT_RENEWED` event. Added post-activation; excluded from JCS canonicalization (see §A.5) |

Each endpoint object:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `protocol` | enum (`A2A`, `MCP`, `HTTP-API`, `PAYMENT`) | Yes | Protocol token |
| `agentUrl` | URI | Yes | Endpoint URL where the protocol terminates |
| `metaDataUrl` | URI | No | Path to the protocol-native metadata file (e.g. `/.well-known/agent-card.json` for A2A) |
| `metaDataHash` | `SHA256:`-prefixed string | No | SHA-256 of the document at `metaDataUrl`; sealed into the TL `attestations.metadataHashes` map under the uppercase protocol key |
| `documentationUrl` | URI | No | Developer documentation |
| `transports` | array of strings | No | Transport tokens (`STREAMABLE-HTTP`, `SSE`, `JSON-RPC`, `GRPC`, `REST`, `HTTP`) |
| `functions` | array of function objects | No | Function declarations: `id`, `name`, optional `tags` |

Each `verifiableClaims` entry MUST be a W3C Verifiable Credential 2.0 with proof. Operators MAY embed additional claim types beyond `ANS_DELEGATION` and `ANS_SKILL_DELEGATION`; consumers ignore claim types they do not recognize. Unrecognized claims are not a registration failure.

### A.4 Canonicalization and hashing

The RA computes the Trust Card's content digest as `SHA-256(JCS(trustCardContent))` per [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), with the `transparencyReceipt` member removed from the JSON object before canonicalization (the member MUST be absent, not set to `null`; JCS canonicalizes a `null` member to bytes that change the digest). The result is stored `SHA256:`-prefixed (uppercase
`SHA256:` + lowercase hex, per the V2 TL `metadataHashes` schema) in `attestations.metadataHashes.capabilitiesHash`. The same digest re-encoded as base64url populates the SVCB `card-sha256` SvcParam at `agentHost`.

At registration the AHP submits a body without `transparencyReceipt`, since no SCITT receipt has been issued yet; after the RA seals the `AGENT_REGISTERED` or `AGENT_RENEWED` event, the AHP MAY add the issued receipt to the served body without changing `capabilitiesHash`. A verifier comparing a live-fetched body to the TL-sealed hash MUST remove the `transparencyReceipt` member entirely before
applying JCS and recomputing the digest.

Three values record the same SHA-256 digest over the JCS-canonical Trust Card bytes, each in a different encoding:

1. TL receipt's `attestations.metadataHashes.capabilitiesHash` (`SHA256:`-prefixed hex): what the RA sealed.
2. DNS `card-sha256` SvcParam (base64url): what the operator published.
3. `SHA-256(JCS(live-fetched-body))` (verifier's choice of encoding): what the agent serves now.

A verifier MUST decode all three to raw bytes, or re-encode to a common form, before equality check.

ANS-5's `capabilitiesHashMatch` check (per [ANS-5 §4](ans-5-integrity-monitoring.md#4-verification-checks)) reads all three and reports an integrity finding when any pair disagrees. The check is a verification-time signal, not a registration-time gate.

A registration that submits no `trustCardContent` produces no `capabilitiesHash` in the TL event and no `card-sha256` in the SVCB row.

### A.5 Stapled SCITT receipt

A Trust Card MAY embed the most recent SCITT receipt for the agent in the `transparencyReceipt` field as base64-encoded bytes. The receipt is added to the served body AFTER the RA seals the relevant `AGENT_REGISTERED` or `AGENT_RENEWED` event; an AHP MUST NOT include `transparencyReceipt` in the `trustCardContent` it submits at registration. A staple lets a verifier confirm TL inclusion offline;
the SDK's `verify-trust-card` CLI extracts the staple, fetches the live receipt from the TL for the same agent, and confirms byte equality.

Operators that staple SHOULD republish the Trust Card on every `AGENT_RENEWED` event so the staple stays current.

## Appendix B: Worked examples (non-normative)

Non-normative worked examples (registration request, event payloads, Trust Card overview) live at [`examples/ans-1-examples.md`](examples/ans-1-examples.md).

## References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md) — anchor types, `IdentityClaim`, freshness budgets, persistence rules.
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md) — ANSName form, Identity Certificate, PriCC.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md) — DNS record emission per registration.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md) — TL append, receipt, witness profiles.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md) — verification worker contract, RDAP monitoring.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): X.509 (revocation reason codes).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS (signature envelope).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JWK (JSON Web Key).
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519): JWT (JSON Web Token).
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): JWK Thumbprint.
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME (FQDN domain-control proof).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421): HTTP Message Signatures.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): OAuth 2.0 Demonstration of Proof-of-Possession (DPoP).
- [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849): Encrypted Client Hello.

