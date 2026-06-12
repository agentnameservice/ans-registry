# ANS-0: Identity Anchor

Status: DRAFT v1.0
Spec: ANS-0 (Identity Anchor)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building an ANS-conformant Registration Authority, Integrity Monitor, or Agent Finder Discovery Service

## 1. Scope

ANS-0 defines how an agent proves its identity to a verifier through a cryptographically anchored, publicly resolvable identifier. This specification is the foundation of the ANS composition: every higher specification (ANS-1 through ANS-5) reads identity through the `AnchorResolver` interface defined here and never branches on the underlying anchor type.

ANS-0 specifies:

- The `IdentityClaim` data type that resolution produces.
- The distinction between an agent's operational endpoint (`AgentHost`) and its identity anchor (`resolvedId`).
- The `AnchorResolver` code-interface contract with its two entry points and the lexical-form dispatch rules.
- The three anchor profiles (FQDN, DID, LEI) defined in this version.
- The anchor profile registration mechanism for adding new types in future versions.
- The freshness budgets and persistence rules common to every profile.
- The cross-anchor identity-equivalence rules a verifier MUST apply when an agent claims identity through more than one anchor at once.

ANS-0 does **not** specify:

- The internal resolution algorithm for a specific anchor type. That lives inline in §5 (FQDN §5.1, DID §5.2, LEI §5.3).
- What an agent does with a verified identity. That is ANS-1.
- How the anchor's public key is rotated. That is anchor-profile-specific and lives in each profile document.
- How the ANS system scores agents or recommends trust policies to callers. Trust scoring is a separate consumer of ANS data and is out of scope here.

## 1.1 Architectural foundation

The RA acts as a notary in this system. It verifies domain control and seals events into a Transparency Log. Verifiers consume what ANS produces (identities, certificates, log proofs) to make independent trust decisions. Trust scoring is out of scope for ANS and lives in a separate `ti-*` layer set.

The principle: **Notary role, not judge role.** The RA verifies domain control and seals events. The caller decides whether to delegate. ANS records what can be cryptographically verified; it does not classify agents by risk, stakes, or purpose.

## 2. Terminology

The following terms are defined here as they apply to ANS-0.

- **Anchor**: a public, resolvable identifier the agent operator controls. ANS-0 admits three anchor types: FQDN, DID, LEI. New anchor types MAY be added by amending this specification as described in the "Adding a new anchor type" subsection below.
- **Anchor type**: an inline subsection of this specification (§5.1 FQDN, §5.2 DID, §5.3 LEI) specifying how that anchor type is resolved. Each subsection implements the rules in this specification's `AnchorResolver` interface.
- **Identity claim**: the typed result of a successful anchor resolution. Carries the anchor type, the canonical resolved identifier, the active public key, and optional pointers.
- **Anchor proof**: the cryptographic evidence the operator presents to bind the anchor to a fresh public key during ANS-1 registration. Distinct from the resolution check ANS-0 performs every time the claim is verified.
- **Operational endpoint** (`AgentHost`): the FQDN where the agent terminates TLS and serves traffic. For an FQDN-anchored registration, the operational endpoint and the anchor's resolved ID coincide; for non-FQDN anchors they diverge (see the operational-endpoint-vs-anchor subsection below).
- **Attestation key source**: how an anchor profile retrieves the candidate verification key at resolution time. Each profile names a concrete source: FQDN reads from the certificate chain (plus optional external locator); `did:web` HTTP-GETs the DID document; LEI reads from the GLEIF API plus vLEI attestation.

## 3. The `IdentityClaim` type

A successful anchor resolution returns an `IdentityClaim`. The canonical type definition is:

```typescript
interface IdentityClaim {
  anchorType: "fqdn" | "did" | "lei";
  resolvedId: string;
  publicKey: JWK;
  metadataUrl?: string;
  issuedAt: string;    // RFC 3339 UTC
  expiresAt?: string;  // RFC 3339 UTC, present when the anchor has an inherent expiry
}
```

Field semantics that bind ANS-0 specifically:

- `anchorType` is one of the three values above. New anchor types add a new value through a profile document AND a non-breaking enum extension to this specification (a profile cannot retrofit a new anchor type without an ANS-0 amendment).
- `resolvedId` is the canonical normalized form of the anchor identifier. Profiles specify normalization (FQDN: lowercase, no trailing dot; DID: per [W3C DID Core §3.1](https://www.w3.org/TR/did-core/#did-syntax); LEI: 20-character ISO 17442 with mod-97 check digits validated).
- `publicKey` is the JWK form of the verification key currently authoritative for the anchor. JWK is the canonical representation; conversions to PEM, COSE, or DER are profile-specific concerns. The field is **transient** within a verification cycle (see the persistence rules below).
- `metadataUrl` is an optional URI where extended properties of the anchor are published (a DID document, an LEI Level 2 record, an agent's Trust Card). ANS-1 through ANS-5 MUST treat this URL as informational only and MUST NOT trust its content for security decisions; metadata that affects security MUST be embedded in `IdentityClaim` itself.
- `issuedAt` records when the resolution occurred. Verifiers cache claims; `issuedAt` plus the claim's freshness policy (see the freshness-budget subsection below) determines whether a cached claim is still valid.
- `expiresAt` is present when the anchor has an inherent expiration (DNSSEC RRSIG validity, DID document expiry). FQDN anchors with an active DNSSEC chain SHOULD set `expiresAt` to the earliest RRSIG inception+lifetime in the resolution chain. Non-expiring anchors (most LEIs) omit the field.

### 3.1 Operational endpoint (`AgentHost`) vs. identity anchor (`resolvedId`)

For FQDN-anchored registrations, the agent's operational endpoint and its identity anchor coincide: the agent at `invoicing.acme.com` terminates TLS at that hostname and proves identity through the same hostname's certificate chain. Implementations of FQDN-only ANS deployments may treat the two as one field without harm.

Non-FQDN anchors break the coincidence. A `did:web`-anchored agent typically still serves traffic at an FQDN, but its identity is the DID URI rather than the hostname:

| Field | FQDN registration | `did:web` registration | LEI registration |
| --- | --- | --- | --- |
| `AgentHost` | `invoicing.acme.com` | `sdk-did-agent.plang.example.com` | operator's chosen service endpoint |
| `IdentityClaim.resolvedId` | `invoicing.acme.com` | `did:web:sdk-did-agent.plang.example.com` | `549300EXAMPLE00LEI17` |

For LEI registrations the divergence is starker still. LEIs do not carry an FQDN; the operator chooses the endpoint and binds it to the LEI through a cross-anchor link in ANS-1 (see the LEI subsection below).

ANS-1 stores both fields on a registration (`AgentHost` for operational addressing, `IdentityClaim.resolvedId` for identity verification). Higher specs (ANS-3 DNS publication, ANS-5 verification) name explicitly which field a given operation consumes. An implementer who collapses the two for the FQDN case alone produces a working RA; an implementer who collapses them generally cannot accept
non-FQDN anchors.

## 4. The `AnchorResolver` interface

The `AnchorResolver` interface admits two entry points because profiles split on where the verification key originates:

```typescript
interface AnchorResolver {
  resolve(input: string): Promise<IdentityClaim>;
  resolveWithKey(input: string, key: JWK, metadataUrlHint?: string): Promise<IdentityClaim>;
  supportedProfiles(): string[];
}
```

- **`resolve(input)`** is for anchors that own their key fetch end-to-end. The DID profile (0.B) reads the DID document over HTTPS or chain-RPC and extracts the active verification method. The LEI profile (0.C) reads the GLEIF Level 1/Level 2 record and extracts the entity's vLEI attestation key. Both call paths are self-contained.
- **`resolveWithKey(input, key, metadataUrlHint)`** is for the FQDN profile (0.A). The verification key for an FQDN anchor lives in the agent's certificate chain that ANS-1 has already validated (or the operator has presented as a Bring-Your-Own Cert). A resolver that re-fetched the certificate would duplicate ANS-1's work and risk observing a different certificate than the service signed. The
  FQDN resolver instead consumes the key ANS-1 supplies and verifies that key against DNS state (DNSSEC chain when present, SAN match in any case). The `metadataUrlHint` parameter is an optional suggestion from the caller about where to find anchor-specific metadata; the resolver MAY ignore it and use its own resolution path.

A profile MAY implement only one entry point. The FQDN profile MUST implement `resolveWithKey` and MAY return `FQDN_RESOLVE_NOT_IMPLEMENTED` from `resolve`. The DID and LEI profiles MUST implement `resolve` and MAY return `<TYPE>_RESOLVE_WITH_KEY_NOT_APPLICABLE` from `resolveWithKey`. A multi-profile facade dispatches based on the lexical-form rules below and routes to whichever entry point the
matched profile implements.

The two-entry-point shape is normative for v0.1.0. A future ANS-0 amendment that moves the FQDN profile to own DNS resolution end-to-end (so the verification key arrives through the resolver itself rather than through ANS-1's cert chain) MAY collapse `resolveWithKey` into a deprecated alias for `resolve`. Until that amendment lands, both entry points are required and implementations MUST NOT
assume either is universal.

`supportedProfiles` enables configuration-driven composition: an RA configured to accept FQDN registrations only configures an `AnchorResolver` whose `supportedProfiles()` returns `["0.A-fqdn"]`. An RA accepting all three anchor types registers a multi-profile resolver. The set is mechanically auditable.

A resolver implementation MAY compose sub-resolvers (one per profile) behind a single `AnchorResolver` facade. Most production implementations will. The facade dispatches to the right sub-resolver by inspecting the input's lexical form and routes to the entry point that profile implements.

### 4.1 Input form recognition

The facade recognizes anchor inputs by lexical form. The dispatch order is fixed:

1. Inputs prefixed with `did:` dispatch to the DID profile (0.B).
2. Inputs that are 20 ASCII alphanumeric characters AND match the ISO 17442 mod-97 check-digit rule dispatch to the LEI profile (0.C).
3. Inputs that match RFC 1123 hostname syntax AND **contain at least one dot** dispatch to the FQDN profile (0.A).

The dot requirement on rule 3 is the tie-breaker: a single-label hostname (`myhost`) is not a valid FQDN input. A 20-character ASCII string that is also a syntactically-valid single label (e.g., `12345678901234567abc`) might match both the LEI rule and the FQDN rule without the dot requirement. The dot requirement ensures that LEI matching takes precedence and that single-label hostnames are
rejected as `INVALID_ANCHOR_FORMAT` rather than silently misclassified. This preserves multi-vendor interoperability: implementers who write a regex-based LEI detector and run it before FQDN checks cannot silently misclassify hostnames.

Inputs that match more than one shape after the rules above are handled by profile authors coordinating through an ANS-0 amendment; today no such overlap exists. Inputs that match no shape are rejected with `INVALID_ANCHOR_FORMAT`.

### 4.2 Verification responsibilities

A successful resolution (through either entry point) MUST perform the following checks before returning an `IdentityClaim`:

1. **Lexical validation.** The input matches the recognized form for its anchor type.
2. **Resolution.** The anchor is reachable through the profile's resolution mechanism (DNS for FQDN, HTTPS or method-specific for DID, GLEIF API for LEI).
3. **Key authenticity.** The public key returned by resolution (or supplied to `resolveWithKey`) is currently authoritative for the anchor. Authenticity checks are profile-specific (DNSSEC chain validation plus SAN match for FQDN; DID document signature verification for DID; vLEI attestation chain for LEI).
4. **Freshness.** The resolution result is no older than the profile's freshness budget.

Failures at any step throw a typed error. The error type carries the failed step and a reason; verifiers map errors to user-facing messages without re-running the resolver.

## 5. Anchor types

Three anchor types are normative: FQDN, DID, LEI. Each section below specifies the resolution sequence, the key authenticity check, the freshness budget, and the conformance posture.

### 5.1 FQDN (Status: Active)

Resolves a fully-qualified domain name through DNS plus TLS-PKI. Uses `resolveWithKey(input, jwk, metadataURL)`; ANS-1 supplies the JWK from the validated certificate chain.

**Resolution.** Validate FQDN syntax per RFC 1123 (at least one dot). Lowercase, strip any trailing dot. Validate the certificate chain through the system trust store (or a configured private CA). Validate the certificate's SAN includes the FQDN; for versioned registrations, validate the URI SAN encodes the matching ANSName. If the zone is DNSSEC-signed, validate the chain and capture the earliest
RRSIG validity end as `expiresAt`.

**Domain-control proof for ANS-1.** Standard ACME (RFC 8555, DNS-01 or HTTP-01). The RA validates the ACME response, then validates the registration's signed payload against the certificate's key. Domain control plus key control; both required.

**Freshness budget.** 1 hour, matching typical DNS TTLs. MAY be shortened to honor an observed sub-hour TTL; MUST NOT be lengthened without an ANS-0 amendment.

**Errors.** `FQDN_BAD_FORMAT` (malformed input), `FQDN_CERT_CHAIN_INVALID` (chain failure), `FQDN_SAN_MISMATCH` (SAN does not include FQDN), `FQDN_DNSSEC_INVALID` (broken signed chain).

### 5.2 DID (Status: Active)

Resolves a [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) URI through the method's resolution mechanism. Uses `resolve(input)`. The `did:web` method is REQUIRED; `did:plc`, `did:key`, `did:ethr` / `did:pkh` (the path for [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) on-chain agent registries), and `did:ion` are OPTIONAL.

**Verification-method selection.** Prefer methods referenced by `assertionMethod`; fall back to `authentication`. On ties, select by the most recent `created` or `updated` timestamp (missing timestamps treated as oldest); on remaining ties, by lexicographic order of the verification method id (NFC-normalized, UTF-8 byte sort).

**`did:web` resolution.** Issue HTTPS GET to `https://<domain>/.well-known/did.json` (or `https://<domain>/<path>/did.json` for path-component DIDs). Follow up to 5 redirects, all on the same registrable domain (public-suffix-plus-one); cross-registrable-domain redirects fail closed with `DID_REDIRECT_DOMAIN_MISMATCH`. Validate response status, content-type (`application/did+json` or
`application/json`), and that the document `id` equals the input DID URI.

**`did:web` domain-control proof for ANS-1.** RA generates a 32-byte challenge token `T`. Operator publishes `T` at `https://<domain>/.well-known/ans-did-web-challenge.txt`. RA fetches, validates response status, content-type starts with `text/plain`, body equals `T`, and the TLS chain matches the chain seen during DID document resolution. RA then verifies the registration's signed payload against
the verification-method-selected key.

**`did:plc` / `did:key` / `did:ethr` / `did:ion`.** `did:plc` resolves through the PLC directory (verifiers SHOULD configure a mirror to avoid single-operator dependency); `did:key` is offline (multibase-decode the suffix, validate the multicodec key-type prefix); `did:ethr` reads on-chain state through Ethereum JSON-RPC and SHOULD require 12 block confirmations before treating a transfer event as
final; `did:ion` reads from a Sidetree-on-Bitcoin endpoint.

**Freshness budgets.** `did:web` 24 hours; `did:plc` 6 hours; `did:key` always fresh; `did:ethr` 1 hour; `did:ion` 12 hours.

**Key rotation.** A key rotation MUST appear in the ANS-4 Transparency Log signed by the previous key. A verifier observing a different active key from the cached value MUST cross-check the TL for a corresponding rotation event before accepting the new key.

### 5.3 LEI (Status: Active)

Resolves an [ISO 17442](https://www.iso.org/standard/78829.html) Legal Entity Identifier through the [GLEIF](https://www.gleif.org/) Level 1 / Level 2 API. Uses `resolve(input)`. LEI binds an agent to the legal entity that operates it; FQDN proves technical control, DID proves cryptographic control, LEI proves organizational identity. Regulated deployments typically pair LEI with FQDN or DID.

**Resolution.** Validate the 20-character LEI (4 LOU prefix + 2 reserved `00` + 12 entity-specific + 2 ISO 17442 mod-97 check digits) before any network call; reject with `LEI_BAD_FORMAT` on check-digit failure. HTTPS GET to `https://api.gleif.org/api/v1/lei-records/{LEI}` with `Accept: application/vnd.api+json`. Validate TLS through the system trust store (reject below TLS 1.2). Validate response
status (200; 404 maps to `LEI_UNKNOWN`), JSON shape (`data.type == "lei-records"`, `data.id == <LEI>`), and entity status (`attributes.entity.status == "ACTIVE"`; `INACTIVE` / `LAPSED` / `RETIRED` / `MERGED` reject with `LEI_INACTIVE`). Verify the LOU's response signature (`GLEIF-Record-Signature` header) through the GLEIF root certificate.

**GLEIF root certificate pinning.** The GLEIF root MUST be pinned in the resolver implementation; trust-store fallback is not acceptable. The root rotates every ~5 years; track GLEIF's published rotation schedule and update during the overlap window.

**Entity's ANS attestation key.** Two transports admitted; the spec is transport-agnostic. **Option A (preferred):** GLEIF vLEI self-attestation of type `ans:public-key:v1` carrying the entity's public key in JWK form, signed by the entity's vLEI signing key. **Option B (transition):** out-of-band registration with the entity's LOU under a custom Level 2 field (`ansAttestationKey`); LOU returns
the field on the standard API response. Implementations MUST support Option A; SHOULD support Option B for transition.

**Cross-anchor binding for ANS-1.** LEI anchors do not bind a service endpoint. ANS-1 requires a cross-anchor binding to at least one anchor that does (FQDN or DID). The operator first registers under the FQDN or DID anchor, then registers the LEI as a cross-reference signed by both the FQDN/DID-controlled key and the LEI-controlled key. The RA verifies both signatures before recording the link as
an EquivalenceLink event (defined in the cross-anchor identity equivalence section below) in the TL. Without the cross-anchor binding, an LEI registration is purely organizational identity with no operational endpoint claim.

**Freshness budget.** 7 days. Verifiers in regulated verticals operating under same-day reporting requirements SHOULD shorten to 24 hours.

### 5.4 Adding a new anchor type

A new anchor type is added by amending this specification to extend the `AnchorType` enum, adding a new subsection here covering resolution, authenticity, and freshness, and adding test vectors at `docs/tests/conformance/anchor-<type>/`. Adding a new DID method does NOT require an ANS-0 amendment because the type stays `"did"`; adding a fourth top-level anchor type (for example `"spiffe"`) does.

## 6. Freshness, caching, and persistence

### 6.1 Freshness budget

`IdentityClaim` is cacheable. A verifier that has resolved an anchor recently SHOULD reuse the cached claim rather than re-resolving on every check. Caching reduces load on the underlying resolution infrastructure (DNS, DID method endpoints, GLEIF) and enables offline verification of stapled SCITT receipts (ANS-4).

Each anchor profile specifies a **freshness budget**: the maximum age a cached claim can have before it MUST be re-resolved. Defaults:

| Profile | Freshness budget | Rationale |
| --- | --- | --- |
| 0.A FQDN | 1 hour | Matches typical DNS TTLs; profile MAY shorten to honor an observed TTL below 1 hour. |
| 0.B DID (`did:web`) | 24 hours | Matches typical HTTPS cache expectations for DID document fetches. |
| 0.B DID (other methods) | per-method (see the DID subsection above) | Method-specific resolution costs and confirmation latencies vary. |
| 0.C LEI | 7 days | LEI records change rarely; GLEIF API rate limits favor longer caching. |

A claim with a non-empty `expiresAt` MUST be re-resolved before its `expiresAt`. Both the freshness budget and `expiresAt` (when present) are upper bounds on cache validity; the verifier MUST re-resolve at the earlier of the two.

Verifiers MAY implement a soft-stale fallback: when the resolution endpoint is unreachable, the verifier MAY use a claim past its freshness budget for up to 4× the budget, marking the resulting verification record as `degraded`. This is a per-verifier policy, not an ANS-0 requirement, and the degraded record MUST surface through ANS-5 reporting so consumers see the soft-stale read.

### 6.2 Persistence rules

`IdentityClaim.publicKey` is **transient within a verification cycle** and MUST NOT be persisted on a registration row. The verification key is recomputed on demand to honor the freshness budget; a stored JWK that bypasses the resolver defeats the freshness budget by construction.

Implementations MAY cache `publicKey` in process memory between calls within the same verification cycle. They MUST NOT write the key to durable storage tied to the registration. A configuration cache (a system-wide JWK cache shared across verification cycles, with its own TTL not exceeding the freshness budget) is acceptable; a registration-row column carrying the key is not.

### 6.3 Absent-claim treatment

An implementation that loads a registration without an attached `IdentityClaim` MUST treat the registration as **FQDN-implicit**: the resolved identifier is the registration's `agentHost`, the anchor type is FQDN, and the freshness budget for FQDN applies. New registrations MUST attach a typed `IdentityClaim`; the FQDN-implicit treatment lets registrations that predate typed anchor support
continue to load.

Storage shape (column nullability, migration mechanics, backfill schedule) is implementation guidance and is not specified here.

## 7. Cross-anchor identity equivalence

An agent operator MAY register a single agent under multiple anchors (FQDN + DID + LEI) to claim independence-of-trust across compromise scenarios. ANS-0 does not require this. When it occurs, the verifier sees multiple `IdentityClaim` values for what the operator asserts is one agent.

The cross-anchor equivalence rules:

1. **The agent's `Registration` aggregate (ANS-1) carries one anchor as its primary claim.** The other anchors are recorded as cross-references. They are not alternates a verifier may substitute for the primary.
2. **Each cross-reference is itself a separate `Registration`** linked to the primary by a typed `EquivalenceLink` event. The event schema is defined in [ANS-1 §6](ans-1-registration.md#6-event-set). Verifiers can see the link in the ANS-4 event stream.
3. **Until the `EquivalenceLink` event lands**, the operational signal a verifier uses to construct the equivalence graph is a shared `agentHost` across registrations of different `anchor_type`. ANS-1's V2 list endpoint exposes this filter; verifiers join client-side. This is a transitional rule and SHOULD be retired once `EquivalenceLink` reaches Active per the profile retirement lifecycle.
4. **Verification of the primary registration is independent of the cross-references.** A verifier that trusts only FQDN anchors verifies the FQDN registration and ignores the DID cross-reference; a verifier that requires LEI for high-value transactions checks the LEI cross-reference and applies it as an additional control on top of the primary.
5. **Compromise of one anchor does not silently revoke the others.** The operator MUST submit a revoke event against each registration affected. ANS-5 detects cases where one anchor is revoked but a cross-referenced anchor still claims authority and surfaces the inconsistency as a verification failure.

Cross-anchor equivalence is a strong tool against threat-model Group D (transfer and continuity). An attacker who acquires an FQDN through registrar takeover does not automatically acquire the LEI bound to the same agent.

## 8. Conformance

An ANS-0 conformant implementation:

1. Exposes an `AnchorResolver` whose `resolve` and/or `resolveWithKey` methods return an `IdentityClaim` matching the type defined above for at least one supported profile.
2. Implements at least one anchor type from §5 (§5.1 FQDN, §5.2 DID, §5.3 LEI).
3. Performs all four verification checks (lexical, resolution, key authenticity, freshness) before returning a claim, regardless of which entry point was called.
4. Honors the lexical-form dispatch rules above, including the dot requirement for FQDN classification.
5. Honors the freshness budget specified by each profile it implements.
6. Treats `IdentityClaim.publicKey` as transient and does NOT persist it on registration rows.
7. Treats a registration loaded without an attached `IdentityClaim` as FQDN-implicit.
8. Emits a typed error (with a documented error code from the profile document) on any resolution failure.
9. Passes the conformance test vectors in `docs/tests/conformance/anchor-*/` for each profile it claims to implement.

Conformant implementations advertise the profiles they support through `supportedProfiles()`.

## 9. Security considerations

### 9.1 Resolution-path attacks

The anchor resolution path is part of ANS's trust boundary. An attacker who compromises the resolution path (a DNS hijack, a poisoned DID document, a forged GLEIF response) compromises every higher-spec defense built on the resolution result. Profile documents MUST specify the integrity controls applied to the resolution path: DNSSEC for FQDN, signature verification for DID document fetches,
certificate chain validation pinned to the GLEIF root for LEI responses.

### 9.2 Key rotation

`IdentityClaim` carries the **active** public key, not the full key history. A verifier that has cached a claim with key K1 and resolves the anchor again to find key K2 has observed a rotation. ANS-0 does not specify whether the rotation is legitimate; that determination requires the rotation event to appear in the ANS-4 Transparency Log signed by K1. Verifiers SHOULD check the TL for a
corresponding rotation event before accepting K2 as authoritative.

A key rotation that does NOT appear in the TL is a candidate compromise. ANS-5 surfaces this as a verification finding.

### 9.3 Anchor squatting

The resolution interface gives no protection against anchor squatting (an attacker registering `acme-payments.example.com` to fool users into mistaking it for `payments.example.com`). Anchor squatting is a discovery-layer concern (addressed by the Trust Index, in the `ti-*` layer set); the threat model maps it to Group A. ANS-0 specifies how to verify the anchor proves what it claims to prove;
whether what the anchor claims to be is what the user intended is outside scope.

### 9.4 Cross-anchor inconsistency

When an agent registers under multiple anchors (cross-anchor identity equivalence), an attacker who compromises one anchor may attempt to drive divergent state across the others (revoke the FQDN registration but leave the LEI registration claiming the agent is healthy). ANS-5's continuous verification detects the divergence. ANS-0 itself does no cross-anchor consistency checking; the consistency
check is a higher-spec responsibility.

### 9.5 Time discipline

`issuedAt` and `expiresAt` are RFC 3339 UTC. A verifier with a clock skewed beyond ±5 minutes MAY accept claims that should be expired or reject claims that are still fresh. Implementations MUST NTP-sync; air-gapped verifiers MUST document their clock-discipline procedure.

## 10. References

- Anchor types are defined inline above (FQDN, DID, LEI).
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/): DID syntax and resolution model.
- [ISO 17442](https://www.iso.org/standard/78829.html): LEI structure and checksum.
- [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123): Hostname requirements.
- [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033): DNSSEC.
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE (DNS-based Authentication of Named Entities).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME (Automatic Certificate Management Environment).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JSON Web Key (JWK).
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052): CBOR Object Signing and Encryption (COSE).
