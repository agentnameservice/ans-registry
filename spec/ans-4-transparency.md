# ANS-4: Transparency & Receipts

Status: DRAFT v1.0
Spec: ANS-4 (Transparency & Receipts)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building or operating an ANS Transparency Log (TL), AHPs and verifiers consuming SCITT receipts, and witness operators

## 1. Scope

ANS-4 specifies how registration **and identity** events flow into an append-only cryptographic
log that produces verifiable receipts. ANS-4 is part of the ANS notary layer, which records what
can be cryptographically verified without making judgments about trust. Trust scoring is out of
scope for ANS and lives in a separate `ti-*` layer set. There is one Merkle tree; agent and
Verified-Identity events share it, read through per-object indexes (§5.4).

ANS-4 specifies:

- The inner-event JCS canonicalization and the cryptographic envelope (SCITT statement plus receipt).
- The `TransparencyLog` code-interface contract: append, range query, inclusion proof, witness query.
- The TL's public verification API surface.
- Producer authentication (RA → TL).
- Receipt distribution: live retrieval and SCITT stapling.
- The witness contract: a profile mechanism by which the log's state roots are anchored to external consensus systems.
- Integrity commitment sealing: the TL preserves committed deployment hashes; the commitment format and verification mechanics live in ANS-1.

ANS-4 is **deployment-optional**. Single-tenant deployments with no cross-organizational trust MAY skip it.

ANS-4 does **not** specify:

- The wire format an RA submits over (HTTPS POST is recommended; the spec is transport-agnostic on this point).
- Which witness profile to deploy. Witness profiles are operator-choice within the constraint that a multi-operator deployment requires at least one.
- How verifiers score the freshness of a receipt. Receipt-staleness scoring is out of scope here.
- How verifiers enforce token-discipline policy at runtime. (See ANS-1 §9 for runtime token-verification mechanics.)
- The integrity commitment composition (Trust Card hash, capabilities manifest, SBOM, SLSA attestation). (See ANS-1 §A and §9 for commitment content.)

## 2. Terminology

- **SCITT statement**: the unit the TL accepts and seals. Carries the issuer (anchor URI form), the JCS-canonical inner-event payload, and a producer signature. Aligned to [`draft-ietf-scitt-architecture`](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/).
- **SCITT receipt**: the proof of inclusion the TL returns. Carries the statement hash, log identifier, Merkle inclusion proof, and a TL signature.
- **Stapling**: distribution shape where a SCITT receipt is carried inline in the agent's Trust Card payload, allowing offline verification.
- **Witness profile**: a normative subsection of this document (§7) specifying how the TL's state roots are anchored to an external consensus system (Hedera, ENS, OpenTimestamps, RFC 6962-style trillian instances).
- **Producer key**: the signing key an RA instance uses to sign events submitted to the TL. Distinct from the TL's own signing keys (which sign checkpoints and receipts).
- **Checkpoint**: a signed snapshot of the log's state at a given size. Produced periodically; consumed by witnesses and consistency-proof verifiers.

## 3. Cryptographic standards

| Requirement | Standard | Rule |
| --- | --- | --- |
| Canonicalization | [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) | All JSON inner-event payloads MUST be canonicalized before signing or hashing. Without deterministic serialization, two implementations hashing the same logical object produce different results |
| Signature format | [JWS Detached (RFC 7515 Appendix F)](https://www.rfc-editor.org/rfc/rfc7515) | Payload is not embedded. Signatures are stored in separate fields from the data they sign |
| Co-located signatures | JWS Detached | When a signature resides in the same JSON object as its data, the signature fields MUST be excluded from the signed payload. The exclusion scope MUST be explicit |
| Algorithm | ES256 (ECDSA P-256/SHA-256) | Default. Implementations MUST support algorithm agility through the JWS `alg` header |
| Signature wire format | JWS Compact | `<protected_header>..<signature>` (two dots; empty middle section is the detached payload) |

Every signature MUST include the following protected headers:

| Header | Value |
| --- | --- |
| `alg` | Signing algorithm |
| `kid` | Key identifier |
| `typ` | Type indicator (e.g., `JWT`) |
| `timestamp` | Unix timestamp of signature creation |
| `raid` | RA instance identifier |

## 4. The `TransparencyLog` interface

The `TransparencyLog` interface is the protocol contract for ANS-4: append, batched checkpoint, public verification API, witness binding.

`append` is the primary write operation. The TL validates the producer signature on the statement, sequences the statement into the next available log position, batches with other statements arriving in the same window, signs a checkpoint that includes the new tree root, and returns a SCITTReceipt covering the inclusion proof for the appended statement.

`range` is the primary read operation for downstream consumers (Discovery Services, federated discovery catalogs, scoring services). Pagination is index-based; `start` is an absolute leaf index, `count` bounds the response size.

`proofFor` is the lookup-by-statement-hash variant. Verifiers that have a SCITT statement and want to confirm inclusion query this endpoint and validate the returned proof against the latest checkpoint.

`witnesses` returns the most recent attestation from each configured witness profile, plus the checkpoint each attestation was made against.

## 5. Public verification API

A conforming TL MUST expose the following REST API surface (HTTPS, JSON unless noted; binary endpoints serve `application/cbor` or COSE):

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/agents/{agentId}` | Sealed event, TL signature, and inclusion proof for one agent (HTML or JSON) |
| `GET /v1/agents/{agentId}/audit` | Paginated history of all lifecycle events for one agent, each with its own proof |
| `GET /v1/log/checkpoint` | Latest signed checkpoint: log size, root hash, and TL signature |
| `GET /v1/log/checkpoint/history` | Checkpoint history with pagination, for consistency-proof verification |
| `GET /v1/log/schema/{version}` | JSON Schema definition for a given event schema version |
| `GET /root-keys` | TL verification keys, including historical keys for older proofs |
| `GET /v1/witnesses` | Witness profile attestations (per the `witnesses()` operation defined above) |

Implementations MAY expose additional endpoints specific to their proof format. Verification MUST NOT require access to producer public keys, authentication for read-only operations, or knowledge of RA implementation details.

### 5.1 Inline Receipt Distribution (SCITT Stapling)

A staple is a SCITT receipt copied inline into the agent's Trust Card payload at registration or renewal time. A verifier consuming a stapled Trust Card validates the receipt locally without a TL roundtrip.

The staple format is the binary COSE receipt produced by the TL's `proofFor` endpoint, base64-encoded, embedded as a `transparencyReceipt` field in the Trust Card body (see ANS-1 Appendix A.5).

### 5.2 Key distribution

The TL MUST distribute verification keys via the `GET /root-keys` endpoint so any verifier can check root signatures without contacting the RA. Historical keys SHOULD be retained; without them, proofs signed before a key rotation become unverifiable.

### 5.3 ANS-BADGE attestation type identifier

Discovery surfaces (Agent Finder catalogs, search indices, peer agent runtimes) point at the TL badge endpoint using the `ANS-BADGE` attestation-type identifier:

**Attestation fields.** `type` is always `ANS-BADGE`. `issuer` is the TL's DID (typically `did:web:<tl-host>`). `uri` is the TL badge endpoint. `evidenceHash` is the SHA-256 fingerprint of the agent's Server Certificate; a poisoned redirect to an attacker's lookalike TL endpoint cannot also produce a matching `evidenceHash` against the genuine agent's certificate.

**Verification procedure for an `ANS-BADGE` consumer.** A discovery client consuming an attestation MUST:

1. Issue an HTTPS GET against `ANS-BADGE.uri`; validate the response is a TL badge response per the public verification API above.
2. Resolve `ANS-BADGE.issuer`; retrieve the TL's signing key; validate the badge response's signature.
3. Walk the badge's Merkle inclusion proof; confirm the leaf hash recovers a root the TL has signed.
4. **Authority matching.** Confirm the `agentHost` (or the DID's resolved domain) inside the sealed event payload matches the authority of the consumer's target URL. A poisoned entry whose target points at the legitimate domain but whose `ANS-BADGE.uri` resolves to a registration for `attacker.example.com` fails closed here.
5. **Evidence hash check.** Open a TLS connection to the agent's target URL; extract the Server Certificate; compute its SHA-256 fingerprint; compare against `ANS-BADGE.evidenceHash`. A match confirms the running agent is the agent the attestation points at.

A failure at any step is a poisoning finding; the consumer SHOULD record the finding and SHOULD NOT proceed with delegation. A consumer that skips steps 4 or 5 is vulnerable to poisoning even when the badge itself is valid.

```json
{
  "type": "ANS-BADGE",
  "issuer": "did:web:transparency-log.example.com",
  "uri": "https://transparency-log.example.com/v1/agents/{agentId}",
  "evidenceHash": "SHA256:..."
}
```

### 5.4 Identity surface

This surface is present only when the RA implements the **optional** Verified Identity capability
([ANS-0 §12.2](ans-0-identity-anchor.md#122-optional-capability-verified-identities)). A TL
serving an RA without it exposes none of the `/v1/identities/*` routes and seals no `IDENTITY_*`
events, and is fully conformant.

There is **one transparency log — a single Merkle tree.** Every event, agent or identity, is
producer-signed and appended to that one tree in log order. A **"stream"** is a **read index**
over that single log (by `agentId` or `identityId`), never a separate tree. The Verified-Identity
object ([ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)) is sealed and read
through this surface; ANS-0 defines the object and the visibility semantics, ANS-4 the routes.

The identity **event family** is `IDENTITY_VERIFIED`, `IDENTITY_UPDATED`, `IDENTITY_REVOKED`,
`IDENTITY_LINKED`, `IDENTITY_UNLINKED` ([ANS-0 §8.1](ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest)).
The sealed-payload field set and per-type required-field matrix are documented there; the
machine-readable conformance schema is [`api/identity-event-schema-v2.json`](../api/identity-event-schema-v2.json),
which a sealed identity log entry MUST validate against. Proof, rotation, and revocation events
are indexed under `identityId`; link/unlink events are additionally indexed under each named
`ansId` for the read-time join. The TL public read surface gains:

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/identities/{identityId}` | Latest sealed event + proof + computed `{status, keys[], keysLogId}` for one identity |
| `GET /v1/identities/{identityId}/audit` | Paginated history of the identity's event chain, each with its own proof |
| `GET /v1/identities/{identityId}/receipt` | SCITT COSE receipt for the identity leaf |
| `GET /v1/identities/{identityId}/agents` | Reverse join — currently-linked agents (paginated) |
| `GET /v1/agents/{agentId}/identities` | The computed who-identities list for one agent (paginated) |
| `GET /v1/agents/{agentId}/identities/history` | Link/unlink events naming this agent (audit envelope) |

The agent badge (`GET /v1/agents/{agentId}`) additionally carries a computed `identities[]` array
joining the agent's live who-identities, governed by the visibility predicate and read-side
revocation terminality of [ANS-0 §8.2–§8.3](ans-0-identity-anchor.md#82-computed-reads-and-the-visibility-predicate):
a link is visible when the link's latest event is `LINKED` **and** the agent is live; a `REVOKED`
identity stays listed with `keys[]` omitted; when the join cannot be computed the array is omitted
and `identitiesUnavailable: true` is set. These reads require no authentication (the verifier's
offline-evidence hop); only the ingest lane (§6) requires the producer credential.

## 6. Producer authentication

The TL MUST verify that each event came from an authorized RA instance before sealing it. Each RA instance registers a public key with the TL and signs every submitted event; the TL validates the signature before accepting the event.

Producer-key registration sequence:

1. RA generates a key pair inside a secure key store it controls (the choice of HSM, cloud KMS, hardware enclave, or software keystore with OS-level isolation is implementation; the spec requires only that the private key never leave the RA instance).
2. RA submits the public key with `validFrom` and an algorithm identifier to the TL's producer-key registration endpoint.
3. TL acknowledges with a `keyId` and stores the key in its producer-key registry.
4. RA includes `keyId` in the protected header of every subsequent statement signature.

Rotation uses an overlap window: new keys are registered with future `validFrom` dates; both old and new remain active during the transition. Producer private keys never leave the RA instance. Historical signatures remain valid after key expiration; a key whose `validFrom` window has elapsed cannot sign new events but its prior signatures continue to verify.

A revocation of a producer key invalidates the key's authority for new signatures; previously-sealed events remain verifiable through the TL's preserved key history.

Agent and identity events ride the **same** producer lane (the same producer-key registry and
signature check) through **separate** ingest routes: `POST /v1/internal/agents/event` for the
agent event family and `POST /v1/internal/identities/event` for the identity event family. The TL
rejects a cross-lane body — an `IDENTITY_*` payload on the agent route, or an `AGENT_*` payload on
the identity route — with `422 INVALID_EVENT`, so the two object types never interleave at ingest.

## 7. Witness profiles

The TL's state roots are anchored to external consensus systems through witness profiles. Multiple witnesses may attest to the same TL state in parallel; verifiers compose with whichever witnesses they trust.

ANS-4 admits four witness profiles in v0.1.0. The profile identifier carried in `WitnessAttestation.witnessProfile` is the suffixed form below (e.g., `4.A-hedera`).

| Profile | Backend | Status |
| --- | --- | --- |
| 4.A | Hedera Consensus Service (HCS-27 Merkle profile) | Active (reference deployment) |
| 4.B | ENS / ENSIP-25 (Ethereum Name Service anchoring) | Reserved (ENS partnership in design) |
| 4.C | OpenTimestamps (Bitcoin-anchored timestamps) | Active |
| 4.D | RFC 6962 / Trillian (classic CT-style log anchoring) | Reserved |

A Federated deployment MUST run at least one Active witness profile.

### 7.A Hedera Consensus Service (Status: Active, reference deployment)

Profile identifier `4.A-hedera`. Anchors the TL's state roots to the [Hedera Consensus Service (HCS)](https://hedera.com/consensus-service) per the [HCS-27 Merkle Tree Checkpoint standard](https://hashgraphonline.com/) `[DRAFT:HCS-27]`. The TL emits checkpoints to a designated HCS topic; the topic's append-only consensus history neither the TL operator nor any single Hedera node can rewrite.

**Attestation shape.** `logCheckpoint` carries a [HCS-27 Merkle Tree Checkpoint](https://hashgraphonline.com/) record (tree size, root hash, TL signature). `externalProof` is the Hedera consensus receipt (`TransactionRecord` with topic ID, sequence number, consensus timestamp). `attestedAt` is the consensus timestamp from the HCS receipt.

**Cadence.** One attestation per TL batch (5-second window in the reference deployment). Operators MAY configure a coarser cadence when HCS topic costs dominate; the cadence MUST be documented through `GET /v1/witnesses`.

**Verification.** Parse `externalProof` as a Hedera `TransactionRecord`. Query the HCS mirror node for the message at the recovered topic ID and sequence number; confirm the message body matches `logCheckpoint` byte-for-byte. Validate `logCheckpoint`'s signature against the TL's public key. Validate the HCS topic ID matches the topic the TL operator publishes through the signed `GET /v1/witnesses`
endpoint. Implementations MUST configure at least two HCS mirror nodes to avoid single-mirror dependency.

**Security.** Topic substitution is the primary attack; defense is the signed `GET /v1/witnesses` distribution that ties the topic ID to the TL's identity. A compromise of Hedera's consensus would invalidate every attestation against an HCS topic; ANS-4's general defense is parallel witnesses. HCS topic write-rate limits may force coarser cadence at very high event volumes; verifiers SHOULD accept
witness gaps up to the operator's published cadence.

### 7.B ENS / ENSIP-25 (Status: Reserved)

Profile identifier `4.B-ens`. Reserved for an ENS-anchored witness per [ENSIP-25](https://docs.ens.domains/ensip/25); spec text pending.

### 7.C OpenTimestamps (Status: Active)

Profile identifier `4.C-opentimestamps`. Anchors the TL's state roots to the Bitcoin blockchain through the [OpenTimestamps protocol](https://opentimestamps.org/). The TL submits checkpoints to an OpenTimestamps calendar service, which aggregates and commits them to Bitcoin. The Bitcoin block confirming the OpenTimestamps commitment provides a backend that no party can rewrite without controlling
Bitcoin's consensus.

**Attestation shape.** `logCheckpoint` carries the TL state. `externalProof` is an OpenTimestamps proof file (`.ots` format) covering the SHA-256 hash of `logCheckpoint`; the proof carries the calendar-service signatures plus the Bitcoin Merkle path. `attestedAt` is the Bitcoin block timestamp of the confirming block.

**Cadence.** OpenTimestamps batching makes per-event attestation impractical; the calendar service aggregates and commits one Merkle root per ~10-minute Bitcoin block. A reasonable witness cadence is one attestation per hour. Operators MAY configure sparser cadence (per day, per week) for low-volume deployments. Cadence MUST be documented through `GET /v1/witnesses`.

**Confirmation depth.** A Bitcoin block carrying an OpenTimestamps commitment is provisional until enough subsequent blocks confirm it. The reference deployment treats commitments as final after 6 confirmations (~1 hour). The depth MUST be documented through `GET /v1/witnesses`; verifiers handling high-stakes flows MAY require deeper confirmations.

**Verification.** Parse `externalProof` as an OpenTimestamps proof file. Walk the proof's calendar signatures and Merkle path to recover the Bitcoin block hash. Query a Bitcoin node (or configured mirror set) for the block; confirm the OpenTimestamps commitment is in the block's Merkle tree. Validate `logCheckpoint`'s signature against the TL's public key. Validate the SHA-256 hash of
`logCheckpoint` matches the leaf the proof commits to. Validate the Bitcoin block has at least the documented confirmation depth.

**Security.** A calendar that lies cannot forge a Bitcoin block (the verifier-side Merkle check catches it); a calendar that drops submissions silently is a denial-of-service against the witness, not a forgery. Defense: configure multiple calendars in parallel and treat any one calendar's commitment as sufficient. A Bitcoin reorganization that rolls back the block invalidates the attestation until
it lands again; the documented confirmation depth bounds the risk. Bitcoin-confirmation lag (~1 hour at default depth) means 4.C is not available immediately after a checkpoint; high-stakes flows requiring fresh attestations within minutes SHOULD also configure 4.A.

### 7.D RFC 6962 / Trillian (Status: Reserved)

Profile identifier `4.D-trillian`. Reserved for an RFC 6962-style cross-witness arrangement using independent Merkle tree logs; spec text pending. References: [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), [Trillian](https://github.com/google/trillian).

### 7.1 Witness binding interface

Each witness profile registers through a witness-binding interface that takes a TL checkpoint and produces an external attestation. The binding interface is profile-agnostic:

```typescript
interface WitnessBinding {
  profileId: string;
  attest(checkpoint: Uint8Array): Promise<WitnessAttestation>;
  verify(attestation: WitnessAttestation, checkpoint: Uint8Array): Promise<boolean>;
}
```

The profile document specifies the `externalProof` shape, the verification procedure, and the cadence at which the witness produces fresh attestations.

## 8. Integrity commitment sealing

ANS-1 §9 specifies the operator-declared integrity commitment over Trust Card content, capabilities manifest, endpoint configuration, SBOM, and optional SLSA attestation. ANS-4's role is to seal the commitment hash plus a timestamp and to preserve them with cryptographic proof of inclusion.

The TL's conformance contract: accept commitment-bearing events from authorized RA producers, seal each into a leaf with its statement hash, return an inclusion proof, and preserve the leaf for the lifetime of the log. The TL does not evaluate the commitment; it preserves the reference.

### 8.1 Cost envelope

Each capability entry in the Trust Card's capabilities manifest MAY declare a `cost_envelope` with per-invocation and per-window maxima:

```json
{
  "cost_envelope": {
    "per_invocation_max_units": 0.25,
    "per_window_max_units": 500.0,
    "window_seconds": 3600,
    "unit": "USD"
  }
}
```

The unit is operator-defined (USD, LLM tokens, external API calls). A verifier presented with a request whose projected cost would exceed the per-invocation or per-window limit MUST refuse. The envelope sits inside the capabilities manifest that the integrity commitment hashes, so changing it bumps the commitment.

## 9. Conformance

A conformant ANS-4 implementation:

1. Exposes a `TransparencyLog` whose `append` accepts SCITT statements with verified producer signatures.
2. Returns SCITT receipts matching the receipt format defined above with binary COSE inclusion proofs.
3. Exposes the verification API over HTTPS with no authentication required for read-only endpoints.
4. Implements producer authentication with overlap-window key rotation.
5. Supports SCITT stapling.
6. Accepts at least one witness profile if the deployment involves cross-organizational verification.
7. Distributes verification keys via `/root-keys` with historical keys retained.
8. Honors JCS canonicalization, JWS Detached signatures, and the protected-header set defined in the cryptographic-standards section above.


**Optional surface.** Which witness profile to deploy is operator choice within the multi-operator-deployment constraint; SCITT alternative profiles (`draft-ietf-scitt-architecture` admits implementation choices the spec leaves open); TL operator policy (rotation cadence, checkpoint frequency, batching window). A conforming verifier MUST NOT downgrade integrity scoring solely because an operator
chose witness profile 4.A over 4.C (or vice versa), and MUST NOT reject a receipt because the operator's checkpoint cadence differs from another deployment's.

## 10. Security considerations

### 10.1 RA / TL collusion

When the RA and TL are operated by the same entity, that entity could in principle forge events with no independent check, because the keys that sign producer signatures and TL checkpoints are under the same operator's control. Witness profiles are the primary mitigation: a witness's external attestation against the TL state cannot be forged without compromising the witness's backend (Hedera,
OpenTimestamps, etc.) too. A private audit trail inside the registry's own infrastructure cannot be checked by third parties; a multi-operator log with witness-based monitoring can.

A federated deployment runs the RA and TL under different operators, eliminating collusion as a single-entity risk.

### 10.2 Producer-key compromise

A compromised producer key allows an attacker to submit forged events to the TL. The TL accepts them because the signature validates. Mitigations:

- The overlap-window rotation rule above lets the operator revoke the compromised key without breaking historical signatures.
- Witness attestation cadence: a witness attestation made before the compromise becomes a recovery point that lets verifiers know what state was sealed pre-compromise.

### 10.3 Stapled-receipt freshness

A stapled receipt sealed before a revocation event remains cryptographically valid against the TL's historical checkpoint even after the registration is revoked. Verifiers handling high-stakes transactions MUST cross-check against live TL state for revocation events; stapling is offline-capable evidence of inclusion at sealing time, not evidence of current liveness.

### 10.4 Witness backend compromise

A compromised witness backend (Hedera consensus topic operator collusion, OpenTimestamps timestamp authority compromise) allows the witness's attestations to be forged. A deployment using only one witness profile inherits that backend's compromise surface. Defense: configure two or more witness profiles and treat divergent attestations as a finding.

### 10.5 Sealed event types

The TL records the agent event family — `AGENT_REGISTERED`, `AGENT_RENEWED`, `AGENT_REVOKED`,
`EQUIVALENCE_LINK`, `INTEGRITY_WARNING`, `INTEGRITY_RESOLVED`, `IDENTITY_CERT_UPDATED` — and the
Verified-Identity event family — `IDENTITY_VERIFIED`, `IDENTITY_UPDATED`, `IDENTITY_REVOKED`,
`IDENTITY_LINKED`, `IDENTITY_UNLINKED` (defined in
[ANS-0 §8.1](ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest)). Event payload
schemas for `INTEGRITY_WARNING` and `INTEGRITY_RESOLVED` are defined in ANS-5; ANS-4 specifies
only that the TL accepts these event types, seals them with the same receipt format as other
events, and preserves them. All of them are appended to the one Merkle tree (§5.4); the
per-object "streams" are read indexes, not separate logs.

## Appendix A: Worked examples

Non-normative worked examples (Pub/Sub envelope, TL badge response, revocation event, producer key registration) live at [`examples/ans-4-examples.md`](examples/ans-4-examples.md).

## 14. References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md). Binding rule, foundational principles.
- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Event set, registration aggregate, integrity commitment composition, capability token discipline.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). `_ans-badge` record carrying the TL endpoint pointer.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md). Integrity Monitor operating principles, INTEGRITY_WARNING/RESOLVED event semantics, verification procedure consuming TL receipts.
- Witness profiles defined inline above (Hedera Consensus Service, ENS Reserved, OpenTimestamps, Trillian Reserved).
- [draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/): SCITT Transparency Service.
- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943): SCITT (informational reference; consult `draft-ietf-scitt-architecture` for the in-progress normative shape).
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS.
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052): COSE (binary receipt envelope).
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962): Certificate Transparency (witness profile 4.D reference).
