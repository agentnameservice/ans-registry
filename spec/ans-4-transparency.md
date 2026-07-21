# ANS-4: Transparency & Receipts

Status: DRAFT v1.0
Spec: ANS-4 (Transparency & Receipts)
Version: 0.2.0
Date: 2026-07-18
Audience: implementers building or operating an ANS Transparency Log (TL), and AHPs and verifiers consuming SCITT receipts

## 1. Scope

ANS-4 specifies how registration **and identity** events flow into an append-only cryptographic
log that produces verifiable receipts. ANS-4 is part of the ANS notary layer, which records what
can be cryptographically verified without making judgments about trust. Trust scoring is out of
scope for ANS and lives in the separate Trust Index specification. There is one Merkle tree; agent and
Verified-Identity events share it, read through per-object indexes (§5.3).

ANS-4 specifies:

- The inner-event JCS canonicalization, the sealed envelope, and the leaf-hash rule.
- The `TransparencyLog` contract: append with producer-signature verification, per-object reads, checkpointing.
- The TL's public verification API surface, including the C2SP checkpoint and tile endpoints.
- Producer authentication (RA → TL).
- Receipt distribution: live retrieval.
- Optional checkpoint anchoring to the Hedera Consensus Service per HCS-14 and HCS-27 (§7).

ANS-4 is **deployment-optional**. Single-tenant deployments with no cross-organizational trust MAY skip it.

ANS-4 does **not** specify:

- The wire format an RA submits over (HTTPS POST is recommended; the spec is transport-agnostic on this point).
- How verifiers score the freshness of a receipt. Receipt-staleness scoring is out of scope here.

## 2. Terminology

- **SCITT statement**: the unit the TL accepts and seals — the JCS-canonical inner-event payload plus a producer signature. Aligned to [`draft-ietf-scitt-architecture`](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/).
- **Sealed envelope**: the record the TL appends — `{payload: {logId, producer: {event, keyId, signature}}, schemaVersion, signature, status}`, where the outer `signature` is the TL's own attestation. The leaf hash covers the fully signed envelope (§3).
- **SCITT receipt**: the proof of inclusion the TL returns — a binary COSE_Sign1 carrying the inclusion proof (§5.2).
- **Producer key**: the signing key an RA instance uses to sign events submitted to the TL. Distinct from the TL's own signing key (which signs checkpoints, receipts, attestations, and status tokens).
- **Checkpoint**: a C2SP signed note recording the log's size and root hash at a point in time. Produced as batches seal; consumed by consistency-proof verifiers.

## 3. Cryptographic standards

| Requirement | Standard | Rule |
| --- | --- | --- |
| Canonicalization | [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) | All JSON payloads MUST be canonicalized before signing or hashing. Without deterministic serialization, two implementations hashing the same logical object produce different results |
| Signature format | [JWS Detached (RFC 7515 Appendix F)](https://www.rfc-editor.org/rfc/rfc7515) | Payload is not embedded. Signatures are stored in separate fields from the data they sign |
| Co-located signatures | JWS Detached | When a signature resides in the same JSON object as its data, the signature fields MUST be excluded from the signed payload. The exclusion scope MUST be explicit |
| Signature wire format | JWS Compact | `<protected_header>..<signature>` (two dots; empty middle section is the detached payload) |
| Algorithms | ES256 (ECDSA P-256/SHA-256) | Every TL-produced signature — checkpoint, attestation, receipt, status token — and every producer key is ES256. The JWS layer additionally recognizes RS256 for interoperability (verified if presented, never emitted) and EdDSA on the ANS-0 identity-proof surface |
| Leaf hash | [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962) | `SHA-256(0x00 ‖ JCS(envelope))` over the **fully signed envelope** — including the TL's outer attestation signature. This is the leaf Tessera appends and the hash an offline verifier recomputes when walking an inclusion proof |

JWS protected headers: `alg` and `kid` are REQUIRED on every signature; `typ`, `timestamp` (unix
seconds at signing), and `raid` (RA instance identifier, producer signatures only) are OPTIONAL.

**TL signing-key topology.** One ECDSA P-256 key drives every outbound TL signature: the C2SP
checkpoint's primary signature line, the JWS additional-signer line on the same checkpoint, the
outer envelope attestation on every appended event, SCITT COSE receipts, and status tokens.
`GET /root-keys` advertises exactly one verification line (§5.1); verifiers map the 4-byte `kid`
in a receipt's protected header to that key in O(1). The single-key topology is intentional —
multiple signing keys would force verifiers to maintain a key-rotation strategy that adds no
security but doubles the implementation burden.

## 4. The `TransparencyLog` interface

The `TransparencyLog` contract is the protocol surface for ANS-4: append, per-object reads, and checkpointing.

`append` is the write operation. The RA POSTs the raw inner-event body with its producer signature in the
`X-Signature` header (a detached JWS; request bodies are capped at 256 KiB). The TL validates the signature
against the producer-key registry (§6), wraps the event in a sealed envelope, sequences it into the next
available log position — batching with other events arriving in the same window — and signs a checkpoint
covering the new tree root as each batch seals. The append response is `200` with the assigned `logId`; the TL
**dedupes by content hash**, so a retried submission of the exact same signed bytes lands on the same leaf
rather than a duplicate. Receipts are retrieved afterward from the per-object receipt endpoints.

Per-object reads serve one agent's or identity's sealed state: the badge (latest sealed event plus inclusion proof and computed status), the audit history (every event on the object's stream, each with its own proof), the COSE receipt, and — for agents — a status token (§5.2).

Bulk reads are the checkpoint endpoints plus the static C2SP tile surface (§5.2): consumers that want the whole log walk the tiles; there is no separate paginated range API.

## 5. Public verification API

A conforming TL MUST expose the following REST API surface (HTTPS; JSON unless noted):

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/agents/{agentId}` | Badge: sealed event, TL attestation, inclusion proof, and computed status for one agent |
| `GET /v1/agents/{agentId}/audit` | Paginated history of the agent's events, each with its own proof |
| `GET /v1/agents/{agentId}/receipt` | SCITT COSE receipt for the agent's leaf (binary COSE) |
| `GET /v1/agents/{agentId}/status-token` | Short-lived signed status token (`application/ans-status-token+cbor`, §5.2) |
| `GET /v1/log/checkpoint` | Latest signed checkpoint (JSON view) |
| `GET /v1/log/checkpoint/history` | Checkpoint history with pagination, for consistency-proof verification |
| `GET /v1/log/schema/{version}` | JSON Schema definition for a given event schema version |
| `GET /root-keys` | The TL verification line (§5.1, text/plain) |
| `GET /checkpoint` | The raw C2SP signed checkpoint note (static tile surface) |
| `GET /tile/*` | C2SP tlog-tiles: Merkle tree tiles and entry bundles for bulk verification |

Read-only endpoints require no authentication. Verification MUST NOT require access to producer public keys or knowledge of RA implementation details: every proof verifies against the TL's own published key.

### 5.1 Key distribution

The TL distributes its verification key via `GET /root-keys` as a single sumdb-note verifier line
(text/plain), so any verifier can check checkpoint, receipt, attestation, and status-token
signatures without contacting the RA. The single line reflects the single-key topology (§3); the
4-byte key hash embedded in the line is the same value receipts carry as the COSE `kid`.

### 5.2 Receipts, status tokens, checkpoints

**COSE receipt profile.** A receipt is a COSE_Sign1 (RFC 9052): protected header `{alg: ES256,
kid: <4-byte SPKI key hash>, vds: 1 (RFC 9162 SHA-256), CWT claims: {iss, iat}}`; unprotected
header `{396 (verifiable-data-structure proofs): {-1: treeSize, -2: leafIndex, -3: inclusion
path, -4: rootHash}}`. The signature covers the leaf; a verifier recomputes the leaf hash from
the envelope (§3) and walks the path to the signed root.

**Status tokens.** `GET /v1/agents/{agentId}/status-token` returns a short-lived signed
assertion of the agent's computed status (`application/ans-status-token+cbor`; default TTL one
hour), signed by the same TL key. Verifiers that need a fresh liveness signal without walking
proofs consume this; verifiers MUST check the token's expiry themselves.

**Checkpoints and tiles.** The raw checkpoint at `GET /checkpoint` is a C2SP signed note. Its
primary signature line carries `<4-byte keyhash> ‖ <ASN.1 DER ECDSA signature over SHA-256(note
body)>`, base64-encoded per the note format; a standard-JWS additional-signer line is appended to
the same note by the same key. The `GET /tile/*` surface serves the Merkle tree in C2SP
tlog-tiles form for bulk and offline verification.

### 5.3 Identity surface

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

The TL MUST verify that each event came from an authorized RA instance before sealing it. Every submitted event carries a detached-JWS producer signature in the `X-Signature` header; the TL resolves the `(raid, kid)` pair from the signature's protected header against its producer-key registry and rejects an unknown, expired, or revoked key.

Producer-key registration:

1. The operator generates the producer key pair under the RA's key manager; the private key never leaves the RA instance.
2. The operator registers the public key with the TL (`POST /internal/v1/producer-keys`, admin-gated), supplying the client-chosen `key_id`, the `ra_id`, `public_key_pem` (SPKI), `algorithm` (`ES256`), and the required `valid_from` and `expires_at` window (`valid_from` must precede `expires_at`). A duplicate `key_id` is rejected (409). Bootstrap seeding via configuration is equivalent.
3. The TL stores the key under `(ra_id, key_id)` and returns the `key_id`, `status`, and a `fingerprint` of the registered key.
4. The RA carries the `kid` and `raid` in the protected header of every statement signature.

Rotation uses an overlap window: new keys are registered with future `valid_from` dates; both old and new
remain active during the transition. Expiry and revocation both gate **new** ingest — an expired or revoked
key can no longer sign events the TL will accept. Already-sealed events are unaffected: the log is
append-only, and verifiers check the TL's own attestations, receipts, and checkpoints against `/root-keys`,
never producer keys.

Agent and identity events ride the **same** producer lane (the same producer-key registry and
signature check) through **separate** ingest routes: `POST /v1/internal/agents/event` and `POST
/v2/internal/agents/event` for the agent event families and `POST /v1/internal/identities/event`
for the identity event family. The TL rejects a cross-lane body — an `IDENTITY_*` payload on an
agent route, or an `AGENT_*` payload on the identity route — with `422 INVALID_EVENT`, so the two
object types never interleave at ingest.

## 7. Checkpoint anchoring to Hedera (HCS)

The TL's checkpoints MAY additionally be published to the [Hedera Consensus Service](https://hedera.com/consensus-service),
anchoring the log's state roots in a public, append-only consensus history that neither the TL
operator nor any single network node can rewrite. Two finalized Hashgraph Online standards define
the shape:

- **[HCS-27 (Merkle Tree Profile and Proofs)](https://hol.org/docs/standards/hcs-27/merkle-profile/)**
  defines the checkpoint commitment: the TL publishes periodic Merkle root checkpoints (root hash
  and tree size) to a designated HCS topic as typed consensus messages. The HCS-27 "Merkle v1"
  tree profile is the RFC 9162 §2 Merkle Tree Hash — SHA-256 with the `0x00` leaf prefix and
  `0x01` node prefix — which is exactly the tree this TL already builds (§3), so an on-ledger
  root verifies directly against the log's tiles with no profile translation.
- **[HCS-14 (Universal Agent ID)](https://hol.org/docs/standards/hcs-14/)** defines the portable
  agent identifier (`uaid:` scheme) used when referencing ANS-registered agents across networks;
  its ANS resolution profile maps UAIDs onto the DNS- and web-published ANS surface.

Only cryptographic commitments go on-ledger: log entries, metadata, and proof bundles remain
off-ledger with the TL. A verifier checks an anchored checkpoint by fetching the topic message
from at least two independent HCS mirror nodes, comparing it against the TL's published
checkpoint byte-for-byte, and validating the TL signature via `/root-keys` (§5.1). The operator
publishes the HCS topic ID alongside its TL origin documentation; pinning the topic ID to the
TL's identity is the defense against topic substitution.

**Status.** The HCS-14 and HCS-27 standards are finalized. The open-source reference
implementation does not yet ship the HCS publishing adapter; it slots in at the checkpoint
boundary without changing the wire contract of any surface above.

## 8. Conformance

A conformant ANS-4 implementation:

1. Accepts statements only with verified producer signatures (§6) and seals each into a leaf per the leaf-hash rule (§3).
2. Dedupes appends by content hash, so byte-identical retries land on the same leaf.
3. Returns SCITT receipts matching the COSE profile in §5.2.
4. Exposes the verification API (§5) over HTTPS with no authentication on read-only endpoints.
5. Implements producer authentication with overlap-window key rotation (§6).
6. Distributes its verification key via `/root-keys` (§5.1).
7. Honors JCS canonicalization, JWS Detached signatures, and the protected-header rules of §3.

**Operator policy** (rotation cadence, checkpoint batching window, status-token TTL, HCS anchoring cadence) is deployment choice; a conforming verifier MUST NOT reject a receipt because an operator's cadence differs from another deployment's.

## 9. Security considerations

### 9.1 RA / TL collusion

When the RA and TL are operated by the same entity, that entity could in principle forge events with no
independent check, because the keys that sign producer signatures and TL checkpoints are under the same
operator's control. The public checkpoint and tile surface is the mitigation the log itself provides:
checkpoints are signed, history is retained, and any third party can fetch tiles and verify consistency
between checkpoints — a rewritten log cannot produce consistent proofs against previously published
checkpoints. Anchoring checkpoints to the Hedera Consensus Service (§7) strengthens this further: the
on-ledger consensus history is outside the operator's control entirely. A federated deployment runs the RA
and TL under different operators, eliminating collusion as a single-entity risk.

### 9.2 Producer-key compromise

A compromised producer key allows an attacker to submit forged events to the TL. The TL accepts them because
the signature validates. The overlap-window rotation rule (§6) lets the operator revoke the compromised key
without disturbing the log: revocation stops new ingest under that key, previously-sealed events remain
verifiable through the TL's own signatures, and the sealed history bounds what the attacker could have
injected to the compromise window.

### 9.3 Sealed event types

The TL records the agent event family — `AGENT_REGISTERED`, `AGENT_RENEWED`, `AGENT_DEPRECATED`,
`AGENT_REVOKED` — and the
Verified-Identity event family — `IDENTITY_VERIFIED`, `IDENTITY_UPDATED`, `IDENTITY_REVOKED`,
`IDENTITY_LINKED`, `IDENTITY_UNLINKED` (defined in
[ANS-0 §8.1](ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest)). ANS-4 specifies
that the TL accepts these event types, seals each with the same receipt format, and preserves
them. All of them are appended to the one Merkle tree (§5.3); the per-object "streams" are read
indexes, not separate logs.

## Appendix A: Worked examples

Non-normative worked examples (sealed envelope, TL badge response, revocation event, producer key registration) live at [`examples/ans-4-examples.md`](examples/ans-4-examples.md).

## 10. References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md). Binding rule, foundational principles.
- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Event set, registration aggregate, lifecycle.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). `_ans-badge` record carrying the TL endpoint pointer.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md). Integrity Monitor operating principles, verification procedure consuming TL receipts.
- [draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/): SCITT Transparency Service.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JCS canonicalization.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JWS.
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052): COSE (binary receipt envelope).
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962): Merkle tree leaf hashing (§3).
- [HCS-14](https://hol.org/docs/standards/hcs-14/): Universal Agent ID (§7).
- [HCS-27](https://hol.org/docs/standards/hcs-27/merkle-profile/): Merkle Tree Profile and Proofs — HCS checkpoint anchoring (§7).
- [C2SP tlog-checkpoint / tlog-tiles](https://c2sp.org/): checkpoint note and tile formats (§5.2).
