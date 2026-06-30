# ANS-0: Identity

Status: DRAFT v1.0
Spec: ANS-0 (Identity)
Version: 0.2.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority, Transparency Log, Integrity Monitor, or verifier

## 1. Scope

ANS-0 defines what an **identity** is in ANS and the single rule that governs every one of them:

> An ANS identity is a **control-proven identifier**. The Registration Authority (RA) seals an
> identity attestation only after control of the identifier is *proven* — never on resolution
> alone.

Two kinds of identity exist in the system, and the distinction runs through every higher spec:

- The **what** — the agent. An agent registration (ANS-1) is anchored to exactly one mandatory
  **primary anchor**, an FQDN, proven at registration time. The agent is the thing that serves
  traffic and accrues behavior history.
- The **who** — the operator or legal entity behind the agent. A **Verified Identity** is a
  first-class object owned by a `providerId`, proven once through a per-kind control proof,
  sealed onto its own Transparency-Log read index, and **linked** to any number of that owner's
  agents.

**The who is optional; the what is not.** Every agent registration MUST have an FQDN primary
anchor (the what; ANS-1) — that is mandatory, and ANS-0 governs how it is proven. The **Verified
Identity** object and its entire surface — the lifecycle (§5), links (§6), the API (§7), the
Transparency-Log identity reads (§8), and the who-identity profiles — are an **optional
capability**. An RA MAY implement them; an RA that does not is fully conformant (it exposes no
`/v2/ans/identities` routes and seals no `IDENTITY_*` events). What ANS-0 makes non-negotiable is
the *rule*, not the feature: whenever an identity attestation is sealed — the agent's primary
anchor always, a Verified Identity only where the capability is implemented — it is sealed only
on proven control (§3), never on resolution. Conformance is split accordingly in §12.

ANS-0 specifies, for both:

- The **proof-of-control gate** — the universal primitive every identity passes before anything
  is sealed (§3).
- The **Verified Identity** object model and lifecycle (§4, §5), the link model (§6), the API
  surface (§7), and the Transparency-Log read surface (§8).
- The **who/what relationship** and the agent's FQDN primary anchor (§9).
- The **identity-profile registration mechanism** — how each identifier kind plugs in without
  touching this core contract (§10), and the registry of profiles defined today.
- Cross-identity equivalence within and across RAs (§11).

ANS-0 does **not** specify:

- The per-kind resolution, control-proof, and validation mechanics. Each kind has its own
  **identity profile** under [`identity-profiles/`](identity-profiles/) (§10).
- How an agent registration is created, renewed, or revoked. That is [ANS-1](ans-1-registration.md).
- The internal mechanics of the Transparency Log (Merkle structure, SCITT receipts, witnesses).
  That is [ANS-4](ans-4-transparency.md); §8 specifies only the identity-facing surface.
- How identities and anchors are monitored over time. That is [ANS-5](ans-5-integrity-monitoring.md).
- How the system scores agents or recommends trust. Trust scoring is a separate consumer of ANS
  data and lives in the `ti-*` layer set.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in RFC 2119,
as used throughout the ANS specification set.

### 1.1 Architectural foundation

The RA acts as a **notary**, not a judge: it verifies control and seals events into a
Transparency Log; verifiers consume what ANS produces (identities, certificates, log proofs) and
make their own trust decisions. ANS records what can be cryptographically verified; it does not
classify identities by risk, stakes, or purpose.

The change from earlier drafts of this document is foundational. ANS-0 v0.1.0 modelled identity
as resolution: an `AnchorResolver` fetched whatever key an identifier published and produced an
`IdentityClaim`. That is unsafe for any identifier whose key is *published* rather than *proven*
— resolving `did:web:google.com` returns Google's real key and says nothing about who is
registering. v0.2.0 replaces resolution-as-identity with **proof-of-control-as-identity**: the
authoritative key is still resolved, but resolution is only an internal step of a control proof,
and nothing is sealed until the registrant demonstrates possession of that key bound to this
operation. The resolver interface and the `IdentityClaim` type of v0.1.0 are retired; the
"FQDN-implicit" treatment is **narrowed, not removed** — it now applies only to an agent's FQDN
primary anchor, never to Verified Identities (§9). §9 and §11 describe what replaces
resolution-as-identity.

## 2. Terminology

- **Identifier** — a public, stable string an operator controls: an FQDN, a DID, an LEI.
- **Identity** — a *control-proven* identifier. ANS holds two identity shapes: the agent's
  primary anchor (the what) and a Verified Identity (the who).
- **The what** — an agent registration (ANS-1), anchored to one FQDN primary anchor.
- **The who** — a Verified Identity: the operator/legal entity behind one or more agents.
- **Verified Identity** — the first-class object this spec introduces: `{identityId, providerId,
  kind, value, status, …}`, owned by a `providerId`, proven through a control proof, sealed on
  its own TL read index.
- **Identity profile** — a separate document under [`identity-profiles/`](identity-profiles/)
  that defines how one identifier **kind** (`did:web`, `did:key`, `lei`, `fqdn`, …) is selected,
  control-proven, validated, sealed, and monitored. Profiles plug into this core; adding one does
  not change the core contract (§10).
- **Kind** — the profile selector carried on an identity (`did:web`, `did:key`, `lei`, …). The
  set is closed and spec-governed; a new kind requires a new profile document and an ANS-0
  amendment of the registry table (§10).
- **Control proof** — the cryptographic evidence the registrant presents to prove control of an
  identifier. Composed of up to two axes (§3.1). Distinct from resolution: resolution retrieves
  the authoritative key; the control proof demonstrates possession of it, bound to this object
  and operation.
- **Proven key** — a verification method whose possession the registrant demonstrated and which
  the RA therefore sealed. An identity may have several (§3.2 multi-key).
- **Identity link** — an owner-gated association binding a Verified Identity to one of that
  owner's agents (§6). A link is a sealed fact, not a cryptographic operation.
- **Seal** — the act of appending a producer-signed event to the Transparency Log. ANS seals the
  *proof of control*, never resolution alone (§3.4).

## 3. The proof-of-control gate

The gate is the one mechanism every identity passes. FQDN's existing ANS-1 flow (ACME + a
self-signed CSR) is its archetype; ANS-0 generalizes *exactly* that, per kind. The proof binds
the **identity object**, never an agent; links carry no proof (§6).

### 3.1 The two axes

Every identity seals only after **both** applicable axes pass:

| Axis | Question | FQDN primary (the what) | Verified Identity (the who) |
| --- | --- | --- | --- |
| **Identifier control** | "Can you act as the controller of this identifier?" | ACME DNS-01 (`_acme-challenge` TXT) | A *location challenge* — only for kinds with a writable location. No kind in this version's Verified-Identity set has one (§9, profiles). |
| **Key control** | "Do you hold the key you will sign as?" | CSR self-signature, bound to the FQDN by the issued certificate | A *challenge-bound signature* over the canonical proof input (§3.2). |

A profile names which axes apply. The FQDN primary applies both on the ANS-1 registration path.
Today's Verified-Identity profiles (`did:web`, `did:key`, `lei`) are **key-control only**:
control of a DID *is* possession of its listed keys per DID Core, and an LEI is proven by a vLEI
credential chain plus a possession signature. A location challenge is introduced only when a kind
arrives that has a writable location and needs one — the seam exists (§3.3) but no interface
ships before a second real implementer does.

### 3.2 Key control — a challenge-bound proof of key possession

The concept is uniform: prove possession of the identifier's *authoritative* key, with the proof
bound to **this object and operation** (anti-replay, anti-cross-use).

1. On register / rotate (`PUT`), the RA issues a random single-use `nonce`, stores it on the
   identity row with an expiry, and returns the **list of challenges to sign**.
2. The registrant signs the **served signing input**. There is exactly **one** signing input in
   the system: the RFC 8785 (JCS) canonical bytes of **`IdentityProofInput`**, base64url-encoded:

   ```json
   {
     "identifier": "<canonical identifier>",
     "identityId": "<uuid>",
     "nonce": "<issued nonce>",
     "purpose": "ans:identity-proof:v1",
     "raId": "<ra id>",
     "scheme": "<kind, e.g. did:web | did:key | lei>"
   }
   ```

   - **`purpose`** is a fixed domain separator. The operator's keys also sign VCs, DIDComm, and
     application payloads; a domain-separated input can never verify as any of those, nor they as
     it. It also future-proofs a second ANS proof type (e.g. cross-owner link consent, §6).
   - **`raId`** is the RA's configured issuer identifier — its external base URL, set in
     deployment config, advertised identically to every registrant, **never derived from request
     headers**. One deployment = one `raId`; a signature minted against staging cannot replay
     against production.
   - **The RA serves the signing input; clients never canonicalize.** The register/rotate `202`
     carries `challenges[].signingInput` = the base64url of the exact JCS bytes. For JWS schemes
     the compact JWS's **payload segment MUST equal that string verbatim** (the RA checks
     payload-equality *before* verifying any signature); for non-JOSE schemes (lei CESR) the
     signed message is the decoded bytes. Canonicalization-mismatch interop failures fail closed
     at the payload-equality check, before any signature is verified.
3. The RA verifies the proof(s) against the **authoritatively resolved** key(s), with `alg`
   pinned to the resolved key type (alg-confusion defense), confirms the `nonce` is unexpired and
   unconsumed, and consumes it **in the same transaction that flips the row state** — a
   conditional update, so two concurrent verify calls cannot both succeed.

**Why a `kid` selector, not a key in the body.** The verifying key MUST be the one the
*identifier authoritatively publishes* — resolved by the RA from the DID document, decoded from
the `did:key` string, or established by an ACDC credential chain for `lei`. A key handed over in
the request body would only prove "the registrant holds the key they sent," which says nothing
about the identifier. The `kid` is a *selector* into the resolved key set; the signature is
always checked against the resolved key. (FQDN is the apparent exception that proves the rule:
its key arrives in a CSR but is trusted only after ACME binds it to the domain.) The `kid` lives
in the JWS protected header as a pragmatic choice (JWS is the envelope the DID/JOSE ecosystem
emits; it keeps `alg`+`kid`+payload+signature one self-describing unit); a wrong selector
fails closed against the wrong resolved key and can never redirect to another identifier's key,
because the RA resolves from `identifier`, not from the selector.

**Multiple keys.** When the identifier authoritatively publishes several keys (`did:web`, and the
deferred `did:plc`/`did:ion`), the registrant MAY prove possession of more than one by submitting
**one JWS per key** (`signedProofs[]`), each the *same* `IdentityProofInput` signed under a
different key, each header naming that key's `kid`. The RA verifies **every** submitted proof
(one bad proof fails the call closed) and **seals every key that verifies** as its own proven key
(§8), against the **one** shared nonce, consumed once. `did:key` and `lei` are single-key.

**Token discipline (normative).** The `nonce` is single-use and bound to its row; default TTL 1
hour (configurable; ANS-2's 5-minute PriCC (Private-key Confirmation Challenge) recommendation is the floor for high-assurance
deployments). A proof against a consumed or expired nonce is rejected. A **failed** verify
attempt does **not** consume the nonce — consumption happens only inside the success transaction
— so a registrant may retry a bad proof until expiry. After expiry, recovery is the **idempotent
re-add** (§5): re-`POST` the same `value` and receive `202` with a fresh nonce on the **same**
identity row. No dead-end state, no separate re-challenge route.

### 3.3 Identifier control: the location challenge

Only kinds with a *writable location* need the interactive identifier-control round-trip. Exactly
one identity in this version has one: the **FQDN primary**, whose location challenge is the
existing ACME DNS-01 flow on the agent-registration path (the [fqdn profile](identity-profiles/fqdn.md)).

A `did:web` identity carries **no** location axis: control of a DID *is* possession of its listed
keys, and a who-identity's `did.json` legitimately lives wherever the operator's identity lives
(the apex, a corporate identity domain), not at an agent's host. The holder of a listed
`assertionMethod` key is, per DID Core, authorized to make assertions as the DID; demanding a
location check would be ANS requiring more than the DID method itself defines as control. (The
v0.1.0 `.well-known/ans-did-web-challenge.txt` flow is therefore **removed**, along with the
rev-3 host-match rule — see the did:web profile.)

Consequence for implementations: a `LocationChallenger` interface would have exactly one
implementer today (ACME, already in the FQDN lifecycle), so the interface is **not introduced**.
The location axis is a concept here; it becomes a seam when a second real implementer arrives.

### 3.4 Seal the proof, not the claim

The RA MUST NOT emit an attestation naming an identifier until key control (and, for the FQDN
primary, identifier control) has returned clean. The sealed attestation records *that control was
proven, of which keys, by what method, when* — self-verifyingly for the public-key schemes (§8).
"Resolution" survives only as an *internal step* of key control for fetch-based kinds (`did:web`
fetches the document to check signatures against, then discards it). Keys are sealed in the
identity's events, never persisted as live row state (§4, key transience).

## 4. The Verified Identity object

A Verified Identity is owned by a `providerId` and is independent of any agent.

```typescript
interface VerifiedIdentity {
  identityId: string;     // UUIDv7, RA-assigned
  providerId: string;     // owner — the same authentication principal as the owner's agents
  kind: string;           // profile selector: "did:web" | "did:key" | "lei" | …
  value: string;          // canonical identifier (profile-normalized)
  status: "PENDING_CONTROL" | "VERIFIED" | "REVOKED";
  proofMethod: string;    // e.g. "did-web-sig" | "did-key-sig" | "lei-vlei-acdc"
  verifiedAt?: string;    // RFC 3339 UTC, set when status becomes VERIFIED
}
```

There is **no public-key column**. Proven keys live in the identity's sealed TL events (§8), not
as durable row state — the same key-transience rule v0.1.0 applied to `IdentityClaim.publicKey`,
preserved here: a stored key would be a second copy that can drift from the freshness-bounded
sealed source, so the authoritative key state lives only in the sealed events.

An identity is created and proven entirely on its own; an identity with **zero** linked agents is
a valid state, and that independence is what makes the continuity story (§9) work.

## 5. Identity lifecycle

```text
[*] --> PENDING_CONTROL          register (202 + challenges)
PENDING_CONTROL --> PENDING_CONTROL   re-add same value (idempotent, fresh nonce)
PENDING_CONTROL --> VERIFIED     verify-control clean → seal IDENTITY_VERIFIED
VERIFIED --> VERIFIED            PUT + verify-control → seal IDENTITY_UPDATED (rotation)
VERIFIED --> REVOKED             POST …/revoke → seal IDENTITY_REVOKED
REVOKED  --> [*]                 terminal
```

1. **Register** — `POST /v2/ans/identities {value}`. The RA infers the kind from lexical form
   (§10), canonicalizes it, runs the profile's advisory resolution to seed the challenge list,
   creates the row `PENDING_CONTROL` under the caller's `providerId`, and returns `202` with the
   challenges to sign. **Idempotent re-add:** while the row is `PENDING_CONTROL`, the same owner
   re-`POST`ing the same value gets `202` with the **same `identityId`** and a fresh nonce.
   `IDENTIFIER_DUPLICATE` is reserved for genuine conflicts: already `VERIFIED` by this owner
   (rotate instead), or proven by another owner (§11 uniqueness).
2. **Verify-control** — `POST /v2/ans/identities/{identityId}/verify-control` with the proof(s)
   over `IdentityProofInput` (§3.2). Clean → `VERIFIED`, seal `IDENTITY_VERIFIED`.
3. **Rotate / replace** — `PUT /v2/ans/identities/{identityId} {value}` stages a same-kind
   replacement and returns fresh challenges. The previously sealed state **stands** until the new
   proof lands (the row remains `VERIFIED` with the replacement staged); a replacement that never
   verifies expires with its nonce. A clean verify-control seals `IDENTITY_UPDATED` — **one
   event, regardless of how many agents are linked** (§8 fan-out). Cross-kind replacement is
   rejected (remove + add, not a rotation). Value-stable rotation applies only to kinds whose
   identifier value survives a key change; for `did:key` the value *is* the key, so a key change
   is a new identifier (a new identity object), not a `PUT` rotation (see the did:key profile).
4. **Revoke** — `POST /v2/ans/identities/{identityId}/revoke` → `REVOKED`, seal
   `IDENTITY_REVOKED`. **Not a `DELETE`:** an identity cannot be deleted, only state-changed; its
   history is append-only in the TL, and the verb mirrors the agent's `POST …/revoke`.

### 5.1 Seal-before-success (normative)

No identity operation reports success before its event is sealed. Verify-control, `PUT`, revoke,
link, and unlink return success **only after the TL acknowledges the seal**, and the row
transition (and nonce consumption) commits with that acknowledgment. If the TL is unavailable the
operation fails retryable (`503 TL_UNAVAILABLE`), the nonce is **not** consumed, and the prior
row state stands. If the TL *rejects* the event (a producer-side bug), the operation fails
(`502 TL_REJECTED_EVENT`). Consequence: the RA row can never be ahead of the log — anything the
RA reports as set up is resolvable in the TL at that moment.

This mirrors the rule ANS-1 §4.2 applies to agent activation (an agent MUST NOT activate without
a sealed event). The RA serializes concurrent verify attempts on one nonce with a short-TTL
provisional **claim** taken before the seal round trip (a second concurrent attempt gets
`409 VERIFICATION_IN_FLIGHT`); failed attempts release the claim. Revoke and link/unlink commit
through conditional updates (status re-checked at commit), so an operation that loses a race
fails cleanly rather than clobbering a committed state. A sealed event whose row transition then
loses a race is benign: it asserts a true fact, the row never flips, and read-side terminality
(§8.3) prevents a late non-revocation event from resurrecting a revoked identity.

## 6. Identity links

A link binds a Verified Identity to one of the owner's agents.

**Authorization (normative).** A link is a **single owner-gated call**. The caller MUST be the
authenticated owner of **both** sides — the identity's `providerId` and every agent's
`providerId` equal the caller's principal. Key possession never authorizes a link: holding an
identity's keys without owning the agent gets nothing, and owning an agent without owning the
identity gets nothing.

**Liveness gate (normative).** The identity MUST be `VERIFIED`, and every agent MUST be in a
**live** registration state — `ACTIVE` or `DEPRECATED`. (The link gate sees only *registration*
status; the TL-computed read-time badge states `WARNING`/`EXPIRED` are not registration statuses,
so they do not appear here — but the §8.2 visibility predicate, which reads the TL badge status,
additionally treats `WARNING` as live.) Terminal agents (`REVOKED`/`EXPIRED`/`FAILED`) and
pre-activation agents are rejected with `AGENT_NOT_LINKABLE` (a terminal link is dead on arrival
under the §8.2 predicate; a pre-activation agent has no sealed presence to join). `DEPRECATED` is
deliberately linkable: it still serves during migration and the who remains true.

**No link signature.** Within one owner, a link asserts a fact the owner gate already establishes
— these ARE the owner's agents and identity; the only *false* binding (cross-owner) is blocked by
the gate itself. A mandatory identity-key signature would be incoherent (revoke and unlink, more
destructive, are credential-gated, not key-gated) and harmful to key hygiene (autoscaling fleets
would need the org's identity private key in the provisioning path). The identity key signs in
exactly two places — proof and rotation — never for routine fleet operations.

**Named residual risk + compensating controls.** The one scenario a link signature uniquely
blocked: an attacker with a **stolen owner credential** registers an agent on their own domain
under the victim's account and links the victim's identity to it (reputation transfer). Accepted
for v1 with the system's standard answer — **detection via transparency**: `IDENTITY_LINKED` is a
sealed event on the victim identity's own audit stream (`GET /v1/identities/{identityId}/audit`),
so the owner, a third party, or an ANS-5 monitor catches it — but detection is **pull-only**: it
depends on someone actively polling that stream. The RA pushes nothing (it collects no contact
info, and the account it could notify is the one whose credential performed the link). Deployments MAY additionally require **step-up
authentication** on link/unlink/revoke. The link route enforces a per-owner rate limit and a
per-call `agentIds[]` cardinality cap (both deployment-configured).

**Mechanics.** Linking a batch is **one** owner-gated call sealing **one** `IDENTITY_LINKED`
event whose `ansIds[]` carries exactly the agent ids submitted as the request's `agentIds[]` (§7);
fleet linking is O(1) sealed events. Unlink (`DELETE
…/links/{agentId}`) seals `IDENTITY_UNLINKED`; the association ends but its history persists, and
the RA's write-side link row is retained as `UNLINKED` (never deleted) — that retained row is a
projection-fidelity contract, not an API feature. Cross-owner linking is out of scope (§11); if
ever admitted it returns with both-sided link signatures and its own security review.

## 7. API surface

The identity object is managed through the V2 RA API. The route table:

```text
POST   /v2/ans/identities                              register → 202 + challenges to sign
GET    /v2/ans/identities                              list (mine) — paginated
GET    /v2/ans/identities/{identityId}                 detail (status, live links)
PUT    /v2/ans/identities/{identityId}                 rotate / replace → 202 + fresh challenges
POST   /v2/ans/identities/{identityId}/verify-control  proof → seal IDENTITY_VERIFIED | IDENTITY_UPDATED
POST   /v2/ans/identities/{identityId}/revoke          state change → seal IDENTITY_REVOKED (not DELETE)
POST   /v2/ans/identities/{identityId}/links           {agentIds[]} → seal ONE IDENTITY_LINKED (200)
DELETE /v2/ans/identities/{identityId}/links/{agentId} unlink → seal IDENTITY_UNLINKED
```

Every route is owner-scoped: the caller's `providerId` MUST own the identity, and link routes
additionally require owning the agent (§6). A read for an identity the caller does not own returns
404 (existence hidden); a write returns 403. A kind with no enabled profile returns
`422 IDENTIFIER_KIND_UNSUPPORTED` — no placeholder seal.

**Wire bodies (summary; the authoritative schemas are in
[`api/api-spec-v2.yaml`](../api/api-spec-v2.yaml)):**

- Register/rotate request: `{value}`. Response `202`: `{identityId, nonce, expiresAt,
  challenges:[{kid, signingInput}]}` — one challenge entry per eligible key, all over the one
  shared nonce.
- Verify-control request: JWS schemes `{signedProofs:[<compact JWS>, …]}`; `lei`
  `{cesrSignature}` (the presentation rides register; see the [lei profile](identity-profiles/lei.md)).
- Link request: `{agentIds:[…]}`; response `200 {linked: N}`.
- List response: the standard cursor-paginated envelope shared with the agent list —
  `{items:[IdentityDetails], returnedCount, limit, nextCursor, hasMore}`.

The agent detail/list responses (ANS-1) additionally carry a **computed**, optional
`identities[]` array — the RA-side current-links view, never stored on the registration. It is
the common-core subset (`identityId, kind, value, identityStatus, linkedAt`) of the TL badge
entry (§8).

## 8. Transparency-Log surface

There is **one transparency log — a single Merkle tree** (ANS-4). Every event, agent or identity,
is producer-signed and appended to that one tree; the tiles contain whatever event type was
written, in log order. A **"stream"** in this document is a **read index** over that single log
(by `ansId` or `identityId`) — never a separate tree.

### 8.1 The identity event family and ingest

ANS-0 adds five V2 event types, all indexed under the identity stream:

```text
IDENTITY_VERIFIED   first proof — carries the full proven key set
IDENTITY_UPDATED    rotation — proven key set replaced (carries previousValue)
IDENTITY_REVOKED    state change
IDENTITY_LINKED     batch link — carries ansIds[]
IDENTITY_UNLINKED   unlink — carries ansIds[]
```

Identity events ride the **same producer lane** as agent events (RA producer-signed, validated at
submission) but through their **own ingest route**, `POST /v1/internal/identities/event` —
different object type, different payload schemas. An `IDENTITY_*` body on the agent route (or an
`AGENT_*` body on the identity route) is rejected `422 INVALID_EVENT`; the V1 lane stays frozen.
(The `/v1/...` route namespace and the events' `SchemaVersion = V2` are independent: the route
prefix is the TL's HTTP-API generation, the schema version is the event-envelope generation.)
The TL dispatches on `eventType` + payload, indexes proofs/rotations/revocations under
`identityId`, and additionally indexes link events under **each named `ansId`** for the read-time
join. (ANS-4 specifies the ingest contract and read routes.)

**An identity operation never writes to an agent's event or audit history**, and an agent
operation never writes to an identity's. The join is read-time, in both directions.

**Sealed payload (the append-only contract).** The producer-authored inner event — JCS-canonical
before signing, keyed by `identityId` — carries:

| Field | Type | Present on |
| --- | --- | --- |
| `eventType` | enum (the five tokens above) | every event |
| `identityId` | string (UUIDv7, the stream key) | every event |
| `kind` | enum `did:web` \| `did:key` \| `lei` | every event |
| `value` | string (canonical identifier) | every event |
| `timestamp` | string (RFC 3339) | every event |
| `keys[]` | array of `ProvenKey` | `IDENTITY_VERIFIED`, `IDENTITY_UPDATED` (required, non-empty) |
| `verifiedAt` | string (RFC 3339) | `IDENTITY_VERIFIED`, `IDENTITY_UPDATED` (required) |
| `providerId` | string (the who's owner) | `IDENTITY_VERIFIED`, `IDENTITY_UPDATED` (required) |
| `proofMethod` | enum `did-web-sig` \| `did-key-sig` \| `lei-vlei-acdc` | proof events |
| `previousValue` | string (pre-rotation identifier) | `IDENTITY_UPDATED` |
| `revokedAt` | string (RFC 3339) | `IDENTITY_REVOKED` (required) |
| `ansIds[]` | array of agent ids (the whole batch) | `IDENTITY_LINKED`, `IDENTITY_UNLINKED` (required, non-empty) |
| `raId` | string | optional, all |

**Per-type required-field matrix** (the closed contract a conformance check enforces):

| Event type | Requires | Forbids |
| --- | --- | --- |
| `IDENTITY_VERIFIED` / `IDENTITY_UPDATED` | non-empty `keys[]` (each a verbatim verification method with an `id`, plus `signedProof`), `verifiedAt`, `providerId` | `ansIds[]` |
| `IDENTITY_REVOKED` | `revokedAt` | `ansIds[]` |
| `IDENTITY_LINKED` / `IDENTITY_UNLINKED` | non-empty `ansIds[]` | — |

A **`ProvenKey`** is `{verificationMethod, signedProof}`: the `verificationMethod` is the source's
object quoted verbatim (§8.4), and `signedProof` is the registrant's compact JWS over the served
`IdentityProofInput` (the `lei` thumbprint-only variant is the documented exception — see the lei
profile). Worked `IDENTITY_VERIFIED` example (a `did:web` identity with one proven P-256 key):

```json
{
  "schemaVersion": "V2",
  "status": "VERIFIED",
  "signature": "<TL attestation — detached JWS>",
  "payload": {
    "logId": "0193f1a2-9c00-7d11-8aaa-loglogloglog",
    "producer": {
      "keyId": "ans-ra-local:1",
      "signature": "<RA producer attestation — detached JWS over the JCS-canonical event>",
      "event": {
        "eventType": "IDENTITY_VERIFIED",
        "identityId": "0193f0c5-7b2e-7a41-9c3d-2f9a1e4b6d80",
        "kind": "did:web",
        "value": "did:web:identity.acme-corp.com",
        "providerId": "acme-corp",
        "proofMethod": "did-web-sig",
        "verifiedAt": "2026-06-23T18:30:00Z",
        "timestamp": "2026-06-23T18:30:00Z",
        "raId": "ans-ra-local",
        "keys": [
          {
            "verificationMethod": {
              "id": "did:web:identity.acme-corp.com#key-1",
              "type": "JsonWebKey2020",
              "controller": "did:web:identity.acme-corp.com",
              "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "f83OJ3D2…", "y": "x_FEzRu9…" }
            },
            "signedProof": "<compact JWS; payload segment == the served signingInput>"
          }
        ]
      }
    }
  }
}
```

The machine-readable conformance schema for this payload — the closed `eventType` set, the field
set, and the per-type required-field matrix encoded as JSON Schema (draft-07) `if`/`then` — is
[`api/identity-event-schema-v2.json`](../api/identity-event-schema-v2.json). A sealed identity log
entry MUST validate against it.

### 8.2 Computed reads and the visibility predicate

Higher-spec views that show "who is behind this agent" are **computed at query time** from the
link events' indexes — the same pattern as the V2 badge's computed `status`. Rotation and
revocation are therefore visible on every linked agent's badge immediately, with **zero write
fan-out**: rotating an identity linked to 10,000 agents seals **one** `IDENTITY_UPDATED`.

A link is **visible** in a "current" view when the link's latest event is `LINKED` **and** the
agent is **live** — `ACTIVE`, `DEPRECATED`, or `WARNING` (not terminal). `WARNING` is a
TL-computed read-time badge state: the agent's identity or server certificate is approaching
expiry but it is still serving; the TL derives it at read time (not a registration lifecycle
status) and ANS SDKs honor it for validation — which is why it appears here but not in §6's
registration-status link gate. Within a visible entry, the identity's own status is reported
as-is:

- A `VERIFIED` identity carries its current proven `keys[]` (verbatim verification methods, §8.4)
  and `keysLogId` — the `logId` of the `IDENTITY_VERIFIED`/`IDENTITY_UPDATED` seal those keys are
  quoted from.
- A `REVOKED` identity **stays listed** with `identityStatus: REVOKED` and `keys[]` omitted — a
  verifier looking at a still-linked agent MUST see that the who was revoked, not have it
  silently vanish. Only an unlink removes the entry.

When the join cannot be computed, the badge omits `identities[]` and sets
`identitiesUnavailable: true` — an empty array always means "no visible links", never "the join
failed".

The identity read surface (TL):

```text
GET /v1/identities/{identityId}            latest sealed event + proof + computed {status, keys[], keysLogId}
GET /v1/identities/{identityId}/audit      the identity's full event chain (standard audit envelope)
GET /v1/identities/{identityId}/receipt    SCITT COSE receipt for the identity leaf
GET /v1/identities/{identityId}/agents     reverse join — currently-linked agents (paginated)
GET /v1/agents/{agentId}                   agent badge — gains the computed identities[] join
GET /v1/agents/{agentId}/identities        the computed list, served alone (paginated)
GET /v1/agents/{agentId}/identities/history the link/unlink events naming this agent (audit envelope)
```

These reads are **public** under the deployment's public-read policy (they are the verifier's
offline-evidence hop); only the `/v1/internal/*` ingest requires the producer credential.

### 8.3 Read-side revocation terminality

Identity status on a "current" view is derived from the rule **REVOKED iff any `IDENTITY_REVOKED`
exists on the stream** — not merely when it is the stream tail. Seal-before-success spans a
network round trip, so a racing operation's event can land *after* a revocation leaf; a late leaf
MUST NOT flip a revoked identity's public answer back to `VERIFIED`. This is sound because no
legitimate flow appends to a revoked identity's stream (re-registration mints a new `identityId`).

### 8.4 Seal-verbatim rule

Each proven key is sealed as the **verification method exactly as the identifier published it** —
`id`, `type`, `controller`, and the key material in whichever representation the source used
(`publicKeyJwk`, or `publicKeyMultibase` for Multikey documents) — copied member-for-member,
values untouched, alongside the signed challenge. **No derived values are sealed**: no
thumbprints, no re-encodings, no normalization. Derivations are computed at read time from the
sealed source and can always be recomputed; a sealed derivation is just one more thing that can
disagree with it. A third-party verifier checks operator signatures from the badge alone
(byte-recompute the `IdentityProofInput`, verify the JWS against the sealed method, reject
unrecognized `crit` headers per RFC 7515 §4.1.11) — no audit walk, no trust in the RA. The
profile names which representation it seals; `lei` is the deliberate exception (subject AID + key
thumbprint only — the ACDC is PII and KERI's KEL is the authoritative key history).

## 9. The who, the what, and the FQDN primary anchor

An agent registration (ANS-1) is anchored to exactly **one mandatory FQDN primary anchor**, the
agent's `agentHost`, proven at registration by the [fqdn profile](identity-profiles/fqdn.md)'s
two-axis gate (ACME identifier control + CSR key control). That FQDN is the **what** — it is not a
Verified Identity, is not addressable through the identity API, and is managed only through the
registration lifecycle. FQDN-primacy is a **policy** (`a registration's primary anchor MUST be
fqdn`), not a structural limit; the gate and the identity object are kind-agnostic, so the day
keyless primaries become in-scope the policy relaxes without touching this model.

**Absent-claim treatment (refined).** A registration loaded without explicit anchor metadata is
**FQDN-implicit**: its primary anchor is `agentHost`, proven via the fqdn profile. This refinement
narrows v0.1.0's rule to the *agent's primary anchor only* — Verified Identities are never
implicit; they are explicit, control-proven objects.

**The who survives the what (continuity).** Because a Verified Identity is independent of any
agent and sealed on its own stream, it is the continuity thread across an agent's loss: when an
agent's domain lapses (its registration is revoked), the identity object and its unbroken TL
history survive, and the owner links the *existing* identity to the successor agent — a verifiable
thread (`IDENTITY_VERIFIED → … → IDENTITY_LINKED` across both agents) a counterparty follows to
carry reputation across the domain change. No lifecycle event ever crosses streams: an agent's
revocation emits no identity event, and an identity's revocation emits no agent event; link
effectiveness is computed at read time from both (§8.2).

## 10. Identity profiles

Each identifier **kind** is defined by a separate **identity profile** under
[`identity-profiles/`](identity-profiles/). A profile is where all kind-specific mechanics live;
the core *mechanics* above (the §3 gate and the §4–§9 object / lifecycle / link / API / TL
surfaces) never change when a profile is added, amended, or retired. Adding or retiring a kind is
a bounded ANS-0 amendment touching only the §10.1 registry and the closed `kind` / `proofMethod`
enums it feeds (§10.3).

### 10.1 The profile registry

| Kind | Profile | Requirement | Axes | Seal tier | Status |
| --- | --- | --- | --- | --- | --- |
| `fqdn` (agent primary) | [fqdn](identity-profiles/fqdn.md) | Required | identifier (ACME) + key (CSR) | n/a (cert-bound) | Active |
| `did:web` | [did-web](identity-profiles/did-web.md) | Optional | key only (multi-key) | verbatim verification method | Active |
| `did:key` | [did-key](identity-profiles/did-key.md) | Optional | key only | verbatim verification method (derived Multikey) | Active |
| `lei` | [lei](identity-profiles/lei.md) | Optional | key only (vLEI-validated) | thumbprint-only (AID + key thumbprint) | Postponed |
| `did:plc` | [did-plc](identity-profiles/did-plc.md) | Optional | key only (multi-key) | verbatim verification method | Deferred (sketch) |
| `did:ethr` / `did:pkh` | [did-ethr](identity-profiles/did-ethr.md) | Optional | key only (EIP-712 / ERC-1271) | verbatim verification method | Deferred (sketch) |
| `did:ion` | [did-ion](identity-profiles/did-ion.md) | Optional | key only (multi-key) | verbatim verification method | Deferred (sketch) |
| `dnsid` | [dnsid](identity-profiles/dnsid.md) | Optional | key only (DNS-rooted) | verbatim verification method | Deferred (sketch) |

> `fqdn` is the agent's primary anchor proven on the ANS-1 registration path — it is **not** a
> `/v2/ans/identities` dispatch kind. It sits in this registry only as the archetype the
> proof-of-control gate generalizes; the `(agent primary)` and `n/a (cert-bound)` cells mark it.

**Requirement.** `fqdn` is the one **required** profile — it is the agent's primary anchor (the
what), proven for every agent registration on the ANS-1 path, independent of whether the RA
implements Verified Identities. Every other row is a **who-identity** profile and is **optional**
(§12.2): an RA implementing the optional Verified Identity surface chooses which kinds to support,
including none. Optional refers to *adopting* the kind — once an RA enables a who-profile, that
profile's checks are mandatory (optional to adopt, mandatory in execution).

**Status** is orthogonal to requirement and describes implementation maturity. A profile marked
**Active** is wired, tested, and sealing real proofs. **Postponed** means the flow is the design
of record and de-risked but disabled until its external plumbing is enabled (the kind returns
`IDENTIFIER_KIND_UNSUPPORTED`). **Deferred (sketch)** documents the intended shape only; it ships
when its resolver, tests, and external plumbing are real (per the "404 is the signal" rule — an
unimplemented kind is unregistered, not a placeholder).

### 10.2 What a profile MUST define

Every profile document MUST specify, in this order:

1. **Identifier form and canonicalization**, and **how the kind is selected** — lexical dispatch
   (a prefix/shape the RA recognizes) or explicit-kind registration (for kinds not safely
   lexically distinguishable).
2. **Control proof** — which axes apply and the exact `verify-control` checks, **in order**
   ("passes" = every listed check clean; the seal happens only then).
3. **Key source** — where the authoritative key(s) are resolved/decoded/presented from, and the
   `kid`/key-selection rules.
4. **Seal tier** — verbatim verification method, or thumbprint-only, and exactly what is sealed
   (§8.4).
5. **Freshness and monitoring** — the ANS-5 re-check cadence and the integrity signal.
6. **Lifecycle specifics** — rotation, revocation, re-proof, anything kind-specific.
7. **Outbound-fetch safety** — for fetch-based kinds, the SSRF/egress controls.
8. **Error codes** — the kind's typed failures.
9. **Status and requirement** — Active / Postponed / Deferred, what gates promotion, and whether
   supporting the kind is Required (only `fqdn`) or Optional (every who-identity profile; optional
   to adopt, mandatory in execution once enabled).
10. **Object schemas** — worked request / challenge / seal examples (Active and Postponed profiles).

### 10.3 Adding or changing a kind

A new kind is added by writing a profile document and adding a row to the §10.1 registry table —
an ANS-0 amendment. The core sections (§3–§9) do not change. Generic control failures use the
`IDENTIFIER_*` / `PRICC_*` codes defined here; kind-specific failures use the scheme-prefixed
codes the profile defines (`FQDN_*`, `DID_*`, `LEI_*`). The `PRICC_*` family
(`PRICC_SIGNATURE_INVALID`, `PRICC_TOKEN_EXPIRED`, `PRICC_TOKEN_ALREADY_USED`) names §3.2
proof-of-control failures shared by every key-control profile — distinct from ANS-2's
versioned-issuance PriCC (Private-key Confirmation Challenge).

**Why a closed, spec-governed set rather than an open plugin API.** The kind set is frozen by
specification precisely so verifiers can reason about it: a verifier maps the 4-byte `kid` in a
receipt to the one advertised verification line in O(1), and dispatch is an exhaustive switch over
a known set, not a runtime registry. This is the minimal-abstraction posture — the per-kind logic
is a switch + functions, not a `ControlVerifier` interface introduced before a second real caller
exists; the seam is extracted only when the kinds themselves justify it.

## 11. Cross-identity equivalence

An operator MAY assert that one agent is reachable as the same entity under more than one
identity. ANS handles this in two distinct ways depending on the trust boundary:

- **Within one RA (the common case): identity links.** The owner proves a Verified Identity once
  and links it to the agent(s) it operates (§6). This *supersedes* v0.1.0's model of cross-anchor
  equivalence as separate registrations joined by `EQUIVALENCE_LINK` for the single-RA case: a
  Verified Identity is one owner-level object linked to many agents, not N registrations a
  verifier must reconcile.
- **Across RAs (federated): `EQUIVALENCE_LINK`.** When the registrations live on different RAs,
  the cryptographic co-signature model of ANS-1 §6.4 `EQUIVALENCE_LINK` is **retained unchanged** —
  the inner-event JCS bytes signed by the primary registration's key, the producer envelope
  carrying a co-signature from the equivalent registration's key. That federated, multi-RA case
  is unaffected by this spec and remains a future amendment to admit at the envelope level.

**Uniqueness.** One `(kind, value)` is `VERIFIED` by at most one owner across an RA. Competing
unproven claims race to prove control; the first to prove wins (the loser's verify-time flip
fails `IDENTIFIER_DUPLICATE`). An unproven `PENDING_CONTROL` row cannot squat a value.

**Compromise does not silently cascade.** Revoking one identity does not revoke the agents it was
linked to, nor any other identity. ANS-5 surfaces inconsistencies (an identity revoked while a
linked agent still claims it) as findings.

## 12. Conformance

Conformance is split: a small mandatory core that every RA meets, and the optional Verified
Identity capability, which an RA need not implement at all — but, if it does, must implement
exactly as specified.

### 12.1 Mandatory core

Every ANS-0 conformant RA:

1. Proves the agent's FQDN primary anchor through the proof-of-control gate (§3) — sealing the
   primary anchor only on proven control (the two-axis ACME + CSR form of the
   [fqdn profile](identity-profiles/fqdn.md)), never on resolution alone.
2. Whenever it seals *any* identity attestation — the agent's primary anchor always, a Verified
   Identity only where §12.2 is implemented — seals only after control is proven (§3), never on
   resolution.
3. Emits a typed error (with a documented code) on any failure.

An RA that implements only the mandatory core exposes no `/v2/ans/identities` routes, seals no
`IDENTITY_*` events, and supports no who-identity profile. That is fully conformant.

### 12.2 Optional capability: Verified Identities

An RA **MAY** implement the Verified Identity surface (the who). An RA that does **MUST**:

1. Serve the `IdentityProofInput` signing input itself (§3.2); never require clients to
   canonicalize; check payload-equality before verifying signatures.
2. Support at least one who-identity profile from the §10.1 registry, dispatch by the profile's
   selection rule, and return `IDENTIFIER_KIND_UNSUPPORTED` for kinds it has not enabled.
   *Which* who-profiles to support is the RA's choice; supporting any given kind is optional, but
   the chosen kind's profile checks are then mandatory.
3. Model Verified Identities as owner-scoped objects with the §4 shape and the §5 lifecycle, and
   persist no public key on the row.
4. Honor seal-before-success (§5.1) on every sealing operation.
5. Gate links per §6 (owner + liveness) and seal link batches as one event.
6. Emit the §8.1 event family on the identity ingest lane; compute the §8.2 views with the
   visibility predicate and read-side terminality (§8.3); seal proven keys verbatim (§8.4).

### 12.3 Verifier

A conformant **verifier** reconstructs and checks proofs from sealed events alone (§8.4), and
treats a `REVOKED` identity as revoked regardless of any later stream entry (§8.3).

## 13. Security considerations

- **Proof-of-control is the gate.** Resolution alone proves nothing; the v0.1.0 resolve-then-seal
  model is retired for exactly this reason. An attacker who resolves Google's `did:web` keys
  cannot sign the challenge with Google's private keys, and can never bind any identity to agents
  they do not own (links are owner-gated, §6).
- **Cross-protocol confusion.** The `purpose` domain separator (§3.2) ensures an operator's
  signature for an ANS proof can never be replayed as a VC, DIDComm message, or application
  payload, nor vice versa.
- **Outbound-fetch (SSRF).** Fetch-based profiles (`did:web`, future `did:plc`/`did:ion`) make
  server-side requests to registrant-steered hosts. Every such profile MUST route through one
  hardened fetcher enforcing an egress IP denylist at connect time (RFC 1918, loopback,
  link-local incl. cloud metadata, ULA), per-call IP pinning against DNS rebind, full WebPKI, a
  bounded timeout and response size, and error details that never echo resolved IPs or redirect
  chains (no SSRF oracle). The profile specifies the particulars.
- **Revocation terminality.** Read-side status derives REVOKED from any revocation leaf (§8.3),
  so a racing or replayed later event cannot resurrect a revoked identity on the public surface.
- **Stolen-credential reputation transfer.** The one risk an unsigned link leaves open (§6) is
  detected via the sealed, visible `IDENTITY_LINKED` event and ANS-5 monitoring; deployments MAY
  require step-up auth on link/unlink/revoke.
- **Key transience.** Proven keys are never persisted as live row state (§4); they live in the
  sealed events, recomputable and freshness-bounded.
- **Bounded divergence.** Seal-before-success (§5.1) guarantees the RA row is never ahead of the
  log; any divergence is bounded to an in-flight operation window and resolved by the conditional
  commits and read-side terminality.

## 14. References

- Identity profiles: [`identity-profiles/`](identity-profiles/) (fqdn, did-web, did-key, lei,
  and deferred sketches).
- [ANS-1: Registration & Lifecycle](ans-1-registration.md) — the agent (the what), the event set,
  `EQUIVALENCE_LINK`.
- [ANS-4: Transparency](ans-4-transparency.md) — the single Merkle log, identity ingest and read
  surface, SCITT receipts.
- [ANS-5: Integrity Monitoring](ans-5-integrity-monitoring.md) — per-identity monitoring.
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/): DID syntax, verification relationships.
- [ISO 17442](https://www.iso.org/standard/78829.html): LEI structure and checksum.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JSON Canonicalization Scheme (JCS).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555): ACME.
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JSON Web Signature (JWS).
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517): JSON Web Key (JWK).
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119): Requirement keywords.
