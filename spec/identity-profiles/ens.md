# Identity profile: `ens`

Status: DRAFT v1.0
Profile: ens (Ethereum Name Service names)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-07-27
Audience: implementers building an ANS-conformant Registration Authority

An `ens` identity binds an ENS name to the Ethereum account that currently owns it. The
authoritative "key" is not published in a document; it is the **owner account** resolved from the
ENS registry hierarchy on-chain, and control is proven by an Ethereum account signature from that
owner (EIP-712 for EOAs, ERC-1271 for contract accounts such as Safes). Key-control axis only
([ANS-0 §3.1](../ans-0-identity-anchor.md#31-the-two-axes)); no location challenge.

Like `lei`, this kind is **not** JOSE/JWS: Ethereum signatures are secp256k1 over a Keccak-256
digest with their own message-framing standards (the `did:ethr`/`did:pkh` sketch anticipates the
same proof shape). The `IdentityProofInput` and `purpose` domain separation are unchanged; only
the signing/verification codec differs. An ENS name differs from a raw Ethereum account identity
in one important way: the name-to-account binding is itself mutable on-chain state — names
transfer and expire — which is why §5 monitoring carries more signal here than for any `did:*`
kind.

## 1. Identifier form, canonicalization, selection

- **Form**: an ENS name under `.eth` with at least two labels (e.g. `acme-corp.eth`,
  `agents.acme-corp.eth`).
- **Selection**: **lexical** — a dot-separated name whose final label is `eth`. (Other TLDs
  reachable through the ENS root are not lexically distinguishable from plain FQDNs; admitting
  them is a future amendment of this profile's selection rule, not a change to the gate.)
- **Canonicalization** (each violation → `ENS_BAD_FORMAT`):
  - the name normalizes under [ENSIP-15](https://docs.ens.domains/ensip/15) (ENS Name
    Normalization); the canonical value is the normalized name;
  - at least two labels; no empty labels.
- **Scope rule (mechanical)**: the name MUST resolve to a non-zero owner through the on-chain
  registry walk (§2). Names whose ENS presence is resolver-only — for example DNS domains
  resolved through ENS via DNSSEC-gated resolution — have **no on-chain owner**: their control
  plane is the DNS zone, which ANS already proves through ACME (the
  [fqdn profile](fqdn.md)), not this profile.
- **Derived encodings** (DNS wire format for contract calls, labelhashes) are computed at call
  time and never stored or sealed.

## 2. Control proof — key control, owner signature

The proof demonstrates possession of the key of the name's **current owner account**, bound to
this object and operation through the shared `IdentityProofInput` (ANS-0 §3.2). `verify-control`
checks, **in order** — every check clean before any seal:

1. **Envelope**: exactly one Ethereum-signature proof is present (this kind is single-key — the
   owner; there is no multi-key submission). A malformed envelope →
   `IDENTIFIER_PROOF_INVALID`.
2. **Payload equality** (before any signature work): the signed content **equals** the served
   `signingInput` verbatim — for EIP-712, the `signingInput` field of the typed struct below; for
   EIP-191, the signed message string. Mismatch → `PRICC_SIGNATURE_INVALID`. Clients never
   canonicalize.
3. **Authoritative owner resolution** (verify time): the RA resolves the name's owner by the
   top-down registry walk — from the configured ENS root registry, descend one label at a time
   via `IRegistry.getSubregistry(label)` to the name's parent registry, confirm it supports
   `IOwnedRegistry` (ERC-165), and read `findOwner(label)`. `UniversalResolverV2.findOwner(name)`
   (DNS-encoded name) implements exactly this walk and is the RECOMMENDED entry point. The walk
   starts from the deployment-configured root, so no registrant-supplied registry or resolver
   address is ever consulted, and a registry mounted outside the canonical hierarchy can never
   answer. A zero owner — never registered, expired, or resolver-only ENS presence —
   → `ENS_NAME_UNOWNED` (the RA MAY refine to `ENS_NAME_EXPIRED` by reading the parent
   registry's `getExpiry`). Advisory resolution at challenge time seeds the challenge entry;
   the verify-time resolution is binding.
4. **Signature verification** against the resolved owner:
   - **EOA**: recover the signer per **EIP-712** (preferred) or EIP-191 and require it to equal
     the resolved owner.
   - **Contract account**: **ERC-1271** `isValidSignature(hash, signature)` via `eth_call`
     against the owner contract — this is what lets multisig and smart-account owners prove
     control.
   - An ERC-6492-style universal validator (`isValidSig(signer, hash, signature)`) covers both
     paths in one call and is the RECOMMENDED verification primitive; the ENS contracts
     repository vendors this interface (`IUniversalSignatureValidator`).
   - The signer MUST be the owner itself. Holders of EAC roles on the name and ERC-1155-approved
     operators are **delegates**, not the owner, and are NOT acceptable signers — a
     records-management grant must never become an identity-grade credential. Failure →
     `ENS_SIGNATURE_INVALID`.
5. **Nonce**: unexpired, unconsumed, consumed inside the success transaction (ANS-0 §3.2 token
   discipline).

**EIP-712 binding.** The typed-data encoding is a thin wrapper that carries the served signing
input as its only field, so payload equality (check 2) stays a byte comparison:

```text
EIP712Domain { name: "ans:identity-proof", version: "1", chainId: <configured chain> }
IdentityProof { string signingInput }
```

The wallet-visible `EIP712Domain` adds a second, human-inspectable domain separation on top of
the `purpose` field inside `signingInput`; `chainId` binds the proof to the deployment's
configured network (one deployment = one chain, mirroring `raId`).

## 3. Key source and selection

The one authoritative key-holder is the name's **current owner account**, resolved from the ENS
registry hierarchy at verify time (§2 check 3) — never presented in the request. This kind is
single-key; there is no JWS `kid` selector (the one signer is fully determined by the
identifier, as with `lei`). The challenge entry advisorily names the resolved owner as a CAIP-10
account (`eip155:<chain>:<address>`) so the client can confirm which account must sign.

## 4. Seal tier — derived account method (CAIP-10)

The sealed verification method is **derived deterministically from on-chain state at proof
time** (the same posture as `did:key`'s derived Multikey): the owner account as a CAIP-10
`blockchainAccountId`, alongside the submitted signature.

```json
{
  "id": "ens:acme-corp.eth#owner",
  "type": "EcdsaSecp256k1RecoveryMethod2020",
  "controller": "ens:acme-corp.eth",
  "blockchainAccountId": "eip155:1:0x1234…abcd"
}
```

Registry state — records, expiry, roles, resolver configuration — is **referenced, never
copied** into the seal: the ENS registry is the authoritative, externally-resolvable source, and
a sealed copy would be one more thing that can drift from it (the same argument the
[lei profile](lei.md) makes for KERI's KEL). Verifiability from the badge alone differs by
account type: an **EOA** proof re-verifies offline by signature recovery against the sealed
`blockchainAccountId`; a **contract-account** proof (ERC-1271) verifies against chain state as
of proof time — the seal attests the RA's verification, and a third party re-checks it with one
`eth_call`. For contract accounts the `type` member is nominal; the operative verification path
is ERC-1271.

## 5. Freshness and monitoring

ANS-5 monitors an `ens` identity as a first-class object on its own per-identity cadence
([ANS-5 §4.3](../ans-5-integrity-monitoring.md#43-verified-identity-monitoring)); results
project to every linked agent with zero write fan-out. Because ENS token IDs are mutable
(regenerated on role changes — `TokenRegenerated`), monitors MUST key on the **name** and
re-read state, never track token IDs. Signals, from one state re-read per cycle:

- **Owner change**: re-run the §2 owner resolution; sealed account ≠ current owner is the
  integrity signal. ENS names are transferable assets, so a transfer is a
  reputation-continuity event: surfaced as a finding, never an automatic revocation; the new
  owner re-proves through rotation (§6). Event hints for push-based detection:
  `LabelRegistered`, `LabelUnregistered`, ERC-1155 `TransferSingle`.
- **Expiry**: read `getExpiry` on the parent registry. Approaching expiry is an advisory
  finding. After expiry the owner resolves to zero (ownership is time-bounded), and after the
  `.eth` registrar's grace period (28 days) the name is **re-registerable by anyone** — a
  re-registration under a new owner MUST NOT inherit the identity (re-registration mints a new
  identity object; read-side terminality, ANS-0 §8.3). During the grace window any account can
  renew (`ETHRegistrar.renew`), so a lapsed-but-renewed name resumes cleanly. Event hint:
  `ExpiryUpdated`.
- **Hierarchy integrity**: `SubregistryUpdated` / `ResolverUpdated` / `ParentUpdated` along the
  name's chain. For names deeper than second-level, an ancestor registry in which dangerous
  roles remain granted on `ROOT_RESOURCE` can replace or unregister the subtree; the owner walk
  detects the effect (the resolved owner changes or vanishes), and deployments MAY additionally
  verify ancestor emancipation (`roleCount(ROOT_RESOURCE)` shows no assignees for the dangerous
  roles) as policy.
- **Optional cross-attestation**: an [ENSIP-26](https://docs.ens.domains/ensip/26)
  `agent-endpoint[ans]` text record on the name, naming a linked agent's ANSName — a public,
  name-side declaration that complements the sealed link (the ANS-5 principal-binding check
  set includes it).

## 6. Lifecycle specifics

- **Rotation = ownership change.** The identifier's value survives an owner change, so this is
  a value-stable-rotation kind: after a name transfer, the new owner re-proves via `PUT` +
  `verify-control`, sealing `IDENTITY_UPDATED`; the audit stream preserves the owner succession.
  An owner change **without** re-proof is surfaced by ANS-5 as drift and does not auto-revoke
  (the lei posture for credential expiry); consumers see the finding and act per policy.
- **Name expiry** is likewise surfaced by ANS-5 and does not auto-revoke the identity object;
  revocation is the owner's (or RA policy's) explicit act.
- **Revocation**: `POST …/revoke`; read-side terminality keeps it revoked (ANS-0 §8.3).
- **Re-proof after nonce expiry**: idempotent re-add (ANS-0 §5).

## 7. Outbound-fetch safety

The verification I/O is **chain reads only**: the registry walk (pure `view` calls — the
navigation path performs no CCIP-Read) and, for contract accounts, one ERC-1271 `eth_call`. All
reads go through **configured, pinned JSON-RPC endpoints** — never registrant-supplied URLs —
with bounded call budgets, and RPC failures surface as a generic retryable error
(`ENS_CHAIN_UNAVAILABLE`) that never echoes endpoint details (no oracle). There is no
registrant-steered HTTP fetch on the control path. A deployment that additionally reads ENS
*records* (the §5 ENSIP-26 cross-check) may traverse wildcard/offchain resolution (CCIP-Read),
which **is** registrant-steered and MUST be hardened exactly like the did:web fetcher
(ANS-0 §13).

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `ENS_BAD_FORMAT` | not ENSIP-15-normalizable, fewer than two labels, or not a `.eth` name |
| `ENS_NAME_UNOWNED` | the registry walk resolves no current owner (never registered, expired, or resolver-only ENS presence) |
| `ENS_NAME_EXPIRED` | refinement of `ENS_NAME_UNOWNED` when the parent registry's expiry shows a lapsed registration |
| `ENS_SIGNATURE_INVALID` | signature fails validation against the resolved owner, or the signer is not the owner (role holders and operators are rejected) |
| `ENS_CHAIN_UNAVAILABLE` | chain read failed (retryable; no endpoint detail echoed) |

(Generic identity codes — `IDENTIFIER_KIND_UNSUPPORTED`, `IDENTIFIER_DUPLICATE`,
`IDENTIFIER_CHALLENGE_EXPIRED`, `IDENTIFIER_PROOF_INVALID`, `PRICC_SIGNATURE_INVALID`,
`TL_UNAVAILABLE`, `VERIFICATION_IN_FLIGHT`, … — are defined in ANS-0 / the API spec.)

## 9. Status and requirement

**Requirement: Optional.** A who-identity profile
([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)):
supporting `ens` is optional, but an RA that enables it MUST perform every check in §2.

**Status: Postponed (design of record).** The flow above is settled and its external surface is
live (the ENS registry hierarchy, `UniversalResolverV2.findOwner`, and the universal
signature-validation interface are deployed); the kind is disabled until its plumbing is wired,
returning `IDENTIFIER_KIND_UNSUPPORTED`. Promotion to Active requires: a pinned-RPC registry
navigator behind the port, an Ethereum-signature verifier (EIP-712 + EIP-191 + ERC-1271;
ERC-6492-style universal validation), an ENSIP-15 normalizer, tests against live chain reads
(the `scripts/poc/ethid` proof-of-concept established live-Ethereum feasibility for the
signature path), and the wire shapes below fixed in `api/api-spec-v2.yaml`. The Ethereum
signature verifier is shared with the deferred [`did:ethr`/`did:pkh`](did-ethr.md) kinds —
promoting either substantially promotes both.

## 10. Object schemas (postponed shapes)

`ens` is **Postponed**, so the shapes below are the design of record, **not** frozen wire. The
implemented `VerifyControlRequest` is JWS-only and the machine schema
[`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json) models the
JWS-scheme verbatim-VM seal (`publicKeyJwk`/`publicKeyMultibase`); the Ethereum-signature
request and the CAIP-10 account seal below are a **future amendment**, recorded here so the
contract is settled before the kind ships (the lei precedent).

**Register** — `POST /v2/ans/identities` with the bare identifier:

```json
{ "value": "acme-corp.eth" }
```

**Challenge round** — the `202` response (single entry; the advisory `kid` names the resolved
owner as a CAIP-10 account):

```json
{
  "identityId": "0193f0c5-7b2e-7a41-9c3d-bbbbbbbbbbbb",
  "kind": "ens",
  "value": "acme-corp.eth",
  "status": "PENDING_CONTROL",
  "nonce": "<base64url 32-byte single-use nonce>",
  "expiresAt": "2026-07-27T19:30:00Z",
  "challenges": [
    {
      "kid": "eip155:1:0x1234…abcd",
      "signingInput": "<base64url(JCS({identifier, identityId, nonce, purpose, raId, scheme}))>"
    }
  ]
}
```

**verify-control (postponed, non-JOSE)** — one Ethereum signature over the served signing input
from the name's current owner (`encoding` names the framing; contract-account signatures use the
same envelope and are validated via ERC-1271):

```json
{ "ethSignature": { "encoding": "eip712", "signature": "0x<65-byte signature hex>" } }
```

**Sealed proven key (postponed)** — the proof event records the derived CAIP-10 account method
(§4) plus the submitted signature:

```json
{
  "verificationMethod": {
    "id": "ens:acme-corp.eth#owner",
    "type": "EcdsaSecp256k1RecoveryMethod2020",
    "controller": "ens:acme-corp.eth",
    "blockchainAccountId": "eip155:1:0x1234…abcd"
  },
  "signedProof": "0x<65-byte signature hex>",
  "proofEncoding": "eip712"
}
```
