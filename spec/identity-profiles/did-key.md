# Identity profile: `did:key`

Status: DRAFT v1.0
Profile: did:key
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority

A `did:key` identity proves control of a key that **is** the identifier — the public key is
decoded directly from the DID string, with zero I/O. Key-control axis only; the simplest instance
of the gate, and the reference shape for any future kind whose key material is self-contained.

## 1. Identifier form, canonicalization, selection

- **Form**: `did:key:<multibase-multicodec public key>` (W3C did:key).
- **Selection**: **lexical** — the `did:key:` prefix. The method-specific id must be non-empty
  (`did:key:` alone → `DID_BAD_FORMAT`).
- **Canonicalization**: the value is taken verbatim (the multibase encoding is already canonical);
  ANS does not re-encode it.

## 2. Control proof — key control, single key

Shared JWS-scheme machinery (ANS-0 §3.2), single key. `verify-control` checks, **in order**:

1. **Envelope**: `signedProofs[]` present; within the batch bound; each a compact JWS.
2. **Payload equality** (before signature work): the JWS payload equals the served `signingInput`
   verbatim (`PRICC_SIGNATURE_INVALID` on mismatch).
3. **`kid` present** (`DID_VERIFICATION_METHOD_INVALID` if missing) and unique.
4. **Decode**: the public key and its single legal `kid` (`{did}#{method-specific-id}`) are
   decoded from the DID string itself — no network (`DID_BAD_FORMAT` if the multibase/multicodec
   is unparseable).
5. **`kid` match**: the proof's `kid` equals the decoded `kid`, else
   `DID_VERIFICATION_METHOD_INVALID`.
6. **Signature**: the JWS verifies against the decoded key with `alg` pinned to the key type, and
   unrecognized `crit` headers are rejected. Failure → `PRICC_SIGNATURE_INVALID`.

## 3. Key source and selection

The one authoritative key is decoded from the DID. There is exactly one legal `kid`; the client
names it, and the signature is checked against the decoded key. A `did:key` identity is
inherently single-key (multi-key submission is not applicable).

## 4. Seal tier — verbatim verification method

The sealed verification method is the did:key method's derived **Multikey** entry, built
deterministically from the identifier:

```json
{
  "id": "<did>#<method-specific-id>",
  "type": "Multikey",
  "controller": "<did>",
  "publicKeyMultibase": "<method-specific-id>"
}
```

The key material (`publicKeyMultibase`) is the method-specific id quoted verbatim from the
identifier — nothing derived or re-encoded beyond the method's own deterministic mapping
(ANS-0 §8.4). Sealed alongside the registrant's compact JWS.

## 5. Freshness and monitoring

The key is the identifier, so it cannot rotate under a stable identifier and cannot "drift" — a
`did:key` never changes its published key. ANS-5 monitoring is therefore trivial: the only state
transition is revocation. There is no document to re-resolve.

## 6. Lifecycle specifics

- **Rotation**: a new key is a *new identifier* (`did:key`), hence a new identity object — not a
  `PUT` rotation under the same value. (`PUT` to the same `did:key` value is a no-op re-proof.)
- **Revocation**: `POST …/revoke`; read-side terminality applies (ANS-0 §8.3).

## 7. Outbound-fetch safety

None — `did:key` performs no network I/O at any phase. There is no SSRF surface.

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `DID_BAD_FORMAT` | empty or unparseable multibase/multicodec key |
| `DID_VERIFICATION_METHOD_INVALID` | `kid` missing or not the single decoded verification-method id |
| `IDENTIFIER_PROOF_INVALID` | proof envelope problem (empty, over-batch, malformed JWS, duplicate `kid`) |
| `PRICC_SIGNATURE_INVALID` | payload ≠ signingInput, or signature does not verify against the decoded key |

## 9. Status and requirement

**Requirement: Optional.** A who-identity profile ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)):
optional to support; mandatory in execution once enabled.

**Status: Active.** Wired, tested, sealing real proofs with zero I/O.

## 10. Object schemas (worked example)

Concrete shapes for conformance fixtures. The sealed event validates against the machine schema
[`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json); request/response
shapes are in [`api/api-spec-v2.yaml`](../../api/api-spec-v2.yaml). `did:key` is single-key, so
the challenge round names exactly one `kid` and `verify-control` carries exactly one proof.

**Register** — `POST /v2/ans/identities`:

```json
{ "value": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }
```

**Challenge round** — `202` (one entry; the `kid` is the DID's single derived verification method):

```json
{
  "identityId": "0193f0c5-7b2e-7a41-9c3d-aaaaaaaaaaaa",
  "kind": "did:key",
  "value": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "status": "PENDING_CONTROL",
  "nonce": "<base64url 32-byte single-use nonce>",
  "expiresAt": "2026-06-23T19:30:00Z",
  "challenges": [
    {
      "kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "signingInput": "<base64url(JCS({identifier, identityId, nonce, purpose, raId, scheme}))>"
    }
  ]
}
```

**verify-control** — `POST …/verify-control`, the single compact JWS (header `alg: EdDSA` for an
Ed25519 `did:key`):

```json
{ "signedProofs": [ "<compact JWS over signingInput; header {\"alg\":\"EdDSA\",\"kid\":\"did:key:z6Mkh…#z6Mkh…\"}>" ] }
```

**Sealed proven key** — the `keys[]` entry of the `IDENTITY_VERIFIED` event: the deterministically
derived Multikey method (§4), with `publicKeyMultibase` quoted verbatim from the identifier:

```json
{
  "verificationMethod": {
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "type": "Multikey",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  },
  "signedProof": "<the compact JWS submitted above>"
}
```
