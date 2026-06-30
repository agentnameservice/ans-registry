# Identity profile: `did:web`

Status: DRAFT v1.0
Profile: did:web
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority

A `did:web` identity proves control of a web-hosted DID by demonstrating possession of one or
more keys the DID document lists under `assertionMethod`. Key-control axis only
([ANS-0 §3.1](../ans-0-identity-anchor.md#31-the-two-axes)); no location challenge.

## 1. Identifier form, canonicalization, selection

- **Form**: `did:web:<host>[:<path-segment>…]` (W3C did:web). The host is a DNS name; optional
  colon-separated path segments map to URL path segments.
- **Selection**: **lexical** — the `did:web:` prefix.
- **Canonicalization** (v1, each violation → `DID_BAD_FORMAT`):
  - host lowercased; path segments preserved verbatim;
  - **no port** — the did:web port encoding `%3A` is rejected (fetches are pinned to 443);
  - no userinfo (`@`);
  - no `/` (did:web path segments are colon-separated *in the DID*);
  - **no percent-encoding at all** — v1 keeps the grammar strict so the resolution URL is
    byte-derivable from the DID;
  - host is a plausible DNS name (labels of letters/digits/hyphen, no leading/trailing hyphen,
    ≤63 chars/label, ≤253 total);
  - no empty path segment, and no `.`/`..`/control-character segment (dot segments would re-path
    the resolution URL; the same parsed segments feed both the resolution URL and the SSRF dialer
    check, so the rejection happens exactly once, at canonicalization).
- **Resolution URL** (pure function of the canonical DID):
  - `did:web:example.com` → `https://example.com/.well-known/did.json`
  - `did:web:example.com:user:al` → `https://example.com/user/al/did.json`

**Any host.** The DID host need not match any agent host. Control of a DID *is* possession of its
listed keys (DID Core); a who-identity's `did.json` legitimately lives at the operator's identity
domain, not at an agent's host. (The rev-3 host-match rule and the v0.1.0
`.well-known/ans-did-web-challenge.txt` location flow are **both removed** — ANS-0 §3.3.)

## 2. Control proof — key control, multi-key

The proof is the shared JWS-scheme machinery (ANS-0 §3.2): one compact JWS per claimed key, each
over the served `signingInput`, each naming its key by `kid`. `verify-control` checks, **in
order** — every check clean before any seal:

1. **Envelope** (`signedProofs[]`): present and non-empty; within the per-call batch bound; each
   entry a well-formed compact JWS.
2. **Payload equality** (before any signature work): each JWS's payload segment **equals** the
   served `signingInput` verbatim (`PRICC_SIGNATURE_INVALID` on mismatch — clients never
   canonicalize).
3. **`kid` present** on each proof (`DID_VERIFICATION_METHOD_INVALID` if missing) and **unique**
   across the batch (`IDENTIFIER_PROOF_INVALID` on a duplicate).
4. **Authoritative resolution**: the RA re-fetches the DID document at verify time through the
   hardened fetcher (§7) — the verify-time document is the key source, never a request-supplied
   one — and confirms `document.id == did` (`DID_DOCUMENT_ID_MISMATCH`).
5. **Per-`kid` method selection** (each proof):
   - `kid` is a fragment of *this* DID (`startsWith(did + "#")`), else
     `DID_VERIFICATION_METHOD_INVALID`;
   - `kid` resolves to an `assertionMethod` of the document, else
     `DID_VERIFICATION_METHOD_INVALID` (no cross-controller indirection: a method whose
     `controller` is set and not equal to the DID is rejected);
   - the method carries usable key material (`publicKeyJwk` or `publicKeyMultibase`) that parses
     under a supported type, else `DID_VERIFICATION_METHOD_INVALID`.
6. **Signature**: the JWS verifies against the resolved key with `alg` **pinned to the key type**
   (alg-confusion defense: ES256 ↔ P-256, EdDSA ↔ Ed25519, RS256 ↔ RSA), and unrecognized
   critical (`crit`) headers are rejected. Failure → `PRICC_SIGNATURE_INVALID`.

The RA verifies **every** submitted proof; one failure fails the whole call closed (atomic — no
partial seal). The shared nonce is consumed once, inside the success transaction (ANS-0 §3.2).

## 3. Key source and selection

Keys are the DID document's `assertionMethod` set, resolved authoritatively by the RA at both
challenge time (advisory, to enumerate `kid`s) and verify time (binding). `assertionMethod`
string entries dereference into `verificationMethod`; inline objects are used directly. The
client selects keys by naming each `kid` in its JWS header; the signature is always checked
against the *resolved* method for that `kid`, never a request-supplied key.

The advisory challenge fetch happens before any proof exists, so it is rate-limited per the RA's
identity rate-limit policy.

## 4. Seal tier — verbatim verification method

Each proven key seals as the document's verification-method object **exactly as published** —
`id`, `type`, `controller`, and the key material in the source representation (`publicKeyJwk`, or
`publicKeyMultibase` for Multikey documents) — copied member-for-member, alongside the
registrant's compact JWS (`IDENTITY_VERIFIED`/`IDENTITY_UPDATED` carry the proven set). No
thumbprints, no re-encodings (ANS-0 §8.4). A third-party verifier checks the operator's signature
from the badge alone.

## 5. Freshness and monitoring

ANS-5 re-resolves the DID document per its identity-monitoring cadence and compares the live
`assertionMethod` key set against the sealed `keys[]`. Drift (a sealed key no longer published,
or the document unreachable) is the integrity signal — surfaced as a finding, never an automatic
revocation.

## 6. Lifecycle specifics

- **Rotation** (`PUT` + `verify-control`): prove possession of the new key set; one
  `IDENTITY_UPDATED` replaces the proven keys, regardless of linked-agent count (zero write
  fan-out, ANS-0 §8.2).
- **Revocation**: `POST …/revoke`; read-side terminality keeps it revoked (ANS-0 §8.3).
- **Re-proof after nonce expiry**: idempotent re-add (ANS-0 §5).

## 7. Outbound-fetch safety (SSRF)

The fetch target is registrant-steered, so SSRF is a first-class control. The hardened fetcher
([ANS-0 §13](../ans-0-identity-anchor.md#13-security-considerations)) enforces, on every fetch:

1. An **egress IP denylist at connect time, post-DNS**: loopback, RFC 1918 / ULA private ranges,
   link-local (which covers cloud-metadata addresses), multicast, and unspecified addresses are
   rejected at the dialer — never by hostname-string inspection.
2. **Per-host IP pinning** for the duration of one resolve call: the first connection fixes the
   IP, so a DNS rebind between the initial fetch and a redirect hop cannot slip an internal target
   past check 1.
3. **Full WebPKI** (chain to a trusted root + hostname verification), TLS 1.2+.
4. **Bounds**: hard timeout (default 5 s), response-size cap (default 1 MiB), ≤5 redirects, each
   redirect constrained to `https` and to the **origin's registrable domain** (eTLD+1) — a
   redirect leaving the domain is `DID_REDIRECT_DOMAIN_MISMATCH`; leaving `https` or exceeding the
   hop count is `DID_RESOLUTION_FAILED`. Connections are pinned to port 443.
5. **No SSRF oracle**: wire errors never echo resolved IPs, ports, or redirect chains; the
   diagnosable category goes only to the server-side log.

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `DID_BAD_FORMAT` | malformed/unsupported did:web syntax (port, userinfo, `/`, `%`, bad host/segment) |
| `DID_RESOLUTION_FAILED` | document unreachable, non-200, oversize, unparseable, redirect-limit/scheme |
| `DID_DOCUMENT_ID_MISMATCH` | resolved `document.id` ≠ requested DID |
| `DID_REDIRECT_DOMAIN_MISMATCH` | a redirect left the DID's registrable domain |
| `DID_VERIFICATION_METHOD_INVALID` | `kid` missing / not a fragment of the DID / not an assertionMethod / cross-controller / no usable key material |
| `IDENTIFIER_PROOF_INVALID` | proof envelope problem (empty, over-batch, malformed JWS, duplicate `kid`) |
| `PRICC_SIGNATURE_INVALID` | payload ≠ signingInput, or signature does not verify against the resolved key |

(Generic identity codes — `IDENTIFIER_KIND_UNSUPPORTED`, `IDENTIFIER_DUPLICATE`,
`IDENTIFIER_CHALLENGE_EXPIRED`, `TL_UNAVAILABLE`, `VERIFICATION_IN_FLIGHT`, … — are defined in
ANS-0 / the API spec.)

## 9. Status and requirement

**Requirement: Optional.** A who-identity profile ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)):
supporting `did:web` is optional, but an RA that enables it MUST perform every check in §2.

**Status: Active.** Wired (noop resolver for quickstart, hardened web resolver for production),
tested, sealing real multi-key proofs.

## 10. Object schemas (worked example)

Concrete shapes for conformance fixtures. The sealed event validates against the machine schema
[`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json); the request/response
shapes are in [`api/api-spec-v2.yaml`](../../api/api-spec-v2.yaml).

**Register / rotate** — `POST` (or `PUT`) `/v2/ans/identities` with the bare identifier:

```json
{ "value": "did:web:identity.acme-corp.com" }
```

**Challenge round** — the `202` response (one entry per `assertionMethod` key the resolver could
enumerate; a single unkeyed entry otherwise). Every entry shares the one nonce and signingInput:

```json
{
  "identityId": "0193f0c5-7b2e-7a41-9c3d-2f9a1e4b6d80",
  "kind": "did:web",
  "value": "did:web:identity.acme-corp.com",
  "status": "PENDING_CONTROL",
  "nonce": "<base64url 32-byte single-use nonce>",
  "expiresAt": "2026-06-23T19:30:00Z",
  "challenges": [
    {
      "kid": "did:web:identity.acme-corp.com#key-1",
      "signingInput": "<base64url(JCS({identifier, identityId, nonce, purpose, raId, scheme}))>"
    }
  ]
}
```

**verify-control** — `POST …/verify-control`, one compact JWS per proven key (header `alg`+`kid`,
payload segment **equal to** the served `signingInput`):

```json
{ "signedProofs": [ "<compact JWS over signingInput; header {\"alg\":\"ES256\",\"kid\":\"did:web:identity.acme-corp.com#key-1\"}>" ] }
```

**Sealed proven key** — each `keys[]` entry of the resulting `IDENTITY_VERIFIED` event (the
verification method quoted verbatim, §8.4 + §4; full envelope in
[ANS-0 §8.1](../ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest)):

```json
{
  "verificationMethod": {
    "id": "did:web:identity.acme-corp.com#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:identity.acme-corp.com",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "f83OJ3D2…", "y": "x_FEzRu9…" }
  },
  "signedProof": "<the compact JWS submitted above>"
}
```
