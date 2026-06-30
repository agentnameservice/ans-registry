# Identity profile: `lei`

Status: DRAFT v1.0
Profile: lei (Legal Entity Identifier, via vLEI)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority

An `lei` identity binds a legal entity's ISO 17442 LEI to a key the entity controls, validated
through the GLEIF **vLEI** credential ecosystem (KERI/ACDC). Key-control axis only — but the
"key" is established by a verifiable credential chain, not by resolving a document. This profile
is **Postponed**: the design below is the record, de-risked, but the kind is disabled until its
external plumbing (a vLEI verifier) is enabled, at which point the kind returns
`IDENTIFIER_KIND_UNSUPPORTED`.

## 1. Identifier form, canonicalization, selection

- **Form**: a 20-character ISO 17442 LEI (18 alphanumerics + 2 mod-97 check digits), e.g.
  `5493001KJTIIGC8Y1R12`.
- **Selection**: **lexical** — exactly 20 alphanumeric characters. (This is shape-only dispatch;
  the mod-97 check digit and GLEIF status are validated by the control verifier, not by
  dispatch.)
- **Canonicalization**: uppercase.

## 2. Control proof — key control via vLEI

The LEI itself is public data; possession of it proves nothing. Control is a **legal-entity vLEI
credential chain** terminating in a subject Authentic Chained Data Container (ACDC) whose issuee
is an entity Autonomous Identifier (AID), plus a possession signature from that AID's key.
`verify-control` checks, **in order** (executed by the `port.LEIControlVerifier` seam — the RA
does not re-implement KERI):

1. **Lexical + checksum**: 20 alphanumerics and a valid ISO 17442 mod-97 check digit, else
   `LEI_BAD_FORMAT`.
2. **GLEIF status precondition**: the LEI is ISSUED/active in the GLEIF registry, else
   `LEI_NOT_ACTIVE`.
3. **Credential chain (presented once, at register)**: the full CESR chain — GLEIF root → QVI →
   Legal Entity vLEI → the subject ACDC — verifies end to end (each ACDC's issuer signature and
   KEL anchoring check out), and the subject ACDC's `LEI` attribute equals the canonical LEI, else
   `LEI_CREDENTIAL_INVALID`. The subject **AID** and its current signing key are extracted from
   the verified chain and **pinned** to the identity row.
4. **Possession (every proof)**: a signature over the served signing input from the pinned subject
   AID's current key, validated against the AID's KEL (key state at proof time), else
   `LEI_SIGNATURE_INVALID`.

Because the chain is presented once and the repeatable proof is the AID-key possession, rotation
and re-proof do not re-transmit PII (§4).

## 3. Key source and selection

The authoritative key is the subject AID's current signing key, established by the verified vLEI
chain and tracked through the AID's KEL. There is no JWS `kid` selector; the signed message is the
decoded CESR/KERI signature material, not a compact JWS (the one non-JOSE scheme — ANS-0 §3.2,
"for non-JOSE schemes the signed message is the decoded bytes").

## 4. Seal tier — thumbprint-only

`lei` is the deliberate exception to verbatim sealing (ANS-0 §8.4). The seal records the
**subject AID + a key thumbprint** and the proof — **not** the ACDC and **not** the KEL:

- the ACDC carries entity PII (legal name, registration data) that MUST NOT be written to an
  append-only public log;
- KERI's **KEL is the authoritative, externally-resolvable key history** — copying it into the
  seal would create a second, drift-prone copy.

A verifier resolves the live KEL for the sealed AID to obtain key state; the seal binds *which*
entity AID was proven, not a frozen key blob.

## 5. Freshness and monitoring

ANS-5 re-checks GLEIF status and the AID's KEL key state per its cadence; a revoked vLEI
credential, a lapsed GLEIF status, or a KEL rotation that abandons the pinned key is the integrity
signal.

## 6. Lifecycle specifics

- **Rotation**: a KEL key rotation is followed by re-proving possession with the new current key
  (`PUT` + `verify-control`); the pinned AID is stable across rotations.
- **Revocation**: `POST …/revoke`; read-side terminality applies.
- **Credential expiry/revocation**: surfaced by ANS-5; does not auto-revoke the ANS identity.

## 7. Outbound-fetch safety

vLEI verification and KEL/GLEIF resolution are performed by the `port.LEIControlVerifier`
implementation. Any network resolution it performs (GLEIF API, KERI witnesses) MUST apply the same
egress-hardening posture as the did:web fetcher (ANS-0 §13) — denylist, pinning, bounded I/O — and
MUST NOT become an SSRF oracle.

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `LEI_BAD_FORMAT` | not 20 alphanumerics / failed mod-97 check digit |
| `LEI_NOT_ACTIVE` | LEI not ISSUED/active at GLEIF |
| `LEI_CREDENTIAL_INVALID` | vLEI chain failed to verify, or subject ACDC `LEI` ≠ canonical LEI |
| `LEI_SIGNATURE_INVALID` | possession signature failed against the pinned AID's KEL key state |
| `IDENTIFIER_KIND_UNSUPPORTED` | returned while the profile is Postponed (no verifier enabled) |

## 9. Status and requirement

**Requirement: Optional.** A who-identity profile ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)):
optional to support; mandatory in execution once enabled.

**Status: Postponed (de-risked).** The flow is the design of record; the `port.LEIControlVerifier` seam is
defined; the kind is disabled until a vLEI verifier is wired and tested. Promotion to Active
requires: a conformant verifier implementation behind the port, the GLEIF/KEL resolution path
egress-hardened, and the thumbprint-only seal shape fixed in `api/api-spec-tl-v2.yaml`.

## 10. Object schemas (postponed shapes)

`lei` is **Postponed**, so the shapes below are the design of record, **not** frozen wire. The
implemented `VerifyControlRequest` is JWS-only and the implemented seal carries a verbatim
`verificationMethod`; `lei`'s CESR request and thumbprint-only seal are a **future amendment** and
are **not** covered by [`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json)
(which models the JWS-scheme verbatim-VM seal). They are recorded here so the contract is settled
before the kind ships.

**Register** — the value is the bare LEI; the full vLEI CESR chain is presented once at this step
(a postponed request field, since the current `IdentityRegistrationRequest` carries only `value`):

```json
{ "value": "5493001KJTIIGC8Y1R12", "vleiPresentation": "<CESR full-chain ACDC presentation>" }
```

**verify-control (postponed, non-JOSE)** — a KERI/CESR signature over the served signing input
from the pinned subject AID's current key (the signed message is the decoded `IdentityProofInput`
bytes, not a compact JWS — ANS-0 §3.2):

```json
{ "cesrSignature": "<KERI/CESR signature over the served signingInput, by the subject AID key>" }
```

**Sealed (thumbprint-only, postponed)** — the proof event records the subject AID + a key
thumbprint, **not** a `verificationMethod`: the ACDC is PII and KERI's KEL is the authoritative,
externally-resolvable key history (§4):

```json
{ "subjectAid": "<KERI autonomic identifier>", "keyThumbprint": "<RFC 7638-style thumbprint of the AID's current key>" }
```
