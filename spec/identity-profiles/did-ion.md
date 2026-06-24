# Identity profile: `did:ion` (deferred sketch)

Status: DRAFT v1.0 — deferred sketch
Profile: did:ion
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.0.1
Date: 2026-06-23
Audience: implementers evaluating future identifier kinds

> **Deferred.** Intended shape only. Ships when an ION resolver, tests, and node plumbing are
> real; until then `IDENTIFIER_KIND_UNSUPPORTED` (ANS-0 §10.1). No placeholder seal.

**Requirement: Optional** — a who-identity profile ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)), like every who-profile.

`did:ion` is a Sidetree-based, Bitcoin-anchored DID method. Like [`did:web`](did-web.md) and
[`did:plc`](did-plc.md) it is a JWS-scheme, multi-key, fetch-based kind; it differs only in the
resolution backend (a Sidetree/ION node) and the long-form vs short-form DID handling.

- **Identifier / selection** (lexical, `did:ion:` prefix):
  - **short form** `did:ion:<suffix>` — resolved from an ION node;
  - **long form** `did:ion:<suffix>:<base64url initial-state>` — self-resolving from the embedded
    initial state, then reconciled against the node if anchored.
  - Canonicalization preserves the method's suffix; long-form initial state is validated, not
    rewritten.
- **Key source / control axis** (key only): the resolved DID document's `assertionMethod` keys
  (EC/OKP); possession proven with the shared `signedProofs[]` JWS machinery and alg-pinned
  verification — the exact did:web verify pipeline.
- **Seal tier**: verbatim verification method (ANS-0 §8.4).
- **Freshness/monitoring**: ANS-5 re-resolves through the ION node; the signal is key-set drift
  and Sidetree operation-anchoring status.
- **SSRF**: ION node resolution is an egress dependency. Pin to a configured, trusted resolver
  endpoint; if a registrant-supplied node URL is ever accepted, harden exactly like did:web
  (denylist, pinning, bounds, no oracle).
- **What gates promotion**: an ION resolver behind `port.DIDResolver` (long-form self-resolution +
  node reconciliation), tests, and the node egress path settled.

Open question: whether to accept long-form DIDs that are not yet anchored on Bitcoin (usable but
not yet tamper-anchored) or to require anchoring before VERIFIED — the latter is stronger but adds
unbounded confirmation latency to the proof path.
