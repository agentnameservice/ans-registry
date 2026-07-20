# ANS Architecture and Design

This file is a pointer. The normative ANS specification is layered across six documents under [`spec/`](spec/):

| Layer | File | Topic |
| --- | --- | --- |
| ANS-0 | [`spec/ans-0-identity-anchor.md`](spec/ans-0-identity-anchor.md) | Identity: the proof-of-control gate, the Verified Identity object (the *who*) vs the agent's FQDN primary anchor (the *what*), identity links, and the [identity profiles](spec/identity-profiles/) |
| ANS-1 | [`spec/ans-1-registration.md`](spec/ans-1-registration.md) | Registration aggregate, lifecycle, event set |
| ANS-2 | [`spec/ans-2-versioned-naming.md`](spec/ans-2-versioned-naming.md) | ANSName URI form, Identity Certificate URI SAN binding, mTLS |
| ANS-3 | [`spec/ans-3-dns-publication.md`](spec/ans-3-dns-publication.md) | DNS publication, record styles, DANE, anchor-conditional emission |
| ANS-4 | [`spec/ans-4-transparency.md`](spec/ans-4-transparency.md) | SCITT statements and receipts, Transparency Log, checkpoints and tiles, HCS anchoring |
| ANS-5 | [`spec/ans-5-integrity-monitoring.md`](spec/ans-5-integrity-monitoring.md) | `VerificationWorker`, integrity reporting |

Per-identifier-kind detail (fqdn, did:web, did:key, lei, and deferred sketches for did:plc / did:ethr / did:ion) lives in the [identity profiles](spec/identity-profiles/) under ANS-0 — adding a kind drops in a profile without changing the ANS-0 core contract.

Worked examples live at [`spec/examples/ans-1-examples.md`](spec/examples/ans-1-examples.md).

A companion IETF Internet-Draft tracks the protocol at the IETF: [`draft-narajala-courtney-ansv2`](https://datatracker.ietf.org/doc/draft-narajala-courtney-ansv2/). The layered specs in this repository are the authoritative source; the IETF draft is updated less frequently and is the venue for cross-organizational standards review.
