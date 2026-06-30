# Identity profiles

Each ANS identifier **kind** is defined by one profile document here. A profile specifies how a
kind is selected, control-proven, validated, sealed, and monitored. The core contract —
[ANS-0: Identity](../ans-0-identity-anchor.md) — never changes when a profile is added, amended,
or retired; that is the point of the split.

This index mirrors the registry table in [ANS-0 §10.1](../ans-0-identity-anchor.md#101-the-profile-registry).
The authoritative status is the ANS-0 table; this page is a convenience map.

| Kind | Profile | Requirement | Axes | Seal tier | Status |
| --- | --- | --- | --- | --- | --- |
| `fqdn` (agent primary) | [fqdn.md](fqdn.md) | Required | identifier (ACME) + key (CSR) | n/a (cert-bound) | Active |
| `did:web` | [did-web.md](did-web.md) | Optional | key only (multi-key) | verbatim verification method | Active |
| `did:key` | [did-key.md](did-key.md) | Optional | key only | verbatim verification method | Active |
| `lei` | [lei.md](lei.md) | Optional | key only (vLEI-validated) | thumbprint-only (AID + key thumbprint) | Postponed |
| `did:plc` | [did-plc.md](did-plc.md) | Optional | key only (multi-key) | verbatim verification method | Deferred (sketch) |
| `did:ethr` / `did:pkh` | [did-ethr.md](did-ethr.md) | Optional | key only (EIP-712 / ERC-1271) | verbatim verification method | Deferred (sketch) |
| `did:ion` | [did-ion.md](did-ion.md) | Optional | key only (multi-key) | verbatim verification method | Deferred (sketch) |
| `dnsid` | [dnsid.md](dnsid.md) | Optional | key only (DNS-rooted) | verbatim verification method | Deferred (sketch) |

**Requirement.** `fqdn` is the one required profile (the agent's primary anchor, the *what* —
required by ANS-1 for every agent registration). Every who-identity profile is **optional**: the
whole Verified Identity surface is opt-in ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)),
and an RA implementing it chooses which kinds to support, including none. Optional to adopt;
mandatory in execution once a kind is enabled.

**Status meanings** (ANS-0 §10.1):

- **Active** — wired, tested, sealing real proofs.
- **Postponed** — the flow is the design of record and de-risked, but disabled until its external
  plumbing is enabled; the kind returns `IDENTIFIER_KIND_UNSUPPORTED`.
- **Deferred (sketch)** — intended shape only; ships when its resolver, tests, and external
  plumbing are real. An unimplemented kind is unregistered (404/`IDENTIFIER_KIND_UNSUPPORTED`),
  never a placeholder seal.

## The profile template

Every profile document specifies, in this order (ANS-0 §10.2):

1. Identifier form and canonicalization; how the kind is selected (lexical vs explicit).
2. Control proof — which axes apply and the exact `verify-control` checks, in order.
3. Key source and `kid`/key-selection rules.
4. Seal tier — verbatim verification method, or thumbprint-only, and exactly what is sealed.
5. Freshness and ANS-5 monitoring cadence.
6. Lifecycle specifics (rotation, revocation, re-proof).
7. Outbound-fetch (SSRF) notes, for fetch-based kinds.
8. Error codes.
9. Status and requirement (Required `fqdn` / Optional who-profiles).
10. Object schemas — worked request/challenge/seal examples (Active/Postponed profiles).

All profiles share the one signing input (`IdentityProofInput`, ANS-0 §3.2) and the one
proof-of-control gate (ANS-0 §3). A profile only ever varies the **key source** and the
**per-kind checks** layered on top of that gate.

## Conformance artifacts

The sealed identity event (the `IDENTITY_*` family the TL stores) has a machine-readable
conformance schema — [`../../api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json)
(JSON Schema draft-07, the closed `eventType` set + the per-type required-field matrix). Its
field-by-field contract and a worked example are in
[ANS-0 §8.1](../ans-0-identity-anchor.md#81-the-identity-event-family-and-ingest); the per-kind
request/challenge/seal shapes are the "Object schemas" section of each Active/Postponed profile.
A sealed identity log entry MUST validate against the schema.
