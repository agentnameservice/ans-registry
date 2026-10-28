# Identity profile: `fqdn`

Status: DRAFT v1.0
Profile: fqdn (the agent's primary anchor)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.1.0
Date: 2026-06-23
Audience: implementers building an ANS-conformant Registration Authority

The `fqdn` profile is the archetype of the proof-of-control gate ([ANS-0 §3](../ans-0-identity-anchor.md#3-the-proof-of-control-gate))
— the one ANS generalizes from. It is **not** a Verified Identity (the who); it is the agent's
mandatory **primary anchor** (the what, [ANS-0 §9](../ans-0-identity-anchor.md#9-the-who-the-what-and-the-fqdn-primary-anchor)),
proven on the agent-registration path, not through the `/v2/ans/identities` API.

## 1. Identifier form, canonicalization, selection

- **Form**: a DNS hostname — the agent's `agentHost` (e.g. `agent.example.com`).
- **Canonicalization**: lowercase; IDNA/punycode A-label form; no trailing dot. The version
  prefix (`v1.0.0.`) lives only in the ANS-name hostname label, never in the bare FQDN.
- **Selection**: not lexical and not a kind a client registers through the identity API. The FQDN
  is established by the agent registration itself (ANS-1). A registration loaded without explicit
  anchor metadata is **FQDN-implicit**: its primary anchor is `agentHost`, proven through this
  profile (ANS-0 §9). FQDN-primacy is policy (`a registration's primary anchor MUST be fqdn`),
  not a structural limit on the gate.

## 2. Domain control and credential authorization

Prove the FQDN through ANS-1's registration/renewal domain-control flow (DNS-01 or HTTP-01).
A CA's cached authorization for a shared RA account is not proof of the current owner's control.
Credential admission and owner authorization follow ANS-2 §3; runtime possession follows ANS-6.
The scope of these agent-credential rules versus Verified Identity proofs is defined in ANS-0 §3.1.

## 3. Key source and selection

The authorized key is the leaf key whose full certificate fingerprint the RA binds to this registration
after its domain-control and owner-authorization checks. A CA signature or DNS SAN match alone is not that authorization. No `kid` selector applies; there is one
key per certificate.

## 4. Seal tier

n/a as an identity seal — `fqdn` seals through the **agent** event family
([ANS-1 §6](../ans-1-registration.md#6-event-set)): the issued identity/server certificates are
carried in the `AGENT_REGISTERED`/`AGENT_RENEWED` attestations (`identityCerts[]`,
`serverCerts[]`) and the provisioned records in `dnsRecordsProvisioned[]`. The FQDN is never
sealed as an `IDENTITY_*` event and never appears on the identity read surface.

## 5. Freshness and monitoring

Registration and server renewal follow ANS-1's domain-validation rules; identity enrollment requires an
ACTIVE owner-controlled registration. Metadata edits and binding removal preserve domain-proof age.
ANS-5 monitors current signed certificate and DNS evidence.

## 6. Lifecycle specifics

Rotation, renewal, and revocation of the primary anchor are the **agent** lifecycle
([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations); DNS effects per ANS-3). When the
FQDN lapses (registration revoked), the **who** survives independently: a linked
Verified Identity and its TL history persist, and the owner links the existing identity to a
successor agent (ANS-0 §9, domain-loss continuity).

## 7. Outbound-fetch safety

The verification I/O is DNS (DNS-01) and ACME HTTP to the configured CA, governed by ANS-2's DNS
verifier and the ACME client — not the registrant-steered fetch path of the did fetch profiles.
No `did:web`-style SSRF surface applies.

## 8. Error codes

Failures surface through the registration/verification flows (ANS-1/ANS-2) as RFC 7807 Problem
Details — ACME order failures, DNS-01 validation failures, CSR rejection (`IDENTITY_CSR_NOT_PERMITTED`
when a CSR is supplied on a path that does not permit it), and the certificate-management codes of
ANS-3. This profile defines no `IDENTITY_*`-surface codes of its own.

## 9. Status and requirement

**Requirement: Required.** `fqdn` is the agent's primary anchor (the *what*) — every agent
registration is anchored to one, proven on the ANS-1 path. It is required independent of whether
the RA implements the optional Verified Identity surface ([ANS-0 §12](../ans-0-identity-anchor.md#12-conformance)).

**Status: Active.** This is the original, fully-implemented anchor path; the identity gate
generalizes it. It needs no promotion — the rest of the registry catches up to it.

## 10. Object schemas

`fqdn` seals no `IDENTITY_*` event and has no Verified-Identity object (the *what*, not the *who*).
Its sealed object is the agent's **`AGENT_REGISTERED` attestation** — `identityCerts[]`,
`serverCerts[]`, `dnsRecordsProvisioned[]` — documented in
[ANS-1 §6.1](../ans-1-registration.md#61-agent_registered). The identity-event conformance schema
[`api/identity-event-schema-v2.json`](../../api/identity-event-schema-v2.json) does **not** apply
to the primary anchor; the agent event schema governs it.
