# Identity profile: `dnsid` (deferred sketch)

Status: DRAFT v1.0 — deferred sketch
Profile: dnsid (DNS-rooted identity key)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.0.1
Date: 2026-06-23
Audience: implementers evaluating future identifier kinds

> **Deferred.** Intended shape only. Ships when a DNSSEC-validating resolver path, tests, and
> plumbing are real; until then `IDENTIFIER_KIND_UNSUPPORTED` (ANS-0 §10.1). No placeholder seal.

**Requirement: Optional** — a who-identity profile ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)), like every who-profile.

`dnsid` roots a who-identity directly in DNS: an operator publishes an identity key in a
DNSSEC-signed record under a domain they control, and proves possession of that key. It is the
who-side analogue of the agent's `fqdn` primary anchor, but with an explicit, rotatable identity
key rather than a certificate binding — and unlike `did:web` it leans on DNSSEC rather than WebPKI
for the resolution's authenticity.

- **Identifier / selection**: a domain-scoped identifier (e.g. `dnsid:example.com` or a labelled
  variant); explicit-kind or lexical, to be fixed at promotion. Canonical form lowercases the
  domain (IDNA A-label).
- **Key source**: a verification key published in a DNSSEC-signed record at a well-known name
  under the domain (a TXT/TLSA-style record carrying the key material). Resolution reuses ANS-2's
  DNS verifier path, including the AuthenticatedData (DNSSEC) bit.
- **Control axes**:
  - **identifier control** — the key is published under the operator's own DNS zone, and the
    answer is **DNSSEC-validated** (the resolver's AD bit carried through, mirroring how
    `dnsRecordsProvisioned[].dnssecVerified` is attested for agents);
  - **key control** — possession proven over the served `signingInput` (JWS for EC/OKP keys).
- **Seal tier**: verbatim verification method (the published key material, as published), plus the
  DNSSEC-validation status as attested context.
- **Freshness/monitoring**: ANS-5 re-queries the record on its cadence; the signal is the key
  disappearing, changing without a rotation proof, or losing DNSSEC validation.
- **SSRF**: DNS resolution, not HTTP fetch — governed by ANS-2's DNS verifier, not the did:web
  fetcher. No HTTP egress surface in the base case.
- **What gates promotion**: a DNSSEC-validating resolution path that carries the AD bit into the
  seal, a fixed record format, tests, and a decision on whether un-DNSSEC'd answers are ever
  acceptable (sketch position: no — `dnsid`'s whole value over `did:web` is the DNSSEC root, so an
  unsigned answer fails closed).
