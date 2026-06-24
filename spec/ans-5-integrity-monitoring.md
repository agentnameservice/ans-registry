# ANS-5: Integrity Monitoring (AIM)

Status: DRAFT v1.0
Spec: ANS-5 (Integrity Monitoring)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building or operating the Agent Integrity Monitor (AIM) and verifiers consuming its records

## 1. Scope

ANS-5 specifies the contract for a verification worker that periodically checks each registered fact and produces a verification record.

ANS-5 specifies:

- The `VerificationWorker` code-interface contract: given a `Registration` reference plus its current `IdentityClaim`, produce a typed `VerificationRecord` with per-check results and an evidence pointer.
- The verification check set: which facts the AIM verifies, what passes, what fails.
- The verification procedure: the cryptographic-verification-path checks a verifier runs to confirm an agent.
- The integrity-reporting principles: monitors report, the RA acts; reports are public and signed; quorum before action; evidence MUST be verifiable.
- The transient-vs-mismatch distinction the AIM MUST observe.
- The principal-binding verification procedures for DID_WEB, LEI, BIOMETRIC_HASH, and ENS_ENSIP25 binding types.

ANS-5 is **profile-agnostic and DNS-profile-agnostic by construction**. The same worker runs
across registrations regardless of anchor profile; against legacy `_ans` TXT, against
Consolidated Approach SVCB, against agents with no DNS at all. It consults the relevant ANS-3
profile through the `DNSEmitter.records()` contract for expected DNS state. **Verified
Identities** (the *who*, [ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)) are
monitored on their own per-identity cadence (§4.3), independently of the agents that link them.

ANS-5 does **not**:

- Score, rank, or filter agents. Trust scoring is out of scope for ANS and lives in a separate `ti-*` layer set. The clean separation matters because some deployments want verification (am I being lied to?) without scoring (is this the best one?), and others want both. ANS-5's verb is **verify**.
- Issue revocations or command state changes. Findings are reports; the RA decides what to do with them. ANS-1 specifies the warning event the RA emits when a finding clears quorum; the agent stays ACTIVE. Revocation only happens through the RA's own decision per ANS-1.
- Specify grade-tier rules for principal bindings. ANS-5 specifies *how* to verify each binding type; *which* bindings are acceptable *when* is grade-tier policy that lives outside ANS.

## 2. Terminology

- **AIM (Agent Integrity Monitor)**: the verification worker the RA composes with. Operationally, the AIM is one or more processes running independently of the RA's request path; their findings flow back to the RA.
- **Verification record**: the typed result of one verification cycle for one registration. Carries per-check outcomes, an evidence pointer, and a timestamp.
- **Evidence pointer**: a URL or content-addressed reference to the bundle of network captures, certificate samples, DNS query traces, and external resolution responses the AIM gathered while verifying. Verifiers consuming an `INTEGRITY_WARNING` event can re-verify against the evidence bundle.
- **Finding**: a verification record where one or more checks failed. Findings flow to the RA per the integrity-reporting principles section.
- **Mismatch vs. unreachable**: `Mismatch` means the content has changed (remediation needed); `Unreachable` means a transient network failure (retry later). Conflating the two would let a network glitch trigger suppression of a legitimate agent.

## 3. The `VerificationWorker` interface

The `VerificationWorker` interface is the protocol contract for ANS-5: each worker accepts an ACTIVE `Registration` and an `IdentityClaim`, runs the per-check semantics named in the verification-checks section, and emits a `VerificationRecord` whose `checks` object's optional fields (`identityCertMatch`, `principalBinding`, `onChainBinding`, `witnessAttestation`, `rdapStatus`) are present only
when the registration produces the corresponding evidence.

## 4. Verification checks

The AIM verifies each ACTIVE registration independently. A third party must detect misissuance, drift, or compromise without insider access to the registry; the verification checks below implement this through independent trust channels (PKI, DNS/DNSSEC, TL, witness systems, DNS provider RDAP).

| Check | What the AIM does | Pass condition | Required when |
| --- | --- | --- | --- |
| **TL presence** | Query the ANS-4 TL for the registration's most recent sealed event | Inclusion proof verifies against the TL's Signed Tree Head | Always |
| **DNS pointer** | Authoritative DNS query for the records emitted per ANS-3, with DNSSEC validation when the zone is signed | Records exist and validate | When the anchor profile emits DNS records (ANS-3) |
| **Server Certificate match** | TLS handshake to the operational endpoint, extract certificate fingerprint | Fingerprint matches the value sealed in the TL | When the anchor profile ties to TLS (FQDN; `did:web` resolved domain) |
| **Identity Certificate match** | TLS handshake; extract Identity Cert fingerprint; compare with TL value | Fingerprint matches | Only when ANS-2 versioned registration |
| **Trust Card hash match** | Fetch the Trust Card from the path in the SVCB row's `wk` SvcParam (consolidated style) or the URL in the `_ans` record (legacy style), or fall back to `/.well-known/ans/trust-card.json`; hash the JCS-canonical bytes | Hash matches the `capabilitiesHash` sealed at registration | Only when Trust Card is hosted AND `trustCardContent` was submitted at registration |
| **Schema integrity** | Fetch each endpoint's `metaDataUrl`, hash the document | Hash matches the protocol-keyed entry in the TL `attestations.metadataHashes` map (e.g. `metadataHashes["A2A"]`) | Only when per-endpoint `metaDataHash` values were submitted at registration |
| **Principal binding (ENS_ENSIP25)** | Resolve ENS name; verify `agent-registration[<registry>][<tokenId>]` text record; verify ERC-8004 registration file lists the ENS name | Both directions agree | Only when `principalBinding.type` is `ENS_ENSIP25` |
| **Principal binding (DID_WEB)** | Fetch `/.well-known/did.json` from the declared domain | DID document exists with a valid verification method | Only when `principalBinding.type` is `DID_WEB` |
| **Principal binding (LEI)** | Verify vLEI credential signature against the issuing entity's registered key (Option A) or against the LOU's custom field signature (Option B) per the [lei profile](identity-profiles/lei.md) | Signature valid and LEI ACTIVE in GLEIF database | Only when `principalBinding.type` is `LEI` |
| **Principal binding (BIOMETRIC_HASH)** | Verify the biometric credential against the declared verifier's public key. The raw biometric data is never transmitted; only a hash or zero-knowledge proof | Credential verifies and matches the registered binding | Only when `principalBinding.type` is `BIOMETRIC_HASH` |
| **VC signature** | Resolve issuer DID, retrieve public key, verify signature, check expiration | Signature valid and credential not expired | Only when `verifiableClaims` are present in the Trust Card |
| **On-chain identity (ERC-8004)** | Verify agentId ownership on the Identity Registry, check Reputation Registry for active feedback | Owner address matches `principalBinding.identifier` | Only when `onChainId` references an ERC-8004 registration |
| **Witness attestation** | Query the ANS-4 TL's `/v1/witnesses` endpoint, verify each attestation's external proof against the relevant backend | At least one witness attestation has been made within the witness profile's cadence window | Only when the registration's deployment posture requires a witness profile (Federated deployment) |
| **RDAP status** | Query the registrar's RDAP endpoint for the agent's domain, parse the registrant entity status | No status of `pendingDelete`, `redemptionPeriod`, `serverHold`; no recent registrant-entity-handle change | Only when the FQDN's registrar exposes RDAP per RFC 9083 and the operator has not opted out |

Most registered agents do not host a Trust Card. For those agents, the AIM verifies DNS records and Server Certificate only (plus TL presence). The verification record records which checks fired; downstream consumers react per their own policy.

When `trustCardContent` was submitted at registration, the RA sealed its hash at activation. When omitted, a conforming AIM computes the baseline hash from the live Trust Card on first successful fetch, if one is hosted. Trust Cards behind authentication cannot be fetched by the AIM; the absence of a verifiable hash is recorded in the verification record so consumers see the gap.

### 4.1 ECH key rotation

AHPs rotate ECH keys via `PATCH /v1/agents/{agentId}/ech` without creating a TL entry. ECH is a transport-layer optimization, not an identity change. The AIM observes the rotation through DNS but does not flag it as a finding.

### 4.2 Domain lifecycle monitoring

The AIM MAY monitor RDAP status and NS record changes for registered agents' domains. Status transitions to `pendingDelete`, `redemptionPeriod`, or `serverHold` indicate the domain is at risk. NS record changes indicate a potential provider migration. Both produce findings for the RA. RDAP detail varies by registrar and authorization level (RFC 9083); the AIM uses whatever level is publicly
available.

### 4.3 Verified-identity monitoring

This applies only where the RA implements the **optional** Verified Identity surface
([ANS-0 §12.2](ans-0-identity-anchor.md#122-optional-capability-verified-identities)); a
deployment without Verified Identities has nothing to monitor here.

A Verified Identity (the *who*,
[ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)) is monitored as a
**first-class object on its own cadence**, not once per linked agent. Because one identity can
link to many agents and rotation/revocation seal exactly one event regardless of fan-out
([ANS-0 §8.2](ans-0-identity-anchor.md#82-computed-reads-and-the-visibility-predicate)), the AIM
**probes each identity once** and the result projects to every linked agent's view. For a fleet
of N agents sharing one operator identity this is one probe, not N — the same fan-out saving the
seal side enjoys.

The per-identity check is **sealed-vs-live key drift**: the AIM re-resolves the identifier
through its [identity profile](identity-profiles/)'s key source (re-fetch the `did:web` document,
re-resolve the LEI's KEL key state, etc.) and compares the live authoritative key set against the
`keys[]` the latest sealed `IDENTITY_VERIFIED`/`IDENTITY_UPDATED` event recorded. A sealed key no
longer published, an unreachable document, or a key rotation that abandons the proven key is a
finding. `did:key` cannot drift (the key is the identifier) so its only monitored transition is
revocation.

As everywhere in ANS-5, a drift finding is a **report, not a revocation**: the RA decides. Read-side revocation terminality ([ANS-0 §8.3](ans-0-identity-anchor.md#83-read-side-revocation-terminality)) is independent of monitoring — a revoked identity stays revoked on the public surface regardless of what a later probe sees.

## 5. Verification procedure (verifier-facing)

A verifier checks an agent through independent steps, each using a different trust channel. The cryptographic verification path is anchor-agnostic; the per-step checks reduce to anchor-specific calls inside ANS-0 resolution.

| Step | Check | Trust channel | What it proves |
| --- | --- | --- | --- |
| 1 | PKI certificate validation | CA system | Standard TLS. Cannot detect a compromised CA |
| 2 | DANE record validation (FQDN anchors) | DNS (DNSSEC) | The Server Certificate fingerprint matches the TLSA record at `_443._tcp.{agentHost}`. A compromised CA alone cannot forge this record |
| 3 | TL inclusion proof verification | TL (signed by KMS-rooted key) | The inclusion proof confirms the registration was sealed into the log. A tampered or deleted entry breaks the proof |
| 4 | Witness attestation verification (Federated deployment) | External consensus system | The TL state at the time of inclusion has been anchored to a backend the verifier independently trusts. Defeats RA / TL collusion |
| 5 | Live state match | DNS + TLS + Trust Card fetch | The current DNS records, certificates, and Trust Card hash match what was sealed |

**TLSA parameters.** The RA specifies `TLSA 3 0 1 [sha256_hash]`: DANE-EE (usage 3), full Server Certificate (selector 0), SHA-256 (matching type 1). Selector 0 produces the same hash as the badge fingerprint in the TL, so a single SHA-256 computation of the Server Certificate serves both DANE and badge verification.

**DNSSEC prerequisite for step 2.** DANE requires DNSSEC. Per RFC 6698 §4, a TLSA RRset whose DNSSEC validation state is not "secure" MUST be treated as unusable, and the client falls back to standard PKIX certificate validation. Without DNSSEC in the agent's zone, a client cannot verify the TLSA record, so the DANE and TL verification channels are unavailable to that client. The RA SHOULD verify
DNSSEC status before provisioning TLSA records.

**TL verification strategies.** Trust On First Use (TOFU) caches the fingerprint locally on first contact. TL-Backed Verification queries the TL directly and works in ephemeral environments (containers, serverless). A client performing step 3 MAY use either; new implementations SHOULD use TL-Backed Verification.

## 7. Integrity reporting principles

The AIM is external to the RA. A malicious monitor could try to disable valid agents by flooding the RA with false failure reports. Four principles guard against this:

| Principle | Rule |
| --- | --- |
| **Monitors report, the RA acts** | External monitors publish findings. They cannot command state changes. The RA compares each finding against what the TL records before acting |
| **Reports are public and signed** | Monitors publish findings to cryptographically signed feeds, building a verifiable reputation |
| **Quorum before action** | The RA MUST NOT act on a single report from one monitor. Corroboration from multiple independent monitors is required |
| **Evidence MUST be verifiable** | Every finding MUST include cryptographic proof of the discrepancy. The RA re-verifies independently before sealing an `INTEGRITY_WARNING` |

The RA's remediation scope is infrastructure integrity: do the live DNS records, Server Certificate, and Trust Card hash match what the RA sealed? The RA does not evaluate an agent's behavior or quality.

### 7.1 Warning, not state change

The AIM records integrity findings in its own data store. The RA polls or subscribes to these findings.

When a finding meets the quorum requirement, the RA independently re-verifies the reported mismatch against the TL's sealed records. If confirmed, the RA emits `INTEGRITY_WARNING` to the TL (event payload schema is part of ANS-5; ANS-4 specifies the TL envelope). The agent stays `ACTIVE`. Certificates, DNS, and mTLS are unaffected. When the discrepancy clears, the RA emits `INTEGRITY_RESOLVED`.

A consumer's discovery service MAY suppress agents with unresolved warnings; the suppression is a consumer policy choice, not a state change inside the registry or a command issued to the RA. The RA publishes facts; consumers react.

## 8. Conformance

A conformant ANS-5 implementation:

1. Exposes a `VerificationWorker` whose `verify()` operation produces a `VerificationRecord` for any combination of ANS-0 anchor profile and ANS-3 DNS profile.
2. Implements every check in the verification-checks section that applies to the input registration.
3. Distinguishes `Unreachable` from `Mismatch` per the terminology section and never raises an `Unreachable` as a finding.
4. Does not issue revocations or commit state changes; produces verification records only.
5. Does not score, rank, or filter agents; emits per-check results only (per the scope section).
6. Honors the integrity-reporting principles.
7. Marks records as `degraded` when the underlying ANS-0 claim was retrieved via the soft-stale fallback.


**Optional surface.** Per-binding-type verification coverage (each row in the verification-checks section fires only when the registration carries the corresponding binding); RDAP availability per RFC 9083 (the operator MAY opt out, and unavailability records as a missing check rather than a failure); WHOIS-based monitoring as a deployment-specific extension; AIM verification cadence is
operator-defined. A conforming verifier MUST NOT downgrade integrity scoring solely because a registration omits an optional binding type, and MUST NOT reject a `VerificationRecord` because the AIM omitted an unavailable check.

## 10. Security considerations

### 10.1 Soft-stale claim handling

When a verifier accepts a soft-stale ANS-0 claim, the resulting verification record carries `degraded: true`. Verifiers handling high-stakes transactions SHOULD refuse a degraded record entirely.

### 10.3 Evidence-pointer integrity

The evidence bundle the AIM links to is itself subject to tampering. A finding that survives RA re-verification does not require the operator to re-fetch the evidence bundle, because the RA's independent re-check is the binding step. Verifiers consuming `INTEGRITY_WARNING` events and seeking to inspect evidence SHOULD verify the evidence bundle's signature against the AIM's published key before
relying on its contents.

## Appendix A: Worked examples

Non-normative worked example (AIM finding payload) lives at [`examples/ans-5-examples.md`](examples/ans-5-examples.md).

## 13. References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md). The proof-of-control gate, the Verified Identity object and its monitoring, the [identity profiles](identity-profiles/).
- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, `INTEGRITY_WARNING` event payload schema field consumers, Trust Card structure.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Expected DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). TL receipts, witness attestations, INTEGRITY_WARNING/RESOLVED envelope.
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA records.
- [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083): RDAP JSON responses.
- [ISO 17442](https://www.iso.org/standard/78829.html): Legal Entity Identifier (LEI).
