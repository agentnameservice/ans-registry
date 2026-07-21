# ANS-5: Integrity Monitoring (AIM)

Status: DRAFT v1.0
Spec: ANS-5 (Integrity Monitoring)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building or operating the Agent Integrity Monitor (AIM) and verifiers consuming its records

## 1. Scope

ANS-5 specifies the contract for a verification worker that periodically checks each registered fact and produces a verification record.

ANS-5 specifies:

- The `VerificationWorker` code-interface contract: given a `Registration` reference, produce a typed `VerificationRecord` with per-check results and evidence.
- The verification check set: which facts the AIM verifies, what passes, what fails.
- The verification procedure: the cryptographic-verification-path checks a verifier runs to confirm an agent.
- The integrity-reporting principles: monitors report, the RA acts; reports are public and signed; quorum before action; evidence MUST be verifiable.
- The transient-vs-mismatch distinction the AIM MUST observe.
- The principal-binding verification procedures for DID_WEB, LEI, BIOMETRIC_HASH, and ENS_ENSIP25 binding types.

ANS-5 is **profile-agnostic and DNS-profile-agnostic by construction**. The same worker runs
across registrations regardless of anchor profile; against the `ANS_TXT` `_ans` TXT family, against
the `ANS_DNSAID` SVCB profile, against agents with no DNS at all. It consults the relevant ANS-3
discovery profile through the `ProfileEmitter` composition contract
([ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles)) for expected DNS state. **Verified
Identities** (the *who*, [ANS-0 §4](ans-0-identity-anchor.md#4-the-verified-identity-object)) are
monitored on their own per-identity cadence (§4.3), independently of the agents that link them.

ANS-5 does **not**:

- Score, rank, or filter agents. Trust scoring is out of scope for ANS and lives in a separate `ti-*` layer set. The clean separation matters because some deployments want verification (am I being lied to?) without scoring (is this the best one?), and others want both. ANS-5's verb is **verify**. A conforming AIM MAY be composed into a larger system that also performs scoring, provided the scoring function does not influence verification outcomes.
- Issue revocations or command state changes. Findings are reports; the RA decides what to do with them. ANS-1 specifies the warning event the RA emits when a finding clears quorum; the agent stays ACTIVE. Revocation only happens through the RA's own decision per ANS-1.
- Specify grade-tier rules for principal bindings. ANS-5 specifies *how* to verify each binding type; *which* bindings are acceptable *when* is grade-tier policy that lives outside ANS.

## 2. Terminology

- **AIM (Agent Integrity Monitor)**: the verification worker. Operationally, the AIM is one or more processes running independently of the RA's request path; their findings reach consumers through an implementation-defined integration.
- **Verification record**: the typed result of one verification cycle for one registration. Carries per-check outcomes, an evidence pointer, and a timestamp.
- **Evidence pointer**: an inline bundle or content-addressed reference to the network captures, certificate samples, DNS query traces, and external resolution responses the AIM gathered while verifying. Verifiers consuming an `INTEGRITY_WARNING` event can re-verify against the evidence bundle.
- **Finding**: a verification record where one or more checks failed. Findings are surfaced per the integrity-reporting principles (§7).
- **Mismatch vs. unreachable**: `Mismatch` means the content has changed (remediation needed); `Unreachable` means a transient network failure (retry later). Conflating the two would let a network glitch trigger suppression of a legitimate agent.

## 3. The `VerificationWorker` interface

The `VerificationWorker` interface is the protocol contract for ANS-5: the orchestration layer MUST ensure only ACTIVE registrations are submitted for verification. The worker runs the per-check semantics named in the verification-checks section and produces per-check results. Checks that do not apply to the input registration are omitted (not reported as failures). A conforming implementation MAY emit individual per-check results rather than a single grouped record, provided each is attributable to a verification cycle and carries provenance. The wire format of the AIM's output is implementation-defined.

## 4. Verification checks

The AIM verifies each ACTIVE registration independently. A third party must detect misissuance, drift, or compromise without insider access to the registry; the verification checks below implement this through independent trust channels (PKI, DNS/DNSSEC, TL).

| Check | What the AIM does | Pass condition | Required when |
| --- | --- | --- | --- |
| **TL presence** | Query the ANS-4 TL for the registration's most recent sealed event | Inclusion proof verifies against the TL's Signed Tree Head | Always |
| **DNS pointer** | Authoritative DNS query for the records emitted per ANS-3, with DNSSEC validation when the zone is signed | Records exist, content matches TL-sealed expected values, and DNSSEC validates (when signed) | Always (against the record set the registration's discovery profiles emit, [ANS-3 §6](ans-3-dns-publication.md#6-discovery-profiles)) |
| **Server Certificate match** | TLS handshake to the operational endpoint, extract certificate fingerprint | Fingerprint matches the value sealed in the TL | When the anchor profile ties to TLS (FQDN; `did:web` resolved domain) |
| **Identity Certificate match** | Verify identity certificate fingerprint against TL-sealed value (see §4 note below) | Fingerprint matches | Only when ANS-2 versioned registration |
| **Schema integrity** | Fetch each endpoint's `metaDataUrl`, hash the document | Hash matches the protocol-keyed entry in the TL `attestations.metadataHashes` map (e.g. `metadataHashes["A2A"]`) | Only when per-endpoint `metaDataHash` values were submitted at registration |
| **Principal binding (ENS_ENSIP25)** | Resolve ENS name; verify `agent-registration[<registry>][<tokenId>]` text record; verify ERC-8004 registration file lists the ENS name | Both directions agree | Only when `principalBinding.type` is `ENS_ENSIP25` |
| **Principal binding (DID_WEB)** | Fetch `/.well-known/did.json` from the declared domain | DID document exists with a valid verification method | Only when `principalBinding.type` is `DID_WEB` |
| **Principal binding (LEI)** | Verify vLEI credential signature against the issuing entity's registered key (Option A) or against the LOU's custom field signature (Option B) per the [lei profile](identity-profiles/lei.md) | Signature valid and LEI ACTIVE in GLEIF database | Only when `principalBinding.type` is `LEI` |
| **Principal binding (BIOMETRIC_HASH)** | Verify the biometric credential against the declared verifier's public key. The raw biometric data is never transmitted; only a hash or zero-knowledge proof | Credential verifies and matches the registered binding | Only when `principalBinding.type` is `BIOMETRIC_HASH` |
| **On-chain identity (ERC-8004)** | Verify agentId ownership on the Identity Registry, check Reputation Registry for active feedback | Owner address matches `principalBinding.identifier` | Only when `onChainId` references an ERC-8004 registration |

**DNS pointer record types.** `_ans` and `_ans-badge` (or `_ra-badge`) TXT records MUST be verified. TLSA and HTTPS/SVCB records SHOULD be verified when the registration's attestation includes them.

**DNS pointer content matching.** "Records exist and validate" means: (1) the record exists at the authoritative nameserver, (2) its content matches the TL-sealed expected value, and (3) the record's DNSSEC validation state is secure when the zone is signed. A record that exists but whose content does not match the sealed value is a `Mismatch` finding.

The verification record records which checks fired; downstream consumers react per their own policy.

**Identity certificate verification note.** The identity certificate is typically a client certificate not presented during a standard TLS handshake to the operational endpoint. Runtime re-verification of the identity certificate fingerprint requires a dedicated identity presentation protocol not currently defined in ANS. Implementations SHOULD record the identity certificate type as evidence; fingerprint re-verification is deferred to a future ANS extension. This check does not contribute to conformance level determination until such an extension is published.

### 4.1 Check severity

A conforming implementation MAY assign severity tiers to checks:

- **Verdict-determining** (fail-closed): a failure contributes to an overall FAIL verdict.
- **Evidence-only** (fail-open): a failure is reported but does not change the overall verdict.

The severity assignment is implementation-defined. Implementations MUST document which checks are verdict-determining. An implementation MAY produce an aggregate verdict (PASS/FAIL) from its verdict-determining checks without violating the "does not score" principle — a verification verdict is distinct from trust scoring.

### 4.2 Domain lifecycle monitoring

The AIM MAY monitor NS record changes for registered agents' domains. NS record changes indicate a potential provider migration and produce findings.

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

A verifier checks an agent through independent steps, each using a different trust channel. The cryptographic verification path is profile-agnostic; the per-step checks reduce to per-kind calls into the relevant ANS-0 profile (the §3 proof-of-control gate / the profile's key source).

| Step | Check | Trust channel | What it proves |
| --- | --- | --- | --- |
| 1 | PKI certificate validation | CA system | Standard TLS. Cannot detect a compromised CA |
| 2 | DANE record validation (FQDN anchors) | DNS (DNSSEC) | The Server Certificate fingerprint matches the TLSA record at `_{port}._tcp.{agentHost}` for the endpoint's port ([ANS-3 §6.3](ans-3-dns-publication.md#63-family-trust-records)). A compromised CA alone cannot forge this record |
| 3 | TL inclusion proof verification | TL (signed by KMS-rooted key) | The inclusion proof confirms the registration was sealed into the log. A tampered or deleted entry breaks the proof |
| 4 | Live state match | DNS + TLS | The current DNS records and certificates match what was sealed |

**TLSA parameters.** The RA specifies `TLSA 3 0 1 [sha256_hash]`: DANE-EE (usage 3), full Server Certificate (selector 0), SHA-256 (matching type 1). Selector 0 produces the same hash as the badge fingerprint in the TL, so a single SHA-256 computation of the Server Certificate serves both DANE and badge verification.

**DNSSEC prerequisite for step 2.** DANE requires DNSSEC. Per RFC 6698 §4, a TLSA RRset whose DNSSEC validation state is not "secure" MUST be treated as unusable, and the client falls back to standard PKIX certificate validation. Without DNSSEC in the agent's zone, a client cannot verify the TLSA record, so the DANE and TL verification channels are unavailable to that client. The RA SHOULD verify
DNSSEC status before provisioning TLSA records.


## 7. Integrity reporting principles

The AIM is external to the RA. A malicious monitor could try to suppress valid agents by publishing false failure reports, poisoning trust in the ecosystem. Four principles guard against this:

| Principle | Rule |
| --- | --- |
| **Monitors report, the RA acts** | External monitors publish findings. They cannot command state changes. The RA compares each finding against what the TL records before acting |
| **Reports SHOULD be signed** | Monitors SHOULD publish findings to cryptographically signed feeds, building a verifiable reputation |
| **Quorum before action** | The RA MUST NOT act on an unconfirmed finding. Quorum MAY be satisfied by corroboration from independent monitors, internal re-verification, or other confirmation mechanisms |
| **Evidence MUST be verifiable** | Every finding MUST include cryptographic proof of the discrepancy. The RA re-verifies independently before sealing an `INTEGRITY_WARNING` |

The RA's remediation scope is infrastructure integrity: do the live DNS records and Server Certificate match what the RA sealed? The RA does not evaluate an agent's behavior or quality.

### 7.1 Warning, not state change

The AIM records integrity findings in its own data store. The registry ingests these findings through an implementation-defined integration.

When a finding meets the quorum requirement, consumers of the finding take action per their own policy. The agent remains `ACTIVE` — a confirmed finding is an advisory signal, not a state change. When the discrepancy clears, the finding is resolved.

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


**Optional surface.** Per-binding-type verification coverage (each row in the verification-checks section fires only when the registration carries the corresponding binding); AIM verification cadence is operator-defined. A conforming verifier MUST NOT downgrade integrity scoring solely because a registration omits an optional binding type, and MUST NOT reject a `VerificationRecord` because the AIM omitted an unavailable check.

**Conformance levels.** Implementations declare their conformance level:

- **Level 1 (Core)**: DNS pointer verification with content matching, DNSSEC chain validation, Server Certificate fingerprint match, and the Mismatch/Unreachable distinction. This is the minimum for a conforming implementation.
- **Level 2 (Extended)**: Level 1 plus Schema integrity and TL inclusion proof cryptographic verification.
- **Level 3 (Full)**: Level 2 plus all applicable principal-binding checks and On-chain identity. Level 3 requires protocol extensions not universally deployed; implementations declare which Level 3 checks they support.

## 10. Security considerations

### 10.1 Soft-stale claim handling

When a verifier accepts a soft-stale ANS-0 claim, the resulting verification record carries `degraded: true`. Verifiers handling high-stakes transactions SHOULD refuse a degraded record entirely.

### 10.2 Evidence-pointer integrity

The evidence bundle the AIM links to is itself subject to tampering. A finding that survives RA re-verification does not require the operator to re-fetch the evidence bundle, because the RA's independent re-check is the binding step. Verifiers consuming `INTEGRITY_WARNING` events and seeking to inspect evidence SHOULD verify the evidence bundle's signature against the AIM's published key before
relying on its contents.

## Appendix A: Worked examples

Non-normative worked example (AIM finding payload) lives at [`examples/ans-5-examples.md`](examples/ans-5-examples.md).

## 13. References

- ANS-0 specification: [`ans-0-identity-anchor.md`](ans-0-identity-anchor.md). The proof-of-control gate, the Verified Identity object and its monitoring, the [identity profiles](identity-profiles/).
- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, lifecycle, event set.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Expected DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). TL receipts, witness attestations.
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA records.
- [ISO 17442](https://www.iso.org/standard/78829.html): Legal Entity Identifier (LEI).
