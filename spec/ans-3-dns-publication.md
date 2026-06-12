# ANS-3: DNS Publication

Status: DRAFT v1.0
Spec: ANS-3 (DNS Publication)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers building or operating an ANS Registration Authority that emits DNS records and the AHPs that provision them

## 1. Scope

ANS-3 targets navigational completeness in one unfragmented UDP transaction: one SVCB record at `{agentHost}` plus, in DNSSEC-signed zones, one TLSA record at `_443._tcp.{agentHost}`. Deployments whose DNS provider does not support SVCB in service mode fall back to the `_ans` TXT family.

ANS-3 specifies how a registration's facts surface as DNS records. It defines:

- The `DNSEmitter` code-interface contract: given a `Registration` and one or more style IDs, return the records the operator must publish.
- Two record styles defined inline in §6:
  - **Consolidated SVCB (default):** SVCB rows at the bare FQDN, one per protocol, per [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html).
  - **Legacy `_ans` TXT:** the original `_ans` TXT family, one record per protocol endpoint. Active for AHPs whose DNS provider does not support SVCB in service mode.
- The selection rule (`dnsRecordStyles` array of style IDs; default `["ANS_SVCB"]`).
- The anchor-conditional emission table: which records each anchor profile produces and which it does not.
- The DNS management role split between AHP, RA, and DNS provider.

ANS-3 is **anchor-conditional**. FQDN anchors emit DNS records. DID anchors that resolve through HTTPS still benefit from publishing facts under the resolved domain. Pure cryptographic anchors (`did:key`) emit nothing because they have no resolved domain to publish under. The emission table below spells this out.

ANS-3 specifies **DNS record generation and publication orchestration**. DANE verification (the verifier-side procedure of validating TLSA records and matching Server Certificates) spans ANS-3 and ANS-5. ANS-3 defines the DNS record formats and emission rules; ANS-5 specifies the verifier worker procedure that consults those records during verification.

ANS-3 does **not** specify:

- The wire syntax of `_ans` TXT records or SVCB SvcParams. Those live inline in the record-style-selection section below.
- How the Server Certificate or Identity Certificate is issued. ANS-1 and ANS-2 cover those.
- The verifier-side DANE verification procedure. That is in ANS-5.

## 2. The `DNSEmitter` interface

The `DNSEmitter` interface is the protocol contract for ANS-3 record emission. The emitter is a pure function over the registration aggregate: given the same `Registration` and style, two implementations MUST produce the same `ExpectedDNSRecord[]` modulo TTL choice (operator policy).

## 3. Record set and child-label structure

The RA generates record content for child labels under the agent's `agentHost`. The AHP or domain owner provisions the records using the content the RA specifies. All child-label records coexist with an A, AAAA, or CNAME at the FQDN itself, because child labels are separate DNS nodes.

Operators that also publish an SVCB record at the agent FQDN (per the consolidated SVCB style in §6.1) redirect address resolution for SVCB-aware clients via TargetName per RFC 9460 §3; non-SVCB-aware clients continue to follow the A, AAAA, or CNAME. ANS reads the child-label records and, in consolidated style, the apex SVCB row at `{agentHost}`.

| Record | Label | Type | Purpose | Scope |
| --- | --- | --- | --- | --- |
| Discovery (consolidated, default) | `{agentHost}` | SVCB | One row per protocol carrying alpn / port / wk / `card-sha256` SvcParams (§6.1) | One per protocol; coexists with cross-draft SvcParams via RFC 9460 §8 |
| Discovery (legacy fallback) | `_ans.{agentHost}` | TXT | Which protocol the agent speaks and where to find the metadata (§6.2). Used by AHPs whose DNS provider does not support SVCB in service mode | One per `{version, protocol}` pair for versioned registrations; one per protocol for base-only |
| Badge | `_ans-badge.{agentHost}` | TXT | TL badge URL for verification | One per version for versioned registrations; one for the registration for base-only |
| DANE (Server) | `_443._tcp.{agentHost}` | TLSA | Server Certificate fingerprint (selector 0). Active in DNSSEC-signed zones | Shared across versions |
| Identity DANE | `_ans-identity._tls.{agentHost}` | TLSA | Identity Certificate fingerprint. Managed by the AHP, not the RA, per the duty-split rule in §8.1. Absent in base-only registrations | Multi-valued across coexisting ACTIVE versions |

When the last ACTIVE version for an `agentHost` is revoked, the AHP removes all ANS records it provisioned for that FQDN. The RA's revocation response lists the records to delete (see [ANS-1 §6.3](ans-1-registration.md#63-agent_revoked) for the revoke event payload).

### 3.1 Identity DANE coexistence across ACTIVE versions

The `_ans-identity._tls.{agentHost}` TLSA record set is multi-valued: the AHP publishes one TLSA record per active Identity Certificate and prunes on version revocation, so every ACTIVE version retains its DANE pinning during coexistence windows. The RA does not write `_ans-identity._tls` (per the duty-split rule in §8.1); the AHP owns this record.

### 3.2 Discoverer fallback chain

A discoverer (a service or peer agent that wants to look up an agent's metadata) walks three sources in order when assembling that metadata, stopping at the first source that resolves and verifies:

1. `GET https://{agentHost}/.well-known/ans/trust-card.json`. Use the response if reachable and the integrity check (per [ANS-5](ans-5-integrity-monitoring.md)) passes.
2. Otherwise, query DNS for the consolidated SVCB record at `agentHost` (per the consolidated SVCB style below). Use the record if reachable and DNSSEC-valid, or DNSSEC-unsigned and operator-acceptable. Deployments running the legacy style query `_ans.{agentHost}` TXT instead.
3. Otherwise, use the metadata payload from the Transparency Log event the discoverer already consumed from the log's event stream.

The ordering is normative.

When the Trust Card carries a stapled SCITT receipt, the discoverer verifies locally with no Transparency Log call. When the staple is absent, the discoverer fetches the receipt from the Transparency Log once via HTTPS and SHOULD cache it keyed by `(agentId, TL-checkpoint-id)` with a long TTL; subsequent discoveries for the same agent reuse the cache.

## 4. Anchor-conditional emission

### 4.1 Emission table by anchor type

| Anchor profile | Emits | Does not emit |
| --- | --- | --- |
| 0.A FQDN | All records in the record-set table above | - |
| 0.B `did:web` (path-component-bearing or root) | Records under the resolved FQDN of the DID's `<domain>` component | None. The DID's resolved domain has the same emission rules as a direct FQDN registration |
| 0.B `did:plc` | None | All records. The DID method does not bind to an FQDN |
| 0.B `did:key` | None | All records. Pure cryptographic, no domain |
| 0.B `did:ethr` / `did:pkh` | None at the anchor layer; cross-anchor binding to an FQDN registration emits records under the FQDN partner | Records under the chain (no DNS for chain accounts) |
| 0.B `did:ion` | None at the anchor layer; cross-anchor binding to an FQDN may emit | Records under the layer-2 chain |
| 0.C LEI | None at the LEI; cross-anchor binding to an FQDN partner emits records under the FQDN | Records under the LEI itself (LEIs have no FQDN) |

An ANS-3 implementation MUST consult `claim.anchorType` (and, for DID, the method-specific identifier) before generating records and MUST NOT emit records for anchors that do not bind to an FQDN.

For LEI-only base-only registrations without cross-anchor binding (per [ANS-0 §5.3](ans-0-identity-anchor.md#53-lei-status-active)), the registration is metadata-only; no records emit. The TL still records the registration; discovery surfaces it as a known-organization listing rather than a discoverable agent.

### 4.1.1 DNS-side prerequisites for cryptographic verification

DNS-side prerequisites for verification are: DNSSEC signature validity, record presence at expected labels, and (for versioned registrations) correct media-type routing. An ANS-3 implementation MUST publish DNS records at the correct labels with the correct TTL so verifiers can locate them.

### 4.1.2 Activation validations

Before transitioning a registration from `PENDING_DNS` to `ACTIVE`, the RA runs a conformance check to verify the registrant has provisioned the announced records. The table below enumerates the checks and their required outcomes.

| Record type | Validation procedure | Success criterion | Failure handling |
| --- | --- | --- | --- |
| Discovery (consolidated SVCB at `{agentHost}` per §6.1, or legacy `_ans.{agentHost}` TXT per §6.2) | RA performs DNS lookup for the announced discovery record at the style's label | Record resolves to the announced content | Registration stays in `PENDING_DNS`; the RA retries on schedule and the registrant reconciles by publishing the announced record |
| Badge TXT | RA performs DNS lookup for `_ans-badge.{agentHost}` | Record resolves to announced URL | Badge missing is non-fatal; activation proceeds without `_ans-badge` (the badge URL derives from `agentId`) |
| Server DANE TLSA (DNSSEC-signed zones only) | RA performs DNS lookup for `_443._tcp.{agentHost}` TLSA records and validates the DNSSEC chain | At least one TLSA record present and DNSSEC validates to `fully_validated` | DANE validation failure blocks activation; registrant must reconcile TLSA records and retry. The check is skipped in unsigned zones; the registration activates without it. |
| Identity DANE TLSA (versioned only) | RA queries `_ans-identity._tls.{agentHost}` for TLSA records; compares against the version's Identity Certificate | At least one TLSA record fingerprint matches the version's Subject Public Key Info hash; `dnssecStatus` indicates `fully_validated`, `signed_broken`, or `not_signed` | Version with no matching Identity TLSA is non-fatal; version marks `identityDaneStatus: "not_provisioned"` and transitions to ACTIVE |

**`dnssecStatus` enum.** The RA emits one of three values in the activation record:

- `fully_validated`: The TLSA record carries a valid DNSSEC signature chain to the zone's delegated DNSKEY.
- `signed_broken`: The zone is DNSSEC-signed but the record's signature is missing, expired, or fails validation.
- `not_signed`: The zone is not DNSSEC-signed; the record resolves but DNSSEC validation does not apply.

## 5. DNS management roles

| Actor | Initial registration tasks | Ongoing lifecycle tasks | Deregistration tasks |
| --- | --- | --- | --- |
| **AHP** | Owns domain, obtains DNS write credential, manages A/AAAA records. Provisions ANS records using content the RA generates. Provisions `_ans-identity._tls` independently of the RA (per §8.1) | Autonomous DNS updates, monitors renewals, submits config changes. Updates `_ans-identity._tls` on Identity Certificate rotation | Submits deregistration request, revokes RA access |
| **RA** | Generates ACME challenge, verifies record, generates permanent record content (excluding `_ans-identity._tls`) | Re-runs ACME challenge at each renewal and version bump; updates record content | Specifies records for deletion when last ACTIVE version is deregistered |
| **DNS provider** | Hosts authorization endpoint, processes AHP's API requests to provision ANS records | Processes AHP's modification requests | Processes deletion requests from the AHP |

A CNAME at the agent's FQDN blocks HTTPS and SVCB records at the same label (RFC 1034 §3.6.2) but does not affect child-label records (`_ans`, `_ans-badge`, `_443._tcp`). When the RA detects a CNAME, it skips the HTTPS record. CNAME flattening by the DNS provider avoids this restriction entirely.

## 6. Record-style selection

The `dnsRecordStyles` parameter on `DNSEmitter.records()` is an array of style IDs. The bundled set in v0.1.0:

- `ANS_SVCB` (default): SVCB rows at the bare FQDN per §6.1.
- `ANS_TXT`: `_ans` TXT family per §6.2. AHPs whose DNS provider does not support SVCB in service mode pick this.

Default when the field is omitted: `["ANS_SVCB"]`. An AHP migrating between styles requests both: `["ANS_SVCB", "ANS_TXT"]`. New style IDs (consolidated record shapes from cross-spec convergence) plug in as additional adapters without changing the wire.

Selection is per-registration, set at registration time and stored on the aggregate. Both styles emit the `_ans-badge`, DANE Server, and (when versioned) `_ans-identity._tls` records; the difference is in the discovery record (SVCB at the FQDN for `ANS_SVCB`, `_ans` TXT for `ANS_TXT`).

The consolidated profile collapses discovery from three records (`_ans` TXT, `_ans-badge` TXT, `_443._tcp` TLSA) to one SVCB plus one TLSA. A discoverer walks two DNS lookups instead of three. Empirical 90th-percentile DNS-response size on the consolidated profile is 940 bytes, well within the 1,232-byte unfragmented PMTU limit.

### 6.1 Consolidated SVCB (Status: Active, default)

SVCB rows ([RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)) at the agent's `agentHost`, one per protocol, carrying alpn / port / wk / `card-sha256` SvcParams. The row coexists with SvcParams added by other agent-discovery DNS drafts (DNS-AID and parallel work) per RFC 9460 §8 unknown-key handling.

**TLSA pairing.** In DNSSEC-signed zones the consolidated style pairs the SVCB record with one TLSA at `_443._tcp.{agentHost}` for endpoint cert binding (RFC 6698). Together they meet the navigational-completeness target of one SVCB plus one TLSA in a single unfragmented UDP transaction. In unsigned zones the TLSA record carries no DANE assurance and MAY be omitted.

**Record syntax.** `{agentHost} IN SVCB 1 . alpn="h2" port=443 wk="/.well-known/ans/trust-card.json" card-sha256="..."`.

A multi-protocol agent emits one SVCB row per protocol, each carrying the same `wk` and `card-sha256` (the Trust Card is agent-level); rows differ in `alpn`, `port`, and `protocol`. RFC 9460 §3 priority ordering applies; lowest-priority value preferred.

**SvcParams.**

| SvcParam | Value | Required |
| --- | --- | --- |
| `alpn` | ALPN hint (`h2`, `h3`) | Yes |
| `port` | Service port | Conditional (when not 443 for HTTPS-bearing protocols) |
| `wk` | Absolute path to the agent's Trust Card body, served over HTTPS at `agentHost`. ANS publishes the full URI form (e.g., `/.well-known/ans/trust-card.json`) per [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615), matching the IANA-registered A2A well-known URI `/.well-known/agent-card.json` | Yes |
| `card-sha256` | Base64url-encoded SHA-256 digest of the Trust Card body served at `wk`. Covers the same digest bytes the RA seals as `attestations.metadataHashes.capabilitiesHash` in the `AGENT_REGISTERED` TL event; the TL stores hex-lowercase, this SvcParam stores base64url. Verifiers comparing the two MUST decode both to raw bytes before equality check | Yes when the registration submitted Trust Card content |
| `protocol` | Protocol token (`a2a`, `mcp`, `http`) | Yes when the agent speaks more than one protocol |

Per-protocol metadata files (the A2A AgentCard at `/.well-known/agent-card.json`, an MCP server's published card) are NOT the document at `wk` and are NOT covered by `card-sha256`. They are referenced from the Trust Card body's `endpoints[].metaDataUrl` field, and their integrity is sealed only in the TL under `attestations.metadataHashes` keyed by the uppercase protocol token.

**CNAME interaction.** A CNAME at `agentHost` blocks the SVCB record per RFC 1034 §3.6.2. Operators that need both a CNAME and consolidated SVCB MUST use CNAME flattening at the DNS provider. When the RA detects a CNAME, it skips emission of the SVCB row and emits the legacy family alone.

**Cross-channel hash consistency.** When both styles are emitted (`dnsRecordStyles: ["ANS_SVCB", "ANS_TXT"]`), the `_ans` record's `url` host and the SVCB target SHOULD point to the same service. If the SVCB row carries `card-sha256`, its decoded digest bytes MUST equal the bytes the RA sealed as `attestations.metadataHashes.capabilitiesHash` in the TL for the same version. A mismatch is an
integrity finding ([ANS-5 §4](ans-5-integrity-monitoring.md#4-verification-checks)), not a registration failure.

**Coexistence with other drafts.** A discovery client reading consolidated rows SHOULD ignore SvcParams it does not recognize (per RFC 9460 §8) rather than fail closed.

### 6.2 Legacy `_ans` TXT family (Status: Active)

The original `_ans` TXT family. When `p` is set, one record per protocol endpoint; when `p` is omitted, a single record applies to any protocol. Used by deployments whose DNS provider does not support SVCB in service mode, and by deployments registered against the original ANS DNS shape.

**Discovery record syntax:** `_ans.{agentHost} IN TXT "v=ans1; version=v1.0.0; p=a2a; url=https://agent.example.com/.well-known/agent-card.json"`.

| Field | Required | Values |
| --- | --- | --- |
| `v` | Yes | Always `ans1` |
| `version` | Yes when versioned (ANS-2); omitted for base-only | Semver prefixed with `v`. Implementations strip the `v` before comparison |
| `p` | No | `a2a`, `mcp`, `http`. When omitted, the record applies to any protocol |
| `url` | Unless `mode=direct` | URL to the agent's metadata endpoint. Trust Card default: `/.well-known/ans/trust-card.json`. Protocol Card defaults: `/.well-known/agent-card.json` (A2A, IANA-registered), `/.well-known/mcp/server-card.json` (ANS convention) |
| `mode` | Unless `url` present | `card` (default): fetch the file at `url`. `direct`: connect to the FQDN |

**Configurations.** Static card (`mode=card` + metadata URL at agent's FQDN; TL `capabilitiesHash` = SHA-256 of fetched content); dynamic / direct (`mode=direct`, no `url`, `p` required, `capabilitiesHash` null); SaaS delegate (`mode=card`, cross-domain `url`, `delegate: true` in TL event); multi-protocol (one record per protocol, each with its own `p`).

**Badge record syntax (versioned):** `_ans-badge.{agentHost} IN TXT "v=ans-badge1; version=v1.0.0; url=https://{tl_host}/v1/agents/{agentId}"`. **Base-only:** omit `version`. Each ACTIVE version has its own record; versioned and unversioned `_ans-badge` records MUST NOT coexist for the same `agentHost`.

**FQDN anchoring rule.** Every `url` host MUST exactly match the agent's `agentHost`. SaaS delegates register with `delegate: true`; the RA validates domain control of both FQDNs. The TL event MUST include the `delegate` boolean.

**Version coexistence.** Each ACTIVE version gets its own discovery record. A given FQDN's registration is either versioned or base-only at any time; versioned and unversioned records MUST NOT coexist for the same `agentHost`.

**Resolution sequence.** Query all `_ans` TXT records for the FQDN. Filter by `p={target_protocol}`; if no match, select records with no `p` field. If matching records carry `version=`, select the highest semver (or the exact match if the client needs a specific version); if all omit `version=`, select the single base-only record. `mode=direct`: connect to the FQDN. `url` present: fetch. Neither:
fall back to `/.well-known/agent-card.json`.

**Example records.**

```text
; Static card
_ans IN TXT "v=ans1; version=v1.0.0; url=https://agent.example.com/.well-known/agent-card.json"

; Dynamic / direct
_ans IN TXT "v=ans1; version=v1.0.0; p=mcp; mode=direct"

; SaaS delegate (delegate: true in TL event)
_ans IN TXT "v=ans1; version=v2.1.0; url=https://agents.platform.example.com/metadata/agent-0014x"

; Multi-protocol
_ans IN TXT "v=ans1; version=v1.0.0; p=a2a; mode=direct"
_ans IN TXT "v=ans1; version=v1.0.0; p=mcp; url=https://api.example.com/.well-known/mcp/server-card.json"

; Base-only
_ans IN TXT "v=ans1; url=https://agent.example.com/.well-known/ans/trust-card.json"
```

## 7. DNS verification modes

ANS-3 defines two operational modes for DNS verification.

**Lookup-mode.** The verifier queries DNS directly for records and validates DNSSEC where the zone is signed. The RA runs activation validations against live DNS. Registrants provision records before the registration completes (typically through an AHP-side DNS-management step). Lookup-mode is the production-conformant path.

**Noop-bypass.** The verifier accepts DNS records as provided by the RA in the registration event itself, without querying DNS independently. Noop-bypass exists for local testing and single-RA internal use cases where DNS is unavailable or not yet operational. A deployment running noop-bypass is development-only and non-conformant for production; an operator MUST NOT claim ANS-3 conformance while
serving external verifiers from a noop-bypass deployment.

Implementations MUST document which mode each deployment runs and MUST default to lookup-mode for any deployment exposed to external verifiers.

## 8. Security considerations

### 8.1 RA-DNS privilege separation

The RA's DNS permissions MUST exclude TLSA write access. A compromised RA that could write both `_443._tcp.{agentHost}` (Server DANE) and `_ans-identity._tls.{agentHost}` (Identity DANE) TLSA records plus issue a fraudulent Server Certificate could compromise DANE's defense-in-depth in a single action. The RA generates the expected Server TLSA content from the issued Server Certificate; the AHP
publishes both Server TLSA and Identity TLSA to DNS. The split keeps both DANE records under AHP authority while the certificate-issuance authority stays with the RA, and preserves DANE as an independent verification channel.

A compromise of either party alone is detectable through a mismatch in the verification record (mismatched fingerprints, DNSSEC signature failures, or divergent TL evidence). Compromise of both parties simultaneously requires detection by external scoring services and is out of scope for ANS.

### 8.2 Public discoverability of DNS records

ANS-3 records MUST be published in public DNS zones, queryable by any third party via standard DNS lookups (dig, nslookup, DNS library API calls). No private DNS, DNS delegation to an internal nameserver, or proprietary lookup channel is permitted. Public discoverability is a conformance requirement because:

- Verifiers MUST be able to prove the records exist without special access to the domain owner's infrastructure.
- Attestation by independent witnesses (ANS-4 profiles) requires the witness to query the same DNS zone any other verifier would use.
- DNSSEC validation is only meaningful when all verifiers resolve against the same chain of trust.

An implementation that publishes DNS records only to a private zone, requires authentication to query, or uses a proprietary protocol for record lookup is non-conformant even if the record format and content are otherwise correct. Public DNS publication is what makes the records observable to third parties without insider access; private-zone publication defeats observability.

### 8.3 CNAME blocking at the FQDN

A CNAME at `agentHost` blocks HTTPS and apex-level SVCB records (RFC 1034 §3.6.2). The Consolidated Approach SVCB record sits at `agentHost` and is therefore blocked when a CNAME is present. Operators that need both a CNAME (for example, a CDN front-end) and Consolidated Approach SVCB MUST use CNAME flattening at the DNS provider; most major managed-DNS providers support it.

### 8.4 Coexistence with non-ANS DNS records under the same FQDN

Non-ANS agent-discovery specs (DNS-AID, AID, DN-ANR, AgentDNS, ADS, all parallel proposals for DNS-based agent discovery) publish under different underscored leaves (`_agents`, `_agent`, etc.) so their records do not collide with ANS records under `_ans`. SvcParam coexistence on the consolidated SVCB row is covered in §6.1.

## 9. Conformance

A conformant ANS-3 implementation:

1. Exposes a `DNSEmitter` whose `records(reg, styles)` is a pure function over the registration aggregate and the requested style IDs.
2. Honors the anchor-conditional emission table above.
3. Defaults to publishing the consolidated SVCB record (§6.1). In DNSSEC-signed zones, additionally publishes one TLSA at `_443._tcp.{agentHost}` (§6.1 TLSA pairing). AHPs whose DNS provider does not support SVCB in service mode publish the `_ans` TXT family (§6.2). All three paths are conformant; SVCB is the default.
4. Refuses to emit records for anchor types whose emission table cell says "None."
5. Specifies Identity Certificate TLSA record content (`_ans-identity._tls`) only when the registration is versioned (`version` present); the AHP writes the record per §8.1 (the RA MUST NOT write TLSA records).
6. Honors the per-version TTL parameter from operator policy.
7. Operates in lookup-mode for any deployment exposed to external verifiers; declares noop-bypass mode explicitly when used.
8. Publishes records in public DNS, queryable by any third party.


**Optional surface.** Record-style choice (Legacy, Consolidated, or both); DNS verification mode (lookup vs noop-bypass, with noop-bypass non-conformant for external-facing deployments); the TLSA-write duty split (per §8.1, the RA MUST NOT write `_ans-identity._tls`; the AHP MUST); the per-anchor-type emission table that lists "None" for non-FQDN anchors. A conforming verifier MUST NOT downgrade
integrity scoring solely because an operator chose Legacy over Consolidated (or vice versa), and MUST NOT reject a registration because its `claim.anchorType` cell reads "None."

## 11. References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, revocation cleanup.
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md). Version coexistence rules.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md). Verifier worker procedure consuming DNS records.
- DNS record styles defined inline above (Consolidated SVCB, Legacy `_ans` TXT).
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034): DNS concepts (CNAME blocking).
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): DNS implementation (TXT, label limits).
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA records.
- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html): SVCB and HTTPS resource records.

## Appendix A. Annotated zone-file example

A zone-file snippet showing a versioned ANS registration at `ai-agent.acmecorp.com` running two ACTIVE versions (`v2.1.0` stable and `v2.2.0` beta). Record content matches §6 normative syntax. Per-record ownership is annotated.

```text
; ========== ACME Corp ANS Agent Zone Snippet ==========
; Zone: acmecorp.com
; Agent FQDN: ai-agent.acmecorp.com
; Registration: Federated deployment; versioned dual-track (stable v2.1.0, beta v2.2.0)
;
; Record ownership legend:
;   [RA-content]: RA generates the expected content; AHP publishes the record (discovery, badge, Server DANE)
;   [AHP]: AHP both generates content and publishes the record (Identity DANE, A/AAAA, apex SVCB)

; A/AAAA records (AHP)
ai-agent.acmecorp.com.        300  IN A        203.0.113.42
ai-agent.acmecorp.com.        300  IN AAAA     2001:db8::42

; Consolidated SVCB [RA-content] — §6.1
; One row per protocol the agent speaks; rows differ in `alpn`, `port`, `protocol`.
ai-agent.acmecorp.com.        300  IN SVCB 1 . alpn="h2" port=443 wk="/.well-known/ans/trust-card.json" card-sha256="IrioBFc0rTvY4kxS242apNwSkHM395DucEmZmQIfDrk"

; Legacy `_ans` TXT family (emit when `dnsRecordStyles` includes `ANS_TXT`) — §6.2
; One TXT record per ACTIVE version.
_ans.ai-agent.acmecorp.com.   3600 IN TXT      "v=ans1; version=v2.1.0; url=https://ai-agent.acmecorp.com/.well-known/agent-card.json"
_ans.ai-agent.acmecorp.com.   3600 IN TXT      "v=ans1; version=v2.2.0; url=https://ai-agent.acmecorp.com/.well-known/agent-card.json"

; Badge TXT (RA) — §6.2 carries the badge across both styles.
; One per ACTIVE version.
_ans-badge.ai-agent.acmecorp.com. 3600 IN TXT  "v=ans-badge1; version=v2.1.0; url=https://transparency-log.example.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"
_ans-badge.ai-agent.acmecorp.com. 3600 IN TXT  "v=ans-badge1; version=v2.2.0; url=https://transparency-log.example.com/v1/agents/660f9511-f3ac-52e5-b827-557766551111"

; Server DANE TLSA [RA-content] — SHA-256 over the full Server Certificate (ANS-5 §5)
_443._tcp.ai-agent.acmecorp.com. 3600 IN TLSA 3 0 1 (
  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
)

; Identity DANE TLSA (AHP per §8.1) — SHA-256 over the Identity Certificate's SubjectPublicKeyInfo.
; One record per ACTIVE versioned registration.
_ans-identity._tls.ai-agent.acmecorp.com. 3600 IN TLSA 3 1 1 (
  f1e2d3c4b5a6978869584837261504a3
  2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f
)
_ans-identity._tls.ai-agent.acmecorp.com. 3600 IN TLSA 3 1 1 (
  9f8e7d6c5b4a39281716151413121110
  0f0e0d0c0b0a090807060504030201ff
)
```

**Record ownership summary:**

- RA generates expected content for: consolidated SVCB, legacy `_ans` TXT, `_ans-badge` TXT, Server DANE TLSA.
- AHP publishes all DNS records (using RA-generated content where applicable) and additionally generates content for: A/AAAA, Identity DANE TLSA (`_ans-identity._tls`), and the apex SVCB target. The RA has no DNS write access.
- Both may set: TTL, record management cadence (update/delete).

**Dual-version coexistence:**

- Both v2.1.0 and v2.2.0 are ACTIVE; both legacy `_ans` TXT records and both Identity TLSA records coexist.
- The consolidated SVCB row at `agentHost` carries the agent-level Trust Card hash; per-version routing is at the application layer using the badge URLs above.
- Server DANE TLSA is version-agnostic (all versions terminate at the same port).
- Release-track labeling (`stable`, `beta`) lives in the Trust Card's `releaseChannel` field, not in DNS.
- When v2.1.0 is revoked, the RA's revocation response lists the v2.1.0 `_ans` and `_ans-badge` records to delete; the AHP removes v2.1.0's Identity TLSA at the same time.
