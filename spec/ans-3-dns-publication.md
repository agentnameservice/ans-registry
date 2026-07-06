# ANS-3: DNS Publication

Status: DRAFT v1.0
Spec: ANS-3 (DNS Publication)
Version: 0.1.0
Date: 2026-06-29
Audience: implementers building or operating an ANS Registration Authority that emits DNS records and the AHPs that provision them

## 1. Scope

ANS-3 specifies how a registration's facts surface as DNS records an operator publishes and the RA
verifies. The record set is composed from a **set of discovery profiles** — named DNS record
families carried on the registration as `discoveryProfiles`. The bundled set in v0.1.0 is two
profiles, each defined by one document under [`discovery-profiles/`](discovery-profiles/):

- **`ANS_TXT`** (the [ans-txt profile](discovery-profiles/ans-txt.md)) — the original `_ans` TXT
  family plus an HTTPS RR. The **default**, and the family the V1 lane is pinned to. Widely deployed;
  supported indefinitely.
- **`ANS_DNSAID`** (the [ans-dnsaid profile](discovery-profiles/ans-dnsaid.md)) — a DNS-AID-aligned
  SVCB row per protocol endpoint at the bare FQDN, per [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html).
  **Opt-in**, while the DNS-AID-aligned shape is brought to broad conformance.

The core contract here never changes when a profile is added, amended, or retired; per-profile wire
detail lives in the profile documents. That split is the point of [§6](#6-discovery-profiles).

ANS-3 defines:

- The `ProfileEmitter` / `ProfileRegistry` code-interface contract: given a `Registration` and the
  registry of wired profiles, return the records the operator must publish (§2).
- The record set and child-label structure, including the **family trust records** (`_ans-badge`
  TXT and the server-cert TLSA) every ANS-family profile shares (§3, §6.3).
- The activation validations the RA runs against the announced records before a registration
  transitions from `PENDING_DNS` to `ACTIVE` (§4).
- The discovery-profile registry, the profile template, and the composition rules — set semantics,
  registry-wired emission order, dedup, the required-flag transition, and default normalization (§6).
- The DNS management role split between AHP, RA, and DNS provider (§5).

Every record is generated for the agent's `agentHost` — the FQDN primary anchor every registration
carries ([ANS-1](ans-1-registration.md)) — and the child labels under it.

ANS-3 specifies **DNS record generation and publication orchestration**. DANE verification (the
verifier-side procedure of validating TLSA records and matching Server Certificates) spans ANS-3 and
ANS-5. ANS-3 defines the DNS record formats and emission rules; ANS-5 specifies the verifier worker
procedure that consults those records during verification.

ANS-3 does **not** specify:

- The per-profile wire syntax of the `_ans` TXT records, the HTTPS RR, or the SVCB SvcParams. Those
  live in the [discovery-profile documents](discovery-profiles/).
- How the Server Certificate or Identity Certificate is issued. ANS-1 and ANS-2 cover those.
- The verifier-side DANE verification procedure. That is in ANS-5.

## 2. The `ProfileEmitter` and `ProfileRegistry` interface

A discovery profile is a **`ProfileEmitter`**: `ID()` returns its `DiscoveryProfile` wire identifier
(`ANS_TXT`, `ANS_DNSAID`), and `Records(reg)` returns the `ExpectedDNSRecord[]` the operator must
publish for the registration. `Records` is a **pure function** over the registration aggregate — no
I/O, no context, no error — so two conformant implementations MUST produce the same records modulo
TTL choice (operator policy). Each profile returns both its own discovery records and any
family-level trust records it depends on (§6.3), so a profile registered alone produces a complete,
self-contained set.

The RA composes the per-registration record set by walking a **`ProfileRegistry`** — the set of
profiles wired into the deployment — and emitting each profile whose `ID()` is present in
`reg.discoveryProfiles`. The registry is immutable after construction; `IDs()` returns the profiles
in **wiring order**, which is load-bearing: the composed order is sealed byte-for-byte into the TL as
`dnsRecordsProvisioned[]`, so wiring order — not request order — fixes the canonical bytes (§6.4).

A stored profile unknown to the running registry (for example, a value left by a rename or a
profile this deployment does not wire) is **skipped with a WARN, not an error**; a registration
whose every requested profile is unknown falls back to the default set. The wired profile set MUST
equal the valid `DiscoveryProfile` enum: drift in either direction fails RA start rather than
surfacing as a silent verify-dns failure later (§6.4).

## 3. Record set and child-label structure

The RA generates record content for the agent's `agentHost` and for child labels under it. The AHP
or domain owner provisions the records using the content the RA specifies. All child-label records
coexist with an A, AAAA, or CNAME at the FQDN itself, because child labels are separate DNS nodes.

The apex records — the `ANS_DNSAID` SVCB row and the `ANS_TXT` HTTPS RR — sit at `{agentHost}` and
redirect or hint address resolution for SVCB/HTTPS-aware clients per RFC 9460 §3; non-aware clients
continue to follow the A, AAAA, or CNAME.

| Record | Label | Type | Profile | Purpose | Required |
| --- | --- | --- | --- | --- | --- |
| Discovery (`_ans` TXT) | `_ans.{agentHost}` | TXT | `ANS_TXT` (default) | One per endpoint: protocol token + endpoint URL ([ans-txt](discovery-profiles/ans-txt.md)) | Yes |
| Discovery (SVCB) | `{agentHost}` | SVCB | `ANS_DNSAID` (opt-in) | One per endpoint: DNS-AID SvcParams ([ans-dnsaid](discovery-profiles/ans-dnsaid.md)) | Yes (No in the `ANS_TXT` union, §6.4) |
| Connection hint (HTTPS RR) | `{agentHost}` | HTTPS | `ANS_TXT` | `1 . alpn=h2` service binding | No (CNAME at apex precludes it) |
| Badge | `_ans-badge.{agentHost}` | TXT | family (every profile) | TL badge URL for verification (§6.3) | Yes |
| Server DANE | `_{port}._tcp.{agentHost}` | TLSA | family (every profile) | Server Certificate fingerprint (`3 0 1`, selector 0); one per distinct TLS endpoint port (§6.3) | No (verify-side enforces a match when DNSSEC-validated) |

When the last ACTIVE version for an `agentHost` is revoked, the AHP removes all ANS records it
provisioned for that FQDN. The RA's revocation response lists the records to delete (see
[ANS-1 §6.3](ans-1-registration.md#63-agent_revoked) for the revoke event payload).

### 3.1 Discoverer fallback chain

A discoverer (a service or peer agent that wants to look up an agent's metadata) walks three sources
in order when assembling that metadata, stopping at the first source that resolves and verifies:

1. `GET https://{agentHost}/.well-known/ans/trust-card.json`. Use the response if reachable and the
   integrity check (per [ANS-5](ans-5-integrity-monitoring.md)) passes.
2. Otherwise, query DNS for the registration's discovery records. With `ANS_DNSAID`, read the SVCB
   row at `agentHost` and follow its per-endpoint capability locator (`key65400` / `key65409`); with
   `ANS_TXT`, read the `_ans.{agentHost}` TXT records and follow each row's `url` (`mode=direct`).
   Use the record if reachable and DNSSEC-valid, or DNSSEC-unsigned and operator-acceptable.
3. Otherwise, use the metadata payload from the Transparency Log event the discoverer already
   consumed from the log's event stream.

The ordering is normative.

## 4. Activation validations

DNS-side prerequisites for verification are: DNSSEC signature validity, record presence at expected
labels, and (for versioned registrations) correct media-type routing. An ANS-3 implementation MUST
publish DNS records at the correct labels with the correct TTL so verifiers can locate them.

Before transitioning a registration from `PENDING_DNS` to `ACTIVE`, the RA runs a conformance check
to verify the registrant has provisioned the announced records. The table below enumerates the
checks and their required outcomes. "Announced" means the records the composed profile set emitted
into `dnsRecordsProvisioned[]` for this registration.

| Record type | Validation procedure | Success criterion | Failure handling |
| --- | --- | --- | --- |
| Discovery (the `_ans.{agentHost}` TXT for `ANS_TXT`, the `{agentHost}` SVCB for `ANS_DNSAID`, per §6) | RA performs a DNS lookup for each announced discovery record at its label | Each required discovery record resolves to the announced content | Registration stays in `PENDING_DNS`; the RA retries on schedule and the registrant reconciles by publishing the announced record |
| Badge TXT | RA performs a DNS lookup for `_ans-badge.{agentHost}` | Record resolves to the announced URL | The badge is emitted `Required` (§6.3); a missing badge keeps the registration in `PENDING_DNS` until reconciled |
| Server DANE TLSA (DNSSEC-signed zones only) | RA performs a DNS lookup for each `_{port}._tcp.{agentHost}` TLSA and validates the DNSSEC chain | At least one TLSA record present and DNSSEC validates to `fully_validated` | The TLSA is emitted `Required=false`; in a signed zone a DNSSEC-validated TLSA that does **not** match the expected fingerprint is an attack signal and blocks activation. The check is skipped in unsigned zones; the registration activates without it |

**`dnssecStatus` enum.** The RA emits one of three values in the activation record:

- `fully_validated`: The TLSA record carries a valid DNSSEC signature chain to the zone's delegated DNSKEY.
- `signed_broken`: The zone is DNSSEC-signed but the record's signature is missing, expired, or fails validation.
- `not_signed`: The zone is not DNSSEC-signed; the record resolves but DNSSEC validation does not apply.

## 5. DNS management roles

| Actor | Initial registration tasks | Ongoing lifecycle tasks | Deregistration tasks |
| --- | --- | --- | --- |
| **AHP** | Owns domain, obtains DNS write credential, manages A/AAAA records. Provisions ANS records using content the RA generates | Autonomous DNS updates, monitors renewals, submits config changes | Submits deregistration request, revokes RA access |
| **RA** | Generates ACME challenge, verifies record, generates permanent record content | Re-runs ACME challenge at each renewal and version bump; updates record content | Specifies records for deletion when last ACTIVE version is deregistered |
| **DNS provider** | Hosts authorization endpoint, processes AHP's API requests to provision ANS records | Processes AHP's modification requests | Processes deletion requests from the AHP |

A CNAME at the agent's FQDN blocks apex-level HTTPS and SVCB records (RFC 1034 §3.6.2) but does not
affect child-label records (`_ans`, `_ans-badge`, `_{port}._tcp`). It therefore blocks the `ANS_TXT`
HTTPS RR and the `ANS_DNSAID` SVCB row, which both sit at the apex. When the RA detects a CNAME it
skips the apex record; CNAME flattening by the DNS provider avoids this restriction entirely.

## 6. Discovery profiles

A registration carries a **set** of discovery profiles in `discoveryProfiles`. Each profile is one
DNS record family; the bundled set is `ANS_TXT` (default) and `ANS_DNSAID` (opt-in). New families
plug in as additional `ProfileEmitter` adapters without changing the core contract or the wire.

`discoveryProfiles` is **set semantics**: when omitted or sent as an empty array it normalizes to
the default `["ANS_TXT"]`; the V1 lane is pinned to `["ANS_TXT"]` regardless of request; an operator
opts into `ANS_DNSAID` explicitly, alone or in the `["ANS_DNSAID", "ANS_TXT"]` transition union.
Request order carries no meaning — emission order is the registry's wiring order (§6.4).

### 6.1 The discovery-profile registry

This table is authoritative; the [`discovery-profiles/README.md`](discovery-profiles/README.md) index
mirrors it.

| Profile | Document | Requirement | Discovery records | Status |
| --- | --- | --- | --- | --- |
| `ANS_TXT` | [discovery-profiles/ans-txt.md](discovery-profiles/ans-txt.md) | Default | `_ans` TXT (one per endpoint) + an HTTPS RR at the FQDN | Active |
| `ANS_DNSAID` | [discovery-profiles/ans-dnsaid.md](discovery-profiles/ans-dnsaid.md) | Optional (opt-in) | SVCB (one per endpoint) at the FQDN, DNS-AID SvcParams | Active |

**Status meanings.** **Active** — wired, tested, emitting real records an operator publishes and the
RA verifies at verify-dns. **Default / Opt-in** is the requirement axis, not the status: both
profiles are Active; `ANS_TXT` is the default set and `ANS_DNSAID` is opt-in (the operator must name
it) while the DNS-AID-aligned SVCB shape is brought to broad conformance.

### 6.2 The profile template

Every discovery-profile document specifies, in this order:

1. Records, labels, and selection.
2. Record assembly — the exact value form and parameter composition, in order.
3. Parameter sources — where each field's value comes from, and the selection rules.
4. Required flag and what the profile seals into `dnsRecordsProvisioned[]`.
5. Freshness and ANS-5 monitoring.
6. Lifecycle (version coexistence, revocation cleanup).
7. Coexistence and presentation safety.
8. Error codes.
9. Status and requirement.
10. Object schemas — worked record examples.

A profile only ever varies the **discovery records** layered on the shared family trust records
(§6.3). All profiles share the one composition walker (§6.4) and the one validation flow (§4).

### 6.3 Family trust records

Both ANS-family profiles emit two shared trust records, deduped to a single instance at the
composition walker (§6.4). They are emitted by whichever profile(s) the registration selects, so a
profile registered alone still produces them:

- **Badge** — `_ans-badge.{agentHost}` TXT, value `v=ans-badge1; version={version}; url={badgeURL}`,
  where `{version}` is the registration's semver with no `v` prefix and `{badgeURL}` is the
  Transparency Log badge endpoint for the agent (`{tlPublicBaseURL}/v1/agents/{agentId}`), falling
  back to the agent's first endpoint URL when no public TL URL is configured. Emitted only when the
  registration has at least one endpoint. **`Required=true`**: a badge-verifying client will not
  trust an agent whose discovery records publish without a paired badge.
- **Server DANE TLSA** — `_{port}._tcp.{agentHost}` TLSA, value `3 0 1 {fingerprint}` (DANE-EE,
  full-certificate selector 0, SHA-256 — the fingerprint is SHA-256 over the full DER Server
  Certificate, matching the badge fingerprint in the TL). One record per **distinct TLS endpoint
  port** (ports sorted ascending; plaintext `http` endpoints skipped; an empty port set falls back
  to `443`), so a DANE client connecting to a non-443 endpoint finds a record at `_{its-port}._tcp`.
  Emitted only when the registration has a server certificate. **`Required=false`**: a TLSA is only
  meaningful in a DNSSEC-signed zone, a runtime property the record set cannot know; the verify layer
  enforces the stricter rule that a DNSSEC-validated TLSA MUST match the expected fingerprint
  (§4).

### 6.4 Composition: ordering, dedup, and the required-flag transition

The RA composes `dnsRecordsProvisioned[]` by walking the registry:

1. **Resolve the set.** Filter `reg.discoveryProfiles` to the profiles the registry has wired.
   Empty after filtering (the field was omitted, or every entry was unknown to the registry)
   normalizes to the default `["ANS_TXT"]`. An unknown stored profile is skipped with a WARN; an
   all-unknown request falls back to the default with a distinct WARN so it is not mistaken for an
   operator zone error at verify-dns.
2. **Walk in wiring order.** Iterate the registry's `IDs()` (the bundled wiring is
   `[ANS_TXT, ANS_DNSAID]`, so emission proceeds TXT-first, then SVCB) and collect each resolved
   profile's full record list. Request order on `discoveryProfiles` has no effect.
3. **Dedup by `(name, type, value)`.** The family trust records (`_ans-badge`, the Server TLSA)
   that overlap across sibling profiles emit once; first-seen wins. The dedup key omits `Required`,
   so sibling profiles MUST agree on the flag for a shared record (both do — badge `true`, TLSA
   `false`).
4. **Group discovery-then-trust.** Discovery records first (in walker order), then the trust records
   (badge, TLSA). The canonical wire order for the union case is `[TXT×N, HTTPS, SVCB×N, badge,
   TLSA]`; this pins the TL `dnsRecordsProvisioned[]` canonical bytes.
5. **Required-flag transition.** SVCB rows arrive from the `ANS_DNSAID` adapter with
   `Required=true`. When `ANS_TXT` is also in the resolved set, every SVCB row is flipped to
   `Required=false`: during the transition the legacy `_ans` TXT family carries the operator's
   required signal and SVCB rides along as optional.

**Validation.** Each `discoveryProfiles` element MUST be a valid `DiscoveryProfile`; an unrecognized
value is rejected at the API boundary with `422 INVALID_DISCOVERY_PROFILE`. Duplicate elements are
deduped (first occurrence wins) and an empty array normalizes to the default — the OpenAPI
`minItems: 1` and `uniqueItems: true` are the canonical client contract, which the server normalizes
rather than rejecting. The wired registry and the valid `DiscoveryProfile` enum MUST be identical;
the RA asserts this coherence at server start and refuses to start on drift.

## 7. DNS verification modes

ANS-3 defines two operational modes for DNS verification.

**Lookup-mode.** The verifier queries DNS directly for records and validates DNSSEC where the zone
is signed. The RA runs activation validations against live DNS. Registrants provision records before
the registration completes (typically through an AHP-side DNS-management step). Lookup-mode is the
production-conformant path.

**Noop-bypass.** The verifier accepts DNS records as provided by the RA in the registration event
itself, without querying DNS independently. Noop-bypass exists for local testing and single-RA
internal use cases where DNS is unavailable or not yet operational. A deployment running noop-bypass
is development-only and non-conformant for production; an operator MUST NOT claim ANS-3 conformance
while serving external verifiers from a noop-bypass deployment.

Implementations MUST document which mode each deployment runs and MUST default to lookup-mode for
any deployment exposed to external verifiers.

## 8. Security considerations

### 8.1 RA-DNS privilege separation

The RA's DNS permissions MUST exclude TLSA write access. A compromised RA that could write the
`_{port}._tcp.{agentHost}` (Server DANE) TLSA record plus issue a fraudulent Server Certificate
could compromise DANE's defense-in-depth in a single action. The RA generates the expected Server
TLSA *content* from the issued Server Certificate; the AHP publishes it to DNS. The split keeps the
DANE record under AHP authority while the certificate-issuance authority stays with the RA, and
preserves DANE as an independent verification channel.

A compromise of either party alone is detectable through a mismatch in the verification record
(mismatched fingerprints, DNSSEC signature failures, or divergent TL evidence). Compromise of both
parties simultaneously requires detection by external scoring services and is out of scope for ANS.

### 8.2 Public discoverability of DNS records

ANS-3 records MUST be published in public DNS zones, queryable by any third party via standard DNS
lookups (dig, nslookup, DNS library API calls). No private DNS, DNS delegation to an internal
nameserver, or proprietary lookup channel is permitted. Public discoverability is a conformance
requirement because:

- Verifiers MUST be able to prove the records exist without special access to the domain owner's infrastructure.
- Attestation by independent witnesses (ANS-4 profiles) requires the witness to query the same DNS zone any other verifier would use.
- DNSSEC validation is only meaningful when all verifiers resolve against the same chain of trust.

An implementation that publishes DNS records only to a private zone, requires authentication to
query, or uses a proprietary protocol for record lookup is non-conformant even if the record format
and content are otherwise correct.

### 8.3 CNAME blocking at the FQDN

A CNAME at `agentHost` blocks apex-level HTTPS and SVCB records (RFC 1034 §3.6.2). The `ANS_DNSAID`
SVCB row and the `ANS_TXT` HTTPS RR both sit at `agentHost` and are therefore blocked when a CNAME is
present. Operators that need both a CNAME (for example, a CDN front-end) and an apex record MUST use
CNAME flattening at the DNS provider; most major managed-DNS providers support it. The `_ans` TXT
child label is unaffected, so `ANS_TXT` discovery still functions behind an apex CNAME.

### 8.4 Coexistence with other DNS records under the same FQDN

`ANS_DNSAID` is ANS's own DNS-AID-aligned profile: its draft-02 params (`cap`, `cap-sha256`, `bap`,
`well-known`) ride the SVCB row in the RFC 9460 §14.3.1 Private Use `keyNNNNN` presentation form
(`key65400`–`key65409`), which generic SVCB clients ignore per the §8 unknown-key rule. The
`metadataUrl` that feeds `cap` and `well-known` is validated at registration to be free of every
byte the SVCB presentation format escapes, so the published value stays byte-identical to what a
verifier observes (see the [ans-dnsaid profile](discovery-profiles/ans-dnsaid.md)). Other
agent-discovery specs (AID, DN-ANR, AgentDNS, ADS) publish under different underscored leaves
(`_agents`, `_agent`, …) so their records do not collide with the ANS `_ans` family.

## 9. Conformance

A conformant ANS-3 implementation:

1. Exposes one or more `ProfileEmitter`s composed through a `ProfileRegistry`; each `Records(reg)`
   is a pure function over the registration aggregate, and the RA composes them per the rules in §6.4.
2. Defaults `discoveryProfiles` to `["ANS_TXT"]` when the field is omitted or empty, pins the V1 lane
   to `["ANS_TXT"]`, treats `ANS_DNSAID` as opt-in, and supports the `["ANS_DNSAID", "ANS_TXT"]`
   union. All paths are conformant; `ANS_TXT` is the default.
3. Runs the activation validations (§4) before transitioning a registration from `PENDING_DNS` to
   `ACTIVE`.
4. Emits the family trust records (§6.3): the `_ans-badge` TXT (`Required`) and one Server DANE TLSA
   per distinct TLS endpoint port (`Required=false`), deduped to a single instance across sibling
   profiles.
5. For `ANS_DNSAID`, emits one SVCB row per endpoint at the FQDN with the DNS-AID SvcParams in the
   RFC 9460 §14.3.1 Private Use `keyNNNNN` presentation form, never the named DNS-AID forms.
6. Validates `discoveryProfiles` (`INVALID_DISCOVERY_PROFILE` on an unknown element) and asserts
   registry/enum coherence at server start.
7. Honors the per-version TTL parameter from operator policy.
8. Operates in lookup-mode for any deployment exposed to external verifiers; declares noop-bypass
   mode explicitly when used.
9. Publishes records in public DNS, queryable by any third party.

**Optional surface.** Discovery-profile choice (`ANS_TXT`, `ANS_DNSAID`, or the union); DNS
verification mode (lookup vs noop-bypass, with noop-bypass non-conformant for external-facing
deployments); the TLSA-write duty split (per §8.1, the RA generates TLSA content but MUST NOT write
it; the AHP publishes it). A conforming verifier MUST NOT downgrade integrity scoring solely because
an operator chose `ANS_TXT` over `ANS_DNSAID` (or vice versa).

## References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, revocation cleanup.
- ANS-2 specification: [`ans-2-versioned-naming.md`](ans-2-versioned-naming.md). Version coexistence rules.
- ANS-5 specification: [`ans-5-integrity-monitoring.md`](ans-5-integrity-monitoring.md). Verifier worker procedure consuming DNS records.
- Discovery profiles: [`discovery-profiles/`](discovery-profiles/) — [ANS_TXT](discovery-profiles/ans-txt.md), [ANS_DNSAID](discovery-profiles/ans-dnsaid.md).
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034): DNS concepts (CNAME blocking).
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): DNS implementation (TXT, label limits).
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698): DANE TLSA records.
- [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615): well-known URIs.
- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html): SVCB and HTTPS resource records.

## Appendix A. Annotated zone-file example

A zone-file snippet showing a versioned ANS registration at `ai-agent.acmecorp.com` running the
transition union (`discoveryProfiles: ["ANS_DNSAID", "ANS_TXT"]`) with two protocol endpoints (A2A
on 443, MCP on 8443). Record content matches §3 and §6 normative syntax. Per-record ownership is
annotated.

```text
; ========== ACME Corp ANS Agent Zone Snippet ==========
; Zone: acmecorp.com
; Agent FQDN: ai-agent.acmecorp.com
; Registration: versioned (v2.1.0); discoveryProfiles: ["ANS_DNSAID", "ANS_TXT"]
;
; Record ownership legend:
;   [RA-content]: RA generates the expected content; AHP publishes the record (discovery, badge, Server DANE)
;   [AHP]: AHP both generates content and publishes the record (A/AAAA)

; A/AAAA records (AHP)
ai-agent.acmecorp.com.        300  IN A        203.0.113.42
ai-agent.acmecorp.com.        300  IN AAAA     2001:db8::42

; ANS_TXT discovery [RA-content] — one `_ans` TXT per endpoint; version has no `v` prefix; mode=direct
_ans.ai-agent.acmecorp.com.   3600 IN TXT      "v=ans1; version=2.1.0; p=a2a; mode=direct; url=https://ai-agent.acmecorp.com/a2a"
_ans.ai-agent.acmecorp.com.   3600 IN TXT      "v=ans1; version=2.1.0; p=mcp; mode=direct; url=https://ai-agent.acmecorp.com:8443/mcp"

; ANS_TXT connection hint [RA-content] — one HTTPS RR at the apex (Required=false)
ai-agent.acmecorp.com.        3600 IN HTTPS    1 . alpn=h2

; ANS_DNSAID discovery [RA-content] — one SVCB row per endpoint at the apex; DNS-AID SvcParams in
; keyNNNNN Private-Use form; Required=false here because ANS_TXT is also in the set (§6.4).
ai-agent.acmecorp.com.        3600 IN SVCB     1 . alpn=a2a port=443 key65400=https://ai-agent.acmecorp.com/.well-known/agent-card.json key65401=CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc key65402=a2a key65409=agent-card.json
ai-agent.acmecorp.com.        3600 IN SVCB     1 . alpn=mcp port=8443 key65402=mcp

; Badge TXT [RA-content] — family record; one per registration; points at the TL badge endpoint
_ans-badge.ai-agent.acmecorp.com. 3600 IN TXT  "v=ans-badge1; version=2.1.0; url=https://transparency-log.example.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"

; Server DANE TLSA [RA-content] — family record; one per distinct TLS port (443 and 8443); 3 0 1 over the full Server Certificate
_443._tcp.ai-agent.acmecorp.com.  3600 IN TLSA 3 0 1 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
_8443._tcp.ai-agent.acmecorp.com. 3600 IN TLSA 3 0 1 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

**Record ownership summary:**

- RA generates expected content for: `ANS_TXT` `_ans` TXT, `ANS_TXT` HTTPS RR, `ANS_DNSAID` SVCB, `_ans-badge` TXT, Server DANE TLSA.
- AHP publishes all DNS records (using RA-generated content where applicable) and additionally generates content for: A/AAAA. The RA has no DNS write access.
- Both may set: TTL, record management cadence (update/delete).

**Union and version notes:**

- With `["ANS_DNSAID", "ANS_TXT"]`, both families' discovery records coexist; the `_ans` TXT rows carry the required signal and the SVCB rows are `Required=false` (§6.4).
- The composed canonical order sealed into `dnsRecordsProvisioned[]` is `[_ans TXT×N, HTTPS, SVCB×N, badge, TLSA×ports]`.
- Server DANE TLSA is per distinct TLS port; both 443 and 8443 carry the same full-certificate fingerprint (the cert is FQDN-scoped, not per-port).
- When v2.1.0 is revoked, the RA's revocation response lists the v2.1.0 `_ans`, SVCB, and `_ans-badge` records to delete.
