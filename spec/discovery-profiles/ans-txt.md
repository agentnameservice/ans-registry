# Discovery profile: `ANS_TXT`

Status: DRAFT v1.0
Profile: ANS_TXT (the original `_ans` TXT family)
Core: [ANS-3: DNS Publication](../ans-3-dns-publication.md)
Version: 0.1.0
Date: 2026-06-29
Audience: implementers building an ANS-conformant Registration Authority

`ANS_TXT` is the original `_ans` TXT family — **opt-in** on the V2 lane (the default is
[ANS_DNSAID](ans-dnsaid.md)) and the profile the V1 lane is pinned to. It emits one `_ans` TXT
record per protocol endpoint plus a single HTTPS RR at the agent's bare FQDN, alongside the
ANS-family trust records
([ANS-3 §6.3](../ans-3-dns-publication.md#63-family-trust-records)). Supported indefinitely for
operators whose zone-edit tooling targets `_ans.{fqdn}` and whose DNS provider does not run SVCB in
service mode.

## 1. Records, labels, and selection

- **Selection**: the `ANS_TXT` token in the registration's `discoveryProfiles` set. Opt-in on the
  V2 lane — an operator names it explicitly, alone or in the `["ANS_DNSAID", "ANS_TXT"]` transition
  union; the V1 lane is pinned to it regardless of request
  ([ANS-3 §6.4](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)).
- **Records** (emitted only when the registration has at least one endpoint):
  - one `_ans.{fqdn}` **TXT** discovery record per endpoint, at the `_ans` child label;
  - one **HTTPS** RR at the bare `{fqdn}` (apex), as the connection hint `_ans` TXT cannot carry.
- Plus the required family `_ans-badge` TXT locator (ANS-3 §6.3).
- A profile with no eligible endpoints emits no `_ans` TXT or HTTPS RR. A bare HTTPS RR with no
  `_ans` companions is not emitted. V3 registration itself still requires at least one endpoint.

## 2. Record assembly

**`_ans` TXT discovery record**, one per endpoint, value built in this fixed field order:

```text
v=ans1; version=v{version}; p={protocol-token}; mode=direct; url={agentUrl}
```

- `v` — always `ans1`.
- `version` — the registration's semantic version, **prefixed with `v`** (e.g. `v1.0.0`), matching
  the ANSName's version segment (ANS-2). Omit this entire pair for a versionless registration.
- `p` — the protocol token (§3): `a2a`, `mcp`, or `http-api`.
- `mode` — always `direct` on every emitted row.
- `url` — the endpoint's `agentUrl`, verbatim.

**HTTPS RR**, one per registration, at the bare `{fqdn}`:

```text
1 . alpn=h2
```

SvcPriority `1` (ServiceMode), TargetName `.` (the origin — the owner name itself), `alpn=h2`
(HTTP/2 service binding).

## 3. Parameter sources and selection

- `version` ← the optional registration version (ANS-2), rendered with a `v` prefix when present; otherwise omit the pair.
- `p` ← the endpoint's protocol, mapped to the `_ans` token: `A2A`→`a2a`, `MCP`→`mcp`,
  `HTTP_API`→`http-api`. (A future protocol added to the domain layer passes through unchanged.)
  The `ANS_DNSAID` profile maps `HTTP_API` to `x-http` instead; the two families share `a2a`/`mcp`
  but diverge on the HTTP token.
- `url` ← the endpoint's `agentUrl`. ANS-1 requires the authority of every `agentUrl` to equal the
  agent's `agentHost`, so the published `url` always lives under the agent's FQDN.
- `mode` ← the constant `direct`.

One `_ans` TXT row is emitted per endpoint, in endpoint order; the HTTPS RR is emitted once.

## 4. Required flag and TL seal

| Record | Required | Note |
| --- | --- | --- |
| `_ans.{fqdn}` TXT | **Yes** | The discovery record. verify-dns blocks activation until it resolves to the announced content |
| `{fqdn}` HTTPS RR | No | A CNAME at the apex precludes publishing an HTTPS RR (RFC 1034 §3.6.2); its absence is non-fatal |
| `_ans-badge` TXT (family) | Yes | ANS-3 §6.3 |

Generated instructions carry TTL `3600`. The RA attests the observed applicable production
records into the event's `dnsRecordsProvisioned[]`
([ANS-3 §3](../ans-3-dns-publication.md#3-record-set-and-child-label-structure)). When the resolved
set also includes `ANS_DNSAID`, the `_ans` TXT rows keep `Required=true` and carry the operator's
required signal for the transition union, while the sibling SVCB rows ride along as `Required=false`
([ANS-3 §6.4](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)).

## 5. Freshness and ANS-5 monitoring

Records carry TTL `3600`. ANS-5's DNS-pointer check re-queries the `_ans.{fqdn}` records and
validates DNSSEC where the zone is signed; the check is profile-agnostic and consults this profile's
expected records through the ANS-3 composition contract ([ANS-5 §4](../ans-5-integrity-monitoring.md#4-verification-checks)).

## 6. Lifecycle specifics

The `_ans` records are per-registration: one row per endpoint for the registration's version. Version
coexistence across registrations is an ANS-1/ANS-2 concern
([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations)); every `_ans` family row carries its
optional registration version. On revocation of the last
ACTIVE registration the AHP removes the `_ans`, HTTPS, and family records the RA's revocation response
lists.

## 7. Coexistence and presentation safety

- **CNAME at the apex** blocks the HTTPS RR (RFC 1034 §3.6.2), which is why it is `Required=false`;
  operators needing both a CNAME and an apex HTTPS RR use CNAME flattening at the provider. The
  `_ans` child label is a separate DNS node and is unaffected by a CNAME at the apex.
- **Sibling agent-discovery drafts** publish under different underscored leaves (`_agents`,
  `_agent`, …); `_ans` does not collide with them (ANS-3 §8.4).
- **Presentation**: `_ans` TXT values are free-form character-strings; this profile has none of the
  SVCB SvcParam presentation-escaping constraints `ANS_DNSAID` carries.

## 8. Error codes

This profile defines no codes of its own. Endpoint and URL validation surface the core
`INVALID_ENDPOINT`, `ENDPOINT_HOST_MISMATCH`, `DUPLICATE_ENDPOINT`, and `DUPLICATE_PROTOCOL`
validation errors (ANS-1); a `discoveryProfiles` element naming no wired profile is rejected with
`INVALID_DISCOVERY_PROFILE` (ANS-3 §6.4). A verify-dns mismatch keeps the registration in
`PENDING_DNS` and the operator reconciles by publishing the announced record (ANS-3 §4).

## 9. Status and requirement

**Requirement: Optional (opt-in) on the V2 lane; pinned on V1.** An operator names `ANS_TXT`
explicitly — alone, or in the `["ANS_DNSAID", "ANS_TXT"]` transition union, where the `_ans` TXT
rows carry the required signal (§4). The V1 lane never consults the default and is always pinned to
`ANS_TXT`. Opt-in is a requirement statement, not a deprecation signal: the profile is supported
indefinitely.

**Status: Active.** The original, fully-implemented `_ans` shape, sealing and verifying real
records.

## 10. Object schemas (worked example)

A single A2A endpoint at `https://agent.example.com/a2a`, version `1.0.0`, with a server certificate
on file:

```text
; discovery record — one per endpoint
_ans.agent.example.com.        3600 IN TXT   "v=ans1; version=v1.0.0; p=a2a; mode=direct; url=https://agent.example.com/a2a"

; connection hint — one per registration, at the apex
agent.example.com.             3600 IN HTTPS 1 . alpn=h2

; family trust records (ANS-3 §6.3) — shared with any sibling profile, deduped once
_ans-badge.agent.example.com.  3600 IN TXT   "v=ans-badge1; version=v1.0.0; url=https://transparency-log.example.com/v1/agents/{agentId}"
```

The RA's DNS instructions include publication details such as TTL and required flags. Sealed records use `name`, `type`, `data` and optional `dnssecVerified` for observed production
state.
