# Discovery profile: `ANS_DNSAID`

Status: DRAFT v1.0
Profile: ANS_DNSAID (the DNS-AID-aligned SVCB family)
Core: [ANS-3: DNS Publication](../ans-3-dns-publication.md)
Version: 0.1.0
Date: 2026-06-29
Audience: implementers building an ANS-conformant Registration Authority

`ANS_DNSAID` emits one SVCB record ([RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)) per
protocol endpoint at the agent's bare FQDN, carrying its connection hints and per-endpoint
capability locators in DNS-AID draft-02 SvcParams. It is **opt-in** — an operator names it
explicitly — while the DNS-AID-aligned shape is brought to broad conformance; the stable default is
[ANS_TXT](ans-txt.md). It is self-contained: registering `ANS_DNSAID` alone also emits the ANS-family
trust records ([ANS-3 §6.3](../ans-3-dns-publication.md#63-family-trust-records)).

## 1. Records, labels, and selection

- **Selection**: the `ANS_DNSAID` token in the registration's `discoveryProfiles` set. Not in the
  default set; the operator opts in, alone or in the `["ANS_DNSAID", "ANS_TXT"]` transition union
  ([ANS-3 §6.4](../ans-3-dns-publication.md#64-composition-ordering-dedup-and-the-required-flag-transition)).
- **Records** (one per endpoint, emitted only when the registration has at least one endpoint):
  one **SVCB** row at the bare `{fqdn}` (apex), in ServiceMode.
- Plus the family trust records — `_ans-badge` TXT and the server-cert TLSA (ANS-3 §6.3). This
  profile emits **no** HTTPS RR; the SVCB row is itself the service binding.

## 2. Record assembly

One SVCB row per endpoint, value composed in **ascending SvcParamKey order**:

```text
1 . alpn={token} port={n} [key65400={metadataUrl}] [key65401={cap-sha256}] key65402={token} [key65409={wk-suffix}]
```

- `1 .` — SvcPriority `1` (ServiceMode), TargetName `.` (the origin — the owner name itself).
- `alpn={token}` — the DNS-AID protocol token (§3): `a2a`, `mcp`, or `x-http`. It distinguishes
  protocols within the same RRset. (This carries the DNS-AID agent-protocol token, not an
  IANA-registered TLS ALPN identifier.)
- `port={n}` — the TCP port from the endpoint URL authority; defaults to `443` (https) / `80`
  (http) when the URL omits one.
- `key65400={metadataUrl}` (DNS-AID `cap`) — the endpoint's capability locator (`metadataUrl`),
  emitted **only** when the endpoint supplies one.
- `key65401={cap-sha256}` (DNS-AID `cap-sha256`) — `base64url(raw SHA-256)` of the endpoint's
  metadata document, derived from the endpoint's `metadataHash`. Absent when no hash is supplied
  (or it is malformed).
- `key65402={token}` (DNS-AID `bap`) — the agent protocol, emitted on **every** row. It currently
  equals `alpn`, but DNS-AID consumers read `bap` as the authoritative agent-protocol field, so it
  is always present.
- `key65409={wk-suffix}` (DNS-AID `well-known`) — the RFC 8615 suffix derived from `metadataUrl`,
  emitted **only** when the `metadataUrl` sits at `https://{fqdn}/.well-known/{suffix}` (§3).

**Private-Use presentation form is mandatory.** The DNS-AID draft's named params
(`cap` / `cap-sha256` / `bap` / `well-known`) have no IANA-assigned code point, so they MUST be
emitted in the `keyNNNNN` presentation form (RFC 9460 §2.1). The named forms are unpublishable: the
zone parsers and managed-DNS providers in the path reject `cap=` / `bap=` with "bad SVCB key", and a
lookup verifier only ever observes live records in `keyNNNNN` form. `key65400`–`key65409` sit in the
RFC 9460 §14.3.1 Private Use range (65280–65534) and match DNS-AID draft-02 §4's IANA-Considerations
assignments.

**Deliberately not emitted.** `mandatory=` — marking any of these keys mandatory would make the
whole record invisible to every generic RFC 9460 client that does not understand the key, defeating
the §8 coexistence goal. `ipv4hint` / `ipv6hint` — the RA knows endpoint URLs, not addresses;
registry-sourced address hints go stale and are out of scope.

## 3. Parameter sources and selection

- `alpn` / `bap` ← the endpoint's protocol, mapped to the DNS-AID token: `A2A`→`a2a`, `MCP`→`mcp`,
  `HTTP_API`→`x-http`. The `x-` prefix makes the HTTP token a valid DNS-AID draft-02
  `extension-protocol` (`a2a` / `mcp` are the built-in protocols; everything else MUST be
  `x-`-prefixed). `ANS_TXT` uses `http-api` for the same protocol — the two families diverge on the
  HTTP token only.
- `port` ← the endpoint URL authority; `443` (https) / `80` (http) default. An out-of-range port is
  rejected at registration (`INVALID_ENDPOINT`).
- `key65400` (cap) ← the endpoint's `metadataUrl`, emitted verbatim.
- `key65401` (cap-sha256) ← the endpoint's `metadataHash` (`SHA256:<64 lowercase hex>`), converted
  to `base64url(raw 32 bytes)`, no padding.
- `key65409` (well-known) ← derived from the `metadataUrl` path, and only when the URL is exactly
  `https://{fqdn}/.well-known/{suffix}`: same scheme (https), same host as the agent FQDN
  (port-, case-, and trailing-dot-insensitive), and a single non-empty trailing path segment. Any
  other shape omits the SvcParam — the advertised well-known location is always derived from where
  the metadata document actually lives, never from the protocol.

The `cap` / `cap-sha256` pair locates and digests the **per-endpoint** metadata document (the A2A
AgentCard, the MCP ServerCard — DNS-AID's per-service capability descriptor), one descriptor per
SVCB row.

## 4. Required flag and TL seal

| Record | Required | Note |
| --- | --- | --- |
| `{fqdn}` SVCB | **Yes**, alone; **No** in the `ANS_TXT` union | The profile emits `Required=true`; the walker flips it to `false` when `ANS_TXT` is also resolved, so the legacy `_ans` TXT carries the required signal during the transition (ANS-3 §6.4) |
| `_ans-badge` TXT (family) | Yes | ANS-3 §6.3 |
| `_{port}._tcp.{fqdn}` TLSA (family) | No | ANS-3 §6.3; verify-side enforces a match only when the zone is DNSSEC-validated |

Every emitted record carries TTL `3600`. The composed set is sealed verbatim into the
`AGENT_REGISTERED` attestation's `dnsRecordsProvisioned[]`
([ANS-3 §3](../ans-3-dns-publication.md#3-record-set-and-child-label-structure)).

## 5. Freshness and ANS-5 monitoring

Records carry TTL `3600`. ANS-5's DNS-pointer check re-queries the SVCB row and validates DNSSEC
where the zone is signed. The verifier compares the expected SvcParams against the live record by
value-equality; because the comparison requires equal values, a Private-Use key collision with an
unrelated experiment that picked the same code point can only cause a false negative (verify-dns
fails), never a false accept.

## 6. Lifecycle specifics

The SVCB rows are per-registration: one row per endpoint for the registration's version. Version
coexistence across registrations and revocation cleanup are ANS-1/ANS-2 concerns
([ANS-1 §7](../ans-1-registration.md#7-lifecycle-operations)); on revocation of the last ACTIVE
version the AHP removes the SVCB and family records the RA's revocation response lists.

## 7. Coexistence and presentation safety

- **CNAME at the apex** blocks the SVCB row (RFC 1034 §3.6.2). Operators needing both a CNAME (a CDN
  front-end) and the SVCB row MUST use CNAME flattening at the provider.
- **RFC 9460 §8 unknown-key handling** — generic SVCB clients and sibling agent-discovery drafts
  ignore SvcParams they do not recognize rather than fail closed, so ANS SvcParams coexist with
  others on the same row (ANS-3 §8.4).
- **Presentation safety** — `metadataUrl` is validated at registration to be an `https` URL,
  ≤2048 characters, and free of every byte the SVCB presentation format escapes (whitespace, double
  quote, backslash, semicolon, and non-printable ASCII) in **both** the raw URL (which feeds `cap`)
  and its percent-decoded path (which feeds `well-known`). A violation is rejected with
  `INVALID_ENDPOINT`. This keeps the published value byte-identical to what a lookup verifier
  observes when it splits the record on whitespace and the first `=`, so a stray byte never injects
  a bogus SvcParam into the producer-signed attestation or strands the agent in `PENDING_DNS`.
- **Private-Use range caveat** — collision with another experiment on the same code points is
  intrinsic to Private Use but bounded to denial-of-verification (a false negative; never a false
  accept, §5). If these params are IANA-registered later, switching the presentation form back to
  named keys is a real operator-facing migration (the published record value changes), not a silent
  swap.

## 8. Error codes

| Code | Meaning |
| --- | --- |
| `INVALID_ENDPOINT` | `metadataUrl` not https / over 2048 chars / carrying SVCB-unsafe bytes (raw or decoded path); `metadataHash` not `SHA256:<64 hex>`; `metadataHash` supplied without `metadataUrl`; `agentUrl` port outside 1–65535 |
| `INVALID_DISCOVERY_PROFILE` | (core) a `discoveryProfiles` element naming no wired profile (ANS-3 §6.4) |

A verify-dns mismatch keeps the registration in `PENDING_DNS` and the operator reconciles by
publishing the announced record (ANS-3 §4); it is not a distinct error code.

## 9. Status and requirement

**Requirement: Optional (opt-in).** Supporting `ANS_DNSAID` is optional, and it is never in the
default set; an operator names it explicitly. An RA that enables it MUST emit the SVCB row exactly as
§2 specifies — `keyNNNNN` Private-Use presentation, never the named DNS-AID forms.

**Status: Active.** Wired and tested, emitting real SVCB rows the RA verifies at verify-dns, while
the DNS-AID-aligned shape is brought to broad conformance ahead of any future default change.

## 10. Object schemas (worked example)

A multi-protocol agent — one A2A endpoint with a `/.well-known/` metadata document plus its hash,
and one MCP endpoint with neither — at version `1.0.0`, with a server certificate on file. The
sample hash `SHA256:098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27` renders as the
base64url digest below:

```text
; one SVCB row per endpoint, at the bare FQDN, in endpoint order
agent.example.com.            3600 IN SVCB  1 . alpn=a2a port=443 key65400=https://agent.example.com/.well-known/agent-card.json key65401=CY1lDMbSgN7kwPR0iadc8Xub-7rlMFGAbU4IQQiy_yc key65402=a2a key65409=agent-card.json
agent.example.com.            3600 IN SVCB  1 . alpn=mcp port=443 key65402=mcp

; family trust records (ANS-3 §6.3) — shared with any sibling profile, deduped once
_ans-badge.agent.example.com. 3600 IN TXT   "v=ans-badge1; version=1.0.0; url=https://transparency-log.example.com/v1/agents/{agentId}"
_443._tcp.agent.example.com.  3600 IN TLSA  3 0 1 {server-cert-sha256}
```

The MCP row carries `alpn` / `port` / `bap` only: no `metadataUrl` means no `key65400` (cap) and no
`key65409` (well-known), and no `metadataHash` means no `key65401` (cap-sha256). An off-`/.well-known/`
`metadataUrl` (e.g. `https://agent.example.com/metadata/mcp.json`) would emit `key65400` but omit
`key65409`. The sealed `dnsRecordsProvisioned[]` entry's `purpose` is `DISCOVERY` for the SVCB row.
