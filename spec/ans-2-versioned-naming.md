# ANS-2: Naming and Certificate Binding

Status: DRAFT v1.0
Spec: ANS-2 (Naming and Certificate Binding)
Version: 0.2.0
Date: 2026-07-15
Audience: implementers adding stable naming and Identity Certificate binding to an ANS Registration Authority

## 1. Scope

ANS-2 defines the FQDN-based ANS name, its optional software version, and Identity Certificate binding.
Registration and lifecycle operations are defined in ANS-1; runtime authentication is defined in ANS-6.
The Identity Certificate is optional. Its certificate and authentication rules apply when present.

## 2. The ANSName

A V2 registration request that omits `version` constructs `ans://{agentHost}`. When `version` is
supplied, its existing bare-semver validation applies and the name is `ans://v{version}.{agentHost}`.
The RA MUST NOT invent a placeholder version such as `0.0.0` or emit an empty version label. V1 request
validation remains versioned. Responses and V3 events omit `version` for versionless registrations.

Examples: `ans://sentiment-analyzer.example.com` and `ans://v1.0.0.sentiment-analyzer.example.com`.

| Component | Constraints | Example |
| --- | --- | --- |
| **protocol** | Fixed `ans` scheme | `ans` |
| **version** | Optional; numeric `major.minor.patch`, with no prerelease/build suffix; `v` appears only in the name and legacy TXT value | `v1.0.0` |
| **agentHost** | FQDN per RFC 1123; lowercase LDH labels of at most 63 octets, with no leading/trailing hyphen | `sentiment-analyzer.example.com` |

Name construction and parsing MUST agree with the signed `agent.host` and, when present,
`agent.version`. V3 `agent.version` is bare semver. The parser reserves a leading
`v<digits>.<digits>.<digits>.` for legacy names: a new versionless FQDN with that prefix is rejected
with `422 AMBIGUOUS_ANS_NAME`. If a reserved-prefix input fails legacy-semver parsing, it MUST NOT
fall back to versionless interpretation.

The assigned name, `agentId` and FQDN are immutable. Exact-name uniqueness applies across registration
statuses. Reclaiming a consumed terminal name requires a separate recovery policy. Publication
compatibility follows ANS-1 §6.5.

### 2.1 Length limits

`agentHost` MUST NOT exceed 253 octets (the RFC 1035 §2.3.4 domain-name limit) and MUST contain at
least two labels. The ANSName has no separate length cap; its bound is derived — the fixed
`ans://` prefix, an optional `v{version}.` segment, and the host.

### 2.2 Registration metadata accompanying the ANSName

Two fields accompany the ANSName at registration but are not part of the identifier:

| Field | Max length | Required | Unique | Example |
| --- | --- | --- | --- | --- |
| `agentDisplayName` | 64 chars | Yes | No | `Acme Sentiment Analyzer` |
| `agentDescription` | 150 chars | No | No | `Classifies customer-feedback prose as positive, neutral, or negative.` |

The display name is the human-readable label shown in discovery UIs. It supports spaces, capitalization, and special characters. The ANSName is the unique identifier; display names need not be unique, and a shared FQDN does not make independent registrations or their credentials interchangeable.

### 2.3 Supersession

A software version is a release label, not evidence of the code, model or configuration serving a request.
Software releases can retain the registration; incompatible APIs can use paths such as `/v1/a2a` and
`/v2/a2a` on the same FQDN. An operator may create a separate versioned registration when a separate
identity is needed. Each registration has independent status, credentials and history, with no automatic
merging or retirement. A failed new registration leaves existing registrations intact.

## 3. The Identity Certificate

An RA MUST support owner-authorized identity BYOC and MAY offer private issuance. The owner can
authorize a key held by another party; the holder proves possession at use time under ANS-6.
Management operations are defined in ANS-1 §7.2.

### 3.1 Admission and hostname coverage

Reject an unparseable or CA certificate, unsupported/weak key, unacceptable signature algorithm,
expired/not-yet-valid leaf, or missing DNS SAN coverage of the registered FQDN. Both certificate roles,
imported or issued, use standard DNS SAN hostname matching, including single-label wildcards; a CN
cannot substitute. Apply coverage to submission, issuance, activation and endpoint mutation. Service and
metadata URL hosts must equal that FQDN.

Parse an optional BYOC chain when supplied. Imported identity leaves use informational type
`X509-EXTERNAL`, which does not assert OV/EV identity assurance or external CA revocation status.
Method B's X.509 trust policy is defined in ANS-6 §7.5; server TLS retains ordinary chain validation.

Private identity CSRs require a valid self-signature and FQDN DNS SAN coverage. The issued leaf carries
the FQDN subject/DNS SAN. Credentials for Method A also require its URI/clientAuth profile; existing
URI-bound issuance continues to validate the assigned ANS name. Older credentials lacking DNS coverage
must be replaced or retired before an operation requiring that coverage.

### 3.2 Method-specific certificate use

Method B revision 2 binds the signed registration ID and TL-authorized fingerprint (ANS-6 §7.5), without
requiring an ANS URI SAN. Method A retains its URI binding, clientAuth purpose and private-CA trust rules.
A certificate admitted for Method B is not automatically suitable for Method A.

### 3.3 Rotation and removal

ANS-1 §7.2 defines full-leaf fingerprint updates, valid overlap and retirement of individual bindings.

## 4. mTLS with Identity Certificates

Method A uses URI-bound Identity Certificates issued by a trusted private CA; their `clientAuth` EKU
and applicable key usage make them suitable for presentation at the TLS layer. This section applies to
that certificate profile, not automatically to every BYOC or DNS-only identity credential. The
handshake authenticates each party's ANSName, and a separate badge check (step 6 of the handshake sequence
below) confirms the registration sealed in the TL. The handshake itself runs between agents; ANS components issue
and attest the certificates but are not in the connection path.

### 4.1 Mutual TLS handshake

1. Caller sends `ClientHello`.
2. Server returns Server Certificate plus `CertificateRequest`.
3. Caller presents its Identity Certificate.
4. Server verifies the caller's Identity Certificate against the ANS Private CA's published trust anchor.
5. mTLS tunnel established. The caller knows the server's FQDN; the server knows the caller's ANSName.
6. Caller verifies the server's registered identity via `_ans-badge` TXT record or TL query.

### 4.2 Handshake scenarios across registration shapes

The callee presents its Server Certificate for server-authenticated TLS. The caller presents a
Method-A-compatible Identity Certificate when client authentication is used. A callee's possession of
an identity credential for its own outbound calls does not change the certificate it serves for TLS.

| Caller credential | Connection authentication |
| --- | --- |
| URI-bound identity credential meeting Method A purpose/trust requirements | TLS client authentication plus the required ANS binding/status checks |
| DNS-only identity credential supported by Method B revision 2 | Server-authenticated TLS plus the signed application-layer Method B proof |
| No applicable ANS identity credential | Server-authenticated TLS; caller authorization requires another supported application mechanism |

DANE (`_443._tcp` TLSA) remains an optional additional pinning check across all scenarios.

A server-only registration may later add an identity credential, and an owner may remove its last
identity binding while retaining a valid server registration. Consumers evaluate current evidence and
method support rather than assuming the registration's initial authentication shape is permanent.

## 5. Conformance

A conformant ANS-2 implementation:

1. Constructs names per §2 and preserves them across supported mutations.
2. Enforces DNS SAN coverage for both certificate roles and the admission rules in §3.1.
3. Supports owner-authorized identity BYOC without an enrollment possession ceremony; private issuance
   is optional and enforces the selected CSR/certificate profile.
4. Retains method-specific mTLS rules and uses ANS-6 revision 2 for URI-independent Method B binding.
5. Publishes credential overlap/removal through the existing certificate snapshot lifecycle.

## 6. Security considerations

### 6.1 Identity credential authorization

A certificate's public availability or CA signature does not authorize its use for a registration.
The RA authenticates the owner, validates admission and publishes the authorized fingerprint. A runtime
verifier must establish possession of that leaf's private key and validate its registration/status binding.
A rogue CA cannot create an ANS authorization merely by issuing a matching DNS certificate. Compromise of
an authorized private key remains a separate risk requiring binding retirement and normal revocation policy.

## 7. References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, lifecycle.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Per-version DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). Sealed events, badge endpoint.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) URI generic syntax (`ans://` scheme validity).
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) X.509 (URI SANs, revocation).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) ACME (FQDN domain-control proof).
