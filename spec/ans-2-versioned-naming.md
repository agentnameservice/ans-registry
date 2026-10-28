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

When a registrant submits `identityCsrPEM`, the RA's Private CA issues an Identity Certificate. The binding runs through both artifacts:

- **The CSR MUST carry the registration's full ANSName as a `uniformResourceIdentifier` SAN.** The RA validates the CSR's URI SAN against the expected ANSName before signing; a CSR naming any other identifier is rejected. (Server CSRs differ: they carry the agent's FQDN as a DNS SAN, the TLS server-auth convention.)
- **The issued certificate carries the same ANSName URI SAN**, with `digitalSignature` key usage and the `clientAuth` extended key usage — it is minted as a TLS client certificate — and a CA-configured validity window.

| Property | Value |
| --- | --- |
| Issuer | Private CA operated by the RA |
| SAN type | `uniformResourceIdentifier` |
| SAN value | The assigned ANSName, versioned or versionless, validated against the CSR |
| Key usage | `digitalSignature`; EKU `clientAuth` |
| Purpose | Binds the certificate to the registration; presentable as a TLS client certificate |

The Identity Certificate requires a URI SAN. The `ans://` scheme is syntactically valid per RFC 3986 §3.1 and permitted in URI SANs per RFC 5280 §4.2.1.6. CA/B Forum Baseline Requirements prohibit `uniformResourceIdentifier` SANs in publicly trusted server certificates (BR §7.1.2.7.12). A Public CA cannot issue this certificate. Only a Private CA, operating under its own issuance policy, can.
Identity Certificates MUST NOT be brought-your-own (BYOC): a rogue CA could otherwise issue an Identity Certificate for `ans://v1.0.0.payments.example.com`, and the TL would seal it as if the RA had validated it. The registration request accepts no identity-certificate BYOC input — only a CSR.

## 4. mTLS with Identity Certificates

The RA's Private CA issues Identity Certificates that ANS-aware callers and callees present during the mTLS
handshake — the `clientAuth` EKU (§3) is what makes the certificate presentable at the TLS layer. The
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

Steps 3 and 4 of the handshake sequence above require the party being authenticated to hold an Identity Certificate. Four scenarios cover the combinations:

- **Identity-bearing callee, identity-bearing caller.** Standard mTLS. Both parties present Identity Certificates and verify the other against the ANS Private CA. The caller verifies the server's fingerprint at step 6 against the sealed badge; the server learns the caller's ANSName.
- **Server-Certificate-only callee, identity-bearing caller.** Steps 3 and 4 run for the caller: the callee verifies the caller's Identity Certificate against the ANS Private CA. The callee authenticates itself via its Server Certificate only; the caller verifies the server's identity at step 6 against the badge sealed for the registration.
- **Identity-bearing callee, Server-Certificate-only caller.** Steps 3 and 4 collapse: the caller has no
  Identity Certificate to present, so step 5 establishes a server-authenticated TLS session rather than mTLS.
  The callee authenticates via its Server and Identity Certificates; the caller is anonymous at the TLS layer
  and MUST authenticate through application-layer means (API key, OAuth, delegation token).
- **Both Server-Certificate-only.** Both parties authenticate via Server Certificates only; the session is server-authenticated TLS with no ANS Identity Certificate on either side. Step 6 (badge or TL verification) still runs on the callee.

DANE (`_443._tcp` TLSA) remains an optional additional pinning check across all scenarios.

The combination a callee presents is fixed at registration ([ANS-1
§7.2](ans-1-registration.md#72-registrations-without-an-identity-certificate)): a registration created
without an Identity CSR cannot add an Identity Certificate later, and an identity-bearing registration rolls
its certificate via rotation without changing the combination. Callers therefore learn a stable
authentication shape from the sealed badge and do not need to re-discover the agent across certificate rolls.

## 5. Conformance

A conformant ANS-2 implementation:

1. Constructs ANSNames per §2 with the documented length limits enforced.
2. Validates that an Identity CSR carries the registration's full ANSName as a `uniformResourceIdentifier` SAN before signing, and rejects identity-certificate BYOC input.
3. Issues Identity Certificates that carry the ANSName in a `uniformResourceIdentifier` SAN with the `clientAuth` EKU.
4. Supports the mTLS handshake semantics for caller-side and callee-side roles across the four authentication shapes named above.

## 6. Security considerations

### 6.1 Identity Certificate forgery

A rogue CA cannot impersonate the RA's Private CA without compromising the Private CA's signing key. BYOC Identity Certificates are prohibited (per §3): BYOC would let the AHP bring an Identity Certificate the RA had not validated key possession for, so the RA would seal whatever was submitted and a versioned registration would no longer prove that the actor controlling the version controls the
binding.

## 7. References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, lifecycle.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Per-version DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). Sealed events, badge endpoint.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) URI generic syntax (`ans://` scheme validity).
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) X.509 (URI SANs, revocation).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) ACME (FQDN domain-control proof).
