# ANS-2: Versioned Naming

Status: DRAFT v1.0
Spec: ANS-2 (Versioned Naming)
Version: 0.2.0
Date: 2026-07-15
Audience: implementers adding semantic-version naming and Identity Certificate binding to an ANS Registration Authority

## 1. Scope

Every registration declares a `version` and derives an ANSName ([ANS-1
§4.1](ans-1-registration.md#41-step-1--pending-registration)). What is **optional** is the Identity
Certificate: a registration MAY omit its Identity CSR and operate on its Server Certificate alone ([ANS-1
§7.2](ans-1-registration.md#72-registrations-without-an-identity-certificate)). The identity-certificate
surface of ANS-2 — the URI SAN binding and the mTLS semantics — applies when the certificate is
present. An identity-bearing registration MAY roll its Identity Certificate via the rotation operation ([ANS-1
§7](ans-1-registration.md#7-lifecycle-operations)); the registration's `agentId`, `agentHost`, and ANSName are
unchanged across a roll, and a registration created without an Identity CSR cannot add one later.

ANS-2 specifies:

- The ANSName URI form (`ans://v<MAJOR>.<MINOR>.<PATCH>.<host>`) and version-coexistence rules.
- The version field carried on emitted DNS records and Transparency Log events.
- The Identity Certificate URI SAN binding, including the CSR-side requirement.
- mTLS handshake semantics that consume the Identity Certificate.

ANS-2 is FQDN-shaped. The Identity Certificate URI SAN encodes an ANSName whose host component is an FQDN — true by construction, since every ANSName is derived from the registration's `agentHost`.

## 2. The ANSName

`ans://v{version}.{agentHost}`

Example: `ans://v1.0.0.sentiment-analyzer.example.com`

Every registration declares a version, so every registration has an ANSName; the name is constructed at registration ([ANS-1 §4.1](ans-1-registration.md#41-step-1--pending-registration)) and is consumed **permanently** — uniqueness is checked against all registration rows regardless of status, so a FAILED, EXPIRED, or cancelled attempt still holds its version and a retry must use a new one.

| Component | Constraints | Example |
| --- | --- | --- |
| **protocol** | Fixed. Always `ans` | `ans` |
| **version** | Semantic version, numeric only: `major.minor.patch`. No pre-release or build-metadata suffixes. Prefixed with `v` | `v1.0.0` |
| **agentHost** | FQDN per RFC 1123. Each label is at most 63 octets, uses LDH characters (letters, digits, hyphens), and does not begin or end with a hyphen | `sentiment-analyzer.example.com` |

### 2.1 Length limits

`agentHost` MUST NOT exceed 253 octets (the RFC 1035 §2.3.4 domain-name limit) and MUST contain at
least two labels. The ANSName has no separate length cap; its bound is derived — the fixed
`ans://v` prefix, the version segment, and the host.

### 2.2 Registration metadata accompanying the ANSName

Two fields accompany the ANSName at registration but are not part of the identifier:

| Field | Max length | Required | Unique | Example |
| --- | --- | --- | --- | --- |
| `agentDisplayName` | 64 chars | Yes | No | `Acme Sentiment Analyzer` |
| `agentDescription` | 150 chars | No | No | `Classifies customer-feedback prose as positive, neutral, or negative.` |

The display name is the human-readable label shown in discovery UIs. It supports spaces, capitalization, and special characters. The ANSName is the unique identifier; display names need not be unique, and the FQDN is shared by every version registered under it.

### 2.3 Supersession

Versions are independent registrations: a version bump is a new registration under the same `agentHost` with a new `version` ([ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)). Consumers of the TL event stream reconstruct the version history for an `agentHost` by filtering the log on the host — each version's `AGENT_REGISTERED` event carries the full ANSName.

A patch bump may coexist for hours; a major version change may coexist for months. ANS-2 does not impose a retirement timeline. If the new registration fails validation, the old version remains ACTIVE.

## 3. The Identity Certificate

When a registrant submits a `version` and `identityCsrPEM`, the RA's Private CA issues an Identity Certificate. The binding runs through both artifacts:

- **The CSR MUST carry the registration's full ANSName as a `uniformResourceIdentifier` SAN.** The RA validates the CSR's URI SAN against the expected ANSName before signing; a CSR naming any other identifier is rejected. (Server CSRs differ: they carry the agent's FQDN as a DNS SAN, the TLS server-auth convention.)
- **The issued certificate carries the same ANSName URI SAN**, with `digitalSignature` key usage and the `clientAuth` extended key usage — it is minted as a TLS client certificate — and a CA-configured validity window.

| Property | Value |
| --- | --- |
| Issuer | Private CA operated by the RA |
| SAN type | `uniformResourceIdentifier` |
| SAN value | The full ANSName (`ans://v{version}.{agentHost}`), validated against the CSR |
| Key usage | `digitalSignature`; EKU `clientAuth` |
| Purpose | Binds the certificate to a specific software version, presentable as a TLS client certificate |

The Identity Certificate requires a URI SAN. The `ans://` scheme is syntactically valid per RFC 3986 §3.1 and permitted in URI SANs per RFC 5280 §4.2.1.6. CA/B Forum Baseline Requirements prohibit `uniformResourceIdentifier` SANs in publicly trusted server certificates (BR §7.1.2.7.12). A Public CA cannot issue this certificate. Only a Private CA, operating under its own issuance policy, can.
Identity Certificates MUST NOT be brought-your-own (BYOC): a rogue CA could otherwise issue an Identity Certificate for `ans://v1.0.0.payments.example.com`, and the TL would seal it as if the RA had validated it. The registration request accepts no identity-certificate BYOC input — only a CSR.

## 4. mTLS with Identity Certificates

The RA's Private CA issues Identity Certificates that ANS-aware callers and callees present during the mTLS
handshake — the `clientAuth` EKU (§3) is what makes the certificate presentable at the TLS layer. The
handshake authenticates each party's ANSName, and a separate badge check (step 6 of the handshake sequence
below) confirms the version sealed in the TL. The handshake itself runs between agents; ANS components issue
and attest the certificates but are not in the connection path.

### 4.1 Mutual TLS handshake

1. Caller sends `ClientHello`.
2. Server returns Server Certificate plus `CertificateRequest`.
3. Caller presents its Identity Certificate.
4. Server verifies the caller's Identity Certificate against the ANS Private CA's published trust anchor.
5. mTLS tunnel established. The caller knows the server's FQDN; the server knows the caller's ANSName.
6. Caller verifies the server's versioned identity via `_ans-badge` TXT record or TL query.

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
