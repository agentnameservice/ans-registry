# ANS-2: Versioned Naming

Status: DRAFT v1.0
Spec: ANS-2 (Versioned Naming)
Version: 0.1.0
Date: 2026-05-17
Audience: implementers adding semantic-version routing and Private-key Confirmation Challenge (PriCC) flows to an ANS Registration Authority

## 1. Scope

Every registration declares a `version` and derives an ANSName ([ANS-1
§4.1](ans-1-registration.md#41-step-1--pending-registration)). What is **optional** is the Identity
Certificate: a registration MAY omit its Identity CSR and operate on its Server Certificate alone ([ANS-1
§7.2](ans-1-registration.md#72-registrations-without-an-identity-certificate)). The identity-certificate
surface of ANS-2 — the URI SAN binding, PriCC, and the mTLS semantics — applies when the certificate is
present. An identity-bearing registration MAY roll its Identity Certificate via the rotation operation ([ANS-1
§7](ans-1-registration.md#7-lifecycle-operations)); the registration's `agentId`, `agentHost`, and ANSName are
unchanged across a roll, and a registration created without an Identity CSR cannot add one later.

When present, ANS-2 specifies:

- The ANSName URI form (`ans://v<MAJOR>.<MINOR>.<PATCH>.<host>`) and supersession rules.
- The version field carried on emitted DNS records and Transparency Log events.
- The Identity Certificate URI SAN binding.
- The Private-key Confirmation Challenge (PriCC) flow that proves identity-CSR control during versioned issuance.
- mTLS handshake semantics that consume the Identity Certificate.
- Stable Aliases (§6): operator-facing subdomains that resolve to a specific versioned identifier.

ANS-2 is FQDN-shaped. The Identity Certificate URI SAN encodes an ANSName whose host component is an FQDN — true by construction, since every ANSName is derived from the registration's `agentHost`.

## 2. The ANSName

`ans://v{version}.{agentHost}`

Example: `ans://v1.0.0.sentiment-analyzer.example.com`

Every registration declares a version, so every registration has an ANSName; the name is constructed at registration ([ANS-1 §4.1](ans-1-registration.md#41-step-1--pending-registration)) and is consumed **permanently** — uniqueness is checked against all registration rows regardless of status, so a FAILED, EXPIRED, or cancelled attempt still holds its version and a retry must use a new one.

| Component | Constraints | Example |
| --- | --- | --- |
| **protocol** | Fixed. Always `ans` | `ans` |
| **version** | Semantic version, numeric only: `major.minor.patch`. No pre-release or build-metadata suffixes. Prefixed with `v` | `v1.0.0` |
| **agentHost** | FQDN per RFC 1035 and RFC 1123. Each label is at most 63 octets, uses LDH characters (letters, digits, hyphens), and does not begin or end with a hyphen. Total FQDN length MUST NOT exceed 237 octets | `sentiment-analyzer.example.com` |

### 2.1 Length limits

| Limit | Octets | Derivation |
| --- | --- | --- |
| `agentHost` (FQDN) | ≤237 | The 253-octet domain-name limit (RFC 1035 §2.3.4) less 16 octets reserved for `_acme-challenge.` plus the label separator used during ACME validation |
| Full ANSName | ≤400 | Structured maximum is 7 (`ans://v` prefix) + 17 (three 5-digit semver segments and two dots) + 237 (host) = 261; the 400-octet cap reserves headroom for transport across HTTP headers, TLS fields, and database columns |

### 2.2 Registration metadata accompanying the ANSName

Two fields accompany the ANSName at registration but are not part of the identifier:

| Field | Max length | Required | Unique | Example |
| --- | --- | --- | --- | --- |
| `agentDisplayName` | 64 chars | Yes | No | `Acme Sentiment Analyzer` |
| `agentDescription` | 150 chars | No | No | `Classifies customer-feedback prose as positive, neutral, or negative.` |

The display name is the human-readable label shown in discovery UIs. It supports spaces, capitalization, and special characters. The FQDN is the unique identifier; display names need not be unique.

### 2.3 Supersession

Versions are independent registrations: a version bump is a new registration under the same `agentHost` with a new `version` ([ANS-1 §7](ans-1-registration.md#7-lifecycle-operations)). Consumers of the TL event stream reconstruct the version history for an `agentHost` by filtering the log on the host — each version's `AGENT_REGISTERED` event carries the full ANSName.

A patch bump may coexist for hours; a major version change may coexist for months. ANS-2 does not impose a retirement timeline. If the new registration fails validation, the old version remains ACTIVE.

## 3. The Identity Certificate

When a registrant submits a `version` and `identityCsrPEM`, the RA's Private CA issues an Identity Certificate.

| Property | Value |
| --- | --- |
| Issuer | Private CA operated by the RA |
| SAN type | `uniformResourceIdentifier` |
| SAN value | The full ANSName (`ans://v{version}.{agentHost}`) |
| Purpose | Binds the certificate to a specific software version |

The Identity Certificate requires a URI SAN. The `ans://` scheme is syntactically valid per RFC 3986 §3.1 and permitted in URI SANs per RFC 5280 §4.2.1.6. CA/B Forum Baseline Requirements prohibit `uniformResourceIdentifier` SANs in publicly trusted server certificates (BR §7.1.2.7.12). A Public CA cannot issue this certificate. Only a Private CA, operating under its own issuance policy, can.
Identity Certificates MUST NOT be brought-your-own (BYOC): a rogue CA could otherwise issue an Identity Certificate for `ans://v1.0.0.payments.example.com`, and the TL would seal it as if the RA had validated it.

## 4. mTLS with Identity Certificates

The RA's Private CA issues Identity Certificates that ANS-aware callers and callees present during the mTLS handshake. The handshake authenticates each party's ANSName, and a separate badge check (step 6 of the handshake sequence below) confirms the version sealed in the TL.

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
§7.2](ans-1-registration.md#72-registrations-without-an-identity-certificate)): a registration created without
an Identity CSR cannot add an Identity Certificate later, and an identity-bearing registration rolls its
certificate via rotation without changing the combination. Callers therefore learn a stable authentication
shape from the sealed badge and do not need to re-discover the agent across certificate rolls.

## 5. Private-key Confirmation Challenge (PriCC)

PriCC binds a versioned registration's Identity CSR to the actor controlling the registration's signing key. ANS-1 already proves anchor control (ACME for FQDN); PriCC additionally proves that the entity submitting the Identity CSR controls the private key whose public half the CSR carries.

PriCC sequence:

1. The RA generates a random PriCC token (32 bytes, base64url-encoded; for example `Lzx7nPjQXr_2VbW8C5sDrGYE9q1mF4uHkN0pT-aZsvI`).
2. The RA returns the token plus the registration's pending state in the response to the AHP's `register` call.
3. The AHP signs the token concatenated with the JCS-canonical bytes of the registration's authoritative payload (the registration request body). The signing key is the private key whose public half appears in the Identity CSR.
4. The AHP submits the signed challenge to the RA's `POST /v1/agents/{agentId}/pricc-confirm` endpoint.
5. The RA verifies the signature against the Identity CSR's public key. Match → registration proceeds to activation. Mismatch → RA rejects with `PRICC_SIGNATURE_INVALID` and the registration stays in `PENDING`.

## 6. Stable Aliases

Operators running high-frequency rolling deployments may find a versioned subdomain per deployment operationally costly. ANS-2 supports Stable Aliases: an operator-facing subdomain (`prod.agent.example.com`) that cryptographically resolves to a specific versioned identifier. The alias changes where it points across deployments; the versioned identifiers it points to are immutable.

A Stable Alias MUST carry a signed pointer to its current versioned identifier. The pointer mechanism is a DNSSEC-signed SVCB or TXT record at `_ans-alias.prod.agent.example.com` containing the fully-qualified versioned identifier and a TL checkpoint reference for the deployment that established the pointer.

Callers that want operational stability resolve the alias and accept whichever version it currently points to. Callers that want integrity resolve the alias, follow the signed pointer to the versioned identifier, and pin to that version.

An operator cannot use aliasing to repaint an already-declared version; the pattern reduces the operational surface a specific caller sees, nothing more.

## 7. Conformance

A conformant ANS-2 implementation:

1. Constructs ANSNames per the ANSName section above with the documented length limits enforced.
2. Issues Identity Certificates that carry the ANSName in a `uniformResourceIdentifier` SAN.
3. Implements PriCC before activation.
4. Supports the mTLS handshake semantics for caller-side and callee-side roles across the four authentication shapes named above.
5. Implements Stable Aliases per §6 if it offers the feature.

## 8. Security considerations

### 8.1 Identity Certificate forgery

A rogue CA cannot impersonate the RA's Private CA without compromising the Private CA's signing key. BYOC Identity Certificates are prohibited (per §3): BYOC would let the AHP bring an Identity Certificate the RA had not validated key possession for, so the RA would seal whatever was submitted and a versioned registration would no longer prove that the actor controlling the version controls the
binding.

### 8.2 PriCC token replay

The PriCC token is single-use within the registration's lifetime. A token submitted twice is rejected with `PRICC_TOKEN_ALREADY_USED`. Tokens expire 5 minutes after issue (recommended) so an intercepted token cannot be replayed against a future registration; a token submitted past expiry is rejected with `PRICC_TOKEN_EXPIRED`.

### 8.3 Cryptographic consent

An identity-bearing registration's Identity Certificate private key signs transaction payloads when the agent commits to an action. The signature produces a non-repudiable record tying the specific version to the specific transaction. A registration without an Identity Certificate cannot produce this signature; a counterparty requiring cryptographic consent MUST require an identity-bearing
counterparty.

## 9. References

- ANS-1 specification: [`ans-1-registration.md`](ans-1-registration.md). Registration aggregate, lifecycle.
- ANS-3 specification: [`ans-3-dns-publication.md`](ans-3-dns-publication.md). Per-version DNS records.
- ANS-4 specification: [`ans-4-transparency.md`](ans-4-transparency.md). Sealed events, badge endpoint.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) URI generic syntax (`ans://` scheme validity).
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) X.509 (URI SANs, revocation).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) JWS (PriCC signature).
- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) ACME (FQDN domain-control proof).
