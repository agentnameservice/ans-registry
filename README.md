# Agent Name Service (ANS)

My company's payment agent receives an instruction to wire $50,000 to a supplier's
invoicing agent. The payment agent must decide: does this agent actually belong to
the supplier, or has someone stood up a convincing fake? And if the site is
legitimate, has the supplier's code changed since my last transaction?

ANS anchors an agent's identity to a domain name whose control has been verified,
binds authorized certificates to its registration, and records published lifecycle
events in an append-only Transparency Log. A version label does not prove which
code, model or configuration is running. The standard is open and the
services are federated, but the identity always anchors to a domain name.

## Specifications

The ANS protocol is split across seven layered specifications under [`spec/`](spec/):

| Layer | File | Topic |
| --- | --- | --- |
| ANS-0 | [`spec/ans-0-identity-anchor.md`](spec/ans-0-identity-anchor.md) | The proof-of-control gate, Verified Identities, identity profiles |
| ANS-1 | [`spec/ans-1-registration.md`](spec/ans-1-registration.md) | Registration aggregate, lifecycle, event set |
| ANS-2 | [`spec/ans-2-versioned-naming.md`](spec/ans-2-versioned-naming.md) | Stable ANS names, optional versions, certificate binding and mTLS |
| ANS-3 | [`spec/ans-3-dns-publication.md`](spec/ans-3-dns-publication.md) | DNS publication, record styles, DANE, anchor-conditional emission |
| ANS-4 | [`spec/ans-4-transparency.md`](spec/ans-4-transparency.md) | SCITT statements and receipts, Transparency Log, checkpoints and tiles, HCS anchoring |
| ANS-5 | [`spec/ans-5-integrity-monitoring.md`](spec/ans-5-integrity-monitoring.md) | `VerificationWorker`, integrity reporting |
| ANS-6 | [`spec/ans-6-agent-authentication.md`](spec/ans-6-agent-authentication.md) | Agent-to-agent authentication: badge/SCITT verification tiers, mTLS and DPoP (RFC 9449) caller methods |

Worked examples for ANS-1 live at [`spec/examples/ans-1-examples.md`](spec/examples/ans-1-examples.md). [`DESIGN.md`](DESIGN.md) is a pointer to the layered specs and to the IETF draft.

**[MAESTRO.md](MAESTRO.md)** — Security analysis. Applies the CSA
[MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)
threat modeling framework to the ANS architecture. Maps threats and mitigations
across all seven layers, from foundation models through the agent ecosystem,
using a concrete multi-agent travel-booking scenario.

## Related

**[trust-index-spec](https://github.com/agentnameservice/trust-index-spec)** —
Trust evaluation. How a Trust Index crawls sealed data from federated
Registration Authorities, combines it with external signals, and scores agents
across five dimensions: integrity, identity, solvency, behavior, and safety.
Trust Manifest schema, credential formats, identity grades, federation, and
security considerations. Maintained in its own repository; not an ANS protocol
layer.

**[SENDER_VERIFICATION_SPEC.md](SENDER_VERIFICATION_SPEC.md)** — Per-sender
email verification. JWS header-only signing with key bindings sealed in a
SCITT transparency log, discoverable via DNS. Targets business email
compromise where domain-level authentication (DKIM/SPF/DMARC) passes but the
sender is not who they claim. Not an ANS protocol feature.

## API

The OpenAPI contracts and conformance schemas live under [`api/`](api/):

- [Registration Authority management API](api/api-spec-v2.yaml)
- [Complete Transparency Log OpenAPI](api/api-spec-tl-v2.yaml), including V1/V2/V3 ingest and all verification/admin routes
- [Sealed Verified-Identity event (V2)](api/identity-event-schema-v2.json)
- [Historical Transparency Log entry (V2)](api/tl-response-schema-v2.json)
- [Current Transparency Log entry (V3)](api/tl-response-schema-v3.json)

## SDKs

- [ans-sdk-rust](https://github.com/agentnameservice/ans-sdk-rust)
- [ans-sdk-go](https://github.com/agentnameservice/ans-sdk-go)
- [ans-sdk-java](https://github.com/agentnameservice/ans-sdk-java)

## Origin

This architecture builds on "Agent Name Service for Secure AI Agent Discovery"
by Narajala, Huang, Habler, and Sheriff (OWASP), contributed to the IETF as
an internet-draft (draft-narajala-ans).

## License

Apache 2.0. See [LICENSE](LICENSE).
