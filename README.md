# Agent Name Service (ANS)

My company's payment agent receives an instruction to wire $50,000 to a supplier's
invoicing agent. The payment agent must decide: does this agent actually belong to
the supplier, or has someone stood up a convincing fake? And if the site is
legitimate, has the supplier's code changed since my last transaction?

ANS answers both questions. It anchors every agent's identity to a domain name
whose ownership has been verified, issues a version-bound certificate that records
which code is running, and seals every lifecycle event into a Transparency Log
where entries cannot be altered after the fact. The standard is open and the
services are federated, but the identity always anchors to a domain name.

## Specifications

Two open specifications define the protocol and trust evaluation:

**[DESIGN.md](docs/DESIGN.md)** — Architecture and protocol. How the Registration
Authority verifies domain ownership, issues certificates, provisions DNS records,
and seals events into the Transparency Log. Data model, identifiers, verification
tiers, DNS record formats, mTLS exchange, and the full registration lifecycle.

**[TRUST_INDEX_SPEC.md](docs/TRUST_INDEX_SPEC.md)** — Trust evaluation. How a Trust
Index crawls sealed data from federated Registration Authorities, combines it with
external signals, and scores agents across five dimensions: integrity, identity,
solvency, behavior, and safety. Trust Manifest schema, credential formats,
identity grades, federation, and security considerations.

## API

- [OpenAPI specification](https://developer.godaddy.com/doc/endpoint/ans)
  (human-readable)
- [Machine-readable OpenAPI](https://developer.godaddy.com/swagger/swagger_ans.json)

## SDKs

- [ans-sdk-rust](https://github.com/godaddy/ans-sdk-rust)
- [ans-sdk-go](https://github.com/godaddy/ans-sdk-go)
- [ans-sdk-java](https://github.com/godaddy/ans-sdk-java)

## Origin

This architecture builds on "Agent Name Service for Secure AI Agent Discovery"
by Narajala, Huang, Habler, and Sheriff (OWASP), contributed to the IETF as
an internet-draft (draft-narajala-ans).

## License

Apache 2.0. See [LICENSE](LICENSE).
