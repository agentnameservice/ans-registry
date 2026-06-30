# ANS-1 worked examples (registration request, AGENT_REGISTERED event, revocation)

Non-normative worked examples for ans-1-registration. Implementers MAY use these as fixtures or schema cross-checks.

Identifier conventions, by surface (these are distinct identifiers, not aliases):

- **`agentId`** (RA API, `/v1/agents/{agentId}`): the agent *registration instance* UUID the RA assigns and uses on its management API.
- **`ansId`** (TL event, UUIDv7): the *Transparency Log entry* identifier carried inside the sealed event payload.

TL event payloads below follow the **V2 TL response format**: certificates are carried as `identityCerts[]` / `serverCerts[]` arrays of `{fingerprint, type, notAfter}`, and `dnsRecordsProvisioned` is an array of `{name, type, data}` objects.

## A.1 `AGENT_REGISTERED` event (versioned, FQDN-anchored) — V2 TL format

```json
{
  "ansId": "550e8400-e29b-41d4-a716-446655440000",
  "ansName": "ans://v1.5.0.support.example.com",
  "eventType": "AGENT_REGISTERED",
  "agent": {
    "host": "support.example.com",
    "name": "Acme Support Agent",
    "version": "v1.5.0",
    "providerId": "PID-8294"
  },
  "attestations": {
    "identityCerts": [
      {
        "fingerprint": "SHA256:22b8a8045734ad3bd8e24c52db8d9aa4dc12907337f790ee70499999021f0eb9",
        "type": "X509-OV-CLIENT",
        "notAfter": "2026-10-05T18:00:00.000000Z"
      }
    ],
    "serverCerts": [
      {
        "fingerprint": "SHA256:d2b71bc02f119a61611b77eadc44c23670917ac4f435fe4e1095d4e5209087ea",
        "type": "X509-DV-SERVER",
        "notAfter": "2026-10-05T18:00:00.000000Z"
      }
    ],
    "dnsRecordsProvisioned": [
      {
        "name": "_ans.support.example.com",
        "type": "TXT",
        "data": "v=ans1; version=v1.5.0; url=https://support.example.com/.well-known/agent-card.json"
      },
      {
        "name": "_ans-badge.support.example.com",
        "type": "TXT",
        "data": "v=ans-badge1; version=v1.5.0; url=https://transparency.ra.ansregistry.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"
      }
    ],
    "domainValidation": "ACME-DNS-01",
    "dnssecStatus": "fully_validated",
    "metadataHashes": {
      "A2A": "SHA256:3b4f2c1a9e8d7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
      "capabilitiesHash": "SHA256:9f3a2b1c4d5e6f7890abcdef0123456789abcdef0123456789abcdef01234567"
    }
  },
  "expiresAt": "2026-10-05T18:00:00.000000Z",
  "issuedAt": "2025-10-05T18:00:00.000000Z",
  "raId": "id-A",
  "timestamp": "2025-10-05T18:00:00.000000Z"
}
```

`agent.version` carries the `v` prefix (`v1.5.0`) because the TL stores the ANSName-formatted version. The registration request (`AgentRegistrationRequest.version`) accepts `1.5.0` without the prefix; the RA adds it. `providerId` is the provider/organization identifier the RA assigns. `dnssecStatus` is an ANS attestation signal carried alongside the V2 attestation fields.

## A.2 `AGENT_REGISTERED` event (base-only, DID-anchored) — forward-looking

Base-only / non-FQDN anchor registrations are a forward-looking ANS-0/ANS-1 capability not yet modeled by the V2 TL schema (which requires `agent.version` and an `ansName`). The example applies the V2 attestation layout and `ansId`; the anchor (`claim`), the absent `ansName`, the absent `identityCerts`, and the `DID-WEB-CHALLENGE` validation value are the new-design parts.

```json
{
  "ansId": "f3c2d4e5-1234-5678-9abc-def012345678",
  "eventType": "AGENT_REGISTERED",
  "agent": {
    "host": "sdk-did-agent.plang.example.com",
    "name": "SDK DID Sandbox Agent",
    "providerId": "PID-9302"
  },
  "claim": {
    "anchorType": "did",
    "resolvedId": "did:web:sdk-did-agent.plang.example.com",
    "publicKey": { "kty": "OKP", "crv": "Ed25519", "x": "11qYAY..." },
    "issuedAt": "2026-05-17T09:55:00Z"
  },
  "attestations": {
    "serverCerts": [
      {
        "fingerprint": "SHA256:7a91...",
        "type": "X509-DV-SERVER",
        "notAfter": "2027-05-17T10:00:00Z"
      }
    ],
    "dnsRecordsProvisioned": [
      {
        "name": "_ans.sdk-did-agent.plang.example.com",
        "type": "TXT",
        "data": "v=ans1; url=https://sdk-did-agent.plang.example.com/.well-known/ans/trust-card.json"
      },
      {
        "name": "_ans-badge.sdk-did-agent.plang.example.com",
        "type": "TXT",
        "data": "v=ans-badge1; url=https://transparency.ra.ansregistry.com/v1/agents/f3c2d4e5-1234-5678-9abc-def012345678"
      }
    ],
    "domainValidation": "DID-WEB-CHALLENGE",
    "dnssecStatus": "not_signed"
  },
  "issuedAt": "2026-05-17T10:00:00Z",
  "raId": "id-A",
  "timestamp": "2026-05-17T10:00:00Z"
}
```

No `ansName`, no `identityCerts`. `claim.anchorType` and `claim.resolvedId` carry the DID. `agent.host` is the operational endpoint; `claim.resolvedId` is the identity. The two diverge per ANS-0 §3.1.

## A.3 Registration request — V1 RA format

A representative request payload (the AHP submits this to the RA's `POST /v1/agents/register` endpoint). Shared fields use the V1 RA names (`agentDisplayName`, `agentDescription`, `version`, `identityCsrPEM`, `serverCsrPEM`, `metaDataUrl`); `claim`, `trustCardContent`, and `echConfigList` are forward-looking ANS additions on top of the V1 request.

```json
{
  "agentDisplayName": "Acme Support Agent",
  "agentDescription": "Customer support agent.",
  "version": "1.5.0",
  "agentHost": "support.example.com",
  "claim": {
    "anchorType": "fqdn",
    "resolvedId": "support.example.com",
    "publicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
    "issuedAt": "2025-10-05T17:55:00Z"
  },
  "endpoints": [
    {
      "protocol": "A2A",
      "agentUrl": "wss://support.example.com/a2a",
      "metaDataUrl": "https://support.example.com/.well-known/agent-card.json",
      "metaDataHash": "SHA256:3b4f2c1a9e8d7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
      "transports": ["STREAMABLE-HTTP", "SSE"],
      "functions": [{ "id": "lookupOrder", "name": "Lookup Order", "tags": ["order", "support"] }]
    }
  ],
  "identityCsrPEM": "-----BEGIN CERTIFICATE REQUEST-----\n...truncated...\n-----END CERTIFICATE REQUEST-----",
  "serverCsrPEM": "-----BEGIN CERTIFICATE REQUEST-----\n...truncated...\n-----END CERTIFICATE REQUEST-----",
  "trustCardContent": { "...JCS-canonical Trust Card body..." },
  "echConfigList": "AEn+DQBFKwAg...truncated..."
}
```

A base-only request (forward-looking) omits `version` and `identityCsrPEM`. Under the V1 RA, `version` and `identityCsrPEM` are both required.

## A.4 Revocation request

```json
{
  "reason": "CESSATION_OF_OPERATION",
  "comments": "Service is being retired."
}
```

Submitted to `POST /v1/agents/{agentId}/revoke`. `reason` is required (RFC 5280 reason code); `comments` is optional, max 200 chars. The sealed `AGENT_REVOKED` event canonicalizes `reason` to `revocationReasonCode` so the immutable record is unambiguous.

## A.5 Trust Card body

The normative schema and hashing rules for the Trust Card body are in [ANS-1 Appendix A](../ans-1-registration.md#appendix-a-trust-card-and-metadata-normative). The Trust Card is optional. Agents without one register fully; the Trust Index scores their integrity lower because the hash-consistency check is unavailable.

A worked Trust Card document lives in the public ANS registry mirror at `spec/examples/trust-card-example.json`.
