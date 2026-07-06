# ANS-1 worked examples (registration request, AGENT_REGISTERED event, revocation)

Non-normative worked examples for ans-1-registration. Implementers MAY use these as fixtures or schema cross-checks.

Identifier conventions, by surface (these are distinct identifiers, not aliases):

- **`agentId`** (RA API, `/v2/ans/agents/{agentId}` and `/v1/agents/{agentId}`): the agent *registration instance* UUID the RA assigns and uses on its management API.
- **`ansId`** (TL event payload): the agent identifier carried inside the sealed event payload; in the reference implementation it is the same value as `agentId`.
- **`logId`** (TL envelope, UUIDv7): the *Transparency Log entry* identifier the TL assigns when it seals the event.

TL event payloads below follow the **V2 TL response format**: certificates are carried as `identityCerts[]` / `serverCerts[]` arrays of `{fingerprint, type, notAfter}`, and `dnsRecordsProvisioned` is an array of `{name, type, data}` objects.

## A.1 `AGENT_REGISTERED` event (V2 TL format)

```json
{
  "ansId": "550e8400-e29b-41d4-a716-446655440000",
  "ansName": "ans://v1.5.0.support.example.com",
  "eventType": "AGENT_REGISTERED",
  "agent": {
    "host": "support.example.com",
    "name": "Acme Support Agent",
    "version": "1.5.0"
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
        "data": "v=ans1; version=v1.5.0; p=a2a; mode=direct; url=wss://support.example.com/a2a",
        "dnssecVerified": true
      },
      {
        "name": "_ans-badge.support.example.com",
        "type": "TXT",
        "data": "v=ans-badge1; version=v1.5.0; url=https://transparency.ra.ansregistry.com/v1/agents/550e8400-e29b-41d4-a716-446655440000",
        "dnssecVerified": true
      }
    ],
    "domainValidation": "ACME-DNS-01",
    "metadataHashes": {
      "A2A": "SHA256:3b4f2c1a9e8d7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b"
    }
  },
  "expiresAt": "2026-10-05T18:00:00.000000Z",
  "issuedAt": "2025-10-05T18:00:00.000000Z",
  "raId": "id-A",
  "timestamp": "2025-10-05T18:00:00.000000Z"
}
```

The `version=` field in TXT record data carries the `v`-prefixed form (`v1.5.0`), matching the ANSName's
version segment and ANS-3's record syntax. `agent.version` in the event payload and the registration
request's `version` field carry the bare semver (`1.5.0`). `dnssecVerified` appears on a provisioned record
when the verifying resolver returned the DNSSEC Authenticated-Data bit for that record's query; it is absent
otherwise. `metadataHashes` carries the AHP-declared per-endpoint metadata digests keyed by protocol token,
present only for endpoints that submitted a `metaDataHash`.

## A.2 Registration request — V1 RA format

A representative request payload (the AHP submits this to the RA's `POST /v1/agents/register` endpoint; the V2 lane accepts the same fields at `POST /v2/ans/agents`).

```json
{
  "agentDisplayName": "Acme Support Agent",
  "agentDescription": "Customer support agent.",
  "version": "1.5.0",
  "agentHost": "support.example.com",
  "endpoints": [
    {
      "protocol": "A2A",
      "agentUrl": "wss://support.example.com/a2a",
      "metaDataUrl": "https://support.example.com/.well-known/agent-card.json",
      "metaDataHash": "SHA256:3b4f2c1a9e8d7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b",
      "transports": ["STREAMABLE_HTTP", "SSE"],
      "functions": [{ "id": "lookupOrder", "name": "Lookup Order", "tags": ["order", "support"] }]
    }
  ],
  "identityCsrPEM": "-----BEGIN CERTIFICATE REQUEST-----\n...truncated...\n-----END CERTIFICATE REQUEST-----",
  "serverCsrPEM": "-----BEGIN CERTIFICATE REQUEST-----\n...truncated...\n-----END CERTIFICATE REQUEST-----"
}
```

`version`, `agentHost`, `agentDisplayName`, and at least one endpoint are required. Exactly one of `serverCsrPEM` / `serverCertificatePEM` MUST be present. `identityCsrPEM` is optional — omitting it registers the agent without an Identity Certificate ([ANS-1 §7.2](../ans-1-registration.md#72-registrations-without-an-identity-certificate)).

## A.3 Revocation request

```json
{
  "reason": "CESSATION_OF_OPERATION",
  "comments": "Service is being retired."
}
```

Submitted to `POST /v1/agents/{agentId}/revoke` (V2: `POST /v2/ans/agents/{agentId}/revoke`). `reason` is required (an RFC 5280 revocation reason name token); `comments` is optional, max 200 chars. The sealed `AGENT_REVOKED` event canonicalizes `reason` to `revocationReasonCode` so the immutable record is unambiguous.
