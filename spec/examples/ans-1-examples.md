# ANS-1 worked examples (registration request, AGENT_REGISTERED event, EQUIVALENCE_LINK event, revocation)

Non-normative worked examples for ans-1-registration. Implementers MAY use these as fixtures or schema cross-checks.

### A.1 `AGENT_REGISTERED` event (versioned, FQDN-anchored)

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "agentHost": "support.example.com",
  "ansName": "ans://v1.5.0.support.example.com",
  "eventType": "AGENT_REGISTERED",
  "ownerId": "OID-8294",
  "lei": "549300EXAMPLE00LEI17",
  "claim": {
    "anchorType": "fqdn",
    "resolvedId": "support.example.com",
    "publicKey": { "kty": "EC", "crv": "P-256", "x": "f83Or...", "y": "x_FEz..." },
    "issuedAt": "2025-10-05T17:55:00.000000Z"
  },
  "attestations": {
    "identityCert": {
      "fingerprint": "SHA256:22b8a8045734ad3bd8e24c52db8d9aa4dc12907337f790ee70499999021f0eb9",
      "type": "X509-OV-CLIENT"
    },
    "serverCert": {
      "fingerprint": "SHA256:d2b71bc02f119a61611b77eadc44c23670917ac4f435fe4e1095d4e5209087ea",
      "type": "X509-DV-SERVER"
    },
    "dnsRecordsProvisioned": {
      "_ans": "v=ans1; version=v1.5.0; url=https://support.example.com/.well-known/agent-card.json",
      "_ans-badge": "v=ans-badge1; version=v1.5.0; url=https://transparency.ra.ansregistry.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"
    },
    "domainValidation": "ACME-DNS-01",
    "dnssecStatus": "fully_validated"
  },
  "expiresAt": "2026-10-05T18:00:00.000000Z",
  "issuedAt": "2025-10-05T18:00:00.000000Z",
  "raId": "id-A",
  "timestamp": "2025-10-05T18:00:00.000000Z"
}
```

`ansName` carries the `v` prefix on the version segment because the TL stores the ANSName-formatted version. The registration request (`RegisterInput.versionSelector`) accepts `1.5.0` without the prefix; the RA adds it.

### A.2 `AGENT_REGISTERED` event (base-only, DID-anchored)

```json
{
  "agentId": "f3c2d4e5-1234-5678-9abc-def012345678",
  "agentHost": "sdk-did-agent.plang.example.com",
  "eventType": "AGENT_REGISTERED",
  "ownerId": "OID-9302",
  "claim": {
    "anchorType": "did",
    "resolvedId": "did:web:sdk-did-agent.plang.example.com",
    "publicKey": { "kty": "OKP", "crv": "Ed25519", "x": "11qYAY..." },
    "issuedAt": "2026-05-17T09:55:00Z"
  },
  "attestations": {
    "serverCert": {
      "fingerprint": "SHA256:7a91...",
      "type": "X509-DV-SERVER"
    },
    "dnsRecordsProvisioned": {
      "_ans": "v=ans1; url=https://sdk-did-agent.plang.example.com/.well-known/ans/trust-card.json",
      "_ans-badge": "v=ans-badge1; url=https://transparency.ra.ansregistry.com/v1/agents/f3c2d4e5-1234-5678-9abc-def012345678"
    },
    "domainValidation": "DID-WEB-CHALLENGE",
    "dnssecStatus": "not_signed"
  },
  "issuedAt": "2026-05-17T10:00:00Z",
  "raId": "id-A",
  "timestamp": "2026-05-17T10:00:00Z"
}
```

No `ansName`, no `identityCert`. `claim.anchorType` and `claim.resolvedId` carry the DID. `agentHost` is the operational endpoint; `claim.resolvedId` is the identity. The two diverge per ANS-0 §3.1.

### A.3 `EQUIVALENCE_LINK` event

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "eventType": "EQUIVALENCE_LINK",
  "linkedAnsId": "f3c2d4e5-1234-5678-9abc-def012345678",

  "linkedAnchorType": "did",
  "linkedAnchorResolvedId": "did:web:sdk-did-agent.plang.example.com",
  "rationale": "Same agent; FQDN-anchored production registration linked to DID-anchored sandbox registration for cross-environment continuity testing.",
  "raId": "id-A",
  "timestamp": "2026-05-17T18:00:00Z"
}
```

The event is sealed under `agentId` (the primary registration) and references `linkedAnsId` (the equivalent registration). For the single-RA case (the current shape), the RA's authentication system authorizes the link before the RA's producer key signs the envelope. Cryptographic co-signature applies to the federated multi-RA case as a future amendment per §6.4.

### A.4 Registration request

A representative request payload (the AHP submits this to the RA's `/register` endpoint):

```json
{
  "agentHost": "support.example.com",
  "displayName": "Acme Support Agent",
  "description": "Customer support agent.",
  "versionSelector": "1.5.0",
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
      "metadataUrl": "https://support.example.com/.well-known/agent-card.json",
      "transports": ["STREAMABLE-HTTP", "SSE"],
      "functions": [{ "id": "lookupOrder", "name": "Lookup Order", "tags": ["order", "support"] }]
    }
  ],
  "identityCsr": "-----BEGIN CERTIFICATE REQUEST-----\n...truncated...\n-----END CERTIFICATE REQUEST-----",
  "serverCsr": "-----BEGIN CERTIFICATE REQUEST-----\n...truncated...\n-----END CERTIFICATE REQUEST-----",
  "trustCardContent": { "...JCS-canonical Trust Card body..." },
  "echConfigList": "AEn+DQBFKwAg...truncated..."
}
```

A base-only request omits `versionSelector` and `identityCsr`.

### A.5 Revocation request

```json
{
  "reason": "CESSATION_OF_OPERATION",
  "comments": "Service is being retired."
}
```

Submitted to `POST /agents/{agentId}/revoke`. `reason` is required (RFC 5280 reason code); `comments` is optional, max 200 chars. The sealed `AGENT_REVOKED` event canonicalizes `reason` to `revocationReasonCode` so the immutable record is unambiguous.

### A.6 Trust Card body

The normative schema and hashing rules for the Trust Card body are in [ANS-1 Appendix A](../ans-1-registration.md#appendix-a-trust-card-and-metadata-normative). The Trust Card is optional. Agents without one register fully; the Trust Index scores their integrity lower because the hash-consistency check is unavailable.

A worked Trust Card document lives in the public ANS registry mirror at `spec/examples/trust-card-example.json`.

