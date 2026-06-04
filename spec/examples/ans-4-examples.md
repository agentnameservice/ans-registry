# ANS-4 worked examples (Pub/Sub envelope, TL badge response, revocation event, producer key registration)

Non-normative worked examples for ans-4-transparency. Implementers MAY use these as fixtures or schema cross-checks.

### A.1 Pub/Sub envelope and inner event

The TL seals the RA's event and publishes it to subscribers. Each published message carries the TL's signature; subscribers verify authenticity without contacting the TL.

Pub/Sub message envelope:

```json
{
  "logId": "550e8400-e29b-41d4-a716-446655440000",
  "schemaVersion": "V1",
  "payload": { ... }
}
```

The inner event payload mirrors the `AGENT_REGISTERED` event in [ANS-1 Appendix A.1](../ans-1-registration.md#a1-agent_registered-event-versioned-fqdn-anchored).

### A.2 TL badge response

`GET /v1/agents/{agentId}` returns the sealed event, the TL's signature, and an inclusion proof:

```json
{
  "schemaVersion": "V1",
  "status": "ACTIVE",
  "payload": {
    "logId": "550e8400-e29b-41d4-a716-446655440000",
    "producer": {
      "event": { "...same as ANS-1 A.1..." },
      "keyId": "id-B",
      "signature": "eyJhbGciOiJFUzI1NiJ9..."
    }
  },
  "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6InRsLXJvb3Qta2V5LTIwMjUifQ...",
  "inclusionProof": {
    "leafHash": "abc123def456...",
    "leafIndex": 1234567,
    "treeSize": 9876543,
    "treeVersion": 1,
    "path": ["def456789abc...", "012345abcdef...", "..."],
    "rootHash": "current1234abcdef...",
    "rootSignature": "eyJhbGciOiJFUzI1NiJ9..."
  }
}
```

| Section | Contents |
|---|---|
| `status` | `ACTIVE`, `DEPRECATED`, `WARNING`, `EXPIRED`, or `REVOKED`. Computed at query time, not stored in the sealed event |
| `payload.producer.event` | The inner event the RA submitted |
| `payload.producer.keyId` | RA producer key identifier |
| `payload.producer.signature` | RA's JWS over the inner event, retained for forensic purposes |
| `signature` | TL's JWS over the entire `payload` |
| `inclusionProof.path` | log₂(`treeSize`) hashes (about 30 for a billion events, under 1KB) |
| `inclusionProof.rootSignature` | TL's JWS over `rootHash` |
| `inclusionProof.treeVersion` | Increments on TL key rotation so verifiers select the correct historical key |

The field names above use JSON for readability. A conforming TL returns the inclusion proof as a binary COSE receipt; the verification semantics are identical.

### A.3 Revocation event

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "agentHost": "support.example.com",
  "ansName": "ans://v1.5.0.support.example.com",
  "eventType": "AGENT_REVOKED",
  "ownerId": "OID-8294",
  "lei": "549300EXAMPLE00LEI17",
  "claim": { "...same as ANS-1 A.1..." },
  "attestations": { "...same as ANS-1 A.1..." },
  "revocationReasonCode": "CESSATION_OF_OPERATION",
  "revokedAt": "2025-11-20T14:00:00.000000Z",
  "issuedAt": "2025-10-05T18:00:00.000000Z",
  "raId": "id-A",
  "timestamp": "2025-11-20T14:00:00.000000Z"
}
```

### A.4 Producer key registration

| Field | Description |
|---|---|
| `keyId` | Unique key identifier |
| `publicKey` | PEM-encoded public key |
| `algorithm` | Signing algorithm (ES256 default) |
| `raId` | RA instance identifier |
| `validFrom` | Start of validity period |
| `expiresAt` | End of validity period |

The TL returns the `keyId`, status, and a fingerprint of the registered key.
