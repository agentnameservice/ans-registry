# ANS-4 worked examples (Pub/Sub envelope, TL badge response, revocation event, producer key registration)

Non-normative worked examples for ans-4-transparency. Implementers MAY use these as fixtures or schema cross-checks. All payloads use the **V2 TL response format**: `schemaVersion: "V2"`, certificates as `identityCerts[]` / `serverCerts[]` arrays, `dnsRecordsProvisioned` as an array of `{name, type, data}` objects, and the inclusion proof carried as `merkleProof`.

## A.1 Pub/Sub envelope and inner event

The TL seals the RA's event and publishes it to subscribers. Each published message carries the TL's signature; subscribers verify authenticity without contacting the TL.

Pub/Sub message envelope:

```json
{
  "logId": "550e8400-e29b-41d4-a716-446655440000",
  "schemaVersion": "V2",
  "payload": { ... }
}
```

`logId` is the Transparency Log entry identifier (UUIDv7). The inner event payload mirrors the `AGENT_REGISTERED` event in [ANS-1 worked example A.1](ans-1-examples.md#a1-agent_registered-event-v2-tl-format), whose identifier field is `ansId`.

## A.2 TL badge response

`GET /v1/agents/{agentId}` returns the sealed event, the TL's signature, and a Merkle inclusion proof:

```json
{
  "schemaVersion": "V2",
  "status": "ACTIVE",
  "merkleProof": {
    "leafIndex": 1234567,
    "treeSize": 9876543,
    "leafHash": "abc123def456...",
    "rootHash": "Y3VycmVudDEyMzRhYmNkZWY=",
    "path": ["3vT2c4q7...", "EjRWeJq8z..."],
    "treeVersion": 1
  },
  "payload": {
    "logId": "550e8400-e29b-41d4-a716-446655440000",
    "producer": {
      "event": { "...same as ANS-1 A.1 (V2 event)..." },
      "keyId": "id-B",
      "signature": "eyJhbGciOiJFUzI1NiJ9..."
    }
  },
  "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6InRsLXJvb3Qta2V5LTIwMjUifQ..."
}
```

| Field | Contents |
| --- | --- |
| `schemaVersion` | `V2` |
| `status` | `ACTIVE`, `REVOKED`, or `DEPRECATED`. Computed at query time, not stored in the sealed event |
| `merkleProof` | Inclusion proof. `leafHash` is hex; `rootHash` and each `path` entry are standard base64. `treeVersion` increments on TL key rotation so verifiers select the correct historical key |
| `payload.logId` | TL entry identifier (UUIDv7) |
| `payload.producer.event` | The inner event the RA submitted (identifier field `ansId`) |
| `payload.producer.keyId` | RA producer key identifier |
| `payload.producer.signature` | RA's JWS over the inner event, retained for forensic purposes |
| `signature` | TL's JWS over the entire `payload` |

`merkleProof.path` holds log₂(`treeSize`) hashes (about 30 for a billion events, under 1KB). The field names above use JSON for readability; a conforming TL returns the inclusion proof as a binary COSE receipt, with identical verification semantics.

## A.3 Revocation event — V2 TL format

```json
{
  "ansId": "550e8400-e29b-41d4-a716-446655440000",
  "ansName": "ans://v1.5.0.support.example.com",
  "eventType": "AGENT_REVOKED",
  "agent": {
    "host": "support.example.com",
    "name": "Acme Support Agent",
    "version": "v1.5.0",
    "providerId": "PID-8294"
  },
  "attestations": { "...same as ANS-1 A.1 (V2 attestations)..." },
  "revocationReasonCode": "CESSATION_OF_OPERATION",
  "revokedAt": "2025-11-20T14:00:00.000000Z",
  "issuedAt": "2025-10-05T18:00:00.000000Z",
  "raId": "id-A",
  "timestamp": "2025-11-20T14:00:00.000000Z"
}
```

## A.4 Producer key registration

The TL producer-key admin API uses `snake_case` DTOs.

| Field | Description |
| --- | --- |
| `key_id` | Unique key identifier |
| `public_key_pem` | PEM-wrapped SPKI public key |
| `algorithm` | Signing algorithm (ES256 default) |
| `ra_id` | RA instance identifier |
| `valid_from` | Start of validity period |
| `expires_at` | End of validity period |

The TL returns the `key_id`, `status`, and a `fingerprint` of the registered key.
