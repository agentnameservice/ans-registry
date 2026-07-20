# ANS-4 worked examples (sealed envelope, TL badge response, revocation event, producer key registration)

Non-normative worked examples for ans-4-transparency. Implementers MAY use these as fixtures or schema cross-checks. All payloads use the **V2 TL response format**: `schemaVersion: "V2"`, certificates as `identityCerts[]` / `serverCerts[]` arrays, `dnsRecordsProvisioned` as an array of `{name, type, data}` objects, and the inclusion proof carried as `merkleProof`.

## A.1 Sealed envelope and append response

The TL wraps the RA's producer-signed event in a sealed envelope — the record whose JCS-canonical
bytes form the Merkle leaf (`SHA-256(0x00 ‖ JCS(envelope))`, [ANS-4 §3](../ans-4-transparency.md#3-cryptographic-standards)):

```json
{
  "payload": {
    "logId": "550e8400-e29b-41d4-a716-446655440000",
    "producer": {
      "event": "...the inner event the RA submitted (see ANS-1 A.1)...",
      "keyId": "id-B",
      "signature": "eyJhbGciOiJFUzI1NiJ9..."
    }
  },
  "schemaVersion": "V2",
  "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6InRsLXNpZ24ifQ...",
  "status": "SEALED"
}
```

`logId` is the TL-assigned entry identifier (UUIDv7). The outer `signature` is the TL's
attestation, a detached JWS over the JCS-canonical `payload`; it is populated **before** the leaf
hash is computed, so the leaf covers the attested envelope.

The append response returns the Merkle position directly so a producer can fetch a receipt
without a second lookup:

```json
{
  "logId": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "leafIndex": 1234567,
  "leafHashHex": "9f3a...c2b",
  "duplicate": false,
  "treeSize": 1234568
}
```

`duplicate: true` marks a content-hash dedup hit — a byte-identical retry landed on the existing
leaf rather than appending a new one.

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
      "event": "...same as ANS-1 A.1 (V2 event)...",
      "keyId": "id-B",
      "signature": "eyJhbGciOiJFUzI1NiJ9..."
    }
  },
  "signature": "eyJhbGciOiJFUzI1NiIsImtpZCI6InRsLXNpZ24ifQ..."
}
```

| Field | Contents |
| --- | --- |
| `schemaVersion` | `V2` |
| `status` | Computed at query time, not stored in the sealed event: `ACTIVE`, `DEPRECATED`, `REVOKED`, `EXPIRED`, `WARNING` (certificate approaching expiry), or `UNKNOWN` |
| `merkleProof` | Inclusion proof. `leafHash` is hex of the RFC 6962 leaf hash; `rootHash` and each `path` entry are standard base64. `treeVersion` is `1`, reserved to roll forward on breaking tree changes |
| `payload.logId` | TL entry identifier (UUIDv7) |
| `payload.producer.event` | The inner event the RA submitted (identifier field `ansId`) |
| `payload.producer.keyId` | RA producer key identifier |
| `payload.producer.signature` | RA's detached JWS over the inner event, retained for forensic purposes |
| `signature` | TL's detached JWS attestation over the JCS-canonical `payload` |

`merkleProof.path` holds log₂(`treeSize`) hashes (about 30 for a billion events, under 1KB). The JSON `merkleProof` and the binary COSE receipt at `GET /v1/agents/{agentId}/receipt` carry the same proof with identical verification semantics ([ANS-4 §5.2](../ans-4-transparency.md#52-receipts-status-tokens-checkpoints)).

## A.3 Revocation event — V2 TL format

```json
{
  "ansId": "550e8400-e29b-41d4-a716-446655440000",
  "ansName": "ans://v1.5.0.support.example.com",
  "eventType": "AGENT_REVOKED",
  "agent": {
    "host": "support.example.com",
    "name": "Acme Support Agent",
    "version": "1.5.0"
  },
  "revocationReasonCode": "CESSATION_OF_OPERATION",
  "revokedAt": "2025-11-20T14:00:00Z",
  "issuedAt": "2025-11-20T14:00:00Z",
  "raId": "id-A",
  "timestamp": "2025-11-20T14:00:00Z"
}
```

The revocation event carries no `attestations` block — it records the transition (`revocationReasonCode`, an RFC 5280 reason name token, and `revokedAt`) against the same `ansId` whose `AGENT_REGISTERED` leaf holds the attested state.

## A.4 Producer key registration

The TL producer-key admin API (`POST /internal/v1/producer-keys`, admin-gated) uses `snake_case` DTOs.

| Field | Description |
| --- | --- |
| `key_id` | Unique key identifier, chosen by the operator |
| `public_key_pem` | PEM-wrapped SPKI public key |
| `algorithm` | Signing algorithm (`ES256`) |
| `ra_id` | RA instance identifier |
| `valid_from` | Start of validity period (required; must precede `expires_at`) |
| `expires_at` | End of validity period (required) |

The TL returns the `key_id`, `status`, and a `fingerprint` of the registered key. A duplicate `key_id` is rejected (409).
