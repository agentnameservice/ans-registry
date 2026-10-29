# ANS-1 worked examples (registration, lifecycle and metadata updates)

Non-normative worked examples for ans-1-registration. Implementers MAY use these as fixtures or schema cross-checks.

Identifier conventions, by surface (these are distinct identifiers, not aliases):

- **`agentId`** (RA API, `/v2/ans/agents/{agentId}` and `/v1/agents/{agentId}`): the agent *registration instance* UUID the RA assigns and uses on its management API.
- **`ansId`** (TL event payload): the agent identifier carried inside the sealed event payload; in the reference implementation it is the same value as `agentId`.
- **`logId`** (TL envelope, UUIDv7): the *Transparency Log entry* identifier the TL assigns when it seals the event.

Current event payloads below follow the **V3 TL response format**: certificates are carried as `identityCerts[]` / `serverCerts[]` arrays of `{fingerprint, type, notAfter}`, and `dnsRecordsProvisioned` is an array of `{name, type, data}` objects.

## A.1 `AGENT_REGISTERED` event (V3 TL format)

```json
{
  "ansId": "550e8400-e29b-41d4-a716-446655440000",
  "ansName": "ans://support.example.com",
  "eventType": "AGENT_REGISTERED",
  "agent": {
    "host": "support.example.com",
    "name": "Acme Support Agent"
  },
  "attestations": {
    "identityCerts": [
      {
        "fingerprint": "SHA256:22b8a8045734ad3bd8e24c52db8d9aa4dc12907337f790ee70499999021f0eb9",
        "type": "X509-OV-CLIENT",
        "notAfter": "2026-10-05T18:00:00Z"
      }
    ],
    "serverCerts": [
      {
        "fingerprint": "SHA256:d2b71bc02f119a61611b77eadc44c23670917ac4f435fe4e1095d4e5209087ea",
        "type": "X509-DV-SERVER",
        "notAfter": "2026-10-05T18:00:00Z"
      }
    ],
    "dnsRecordsProvisioned": [
      {
        "name": "_ans.support.example.com",
        "type": "TXT",
        "data": "v=ans1; p=a2a; mode=direct; url=wss://support.example.com/a2a"
      },
      {
        "name": "_ans-badge.support.example.com",
        "type": "TXT",
        "data": "v=ans-badge1; url=https://transparency.ra.ansregistry.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"
      }
    ],
    "domainValidation": "ACME-DNS-01",
    "endpointMetadata": [
      {
        "protocol": "A2A",
        "agentUrl": "wss://support.example.com/a2a",
        "metaDataUrl": "https://support.example.com/.well-known/agent-card.json",
        "metaDataHashes": [
          "SHA256:3b4f2c1a9e8d7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b"
        ]
      }
    ]
  },
  "expiresAt": "2026-10-05T18:00:00Z",
  "issuedAt": "2025-10-05T18:00:00.000000Z",
  "raId": "id-A",
  "timestamp": "2025-10-05T18:00:00.000000Z"
}
```

Versionless names omit `version` and the TXT `version=` pair. Versioned registrations remain valid and
retain their assigned name. V3 DNS attestations contain only applicable observed non-TLSA records;
metadata commitments are scoped to the service/metadata tuple. Historical V1/V2 entries are unchanged.

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

`agentHost`, `agentDisplayName`, and at least one endpoint are required. V2 may omit `version` to create
`ans://{agentHost}`; the versioned example above remains valid, and V1 still requires a version. Exactly one
of `serverCsrPEM` / `serverCertificatePEM` MUST be present. `identityCsrPEM` is optional — omitting it
registers the agent without an Identity Certificate ([ANS-1
§7.2](../ans-1-registration.md#72-identity-credential-management)).

## A.3 Revocation request

```json
{
  "reason": "CESSATION_OF_OPERATION",
  "comments": "Service is being retired."
}
```

Submitted to `POST /v1/agents/{agentId}/revoke` (V2: `POST /v2/ans/agents/{agentId}/revoke`). `reason` is required (an RFC 5280 revocation reason name token); `comments` is optional, max 200 chars. The sealed `AGENT_REVOKED` event canonicalizes `reason` to `revocationReasonCode` so the immutable record is unambiguous.

## A.4 Certificate expiry during overlap

At `2026-11-01T00:00:00Z`, assume a sealed `AGENT_REGISTERED` attestation whose certificate evidence
lists these four currently valid certificates. All expiry dates below mean `00:00:00Z` on that date.

| Certificate group | First certificate expires | Second certificate expires | Latest group expiry |
| --- | --- | --- | --- |
| Server | 2026-12-01 | 2027-01-01 | 2027-01-01 |
| Identity | 2027-10-01 | 2027-12-01 | 2027-12-01 |

Applying [ANS-1 §7.3](../ans-1-registration.md#73-expiry):

```text
serverExpiry   = max(2026-12-01, 2027-01-01) = 2027-01-01
identityExpiry = max(2027-10-01, 2027-12-01) = 2027-12-01
expiresAt      = min(2027-01-01, 2027-12-01) = 2027-01-01
```

The attested `expiresAt` is therefore `2027-01-01T00:00:00Z`. After `2026-12-01T00:00:00Z`, the first
Server Certificate has expired, but the second Server Certificate remains valid and the Identity
Certificate group remains valid beyond it. The Server Certificate group's validity includes
`2027-01-01T00:00:00Z`; it lapses only when the current instant is later than that boundary.

For a server-only registration, only the Server Certificate group participates, giving the same
`2027-01-01T00:00:00Z`. Returning to server-only operation requires explicit retirement of the identity
bindings under ANS-1 §7.2; expiration alone does not remove a required group.

## A.5 Renewal while the other certificate group is expired

At activation, an identity-bearing registration sealed a Server Certificate expiring on
`2026-10-01T00:00:00Z` and an Identity Certificate expiring on `2026-09-01T00:00:00Z`:

```text
serverExpiry   = 2026-10-01T00:00:00Z
identityExpiry = 2026-09-01T00:00:00Z
expiresAt      = 2026-09-01T00:00:00Z
```

On `2026-09-13`, its stored RA status remains `ACTIVE`, but the Identity Certificate has expired.
The AHP completes Server Certificate renewal with a replacement expiring on `2026-12-12T00:00:00Z`.

Renewal succeeds and publishes `AGENT_RENEWED` with the replacement server certificate and the expired
identity group's evidence. The new snapshot still has `expiresAt = 2026-09-01T00:00:00Z`, because the
identity group remains the limiting group. The TL reports EXPIRED; server renewal alone does not restore
validity to every required group. The prior `AGENT_REGISTERED` leaf remains unchanged.

## A.6 Metadata rollout and multiple endpoints

The owner reads `/v2/ans/agents/{agentId}/endpoints`, then PUTs the complete replacement with that
resource's `If-Match` ETag. The response is 202 with `status: PENDING_PUBLICATION`. The V3 event's
`attestations.endpointMetadata` contains the complete result. This excerpt shows both rollout overlap
at one location and a second endpoint using the same protocol:

```json
{
  "endpointMetadata": [
    {
      "protocol": "A2A",
      "agentUrl": "https://agent.example.com/v1/a2a",
      "metaDataUrl": "https://agent.example.com/v1/card.json",
      "metaDataHashes": [
        "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      ]
    },
    {
      "protocol": "A2A",
      "agentUrl": "https://agent.example.com/v2/a2a",
      "metaDataUrl": "https://agent.example.com/v2/card.json",
      "metaDataHashes": ["SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]
    }
  ]
}
```

The status-token payload uses native CBOR, shown here in diagnostic notation. Existing keys 1–8
are omitted from this excerpt. It is not JSON text inside a token:

```cbor-diag
{
  9: [
    {
      1: "A2A",
      2: "https://agent.example.com/v1/a2a",
      3: "https://agent.example.com/v1/card.json",
      4: [h'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          h'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']
    },
    {
      1: "A2A",
      2: "https://agent.example.com/v2/a2a",
      3: "https://agent.example.com/v2/card.json",
      4: [h'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc']
    }
  ]
}
```

After the old v1 metadata is retired, replace its set with only `b…`; the v2 set remains `c…`.
Neither the agent ID nor any historical event changes. Existing overlap tokens retain their normal
acceptance window. A digest from v2 cannot authorize the v1 document.

## A.7 Account-scoped parent proof and update-time revalidation

Account 1 owns a pending BYOC registration for `agent.example.com`, with ID
`550e8400-e29b-41d4-a716-446655440000`. To validate its parent, it sends this body to
`POST /v2/ans/agents/550e8400-e29b-41d4-a716-446655440000/domain-validation`:

```json
{
  "domain": "example.com",
  "challengeType": "DNS_01"
}
```

The RA returns 202 using the existing challenge model. The value below is illustrative; production
tokens and key authorizations must be unpredictable and account/request-bound.

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING_VALIDATION",
  "validationId": "a54ae223-9cbf-414a-8d47-f620ade26e84",
  "validationDomain": "example.com",
  "expiresAt": "2026-11-01T00:10:00Z",
  "challenges": [{
    "type": "DNS_01",
    "token": "fresh-account-bound-token",
    "dnsRecord": {
      "name": "_acme-challenge.example.com",
      "type": "TXT",
      "value": "base64url-sha256-key-authorization"
    },
    "expiresAt": "2026-11-01T00:10:00Z"
  }],
  "links": [{
    "rel": "verify",
    "href": "https://ra.example.com/v2/ans/agents/550e8400-e29b-41d4-a716-446655440000/domain-validation/verify"
  }]
}
```

After publishing the TXT record, the owner sends `{ "validationId": "a54ae223-9cbf-414a-8d47-f620ade26e84" }`
to the verify link. Successful verification returns 200:

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "VALID",
  "validatedDomain": "example.com",
  "domainValidation": "ACME-DNS-01",
  "domainValidatedAt": "2026-11-01T00:00:00Z",
  "domainValidUntil": "2026-12-01T00:00:00Z",
  "links": []
}
```

The pending agent can complete its normal certificate/DNS activation using this proof. The same account
can register `other.example.com`, renew either certificate role, and update covered registrations before
December 1 without another ANS ACME challenge. Its certificate must still cover the actual agent FQDN.
Account 2 cannot reuse Account 1's proof. A DNS-01 grant for `agent.example.com` would cover its own
descendants but not `other.example.com`; an HTTP-01 grant covers only its exact host.

At `2026-12-01T00:00:00Z`, the proof becomes non-reusable. The existing registrations remain active,
discoverable and authenticatable, and normal status-token refresh continues, subject to certificate
validity and lifecycle rules. The token format and its normal expiry do not depend on this date.
The next ordinary update without another eligible grant returns 409:

```json
{
  "status": "ERROR",
  "code": "DOMAIN_REVALIDATION_REQUIRED",
  "message": "Complete domain validation before retrying this update.",
  "details": {
    "validationUrl": "/v2/ans/agents/550e8400-e29b-41d4-a716-446655440000/domain-validation",
    "validatedDomain": "example.com",
    "domainValidUntil": "2026-12-01T00:00:00Z"
  }
}
```

Revalidate, then retry against the current ETag/state. A failed challenge or an abandoned update leaves
the existing registration unchanged. Credential retirement and registration revocation remain available
without fresh proof. An update committed just before the reuse deadline can publish afterward: the TL
appends its original signed bytes and the normal certificate/lifecycle checks determine current status.
