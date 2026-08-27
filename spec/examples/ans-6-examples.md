# ANS-6 worked examples (badge record, receipt, status token, root keys, Flavor-B exchange)

Non-normative worked examples for ans-6-agent-authentication. Implementers MAY use these as
fixtures or cross-checks. Hosts, UUIDs, keys, and hashes are illustrative.

## A.1 `_ans-badge` record and version-change coexistence

Steady state — one record:

```text
_ans-badge.agent.example.com. IN TXT "v=ans-badge1; version=v1.0.0; url=https://transparency-log.example.com/v1/agents/7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
```

During a version change — two registrations, two records, both ACTIVE:

```text
_ans-badge.agent.example.com. IN TXT "v=ans-badge1; version=v1.0.0; url=https://transparency-log.example.com/v1/agents/7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"
_ans-badge.agent.example.com. IN TXT "v=ans-badge1; version=v1.0.1; url=https://transparency-log.example.com/v1/agents/019be7f3-5720-77c9-9672-adae3394502f"
```

A callee authenticating a Flavor-A caller whose Identity Certificate URI SAN is
`ans://v1.0.1.agent.example.com` selects the second record by its `version` field and fetches
only that badge. The badge response shape is the V2 TL envelope shown in
[ANS-4 example A.2](ans-4-examples.md#a2-tl-badge-response).

## A.2 SCITT receipt structure

`GET /v1/agents/{agentId}/receipt` → `application/scitt-receipt+cose`:

```text
COSE_Sign1 [CBOR tag 18]
├── Protected header (CBOR map)
│   ├── 1  (alg):  -7 (ES256)
│   ├── 4  (kid):  h'c9e2f584'          ; SHA-256(SPKI-DER)[0:4], matches /root-keys
│   ├── 395 (vds): 1                     ; RFC9162_SHA256
│   └── 15 (cwt-claims): { 1 (iss): "transparency-log.example.com", 6 (iat): 1787529600 }
├── Unprotected header (CBOR map)                      ; NOT covered by the signature
│   └── 396 (vdp): inclusion proof
│       ├── -1 (tree_size):  15
│       ├── -2 (leaf_index): 8
│       ├── -3 (hash_path):  [ h'de5f12…', h'8a4c09…' ]   ; 32-byte sibling hashes
│       └── -4 (root_hash):  h'98a034…'                   ; advisory — unsigned
├── Payload (attached): JCS-canonicalized sealed leaf bytes (ANS-4 §3 envelope:
│   {payload: {logId, producer: {event, keyId, signature}}, schemaVersion, signature, status})
└── Signature: 64 bytes, ECDSA P-256, IEEE P1363 (R || S)
```

The ES256 signature over the `Signature1` Sig_structure — protected header + payload only —
verifies under the `/root-keys` key whose hash is `c9e2f584`; that is what makes the leaf
trustworthy. Walking `hash_path` from `SHA-256(0x00 || payload)` per RFC 9162 *computes* a root;
the receipt itself never authenticates it (the VDP is unprotected, and `-4` is advisory), so a
verifier wanting tree-head trust compares the computed root against the TL's signed
`GET /checkpoint` note.

## A.3 Status token structure

`GET /v1/agents/{agentId}/status-token` → `application/ans-status-token+cbor`:

```text
COSE_Sign1 [CBOR tag 18]
├── Protected header (CBOR map)
│   ├── 1 (alg): -7 (ES256)
│   ├── 3 (content type): "application/ans-status-token+cbor"
│   └── 4 (kid): h'c9e2f584'
├── Unprotected header: {}
├── Payload (CBOR map, integer keys)
│   ├── 1: "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07"        ; agentId
│   ├── 2: "ACTIVE"                                       ; status
│   ├── 3: 1787529600                                     ; iat
│   ├── 4: 1787533200                                     ; exp (iat + 1h)
│   ├── 5: "ans://v1.0.0.agent.example.com"               ; ansName
│   ├── 6: [ {1: h'aebd…', 2: "X509-OV-CLIENT"},          ; validIdentityCerts
│   │        {1: h'9e2c…', 2: "X509-OV-CLIENT"} ]         ;   (rotation overlap: two entries)
│   ├── 7: [ {1: h'e7b6…', 2: "X509-DV-SERVER"} ]         ; validServerCerts
│   └── 8: { "A2A": "SHA256:3b4f2c1a…" }                  ; metadataHashes
└── Signature: 64 bytes, ECDSA P-256, IEEE P1363
```

Key 6 carrying two fingerprints is what makes certificate rotation seamless in the SCITT tier: a
verifier matches the presented certificate against **any** entry.

## A.4 Root-keys line

`GET /root-keys` returns newline-delimited C2SP-format keys:

```text
transparency-log.example.com+c9e2f584+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJiE0eriKUOYbYrXerJlCJv6TZGEglLkPOHo+bEieNtPsL2FjuXfRCZbYF3RCwqF/99iDVxIUHJWTcW3KXqbiCU=
```

`c9e2f584` is the hex first-4-bytes of SHA-256 over the SPKI DER (the base64 part, after
stripping the leading C2SP key-type octet `0x02`), and is the `kid` (label 4) receipts and status
tokens carry. A parser recomputes the hash and rejects the line on disagreement.

## A.5 Flavor-B exchange (DPoP + SCITT headers)

The caller `ans://v1.0.0.caller.example.com` invokes `POST /api/task` on
`payments.example.com`, presenting a DPoP-bound OAuth access token:

```http
POST /api/task HTTP/1.1
Host: payments.example.com
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9…
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7…
X-SCITT-Receipt: 0oRYS6MBJgRE…                (std base64 of A.2's COSE bytes)
X-ANS-Status-Token: 0oRYPqMBJgNY…             (std base64 of A.3's COSE bytes)
Content-Type: application/json
```

The `DPoP` value is a compact JWS. Decoded JOSE header — exactly four parameters, nothing else:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
  },
  "x5c": ["MIIB0zCCAXqgAwIBAgIUY…"]
}
```

`x5c[0]` is the caller's Identity Certificate (DER, standard base64); its public key equals the
`jwk` byte-for-byte, its `ans://` URI SAN names the caller, and its SHA-256 fingerprint appears
in the status token's `validIdentityCerts`.

Decoded payload:

```json
{
  "htm": "POST",
  "htu": "https://payments.example.com/api/task",
  "iat": 1787529605,
  "jti": "4b6ff43ff44e3f65a4f8f3aad4b6f0e2",
  "ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
}
```

`htu` is the normalized target (lowercased scheme/host, default port dropped, no query or
fragment); `ath` is `base64url(SHA-256(access token))` and is present only because the request
carries `Authorization: DPoP`. The callee verifies the proof, binds it to the status token and
receipt, records the `jti`, checks the access token's `cnf.jkt` against the proof key's RFC 7638
thumbprint while validating the token, and only then authorizes and processes the request.

The response carries the callee's own artifacts, which the caller verifies against the TLS Server
Certificate it captured in the handshake:

```http
HTTP/1.1 200 OK
X-SCITT-Receipt: 0oRYS6MBJgRE…
X-ANS-Status-Token: 0oRYPqMBJgNY…
Content-Type: application/json
```

## A.6 Negative example: spoofed `Host` against a misconfigured callee

The §7.7 authority requirement, shown failing. A callee at `api.other.example` sits behind a
TLS-terminating proxy, derives the `htu` comparison URL from the request's own `Host` header, and
configures no trusted-authority allowlist. An attacker who captured the A.5 proof — minted for a
call to `payments.example.com` — replays it, together with the (public) receipt and status token,
with a spoofed `Host`:

```http
POST /api/task HTTP/1.1
Host: payments.example.com        <- client-controlled; this server is api.other.example
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIs…   <- captured proof, htu = https://payments.example.com/api/task
X-SCITT-Receipt: 0oRYS6MBJgRE…
X-ANS-Status-Token: 0oRYPqMBJgNY…
```

The misconfigured callee reconstructs `https://payments.example.com/api/task` from `Host`, the
`htu` comparison passes, every other check passes (the artifacts are genuine and the proof's
`jti` was never seen *here* — single-use is enforced per callee), and a request the caller never
made to this service authenticates as that caller within the `iat` window.

The same request against a conformant configuration fails before any proof verification: a
trusted-authority allowlist containing `api.other.example` rejects the claimed authority
outright, and an externally configured URL makes the comparison
`htu ≠ https://api.other.example/api/task`.
