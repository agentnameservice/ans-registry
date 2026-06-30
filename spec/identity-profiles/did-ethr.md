# Identity profile: `did:ethr` / `did:pkh` (deferred sketch)

Status: DRAFT v1.0 — deferred sketch
Profile: did:ethr, did:pkh (Ethereum-account identities)
Core: [ANS-0: Identity](../ans-0-identity-anchor.md)
Version: 0.0.1
Date: 2026-06-23
Audience: implementers evaluating future identifier kinds

> **Deferred.** Intended shape only. Ships when an Ethereum-account resolver/verifier, tests, and
> RPC plumbing are real; until then `IDENTIFIER_KIND_UNSUPPORTED` (ANS-0 §10.1). No placeholder
> seal.

**Requirement: Optional** — a who-identity profile ([ANS-0 §12.2](../ans-0-identity-anchor.md#122-optional-capability-verified-identities)), like every who-profile.

Ethereum-account identities bind an on-chain account (an EOA or a smart-contract wallet) to an
ANS identity. This is the one currently-anticipated kind that is **not** JOSE/JWS: Ethereum
signatures are secp256k1 over a Keccak-256 digest, with their own message-framing standards. The
profile therefore introduces a second key-control proof shape under the same gate (the
`IdentityProofInput` and `purpose` domain separation are unchanged; only the signing/verification
codec differs).

- **Identifier / selection** (lexical):
  - `did:ethr:[<chain>:]0x<address>` — ERC-1056 registry method; the DID document is derived from
    the on-chain `EthereumDIDRegistry` plus the address.
  - `did:pkh:eip155:<chain-id>:0x<address>` — chain-agnostic, key derived from the address; no
    registry read for the base case.
  - Canonical form lowercases the address per the method (EIP-55 checksum preserved as a
    validation input, not as the canonical key).
- **Key source / control axis** (key only):
  - **EOA**: an EIP-191 `personal_sign` or, preferred, an **EIP-712** typed-data signature over a
    structured encoding of the proof input; the recovered signer address MUST equal the DID's
    address.
  - **Smart-contract wallet**: **ERC-1271** `isValidSignature(hash, signature)` against the
    wallet contract (an on-chain `eth_call`) — this is what lets multisig/AA wallets prove
    control.
  - `did:ethr` additionally honors the ERC-1056 registry's delegate/owner changes and the
    document's listed verification methods.
- **Seal tier**: verbatim verification method — the recovered/declared `blockchainAccountId`
  (CAIP-10) verification method (`EcdsaSecp256k1RecoveryMethod2020` / the method's published VM),
  sealed as published, plus the proof. For ERC-8004 agent-identity registrations, the on-chain
  agent record is referenced, not copied.
- **Freshness/monitoring**: ANS-5 re-reads the ERC-1056 registry / wallet code and owner; the
  signal is an owner/delegate change or a contract that stops validating the sealed authorization.
- **External plumbing (SSRF analogue)**: requires an Ethereum JSON-RPC provider. The chain-read
  path is an egress dependency: pin to configured, trusted RPC endpoints (not registrant-supplied
  URLs), bound calls, and never expose RPC errors as an oracle. CCIP-Read (EIP-3668) off-chain
  gateway resolution, if supported, is itself a registrant-steered fetch and MUST be hardened like
  did:web.
- **What gates promotion**: a secp256k1/Keccak proof verifier (EIP-191 + EIP-712), an ERC-1271
  `eth_call` path, a pinned-RPC resolver behind the port, and tests against real chain reads (the
  `scripts/poc/ethid` proof-of-concept established feasibility against live Ethereum + DNS).

Note: EIP-712 typed-data binding is preferred over `personal_sign` because the structured domain
(`EIP712Domain`) gives a second, wallet-visible domain separation on top of ANS's `purpose`.
