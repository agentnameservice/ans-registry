# Deprecating `_ans-badge` behind a version signal

Status: draft proposal. Follows PR #58, which added the additive `lr` Transparency Log receipt hint to `_ans`.

## Where this starts

PR #58 added `lr` to the `_ans` record as an additive receipt hint. `_ans-badge` stays required; a verifier that reads `lr` fetches the COSE receipt directly, and one that does not resolves the badge as before. This proposal is the second step: let `lr` replace `_ans-badge` in the zone, once that can happen without breaking any verifier.

## Why the badge cannot just be made optional

An earlier version of PR #58 dropped the badge whenever `lr` was present. Review found three blockers, and this design has to clear each:

1. Deployed verifiers bootstrap from `_ans-badge` and read its absence as "not registered." The `_ans` version tag `v=ans1` does not change, so an old verifier cannot tell that a zone dropped the badge on purpose. Removing it silently breaks that verifier.
2. `Records(reg)` is a pure function over the registration aggregate. It has no field that says "omit the badge for this agent" and performs no I/O, so it cannot decide to omit one. verify-dns then holds the published zone to that emitted set verbatim, so an operator cannot add or drop the record by hand either.
3. ANS-3 §6.4 requires sibling profiles to agree on a shared record's Required flag. `ANS_DNSAID` keeps the badge required, so making it conditional in `ANS_TXT` alone breaks that agreement, and the composition walker has no tie-break.

## The design

Three parts, in order:

1. **A version signal.** Introduce `v=ans2` for the `_ans` record (or an explicit capability tag a verifier keys on). A verifier that understands `ans2` knows the zone may carry `lr` in place of `_ans-badge`; a verifier that understands only `ans1` never sees an `ans2` record it would misread. This is the piece that lets the badge disappear without silently breaking anyone.
2. **A defined verifier path for `lr`.** Specify normatively how a verifier resolves trust from `lr`: fetch the COSE receipt at the `lr` URL, verify its inclusion proof against the TL's published root, and treat that as equivalent to the badge check. Until this path is specified and implemented, `lr` cannot carry the trust decision alone.
3. **An emitter opt-in.** Add a field to the registration aggregate (for example `tlReferenceMode`) so `Records(reg)` deterministically emits either the badge or the `lr`-only form. Thread the flag through ANS-3 §3, §4, §6.3, §6.4, and §9, the `ANS_DNSAID` profile, and the ANS-5 monitoring contract, so every consumer of the emitted set agrees on which records are required.

## Migration

Each stage stays backward-compatible:

1. Additive `lr` alongside the required badge. (Shipped in PR #58.)
2. Verifiers implement the `lr` receipt path.
3. `v=ans2` and the emitter opt-in land; the badge becomes omittable only under `ans2`.
4. Once `ans1` verifiers are retired, `ans2` becomes the default.

## Open questions

- Version-signal shape: a new `v=` value versus a capability tag on the existing `v=ans1` record. A new `v=` is a cleaner break; a tag is lighter but risks the same silent-misread problem, since old verifiers skip unknown tags.
- Whether the one-record saving justifies the cross-spec change. The zone shrinks by one record per agent per version; the cost is a version bump threaded through five ANS-3 sections, a sibling profile, and the monitor.
- Interaction with the HCS-14 ANS resolution profile and the agent-auth spec, both of which key on badge presence today and would need to learn the `ans2` path.

## Non-goals

Governance attribution (the `gi` field from the earlier draft) is out of scope. A governance value in `_ans` is unsigned, and even signed in `_dnsid` it proves control of the signing key, not that the named organization endorsed the record. That is a separate design question.
