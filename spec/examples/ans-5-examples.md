# ANS-5 worked example (AIM finding payload)

Non-normative worked examples for ans-5-integrity-monitoring. Implementers MAY use these as fixtures or schema cross-checks.

### A.1 AIM finding payload

The AIM publishes a signed finding when it observes a confirmed mismatch. The payload schema is independent of the RA / TL event format and uses `snake_case`:

```json
{
  "event_type": "integrity_failure_detected",
  "event_timestamp": "2025-10-06T11:00:00Z",
  "worker_id": "id-C",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_host": "support.example.com",
  "ans_name": "ans://v1.5.0.support.example.com",
  "anchor_type": "fqdn",
  "anchor_resolved_id": "support.example.com",
  "check": {
    "record_type": "_ans",
    "failure_type": "MISMATCH",
    "expected_value": "v=ans1; version=v1.5.0; url=https://support.example.com/.well-known/agent-card.json",
    "actual_value": "v=ans1; version=v1.5.0; url=https://malicious-site.com/evil-card.json"
  },
  "evidence_pointer": "https://aim.example.com/evidence/2025-10-06/550e8400-e29b-41d4-a716-446655440000",
  "signature": "eyJhbGciOiJFUzI1NiJ9..."
}
```

The RA, on consuming this finding plus at least one corroborating finding from an independent AIM, re-verifies the discrepancy and, if confirmed, emits `INTEGRITY_WARNING` to the TL per ANS-1 §6.5.
