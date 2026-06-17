# ANS PKI Trust Material

This directory contains the public CA certificates for the
Agent Name Service (ANS). SDK consumers and service operators
use these bundles to verify TLS connections and certificate
chains when interacting with ANS endpoints.

## Directory Structure

```text
pki/
├── README.md
├── ote/
│   └── ca-bundle.pem
└── prod/
    └── ca-bundle.pem
```

## Certificate Hierarchy

ANS uses two independent CA hierarchies. **Hierarchy 1** (AWS
Private CA) issues v1 identity certs; **Hierarchy 2** (GoDaddy
Private CA) issues v2 identity certs. Both are present in the
prod bundle and must be trusted to verify identity certs from
either API version.

```text
Hierarchy 1 — AWS Private CA (v1 identity certs)
  Root CA (self-signed, per-environment)
    CN = gd-domain-parking
    O  = GoDaddy, OU = Engineering, C = US
    │
    ├── Sub-CA (us-east-1)
    ├── Sub-CA (us-west-2)
    └── Sub-CA (ap-south-1)

Hierarchy 2 — GoDaddy Private CA (v2 identity certs)
  Root CA (self-signed, global)
    CN = GoDaddy Private Commercial Root CA - PR1
    O  = GoDaddy.com, C = US
```

## Environments

- **`prod/`** — Production CA chain. Includes the root CA
  and per-region sub-CAs.
- **`ote/`** — OTE (test) CA chain. Same CA hierarchy as
  prod; the OTE RA issues identity certificates under the
  prod PKI.

Inspect individual certificates for details (subject,
validity, extensions, etc.) using the commands in the
[Verifying Certificates](#verifying-certificates) section.

## Bundle Format

Each `ca-bundle.pem` contains all CA certificates for its
environment as concatenated PEM blocks. Comments are included
between certificates for human readability: region labels
(e.g. `# us-east-1`) for regional sub-CAs, and descriptive
labels (e.g. `# godaddy-private-commercial-root`) for
non-regional roots. In the prod bundle, certificates from both
CA hierarchies are present; load the full bundle to trust both.

## Verifying Certificates

Inspect certificates in a bundle:

```bash
# Fingerprint a single cert
openssl x509 -in cert.pem -noout -fingerprint -sha256

# Split a bundle and fingerprint each cert
csplit -z ca-bundle.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
for f in xx*; do
  openssl x509 -in "$f" -noout -subject -fingerprint -sha256
done
rm xx*
```

## Usage

### Go

```go
pool := x509.NewCertPool()
bundle, _ := os.ReadFile("pki/prod/ca-bundle.pem")
pool.AppendCertsFromPEM(bundle)

tlsConfig := &tls.Config{RootCAs: pool}
```

### Rust

```rust
let bundle = std::fs::read("pki/prod/ca-bundle.pem")?;
let certs = rustls_pemfile::certs(&mut &bundle[..])
    .collect::<Result<Vec<_>, _>>()?;

let mut root_store = RootCertStore::empty();
for cert in certs {
    root_store.add(cert)?;
}
```

### OpenSSL CLI

```bash
# Verify a leaf certificate against the bundle
openssl verify -CAfile pki/prod/ca-bundle.pem leaf.pem

# Inspect a certificate in the bundle
openssl x509 -in pki/prod/ca-bundle.pem -noout -text
```

## Rotation Policy

- Hierarchy 1 root CAs have a **10-year** validity window
  (prod) to minimize rotation overhead.
- Hierarchy 2 root CA (`GoDaddy Private Commercial Root CA -
  PR1`) has a **20-year** validity window (2026–2046),
  consistent with GoDaddy commercial CA lifecycle. No
  regional sub-CAs exist in this hierarchy.
- Sub-CAs have a **5-year** validity window.
- New certificates will be committed to this repo **before
  expiry** of the outgoing cert, with both old and new
  present in the bundle during the transition period.
- Retired certificates will be moved to a `retired/`
  subdirectory with a commit message noting the reason
  and date.
- Git history is the version record. Do not create versioned
  subdirectories.

## Important Notes

- **Do not pin individual certificate serial numbers.**
  Regional sub-CAs may be reissued independently. Pin the
  root CA fingerprint or load the full bundle.
- **OTE and prod share the same CA hierarchy.** Never load
  `ote/` bundles in production configurations; always use
  the bundle designated for your target environment.
- **Verify bundle integrity after download.** Use the
  fingerprint commands in the
  [Verifying Certificates](#verifying-certificates) section
  to confirm certificates match expected values.
