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

ANS uses a two-level CA hierarchy. Each environment has a
single root CA and per-region sub-CAs that issue leaf
certificates directly.

```text
Root CA (self-signed, per-environment)
  CN = gd-domain-parking
  O  = GoDaddy, OU = Engineering, C = US
  │
  ├── Sub-CA (us-east-1)
  ├── Sub-CA (us-west-2)
  └── Sub-CA (ap-south-1)   ← prod only
```

## Environments

- **`prod/`** — Production CA chain. Includes the root CA
  and per-region sub-CAs.
- **`ote/`** — OTE (test) CA chain. Includes per-region
  sub-CAs only. Separate CA hierarchy from prod.

Inspect individual certificates for details (subject,
validity, extensions, etc.) using the commands in the
[Verifying Certificates](#verifying-certificates) section.

## Bundle Format

Each `ca-bundle.pem` contains all CA certificates for its
environment as concatenated PEM blocks. Region comments
(e.g. `# us-east-1`) are included between certificates for
human readability. Certificates are ordered by region; the
root CA (when present) appears first.

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

- Root CAs have a **10-year** validity window (prod) to
  minimize rotation overhead.
- Sub-CAs have **5-year** (prod) or **2-year** (OTE)
  validity windows.
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
- **OTE and prod are separate trust domains.** Never load
  `ote/` bundles in production configurations. The
  environments use completely independent CA hierarchies.
- **Verify bundle integrity after download.** Use the
  fingerprint commands in the
  [Verifying Certificates](#verifying-certificates) section
  to confirm certificates match expected values.
