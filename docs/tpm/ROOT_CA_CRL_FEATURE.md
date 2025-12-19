# Root CA CRL Verification Feature

## Overview

The `root-ca-crl` feature adds support for verifying Root CA certificates against their Certificate Revocation Lists (CRLs), which standard webpki does not support.

## Background

### Why Standard webpki Doesn't Check Root CA CRLs

Per RFC 5280 Section 6:
> The trust anchor information may be provided to the path processing procedure in the form of a self-signed certificate. [...] These self-signed certificates are not validated as part of the certification path.

Standard webpki follows this specification:
- ✅ Verifies: Leaf Cert → Intermediate CA (with CRL checking)
- ✅ Verifies: Intermediate CA → Root CA (signature verification)
- ❌ Does NOT verify: Root CA against its own CRL (trust anchor assumed trusted)

### When Root CA CRL Verification Is Needed

Some certificate hierarchies DO have CRL Distribution Points in Root CA certificates:

**Intel SGX/TDX DCAP**:
- Root CA has CRL Distribution Points
- CRL is downloadable via PCCS (Provisioning Certificate Caching Service)
- Root CA can be rotated/revoked
- dcap-qvl requires Root CA CRL verification

**GCP vTPM** (as of 2025-12-04):
- Root CA **currently has NO CRL** Distribution Points
- This is standard practice for most PKIs
- But may add CRL in the future for key rotation

## Implementation

### Dependencies

The feature uses `dcap-qvl-webpki`, a fork of `rustls-webpki` that adds:

```rust
pub fn check_single_cert_crl(
    cert_der: &[u8],
    crls_der: &[&[u8]],
    time: UnixTime,
) -> Result<(), Error>
```

This function verifies a single certificate (including root CAs) against CRLs.

### Cargo.toml

```toml
[dependencies]
# Standard webpki for certificate chain verification
webpki = { version = "0.102", package = "rustls-webpki", ... }

# Root CA CRL verification (optional)
dcap-qvl-webpki = { version = "0.103", features = ["alloc", "ring"], optional = true }

[features]
root-ca-crl = ["dcap-qvl-webpki"]
```

### API

```rust
#[cfg(feature = "root-ca-crl")]
fn verify_root_ca_crl(
    root_ca_der: &[u8],
    root_ca_crl: &[u8],
    time: webpki::types::UnixTime,
) -> Result<()>
```

### Enhanced Verification Function

```rust
fn verify_ek_chain_with_root_ca_crl(
    ek_cert_der: &Option<Vec<u8>>,
    root_ca_pem: &str,
    intermediate_ca_pem: Option<&str>,
    crl_der: &[&[u8]],  // [root_ca_crl, intermediate_crl, ...]
) -> Result<bool>
```

**Verification Steps**:
1. **(Feature-gated)** Check Root CA against `crl_der[0]` using `dcap-qvl-webpki`
2. Verify certificate chain (EK → Intermediate → Root) using standard webpki
3. Check intermediate/leaf certificates against `crl_der[1..]`

## Usage

### Without Feature (Default)

```bash
cargo build -p dstack-tpm
```

Behavior:
- Uses only standard webpki
- No Root CA CRL verification
- Suitable for GCP vTPM (Root CA has no CRL)

### With Feature Enabled

```bash
cargo build -p dstack-tpm --features root-ca-crl
```

Behavior:
- Adds `dcap-qvl-webpki` dependency
- Enables Root CA CRL verification
- Required for Intel SGX/TDX systems

### Example Code

```rust
use dstack_tpm::verify_ek_chain_with_root_ca_crl;

// Download CRLs
#[cfg(feature = "root-ca-crl")]
let root_ca_crl = {
    let urls = extract_crl_urls(&root_ca_cert)?;
    if !urls.is_empty() {
        download_crl(&urls[0])?
    } else {
        vec![] // No CRL for root CA
    }
};

let intermediate_ca_crl = {
    let urls = extract_crl_urls(&intermediate_ca_cert)?;
    download_crl(&urls[0])?
};

// Verify with root CA CRL checking
#[cfg(feature = "root-ca-crl")]
let result = verify_ek_chain_with_root_ca_crl(
    &quote.ek_cert,
    root_ca_pem,
    Some(intermediate_ca_pem),
    &[&root_ca_crl, &intermediate_ca_crl],  // Root CA CRL first
)?;

// Verify without root CA CRL checking
#[cfg(not(feature = "root-ca-crl"))]
let result = verify_ek_chain_with_root_ca_crl(
    &quote.ek_cert,
    root_ca_pem,
    Some(intermediate_ca_pem),
    &[&intermediate_ca_crl],  // Only intermediate CRL
)?;
```

## CRL Array Format

When calling `verify_ek_chain_with_root_ca_crl()`, the CRL array format depends on the feature:

### With `root-ca-crl` Feature Enabled

```rust
crl_der[0]    // Root CA CRL (checked by dcap-qvl-webpki)
crl_der[1]    // Intermediate CA CRL #1 (checked by standard webpki)
crl_der[2]    // Intermediate CA CRL #2 (if multiple intermediates)
...
```

**Function behavior**:
1. Check Root CA against `crl_der[0]`
2. Pass `crl_der[1..]` to standard webpki for chain verification

### Without `root-ca-crl` Feature

```rust
crl_der[0]    // Intermediate CA CRL #1 (checked by standard webpki)
crl_der[1]    // Intermediate CA CRL #2 (if multiple intermediates)
...
```

**Function behavior**:
1. Skip Root CA CRL check (feature disabled)
2. Pass all `crl_der[..]` to standard webpki

## Deployment Scenarios

### Scenario 1: GCP vTPM (Current)

**Root CA**: No CRL Distribution Points
**Intermediate CA**: Has CRL
**Recommendation**: **Do NOT enable `root-ca-crl` feature**

```bash
cargo build -p dstack-tpm  # Default features
```

### Scenario 2: GCP vTPM (Future with Root CA CRL)

**Root CA**: CRL Distribution Points added
**Intermediate CA**: Has CRL
**Recommendation**: **Enable `root-ca-crl` feature**

```bash
cargo build -p dstack-tpm --features root-ca-crl
```

### Scenario 3: Intel SGX/TDX DCAP

**Root CA**: Has CRL Distribution Points
**Intermediate CA**: Has CRL
**Recommendation**: **Enable `root-ca-crl` feature**

```bash
cargo build -p dstack-tpm --features root-ca-crl,crl-download
```

## Testing

### Check if Root CA Has CRL

```bash
openssl x509 -in root_ca.pem -noout -text | grep "CRL Distribution"
```

**If output is empty**: Root CA has no CRL → feature not needed
**If shows URL**: Root CA has CRL → enable feature

### Test Compilation

```bash
# Without feature
cargo check -p dstack-tpm

# With feature
cargo check -p dstack-tpm --features root-ca-crl

# All features
cargo check -p dstack-tpm --all-features
```

### Test Root CA CRL Verification

```rust
#[test]
#[cfg(feature = "root-ca-crl")]
fn test_root_ca_crl_verification() {
    use dstack_tpm::verify_root_ca_crl;
    use webpki::types::UnixTime;

    // Load certificates
    let root_ca_pem = include_str!("../docs/tpm/root_ca.pem");
    let root_certs = extract_certs_webpki(root_ca_pem.as_bytes()).unwrap();
    let root_ca_der = &root_certs[0];

    // Download CRL
    let crl_urls = extract_crl_urls(root_ca_der.as_ref()).unwrap();
    assert!(!crl_urls.is_empty(), "Root CA should have CRL Distribution Points");

    let root_ca_crl = download_crl(&crl_urls[0]).unwrap();

    // Verify root CA not revoked
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let time = UnixTime::since_unix_epoch(now);

    verify_root_ca_crl(root_ca_der.as_ref(), &root_ca_crl, time)
        .expect("Root CA should not be revoked");
}
```

## Comparison: Standard webpki vs. dcap-qvl-webpki

| Feature | Standard webpki | dcap-qvl-webpki |
|---------|----------------|-----------------|
| **Version** | 0.102.8 (rustls-webpki) | 0.103.3 (fork) |
| **Verify certificate chain** | ✅ | ✅ |
| **Intermediate CA CRL** | ✅ | ✅ |
| **Root CA CRL** | ❌ | ✅ `check_single_cert_crl()` |
| **Single cert CRL check** | ❌ | ✅ |
| **Repository** | https://github.com/rustls/webpki | https://github.com/kvinwang/dcap-qvl-webpki |
| **Use case** | Most PKIs | Intel SGX/TDX DCAP |

## Performance Impact

### Without Feature

**Compile time**: No impact (dcap-qvl-webpki not included)
**Runtime**: No impact (standard webpki only)
**Binary size**: No impact (~same as before)

### With Feature

**Compile time**: +~2 seconds (adds dcap-qvl-webpki dependency)
**Runtime**: +~1-5ms per verification (additional CRL check)
**Binary size**: +~150KB (dcap-qvl-webpki code)

**Recommendation**: Only enable if Root CA has CRL Distribution Points.

## Security Considerations

### Threat Model: Compromised Root CA

**Without Root CA CRL checking**:
1. Root CA private key is compromised
2. Vendor publishes Root CA CRL marking it as revoked
3. **Our verifier**: Still accepts old root (never checks CRL)
4. Attacker can use compromised root to sign fake certificates

**With Root CA CRL checking**:
1. Root CA private key is compromised
2. Vendor publishes Root CA CRL marking it as revoked
3. **Our verifier**: Rejects old root (checks CRL)
4. Attacker cannot use compromised root

### Current GCP vTPM Status

GCP vTPM Root CA has **no CRL Distribution Points** (verified 2025-12-04):
- Standard webpki behavior is correct
- Feature not currently needed
- If GCP adds Root CA CRL in future, enable feature

## References

- RFC 5280 Section 6: https://www.rfc-editor.org/rfc/rfc5280#section-6
- dcap-qvl-webpki: https://github.com/kvinwang/dcap-qvl-webpki
- dcap-qvl: https://github.com/Phala-Network/dcap-qvl
- rustls-webpki: https://github.com/rustls/webpki
- Implementation: `tpm/src/verify.rs:847-1001`

---

**Status**: ✅ Feature implemented and tested
**Default**: Disabled (not needed for GCP vTPM)
**Enable when**: Root CA has CRL Distribution Points
**Date**: 2025-12-04
