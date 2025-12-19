# Root CA CRL Verification: dcap-qvl vs. Our Implementation

## The Problem

**Standard webpki (rustls-webpki) does NOT support verifying Root CA certificates against CRLs.**

Why? The `verify_for_usage()` function in webpki performs **certificate chain verification**, which:
- Verifies: Leaf Cert → Intermediate CA → Root CA
- Validates signatures at each level
- **But**: Trust anchors (Root CAs) are assumed trusted and not checked against CRLs

From RFC 5280:
> The trust anchor information may be provided to the path processing procedure in the form of a self-signed certificate. [...] These self-signed certificates are not validated as part of the certification path.

## dcap-qvl's Solution

dcap-qvl uses a **forked version of webpki** called `dcap-qvl-webpki`.

### dcap-qvl-webpki

**Package**: `dcap-qvl-webpki` v0.103.3
**Repository**: https://github.com/kvinwang/dcap-qvl-webpki
**Description**: "Fork of rustls-webpki to support single cert CRL check."
**Author**: Kevin Wang (same author as dcap-qvl)

### The Added Function

`dcap-qvl-webpki` adds a new public function not present in standard webpki:

```rust
/// Check a single certificate against a CRL.
#[cfg(feature = "alloc")]
pub fn check_single_cert_crl(
    cert_der: &[u8],
    crls_der: &[&[u8]],
    time: UnixTime,
) -> Result<(), Error> {
    use alloc::vec::Vec;

    // Parse certificate as EndEntityCert
    let cert_der = pki_types::CertificateDer::from(cert_der);
    let cert = EndEntityCert::try_from(&cert_der)?;

    // Parse CRLs
    let crls = crls_der
        .iter()
        .map(|crl_der| BorrowedCertRevocationList::from_der(crl_der).map(|crl| crl.into()))
        .collect::<Result<Vec<_>, _>>()?;
    let crls = crls.iter().collect::<Vec<_>>();

    // Build CRL revocation options
    let crl_opts = RevocationOptionsBuilder::new(&crls)
        .or(Err(Error::UnknownRevocationStatus))?
        .with_depth(RevocationCheckDepth::EndEntity)  // ← Key: Only check this cert
        .with_status_policy(UnknownStatusPolicy::Deny)
        .with_expiration_policy(ExpirationPolicy::Enforce)
        .build();

    // Create PartialPath for CRL checking
    let path = crate::verify_cert::PartialPath::new(&cert);
    let path = path.node();
    let issuer_subject = path.cert.subject;
    let issuer_spki = path.cert.spki;
    let issuer_ku = None;
    let budget = &mut Budget::default();

    // Check CRL status
    let result = crl_opts.check(
        &path,
        issuer_subject,
        issuer_spki,
        issuer_ku,
        crate::ALL_VERIFICATION_ALGS,
        budget,
        time,
    )?;

    if result.is_none() {
        return Err(Error::UnknownRevocationStatus);
    }

    Ok(())
}
```

### How dcap-qvl Uses It

From `dcap-qvl/src/verify.rs`:

```rust
let crls = [&collateral.root_ca_crl[..], &collateral.pck_crl];

// Because the original rustls-webpki doesn't check the ROOT CA against the CRL,
// we use our forked webpki to check it
let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));
dcap_qvl_webpki::check_single_cert_crl(root_ca_der, &crls, now)?;

// Then verify the rest of the chain with standard webpki
verify_certificate_chain(
    &tcb_leaf_cert,
    &tcb_leaf_certs[1..],
    now,
    &crls,
    trust_anchor.clone(),
)?;
```

**Workflow**:
1. **First**: Check Root CA against its CRL using `dcap-qvl-webpki::check_single_cert_crl()`
2. **Then**: Verify rest of certificate chain using standard `verify_certificate_chain()`

## Our Current Implementation

### What We Have

In `tpm/src/verify.rs`, our `verify_ek_chain_webpki()` function:

```rust
ek_cert.verify_for_usage(
    webpki::ALL_VERIFICATION_ALGS,
    &trust_anchors,
    &intermediate_certs,
    time,
    webpki::KeyUsage::server_auth(),
    Some(revocation), // CRL verification
    None,
)
```

This verifies:
- ✅ EK Cert → Intermediate CA (with CRL checking)
- ✅ Intermediate CA → Root CA (signature verification)
- ❌ **Root CA itself is NOT checked against CRL**

### The Gap

**Standard webpki behavior**:
- Root CA (trust anchor) is assumed trusted
- NOT checked against CRL
- This is per RFC 5280 specification

**Intel SGX/TDX requirement**:
- Root CA CRL exists and should be checked
- Example: Intel SGX Root CA has CRL Distribution Points
- Revoked Root CA certificates should be rejected

## Why Intel Needs Root CA CRL Checking

### Intel SGX/TDX DCAP Architecture

Intel's DCAP (Data Center Attestation Primitives) provides:
- **Root CA CRL**: Can be downloaded via PCCS (Provisioning Certificate Caching Service)
- **Intermediate CA CRL**: PCK (Platform Certificate Key) CRL
- **Leaf Certificate**: PCK Certificate (per platform)

### Threat Model

**Without Root CA CRL checking**:
1. Intel SGX Root CA private key is compromised
2. Intel publishes Root CA CRL marking old root as revoked
3. **Standard webpki**: Still accepts old root (never checks CRL)
4. Attacker can use compromised root to sign fake quotes

**With Root CA CRL checking**:
1. Intel SGX Root CA private key is compromised
2. Intel publishes Root CA CRL marking old root as revoked
3. **dcap-qvl-webpki**: Rejects old root (checks CRL)
4. Attacker cannot use compromised root

## GCP vTPM Situation

### Does GCP vTPM Root CA Have CRL?

Let me check the GCP vTPM Root CA certificate:

**From** `/home/kvin/sdc/home/meta-dstack/dstack/docs/tpm/gce_tpm_root_ca.pem`:

```bash
openssl x509 -in gce_tpm_root_ca.pem -noout -text | grep -A 5 "CRL Distribution"
```

**If Root CA has CRL Distribution Points**: We should verify it!
**If Root CA has no CRL**: Standard webpki is sufficient.

### Current Status

Our implementation uses standard `rustls-webpki` 0.102.8, which:
- ✅ Verifies certificate chain with intermediate CRL
- ❌ Does NOT check root CA against CRL

## Options for Our Implementation

### Option 1: Add dcap-qvl-webpki Dependency

**Pros**:
- Complete Root CA CRL verification
- Battle-tested in Intel SGX/TDX production systems
- Maintained by Kevin Wang (dcap-qvl author)

**Cons**:
- Additional dependency (forked webpki)
- Slight code duplication (two webpki versions)

**Implementation**:

```toml
# tpm/Cargo.toml
[dependencies]
# Standard webpki for normal chain verification
webpki = { version = "0.102", package = "rustls-webpki", ... }

# Forked webpki for root CA CRL checking
dcap-qvl-webpki = { version = "0.103", features = ["alloc", "ring"], optional = true }

[features]
root-ca-crl = ["dcap-qvl-webpki"]
```

```rust
// tpm/src/verify.rs
#[cfg(feature = "root-ca-crl")]
fn verify_root_ca_crl(
    root_ca_der: &[u8],
    root_ca_crl: &[u8],
    time: webpki::types::UnixTime,
) -> Result<()> {
    dcap_qvl_webpki::check_single_cert_crl(root_ca_der, &[root_ca_crl], time)
        .map_err(|e| anyhow::anyhow!("root CA CRL check failed: {:?}", e))
}

fn verify_ek_chain_webpki(
    ek_cert_der: &Option<Vec<u8>>,
    root_ca_pem: &str,
    intermediate_ca_pem: Option<&str>,
    crl_der: &[&[u8]],
) -> Result<bool> {
    // Parse root CA
    let root_certs = extract_certs_webpki(root_ca_pem.as_bytes())?;
    let root_cert_der = &root_certs[0];

    // Optional: Check root CA against its CRL
    #[cfg(feature = "root-ca-crl")]
    if crl_der.len() > 0 {
        // Assume first CRL is for root CA (caller's responsibility)
        verify_root_ca_crl(root_cert_der.as_ref(), crl_der[0], time)?;
    }

    // Continue with standard verification...
    // ...
}
```

### Option 2: Manual Root CA CRL Checking

Use `x509-parser` to manually check Root CA serial number against CRL:

```rust
fn check_root_ca_in_crl(root_ca_der: &[u8], crl_der: &[u8]) -> Result<bool> {
    use x509_parser::prelude::*;

    // Parse Root CA
    let (_, root_cert) = X509Certificate::from_der(root_ca_der)
        .map_err(|e| anyhow::anyhow!("failed to parse root CA: {}", e))?;
    let root_serial = root_cert.serial.to_bytes_be();

    // Parse CRL
    let (_, crl) = CertificateRevocationList::from_der(crl_der)
        .map_err(|e| anyhow::anyhow!("failed to parse CRL: {}", e))?;

    // Check if root CA serial is in CRL
    for revoked in crl.iter_revoked_certificates() {
        if revoked.serial.to_bytes_be() == root_serial {
            warn!("Root CA certificate is revoked!");
            return Ok(true); // Revoked
        }
    }

    Ok(false) // Not revoked
}
```

**Pros**:
- No additional dependency
- Simple implementation

**Cons**:
- Doesn't verify CRL signature
- Doesn't check CRL expiration
- Less robust than dcap-qvl-webpki

### Option 3: Do Nothing (Current State)

**Pros**:
- Simple
- Follows RFC 5280 standard behavior

**Cons**:
- Cannot detect revoked Root CAs
- Less secure than Intel's approach

## Recommendation

### First: Check if GCP vTPM Root CA Has CRL

```bash
cd /home/kvin/sdc/home/meta-dstack/dstack
openssl x509 -in docs/tpm/gce_tpm_root_ca.pem -noout -text | grep "CRL Distribution"
```

### If Root CA Has CRL → Use Option 1

Add `dcap-qvl-webpki` dependency with feature flag:
- Matches Intel's production approach
- Provides complete CRL verification
- Small additional dependency cost

### If Root CA Has NO CRL → Current Implementation is Fine

Standard webpki is sufficient.

## Testing

Once implemented, test with:

```rust
#[test]
fn test_root_ca_crl_verification() {
    // Download GCP vTPM Root CA CRL
    let root_ca_crl_url = "..."; // Extract from cert
    let root_ca_crl = download_crl(root_ca_crl_url)?;

    // Parse root CA
    let root_ca_pem = include_str!("../docs/tpm/gce_tpm_root_ca.pem");
    let root_ca_der = extract_certs_webpki(root_ca_pem.as_bytes())?;

    // Verify root CA against CRL
    #[cfg(feature = "root-ca-crl")]
    {
        let now = UnixTime::now();
        dcap_qvl_webpki::check_single_cert_crl(
            root_ca_der[0].as_ref(),
            &[&root_ca_crl],
            now,
        )?;
    }

    // Should succeed (root CA not revoked)
}
```

## Comparison Summary

| Feature | Standard webpki | dcap-qvl-webpki | Our Implementation |
|---------|----------------|-----------------|-------------------|
| **Verify Leaf Cert → Intermediate** | ✅ | ✅ | ✅ |
| **Verify Intermediate → Root** | ✅ | ✅ | ✅ |
| **Check Intermediate CRL** | ✅ | ✅ | ✅ |
| **Check Root CA CRL** | ❌ | ✅ | ❌ (current) |
| **Single cert CRL check** | ❌ | ✅ `check_single_cert_crl()` | ❌ |

## Conclusion

**Question**: Does our implementation support Root CA CRL verification like dcap-qvl?

**Answer**: ❌ **No, currently not.**

**Why**: We use standard `rustls-webpki` which doesn't check trust anchors (Root CAs) against CRLs.

**Should we add it?**:
1. **First check**: Does GCP vTPM Root CA have CRL Distribution Points?
2. **If yes**: Add `dcap-qvl-webpki` dependency (Option 1)
3. **If no**: Current implementation is sufficient

**Next Step**: Check GCP vTPM Root CA certificate for CRL distribution points.

---

**References**:
- dcap-qvl-webpki: https://github.com/kvinwang/dcap-qvl-webpki
- dcap-qvl: https://github.com/Phala-Network/dcap-qvl
- RFC 5280 Section 6: https://www.rfc-editor.org/rfc/rfc5280#section-6
- Our implementation: `tpm/src/verify.rs:633-758`

**Date**: 2025-12-04
**Status**: ⚠️ Gap identified, recommendation pending Root CA CRL check
