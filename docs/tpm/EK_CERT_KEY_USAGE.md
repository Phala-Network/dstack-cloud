# TPM EK Certificate Key Usage Analysis

## Issue: webpki KeyUsage Mismatch

When integrating webpki-based certificate verification, I initially used:
```rust
webpki::KeyUsage::client_auth() // TPM EK is like a client certificate
```

However, after inspecting the actual GCP vTPM EK certificate on testgcp, this assumption is **INCORRECT**.

## Actual GCP vTPM EK Certificate

Tested on: `testgcp` (GCP VM with vTPM)
Date: 2025-12-04

```
Certificate:
    Subject: L = us-central1-a, O = Google Compute Engine, OU = wuhan-workshop, CN = 3579493998892267121
    Issuer: C = US, ST = California, L = Mountain View, O = Google LLC, OU = Google Cloud, CN = EK/AK CA Intermediate
    X509v3 extensions:
        X509v3 Key Usage: critical
            Key Encipherment
        X509v3 Basic Constraints: critical
            CA:FALSE
```

### Key Findings:

1. **Only has Key Usage: Key Encipherment** (critical)
2. **NO Extended Key Usage extension**
3. **NO client authentication usage**
4. **NO server authentication usage**

## What is "Key Encipherment"?

From RFC 5280 Section 4.2.1.3:

> **keyEncipherment**: The subject public key is used for enciphering private or secret keys, i.e., for key transport. For example, this key usage value is used with RSA keys when they are used for key exchange.

This is **NOT** the same as:
- **digitalSignature**: Used for verifying digital signatures (not present in EK cert)
- **Client authentication** (TLS client auth)
- **Server authentication** (TLS server auth)

## TPM EK Certificate Purpose

According to TPM 2.0 specification:

**Endorsement Key (EK)**:
- Primary purpose: **Attestation and Privacy Protection**
- Used to encrypt sensitive data sent to the TPM
- Used to decrypt credentials during attestation
- **NOT used for signing** (that's what Attestation Key / AK is for)
- **NOT used for TLS authentication**

The EK is essentially a **key encryption key (KEK)** for the TPM.

## webpki KeyUsage Options

From `rustls-webpki` library, the available `KeyUsage` values are:

```rust
pub enum KeyUsage {
    /// Extended Key Usage: id-kp-serverAuth
    server_auth(),

    /// Extended Key Usage: id-kp-clientAuth
    client_auth(),
}
```

**Problem**: webpki only supports TLS authentication use cases (server_auth, client_auth), but TPM EK certificates use **Key Encipherment** which is neither!

## Impact on webpki Integration

### Option 1: Use server_auth (Current Workaround)

```rust
ek_cert.verify_for_usage(
    webpki::ALL_VERIFICATION_ALGS,
    &trust_anchors,
    &intermediate_certs,
    time,
    webpki::KeyUsage::server_auth(), // Workaround: might fail Key Usage check
    None,
    None,
)
```

**Risk**: webpki may reject the certificate because:
- Certificate has `Key Encipherment` usage
- webpki expects `serverAuth` in Extended Key Usage
- EK cert has NO Extended Key Usage at all

### Option 2: Use client_auth

Same problem as Option 1 - mismatch between certificate capabilities and verification requirements.

### Option 3: Skip webpki for EK Verification

Keep webpki integration but **only use it for CRL verification** of intermediate CA, not for the EK certificate itself. Use our custom x509-parser-based verification for the EK cert.

```rust
// Verify intermediate CA with webpki + CRL
verify_intermediate_ca_webpki(intermediate_ca, root_ca, crl);

// Verify EK cert with custom x509-parser code (no Key Usage check)
verify_ek_with_custom_code(ek_cert, intermediate_ca);
```

## Recommendation

**For production use**:

1. **Do NOT use webpki's `verify_for_usage()` for EK certificates**
   - EK certs don't match TLS use cases
   - Will likely fail Key Usage verification

2. **Use hybrid approach**:
   ```rust
   // Step 1: Verify intermediate CA chain with webpki (includes CRL)
   verify_ca_chain_webpki(intermediate_ca, root_ca, crl)?;

   // Step 2: Verify EK cert signature using custom code
   //         Check: issuer == intermediate_ca.subject
   //         Check: signature valid using intermediate_ca.public_key
   //         Check: time validity
   //         Skip: Extended Key Usage (not applicable for EK)
   verify_ek_signature_custom(ek_cert, intermediate_ca)?;
   ```

3. **Why this works**:
   - webpki handles the complex CRL verification for CA chain
   - Custom code handles TPM-specific EK cert verification
   - Avoids forcing square peg (Key Encipherment) into round hole (TLS auth)

## Testing Needed

Test webpki behavior with actual GCP vTPM EK certificate:

```bash
# On testgcp
tpm2_nvread 0x01C00002 > /tmp/ek.der

# Test webpki verification
# Expected: Should it succeed or fail with Key Usage error?
```

## References

- RFC 5280: X.509 Public Key Infrastructure Certificate and CRL Profile
  - Section 4.2.1.3: Key Usage
  - Section 4.2.1.12: Extended Key Usage

- TPM 2.0 Library Specification, Part 1: Architecture
  - Section 24: Privacy
  - Section 25: Credential Protection

- GCP vTPM Documentation:
  - https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#vtpm

- webpki source: https://github.com/rustls/webpki
  - KeyUsage enum definition

---

**Status**: Investigation complete, needs implementation decision

**Author**: Based on live GCP vTPM certificate inspection

**Date**: 2025-12-04
