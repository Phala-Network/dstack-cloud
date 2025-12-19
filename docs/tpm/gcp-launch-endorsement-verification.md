# GCP TDX Launch Endorsement Verification

This document explains how to cryptographically verify GCP's TDX Launch Endorsement to confirm that a VM is running Google's official TDX UEFI firmware.

## Overview

When running TDX VMs on GCP, the MRTD (Measurement of TD) value in the TDX Quote identifies the UEFI firmware being used. Google provides signed "Launch Endorsements" that contain reference MRTD values and prove their authenticity through cryptographic signatures.

## What is a Launch Endorsement?

A Launch Endorsement is a signed protobuf message (`VMLaunchEndorsement`) that contains:

1. **VMGoldenMeasurement** (`serialized_uefi_golden`):
   - Timestamp and build information
   - DER-encoded signing certificate
   - PEM-encoded CA bundle (root CA)
   - SHA-384 digest of UEFI binary
   - VMTdx message with reference MRTD values for different configurations

2. **RSA Signature** (`signature`):
   - 512-byte signature (RSA-4096)
   - Uses **RSA-PSS with SHA256** (not PKCS#1 v1.5)
   - Signs the `serialized_uefi_golden` data

## Key Discovery: RSA-PSS Signature Scheme

**Important**: Google uses RSA-PSS (Probabilistic Signature Scheme) with SHA256, not traditional PKCS#1 v1.5 padding. Standard OpenSSL verification commands will fail with "invalid padding" errors unless you explicitly specify PSS mode.

### Correct Verification Command

```bash
openssl dgst -sha256 -sigopt rsa_padding_mode:pss \
    -verify pubkey.pem \
    -signature signature.bin \
    signed_data.bin
```

### Why PKCS#1 Fails

```bash
# This will FAIL with padding errors:
openssl dgst -sha256 -verify pubkey.pem -signature signature.bin signed_data.bin

# Error: invalid padding, padding check failed
```

## Verification Steps

### 1. Get MRTD from TDX Quote

```bash
# On the TDX VM:
sudo dstack-util show | grep "MRTD:" | awk '{print $2}'
```

Example MRTD:
```
a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694
```

### 2. Download Launch Endorsement

```bash
MRTD="your-mrtd-hex"
gsutil cp "gs://gce_tcb_integrity/ovmf_x64_csm/tdx/${MRTD}.binarypb" launch_endorsement.binarypb
```

### 3. Parse Protobuf Structure

The endorsement uses protobuf encoding. You can parse it with:
- `protoc` if you have the .proto definitions
- Manual parsing (see `verify-gcp-launch-endorsement.py`)
- Google's `gcetcbendorsement` tool

### 4. Extract Components

Extract from the protobuf:
- Field 1: `serialized_uefi_golden` (the signed data)
- Field 2: `signature` (512 bytes)

From `serialized_uefi_golden`:
- Field 4: Signing certificate (DER format)
- Field 6: CA bundle (PEM format)
- Field 8: VMTdx message with MRTD references

### 5. Verify Signature (RSA-PSS)

```bash
# Extract public key from certificate
openssl x509 -inform DER -in cert.der -pubkey -noout -out pubkey.pem

# Verify signature with RSA-PSS
openssl dgst -sha256 -sigopt rsa_padding_mode:pss \
    -verify pubkey.pem \
    -signature signature.bin \
    signed_data.bin
```

✅ Expected output: `Verified OK`

### 6. Verify Certificate Chain

```bash
openssl verify -CAfile ca_bundle.pem cert.der
```

✅ Expected output: `cert.der: OK`

The certificate is issued by: `GCE-cc-tcb-root` (Google's self-signed root CA)

### 7. Match MRTD

Parse the VMTdx message and find measurements that match your VM's MRTD. Each measurement includes:
- RAM configuration (GiB)
- MRTD value (48 bytes)
- Early accept setting

## Using the Verification Script

We provide a ready-to-use Python script:

```bash
./verify-gcp-launch-endorsement.py <mrtd_hex>
```

**Example output:**
```
======================================================================
  GCP TDX Launch Endorsement Verification
======================================================================

MRTD: a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694

✓ Downloaded

[1] Signature Verification (RSA-PSS SHA256)
    ✓✓✓ SIGNATURE VERIFIED ✓✓✓

[2] Certificate Chain
    ✓✓ CERTIFICATE VALID ✓✓

[3] MRTD Match
    ✓✓ MRTD MATCHED ✓✓

======================================================================
🎉 VERIFICATION PASSED 🎉
```

## Security Guarantees

When all verifications pass, you have cryptographic proof that:

1. **Authenticity**: The launch endorsement is signed by Google's private key
2. **Integrity**: The signature cannot be forged without Google's private key
3. **Chain of Trust**: Certificate chains back to Google's root CA (`GCE-cc-tcb-root`)
4. **Firmware Identity**: Your VM's MRTD matches Google's reference value
5. **Conclusion**: The VM is running Google's official TDX UEFI firmware

## Technical Details

### VMLaunchEndorsement Structure

```
message VMLaunchEndorsement {
  bytes serialized_uefi_golden = 1;  // VMGoldenMeasurement
  bytes signature = 2;                // RSA-PSS signature
}

message VMGoldenMeasurement {
  google.protobuf.Timestamp timestamp = 1;
  string cl_spec = 2;                 // Google changelist
  bytes digest = 3;                   // SHA-384 of UEFI binary
  bytes cert = 4;                     // DER signing certificate
  string location = 5;                // GCS path
  bytes ca_bundle = 6;                // PEM root CA
  VMType vm_type = 7;
  VMTdx tdx = 8;                      // TDX measurements
}

message VMTdx {
  repeated Measurement measurements = 1;
}

message Measurement {
  uint32 ram_gib = 1;
  bool early_accept = 2;
  bytes mrtd = 3;                     // 48 bytes
}
```

### Protobuf Wire Format

The binary protobuf uses:
- **Varint encoding**: For integers and tags
- **Length-delimited encoding**: For bytes and strings
- **Tag format**: `(field_number << 3) | wire_type`
- **Wire types**:
  - 0 = varint
  - 2 = length-delimited

### Signature Details

- **Algorithm**: RSA with PSS padding
- **Hash**: SHA256
- **Key size**: 4096 bits (512-byte signature)
- **Signed data**: The entire `serialized_uefi_golden` bytes

## Troubleshooting

### "invalid padding" Error

❌ **Problem**: Using PKCS#1 v1.5 instead of RSA-PSS
```
error:0200008A:rsa routines:RSA_padding_check_PKCS1_type_1:invalid padding
```

✅ **Solution**: Add `-sigopt rsa_padding_mode:pss` to OpenSSL command

### MRTD Not Found

❌ **Problem**: MRTD not in reference measurements

**Possible causes**:
- Wrong MRTD value (verify with `dstack-util show`)
- Corrupted download
- Non-standard VM configuration

### Certificate Verification Fails

❌ **Problem**: `verification failed`

**Check**:
1. Correct CA bundle extracted
2. Certificate and CA bundle not swapped
3. Using correct OpenSSL verify syntax

## References

- GCP Documentation: [Retrieving launch endorsements](https://cloud.google.com/confidential-computing/confidential-vm/docs/tdx-launch-endorsement)
- GCS Bucket: `gs://gce_tcb_integrity/ovmf_x64_csm/tdx/`
- RSA-PSS: [RFC 8017 PKCS #1 v2.2](https://datatracker.ietf.org/doc/html/rfc8017)
- Verification script: `docs/tpm/verify-gcp-launch-endorsement.py`

## Integration with dstack-verifier

The dstack-verifier should eventually integrate MRTD verification:

1. Extract MRTD from TDX Quote
2. Download launch endorsement from GCS
3. Verify signature (RSA-PSS SHA256)
4. Verify certificate chain
5. Match MRTD with reference value
6. Fail verification if any step fails

This ensures that the VM firmware is authentic before trusting any measurements.
