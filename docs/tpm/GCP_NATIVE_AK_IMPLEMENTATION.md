# GCP Native AK Loading Implementation

## Overview

This document describes the native Rust implementation for loading GCP's pre-provisioned Attestation Key (AK) using `tss-esapi`, eliminating the dependency on Go helper programs.

## Implementation

### Location
- **Module**: `dstack-tpm/src/gcp_ak.rs`
- **Feature flag**: `gcp-vtpm`
- **Example**: `dstack-tpm/examples/gcp_ak_test.rs`

### Key Components

#### 1. GCP NV Index Constants
```rust
pub mod gcp_nv_index {
    pub const AK_RSA_CERT: u32 = 0x01C10000;      // RSA AK certificate (DER)
    pub const AK_RSA_TEMPLATE: u32 = 0x01C10001;  // RSA AK template (TPM2B_PUBLIC)
    pub const AK_ECC_CERT: u32 = 0x01C10002;      // ECC AK certificate (DER)
    pub const AK_ECC_TEMPLATE: u32 = 0x01C10003;  // ECC AK template (TPM2B_PUBLIC)
}
```

#### 2. AK Loading Function
```rust
pub fn load_gcp_ak_rsa(tcti_path: Option<&str>) -> Result<(TssContext, KeyHandle)>
```

**Process**:
1. Create TSS context with device TCTI (default: `/dev/tpmrm0`)
2. Read AK template from NV index `0x01C10001`
3. Parse template as `TPM2B_PUBLIC` structure
4. Call `CreatePrimary` under Endorsement hierarchy
5. Return context and AK handle

**Why it works**: TPM2 `CreatePrimary` is deterministic - same template + same parent hierarchy → same key pair

### Dependencies

#### System Requirements
```bash
sudo apt-get install -y libtss2-dev
```

This installs:
- `libtss2-esys` (Enhanced System API)
- `libtss2-sys` (System API)
- `libtss2-mu` (Marshalling/Unmarshalling)
- Header files and pkg-config files

#### Cargo Dependencies
```toml
[dependencies]
tss-esapi = { version = "7.5", optional = true }

[features]
gcp-vtpm = ["tss-esapi"]
```

## Building

```bash
# Build the library with GCP vTPM support
cargo build --features gcp-vtpm -p dstack-tpm

# Build the test example
cargo build --example gcp_ak_test --features gcp-vtpm -p dstack-tpm
```

## Testing on GCP

### 1. Deploy Test Binary to GCP Instance

```bash
# Build for release
cargo build --release --example gcp_ak_test --features gcp-vtpm -p dstack-tpm

# Copy to GCP instance
gcloud compute scp \
  target/release/examples/gcp_ak_test \
  testgcp:/tmp/ \
  --zone=us-central1-a
```

### 2. Run Test on GCP

```bash
# SSH to GCP instance
gcloud compute ssh testgcp --zone=us-central1-a

# Run test
sudo /tmp/gcp_ak_test
```

### Expected Output

```
=== GCP vTPM Pre-provisioned AK Loading Test ===

Loading GCP pre-provisioned RSA AK...
✓ Successfully loaded GCP pre-provisioned AK!
  AK handle: KeyHandle { ... }

Reading AK public key...
✓ AK public key:
  Type: ...

Reading AK certificate from NV index 0x01C10000...
✓ Read AK certificate: XXXX bytes

=== AK Certificate Info ===
Subject: ...
Issuer: ...
Serial: ...
Valid from: ... to ...

=== Test Passed ===
```

## Integration with Quote Generation

### Next Steps

1. **Modify `TpmContext::create_quote()`** to use `load_gcp_ak_rsa()`:
   ```rust
   #[cfg(feature = "gcp-vtpm")]
   {
       // Try to load GCP pre-provisioned AK
       if let Ok((context, ak_handle)) = load_gcp_ak_rsa(Some(&self.device)) {
           // Use loaded AK for quote generation
           return self.create_quote_with_ak(context, ak_handle, report_data);
       }
   }
   // Fall back to temporary AK
   self.create_quote_with_tpm2_createak(report_data)
   ```

2. **Implement `create_quote_with_ak()`**:
   - Use tss-esapi's `quote()` method with the loaded AK handle
   - Extract quote signature and message
   - Format as `TpmQuote` structure

3. **Verify End-to-End**:
   - Generate quote using native Rust implementation
   - Verify quote using existing `dstack-verifier`
   - Ensure certificate chain validation passes

## Architecture Benefits

### Before (Go Helper)
```
Rust (dstack-tpm) → Execute Go binary → TPM2 commands → TPM
                     ↓
                  Parse output
```

### After (Native Rust)
```
Rust (dstack-tpm) → tss-esapi → libtss2 → TPM
```

### Advantages
1. **No external dependencies**: Pure Rust solution
2. **Type safety**: Compile-time guarantees
3. **Better error handling**: Rich error context with anyhow
4. **Performance**: No process spawning overhead
5. **Maintainability**: Single language codebase

## Technical Details

### TPM2 Deterministic Key Generation

The TPM2 specification guarantees that `TPM2_CreatePrimary` with the same:
1. Parent hierarchy (Endorsement)
2. Public template (from NV 0x01C10001)
3. Sensitive data (none)

Will always produce the **same key pair**. This is the foundation of GCP's pre-provisioned AK approach.

### tss-esapi API Usage

Key patterns used:
- `TctiNameConf::Device` for TPM device access
- `execute_without_session()` for handle management
- `execute_with_nullauth_session()` for NV read operations
- `abstraction::nv::read_full()` for reading complete NV index data
- `traits::UnMarshall` for parsing TPM structures

### Error Handling

All errors are wrapped with context using `anyhow`:
```rust
.context("failed to read AK template from NV 0x01C10001")?
```

This provides clear error chains for debugging.

## References

- [tss-esapi documentation](https://docs.rs/tss-esapi)
- [TPM2 Software Stack](https://github.com/tpm2-software/tpm2-tss)
- [GCP vTPM documentation](https://cloud.google.com/compute/shielded-vm/docs/retrieving-endorsement-key)
- [go-tpm-tools implementation](https://github.com/google/go-tpm-tools/blob/main/client/attest.go)

## Status

- ✅ Implementation complete
- ✅ Compilation successful
- ✅ Test example ready
- ⏳ Testing on GCP (pending)
- ⏳ Integration with quote generation (pending)
- ⏳ End-to-end verification (pending)
