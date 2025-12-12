# PCR Policy Recommendations for dstack

## Executive Summary

Based on comprehensive analysis of GCP vTPM PCR measurements, this document provides recommendations for implementing PCR validation in the dstack TPM attestation system.

**Key Finding**: PCR 2 is the ONLY PCR that uniquely identifies your system image (UKI binary hash). All other PCRs either contain fixed values shared across all GCP VMs or have limited security value.

## Critical PCR Policy (P0)

### PCR 0: Firmware Version ⚠️

**What it measures**: OVMF firmware version string ("GCE Virtual Firmware v2") + platform metadata

**Expected value** (for GCP):
```
0x0CCA9EC161B09288802E5A112255D21340ED5B797F5FE29CECCCFD8F67B9F802
```

**Security value**: Low
- Does NOT contain firmware binary hash
- Only version string
- Shared across all GCP VMs with same firmware version
- Cannot detect firmware binary tampering

**Recommendation**:
- ✅ Verify as baseline check
- ❌ Don't rely on it for security
- Document expected value in release notes

### PCR 2: UKI Binary Hash ⭐ CRITICAL

**What it measures**: Complete UKI (Unified Kernel Image) binary hash including:
- Kernel (bzImage)
- Initramfs (cpio.gz)
- Command line
- EFI stub

**Expected value**: Calculated from `dstack-uki.efi` binary:
```bash
sha256sum dstack-uki.efi
# Then extend from zero: SHA256(0x00*32 || <uki_hash>)
```

**Security value**: High ✅
- **This is the ONLY PCR that uniquely identifies your image**
- Contains complete hash of bootable system
- Different for every build
- Critical for attestation

**Recommendation**:
- ✅ **MUST verify** - this is mandatory
- ✅ Calculate expected value during build
- ✅ Reject quotes with mismatched PCR 2
- ✅ Store expected value in release metadata

### Implementation Example

```rust
// In tpm-qvl/src/verify.rs or new policy.rs module

pub struct PcrPolicy {
    /// Expected PCR values (None = don't check)
    pub expected_pcrs: HashMap<u32, Option<Vec<u8>>>,
}

impl PcrPolicy {
    /// Create GCP dstack policy with required PCRs
    pub fn gcp_dstack_policy(expected_pcr2: Vec<u8>) -> Self {
        let mut expected_pcrs = HashMap::new();

        // PCR 0: GCP firmware version (baseline check)
        expected_pcrs.insert(
            0,
            Some(hex::decode("0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802")
                .unwrap()),
        );

        // PCR 2: UKI hash (CRITICAL - must match build)
        expected_pcrs.insert(2, Some(expected_pcr2));

        Self { expected_pcrs }
    }

    /// Verify quote PCR values against policy
    pub fn verify(&self, quote: &TpmQuote) -> Result<()> {
        for (pcr_index, expected_value) in &self.expected_pcrs {
            let Some(expected) = expected_value else {
                continue; // Skip if no expected value
            };

            let actual = quote.pcr_values
                .iter()
                .find(|p| p.index == *pcr_index)
                .ok_or_else(|| anyhow!("PCR {} not included in quote", pcr_index))?;

            if &actual.value != expected {
                bail!(
                    "PCR {} mismatch: expected {}, got {}",
                    pcr_index,
                    hex::encode(expected),
                    hex::encode(&actual.value)
                );
            }
        }
        Ok(())
    }
}

// Update verify_quote signature:
pub fn verify_quote(
    quote: &TpmQuote,
    collateral: &QuoteCollateral,
    root_ca_pem: &str,
    pcr_policy: Option<&PcrPolicy>,  // NEW: optional PCR policy
) -> Result<(), VerificationResult> {
    // ... existing verification ...

    // Verify PCR policy if provided
    if let Some(policy) = pcr_policy {
        policy.verify(quote).map_err(|error| VerificationResult {
            status,
            error: error.context("PCR policy verification failed"),
        })?;
    }

    Ok(())
}
```

## Optional PCR Checks (P1)

### PCR 4: Boot Sequence

**What it measures**: Boot manager actions (standard EFI boot events)

**Expected value** (for GCP + UKI boot):
```
0x7A94FFE8A7729A566D3D3C577FCB4B6B1E671F31540375F80EAE6382AB785E35
```

**Security value**: Low ⚠️
- Fixed value for all GCP VMs using UKI boot
- Can detect abnormal boot sequences (e.g., extra bootloaders)
- Cannot distinguish between different images

**Recommendation**:
- ⚠️ Optional baseline check
- Useful for detecting anomalies, not for image verification

### PCR 7: Secure Boot Configuration

**What it measures**: Secure Boot UEFI variables (PK, KEK, db, dbx, SecureBoot status)

**Current status**: Secure Boot is **DISABLED** on GCP

**Expected value**: Depends on Secure Boot configuration
```python
# Currently varies because it includes:
# - SecureBoot = 0x00 (disabled)
# - PK, KEK, db, dbx databases
```

**Security value**: Medium ⚠️
- Can detect if Secure Boot policy changes
- **BUT** Secure Boot is currently disabled
- No signature verification at boot time
- Only provides post-attestation detection

**Recommendation**:
- ⚠️ Optional check for policy consistency
- 🎯 **Future**: Consider enabling Secure Boot + signing UKI
- If enabled, PCR 7 becomes more important

## Ignored PCRs (P2)

### PCR 3, 5, 6: Platform Configuration

**What they measure**:
- PCR 3: Host platform configuration
- PCR 5: Boot manager configuration
- PCR 6: Manufacturer specific

**Status on GCP**:
- PCR 3: Empty (only separator) - fixed value
- PCR 5: Limited/unclear value - needs more research
- PCR 6: Empty (only separator) - fixed value

**Security value**: None to Low ❌

**Recommendation**:
- ❌ Don't verify - no security benefit
- Only check if researching boot anomalies

## Build System Integration

### 1. Calculate PCR 2 During Build

Add to `meta-dstack/recipes-core/images/dstack-uki.bb`:

```python
do_uki[postfuncs] += "calculate_expected_pcr2"

python calculate_expected_pcr2() {
    import hashlib

    deploy_dir = d.getVar('DEPLOY_DIR_IMAGE')
    uki_filename = d.getVar('UKI_FILENAME')
    uki_path = os.path.join(deploy_dir, uki_filename)

    if not os.path.exists(uki_path):
        bb.warn(f"UKI not found for PCR calculation: {uki_path}")
        return

    # Calculate UKI hash
    with open(uki_path, 'rb') as f:
        uki_hash = hashlib.sha256(f.read()).digest()

    # Extend from zero (PCR 2 starts at zero)
    pcr2 = b'\x00' * 32
    pcr2 = hashlib.sha256(pcr2 + uki_hash).digest()

    # Write to manifest
    manifest_path = os.path.join(deploy_dir, "pcr-manifest.txt")
    with open(manifest_path, 'w') as f:
        f.write(f"PCR_0={d.getVar('EXPECTED_PCR_0')}\n")
        f.write(f"PCR_2={pcr2.hex()}\n")

    bb.note(f"Expected PCR 2: {pcr2.hex()}")
}

# Define expected PCR 0 for GCP
EXPECTED_PCR_0 = "0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802"
```

### 2. Include Manifest in Release

```bash
# In mkimage.sh
cp ${BB_BUILD_DIR}/tmp/deploy/images/${MACHINE}/pcr-manifest.txt \
   ${DIST_DIR}/
```

### 3. Verifier Configuration

```rust
// Example: Load PCR policy from release manifest
pub fn load_pcr_policy_from_manifest(manifest_path: &Path) -> Result<PcrPolicy> {
    let content = std::fs::read_to_string(manifest_path)?;

    let mut pcr0 = None;
    let mut pcr2 = None;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PCR_0=") {
            pcr0 = Some(hex::decode(val)?);
        } else if let Some(val) = line.strip_prefix("PCR_2=") {
            pcr2 = Some(hex::decode(val)?);
        }
    }

    let pcr2 = pcr2.ok_or_else(|| anyhow!("PCR_2 not found in manifest"))?;

    Ok(PcrPolicy::gcp_dstack_policy(pcr2))
}
```

## Security Considerations

### Current Security Model

```
┌─────────────────────────────────────────────────┐
│ Boot Time (Weak - No Prevention)                │
├─────────────────────────────────────────────────┤
│ ❌ Secure Boot DISABLED                         │
│    → OVMF doesn't verify UKI signature         │
│    → Any EFI binary can load                    │
│    → Only PCR measurement, no blocking          │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│ Attestation Time (Strong - Detection)           │
├─────────────────────────────────────────────────┤
│ ✅ TPM Quote Verification                       │
│    → PCR 2 contains UKI hash                    │
│    → Verifier checks PCR 2 == expected          │
│    → Reject if mismatch                         │
│    → Post-boot detection (not prevention)       │
└─────────────────────────────────────────────────┘
```

### Risk Assessment

**High Risk** ❌:
- Secure Boot disabled → No boot-time signature verification
- PCR 0 doesn't contain firmware binary hash → Must trust GCP firmware verification
- Post-attestation only → Compromised system can boot, but will be detected and rejected

**Mitigated by** ✅:
- PCR 2 provides strong post-boot verification
- Certificate chain validation prevents fake TPM quotes
- Nonce prevents replay attacks
- Detection happens before workload deployment

**Future Enhancement** 🎯:
- Enable Secure Boot
- Sign UKI with dstack key
- Register certificate in UEFI db
- Provides defense in depth: boot-time prevention + attestation detection

### Attack Scenarios

| Attack | Current Defense | Future Defense |
|--------|----------------|----------------|
| Replace UKI with malicious one | ❌ Boots, ✅ Detected by PCR 2 | ✅ Blocked by Secure Boot |
| Replace OVMF firmware | ⚠️ Relies on GCP signing | ⚠️ Same (no PCR contains FW hash) |
| Fake TPM quote | ✅ Blocked by cert chain verification | ✅ Same |
| Replay old quote | ✅ Blocked by nonce | ✅ Same |
| Boot sequence manipulation | ⚠️ May detect via PCR 4 | ✅ Secure Boot helps |

## Summary

### Must Implement (P0)

1. **Verify PCR 0** - Baseline firmware version check
   - Expected: `0x0CCA9EC161B09288802E5A112255D21340ED5B797F5FE29CECCCFD8F67B9F802`

2. **Verify PCR 2** - Critical UKI hash validation ⭐
   - Calculate during build
   - Include in release manifest
   - **Reject quotes with mismatched PCR 2**

### Should Implement (P1)

3. **Optional PCR 4 check** - Boot sequence anomaly detection
4. **Optional PCR 7 check** - Secure Boot policy consistency

### Future Enhancements (P2)

5. **Enable Secure Boot** - Defense in depth
6. **Sign UKI** - Boot-time verification
7. **PCR policy versioning** - Support multiple releases

## References

- [GCP PCR Analysis](/home/kvin/sdc/home/meta-dstack/dstack/docs/tpm/GCP_PCR_ANALYSIS.md)
- [PCR 3-7 Security Analysis](/tmp/pcr3_7_security_analysis.md)
- [PCR Calculator Tool](/home/kvin/sdc/home/meta-dstack/dstack/docs/tpm/calculate_pcr.py)
- [tpm-qvl Implementation](/home/kvin/sdc/home/meta-dstack/dstack/tpm-qvl/)
