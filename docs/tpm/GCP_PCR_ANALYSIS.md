# GCP vTPM PCR Analysis for System Image Verification

## Executive Summary

This document explains which TPM Platform Configuration Registers (PCRs) can be used to verify the system image (including OVMF firmware) on Google Cloud Platform, and how to pre-calculate these PCR values.

## Key PCRs for System Image Verification

Based on analysis of GCP vTPM Event Log with dstack UKI (Unified Kernel Image):

| PCR | Content | Use for Verification | Notes |
|-----|---------|---------------------|-------|
| **PCR 0** | OVMF/UEFI Firmware version | ✅ **Essential** | Firmware identity |
| **PCR 2** | UKI binary (kernel+initramfs+cmdline) | ✅ **Essential** | Complete boot image |
| **PCR 4** | EFI actions (UEFI transitions) | ⚠️ Optional | Standard values |
| PCR 1 | Platform configuration | ❌ No | Hardware specific |
| PCR 7 | SecureBoot configuration | ❌ No | Policy, not image |
| PCR 8 | Kernel (traditional boot) | ❌ Zero | Not used with UKI |

### Recommended PCR Policy for Image Verification

**For dstack UKI:**
- **Minimum (Recommended):** PCR 0 + PCR 2
- **Enhanced:** PCR 0 + PCR 2 + PCR 4

**Why PCR 0 + PCR 2 is sufficient:**
- PCR 0 verifies OVMF firmware
- PCR 2 verifies the complete UKI binary which contains:
  - Kernel (bzImage)
  - Initramfs (cpio.gz)
  - Kernel cmdline (with dm-verity hash)
  - All boot code and data

## PCR 0: OVMF Firmware Measurement

### ⚠️ Important Security Note

**PCR 0 does NOT measure the actual firmware file content hash!**

PCR 0 only measures:
- Firmware version **string** ("GCE Virtual Firmware v2")
- Platform metadata (GCE NonHostInfo)
- Standard separator

The actual firmware content hash is recorded in Event 2 (EV_NO_ACTION) as a URL, but **EV_NO_ACTION events do not extend PCRs**. Therefore, PCR 0 verifies the firmware's *version label*, not its actual binary content.

### Events Measured into PCR 0

```
Event 2:  EV_NO_ACTION       - Firmware URL (informational only, digest = 0)
          URL: https://storage.googleapis.com/.../ff11d313b462e2c7...8c61eff4b3a9dd0708e3e5d79e163f39.fd.signed
          ❌ NOT extended into PCR (digest is all zeros)

Event 3:  EV_S_CRTM_VERSION  - "GCE Virtual Firmware v2" (version string)
          Digest: fa129a8f82b65bcbce8f9e8e5f6de509beff9b1df33714116bf918c5a3bba45d
          ✅ Extended into PCR 0

Event 4:  EV_NONHOST_INFO    - GCE NonHostInfo metadata
          Digest: b20ec425e0cea851df1ae32f426cff2e4b8e50e77883b8e9890dcf5369f90e1f
          ✅ Extended into PCR 0

Event 20: EV_SEPARATOR       - End of firmware measurements (0xFFFFFFFF)
          Digest: df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
          ✅ Extended into PCR 0
```

### OVMF Firmware Integrity

While PCR 0 doesn't measure the firmware binary directly, GCP provides integrity through:

1. **Signed firmware**: The `.fd.signed` suffix indicates cryptographic signature
2. **Content hash in URL**: The long hash in the filename (`ff11d313b462e2c7...`) identifies the specific firmware binary (likely SHA-384)
3. **Event Log record**: Event 2 creates an audit trail of which firmware was loaded
4. **Version string**: PCR 0 verifies the firmware *claims* to be version "v2"

**Security implication**:
- ✅ PCR 0 can detect firmware version downgrades
- ⚠️ PCR 0 cannot detect same-version firmware with different content
- ✅ Actual firmware integrity depends on GCP's signature verification (outside TPM)

### PCR 0 Calculation

```python
import hashlib

pcr0 = b'\x00' * 32  # Initial value

# Extend with Event 3 (EV_S_CRTM_VERSION)
digest1 = bytes.fromhex("fa129a8f82b65bcbce8f9e8e5f6de509beff9b1df33714116bf918c5a3bba45d")
pcr0 = hashlib.sha256(pcr0 + digest1).digest()

# Extend with Event 4 (EV_NONHOST_INFO)
digest2 = bytes.fromhex("b20ec425e0cea851df1ae32f426cff2e4b8e50e77883b8e9890dcf5369f90e1f")
pcr0 = hashlib.sha256(pcr0 + digest2).digest()

# Extend with Event 20 (EV_SEPARATOR)
digest3 = bytes.fromhex("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")
pcr0 = hashlib.sha256(pcr0 + digest3).digest()

print(f"PCR 0: {pcr0.hex()}")
# Expected: 0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802
```

## PCR 2: UEFI Drivers and Boot Applications

### Events Measured into PCR 2

```
Event 22: EV_SEPARATOR                     - End of firmware phase
          Digest: df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119

Event 27: EV_EFI_GPT_EVENT                 - GPT partition table (UEFI_GPT_DATA structure)
          Digest: 00b8a357e652623798d1bbd16c375ec90fbed802b4269affa3e78e6eb19386cf
          Note: SHA256 of GPT header + partition entries, NOT raw disk sectors

Event 28: EV_EFI_BOOT_SERVICES_APPLICATION - UKI (Unified Kernel Image)
          Digest: 9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f
          Note: PE/COFF Authenticode hash of dstack-uki.efi, NOT simple SHA256

Event 41: EV_EFI_BOOT_SERVICES_APPLICATION - Linux kernel (from UKI .linux section)
          Digest: ade943a0a7a3189a3201ba17d7df778eb380cbd33ce5e361176e974ccf7cdedb
          Note: PE/COFF Authenticode hash of .linux section extracted from UKI
```

### Event 28: UKI Measurement (Primary Image Verification Point)

**Event 28 is the most critical for image verification** - it measures the complete UKI binary.

For dstack, the UKI (dstack-uki.efi) contains:
- systemd-stub (EFI boot stub)
- .linux section (Linux kernel with EFI stub, ~9.6 MB)
- .initrd section (initramfs cpio archive)
- .cmdline section (kernel command line with dm-verity hash)
- Other metadata sections (.osrel, .uname, .sbat)

**IMPORTANT: Event 28 digest is NOT simple SHA256!**

```bash
# ❌ WRONG - This won't match Event 28
sha256sum dstack-uki.efi

# ✅ CORRECT - Use PE/COFF Authenticode hash
python3 scripts/bin/calculate_pcr.py --build-pcr2 \
    --bootloader dstack-uki.efi \
    --gpt-hash 00b8a357e652623798d1bbd16c375ec90fbed802b4269affa3e78e6eb19386cf

# Or calculate just the UKI hash
python3 -c "from calculate_pcr import authenticode_hash; \
    print(authenticode_hash('dstack-uki.efi'))"
# Output: 9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f
```

### Event 41: Linux Kernel Section (Derived from UKI)

**Event 41 is automatically derived from the UKI** - no separate verification needed.

After UEFI loads the UKI (Event 28), systemd-stub extracts the .linux section and
loads it as a separate EFI application using LoadImage(). This triggers Event 41.

**Security Analysis:**
- Event 41 content (.linux section) is embedded in UKI at fixed offset (0x16e00)
- Verifying Event 28 (UKI) implicitly verifies Event 41 (.linux section)
- Event 41 provides defense-in-depth: even if UKI measurement is bypassed,
  the kernel itself is still independently measured

**Verification Strategy:**
```
Event 28 verified (UKI Authenticode hash)
  ⟹ UKI file content verified
  ⟹ .linux section verified (deterministic extraction from UKI)
  ⟹ Event 41 implicitly verified
```

Therefore: **Only verify Event 28; Event 41 requires no separate golden value.**

### PCR 2 Calculation

```python
import hashlib

pcr2 = b'\x00' * 32

# Extend with all 4 events in order
digests = [
    "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",  # Event 22: EV_SEPARATOR
    "00b8a357e652623798d1bbd16c375ec90fbed802b4269affa3e78e6eb19386cf",  # Event 27: EV_EFI_GPT_EVENT
    "9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f",  # Event 28: UKI (Authenticode hash)
    "ade943a0a7a3189a3201ba17d7df778eb380cbd33ce5e361176e974ccf7cdedb",  # Event 41: Linux kernel (Authenticode hash)
]

for digest_hex in digests:
    digest = bytes.fromhex(digest_hex)
    pcr2 = hashlib.sha256(pcr2 + digest).digest()

print(f"PCR 2: {pcr2.hex()}")
# Expected: 1f74355f18d9aab3a26faa060d2058726554207d040c63d25d501d97f5a41e0f
```

**Note:** The third event (Event 28, UKI measurement) is critical for image verification.
This is GCP OVMF-specific behavior - other platforms may have different event ordering.

## PCR 4: Bootloader Actions

### Events Measured into PCR 4

```
Event 19: EV_EFI_ACTION   - "Calling EFI Application from Boot Option"
          Digest: 3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba

Event 24: EV_SEPARATOR    - End of bootloader phase (0xFFFFFFFF)
          Digest: df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
```

### Why These Are "Standard" Events

Both digests are **fixed values defined by UEFI/TCG specification**:

1. **EV_EFI_ACTION digest** is the SHA256 of the string `"Calling EFI Application from Boot Option"`
   ```python
   sha256(b"Calling EFI Application from Boot Option")
   = 3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba
   ```

2. **EV_SEPARATOR digest** is the SHA256 of 4 bytes `0xFFFFFFFF`
   ```python
   sha256(b'\xff\xff\xff\xff')
   = df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
   ```

### Characteristics

- PCR 4 measures **actions**, not binaries
- Both events have **fixed digests** - same across all systems using the same UEFI firmware
- **Not useful for unique image identification** (all GCP VMs with same OVMF version have identical PCR 4)
- **Useful for detecting boot sequence tampering** (any deviation from standard flow changes PCR 4)

### Comparison: Traditional vs UKI Boot

**Traditional GRUB boot** - PCR 4 contains:
- Standard EV_EFI_ACTION (same as above)
- GRUB configuration measurements (unique per system)
- GRUB commands and parameters (unique per system)
- → **PCR 4 is system-specific**

**dstack UKI boot** - PCR 4 contains:
- Standard EV_EFI_ACTION (fixed)
- Standard EV_SEPARATOR (fixed)
- → **PCR 4 is the same for all dstack instances on GCP**

### PCR 4 Calculation

```python
import hashlib

pcr4 = b'\x00' * 32

# Extend with Event 19 (EV_EFI_ACTION)
digest1 = bytes.fromhex("3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba")
pcr4 = hashlib.sha256(pcr4 + digest1).digest()

# Extend with Event 24 (EV_SEPARATOR)
digest2 = bytes.fromhex("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119")
pcr4 = hashlib.sha256(pcr4 + digest2).digest()

print(f"PCR 4: {pcr4.hex()}")
# Expected: 7a94ffe8a7729a566d3d3c577fcb4b6b1e671f31540375f80eae6382ab785e35
```

## Pre-calculating PCR Values for Image Verification

### Step 1: Calculate Component Hashes

For PCR 0 (OVMF):
```bash
# PCR 0 values are fixed for GCP OVMF firmware version
# No calculation needed - use the values from PCR 0 Calculation section above
PCR0_EVENT3="fa129a8f82b65bcbce8f9e8e5f6de509beff9b1df33714116bf918c5a3bba45d"  # GCE Virtual Firmware v2
PCR0_EVENT4="b20ec425e0cea851df1ae32f426cff2e4b8e50e77883b8e9890dcf5369f90e1f"  # GCE NonHostInfo
PCR0_EVENT20="df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"  # EV_SEPARATOR
```

For PCR 2 (UKI):
```bash
# ✅ CORRECT - Use PE/COFF Authenticode hash (NOT simple SHA256!)
python3 scripts/bin/calculate_pcr.py --bootloader build/tmp/deploy/images/*/dstack-uki.efi

```

For PCR 2 (GPT):
```bash
# GPT hash is calculated during disk image creation
# This value is specific to your disk layout and needs to be extracted from testgcp
# See Event 27 in the Event Log
```

### Step 2: Replay Event Log

Use the TPM extend algorithm:

```python
def tpm_extend(pcr_value: bytes, digest: bytes) -> bytes:
    """TPM PCR extend operation"""
    return hashlib.sha256(pcr_value + digest).digest()

# Start from zero
pcr = b'\x00' * 32

# Extend with each event's digest in order
for event_digest in event_digests:
    pcr = tpm_extend(pcr, event_digest)
```

### Step 3: Create Reference Policy

```python
# Expected PCR values for dstack image v0.6.0
DSTACK_PCR_POLICY = {
    "sha256": {
        0: "0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802",  # OVMF v2
        2: "1f74355f18d9aab3a26faa060d2058726554207d040c63d25d501d97f5a41e0f",  # UKI + GPT
        4: "7a94ffe8a7729a566d3d3c577fcb4b6b1e671f31540375f80eae6382ab785e35",  # Boot sequence
    }
}

# Event 28 digest (UKI Authenticode hash) for comparison
UKI_HASH = "9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f"
```


## Limitations and Considerations

### PCR 0 (OVMF)

- ✅ **Stable** - Only changes with GCP firmware version updates
- ✅ **Predictable** - Can be pre-calculated from version string
- ⚠️ **Shared** - Same PCR 0 for all GCP VMs with same firmware version
- ⚠️ **Version-only** - Measures firmware version string, not actual binary content
- ✅ **GCP Integrity** - Actual firmware integrity enforced by GCP signature verification

### PCR 2 (Bootloader)

- ✅ **Unique** - Different for each custom image
- ✅ **Verifiable** - Can pre-calculate from build artifacts
- ⚠️ **GPT Dependency** - Partition table must be identical
- ⚠️ **Multiple Events** - Must replay all 4 events in correct order

### PCR 4 (Boot Actions)

- ⚠️ **Limited Uniqueness** - `EV_EFI_ACTION` digest is standard
- ✅ **Detects Tampering** - Catches boot sequence modifications
- ⚠️ **Less Image-Specific** - Not unique to your image

### Why PCR 8 (Kernel) is Zero

**PCR 8 is ZERO because dstack uses UKI (Unified Kernel Image), not GRUB!**

#### Boot Flow Explanation

**Traditional Boot (with GRUB):**
```
OVMF → GRUB (PCR 4) → Kernel (PCR 8) → Initramfs (PCR 9)
```
In this flow, GRUB measures kernel into PCR 8 before loading it.

**dstack UKI Boot (Direct UEFI Boot):**
```
OVMF → UKI.efi (PCR 2) → [Kernel+Initramfs already bundled]
```
In this flow:
1. OVMF loads UKI.efi directly as an EFI application
2. UKI.efi is measured into **PCR 2** (EV_EFI_BOOT_SERVICES_APPLICATION)
3. No GRUB involved, so PCR 4 only contains the standard EV_EFI_ACTION event
4. Kernel and initramfs are **already inside** the UKI, so no separate PCR 8/9 measurements

#### Security Implications

✅ **This is actually BETTER for security:**

1. **Single measurement point**: The entire boot chain (kernel + initramfs) is measured as one unit in PCR 2
2. **No GRUB attack surface**: Eliminating GRUB removes a complex component that could be exploited
3. **Immutable boot**: UKI is signed and measured as a single artifact
4. **Simpler verification**: Only need to verify PCR 0 (firmware) + PCR 2 (UKI)

#### What's Measured Where

| Component | Traditional Boot | dstack UKI Boot |
|-----------|-----------------|-----------------|
| OVMF Firmware | PCR 0 | PCR 0 ✅ |
| GRUB Binary | PCR 2 | N/A (no GRUB) |
| UKI Binary | N/A | PCR 2 ✅ |
| Kernel | PCR 8 | Inside UKI (PCR 2) |
| Initramfs | PCR 9 | Inside UKI (PCR 2) |

**Conclusion:** For dstack, **PCR 0 + PCR 2** are sufficient and optimal for image verification.

## References

- [GCP Shielded VM Documentation](https://docs.cloud.google.com/compute/shielded-vm/docs/shielded-vm)
- [TCG PC Client Platform TPM Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
- [UEFI TCG Event Log Specification](https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/)
- [Linux TPM PCR Registry](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)

---

*Analysis performed on a GCP instance running dstack image*
*Date: 2025-12-09*
