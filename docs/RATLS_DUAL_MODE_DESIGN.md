# RA-TLS 双模式验证设计 (TDX + vTPM)

## 核心理念

在 GCP TDX 环境中，同时存在 TDX 和 vTPM 两种 attestation 机制：
- **TDX Quote**: 验证 MRTD, RTMR0-2, RTMR3 (通过 event log)
- **vTPM Quote**: 验证 PCR 0, 2, 4, 7 (UKI hash 通过 PCR 2)

**为什么需要两者？**
1. **TDX** - 验证运行时应用状态 (RTMR3 event log)
2. **vTPM** - 验证系统镜像完整性 (PCR 2 = UKI hash)

两者互补，提供完整的信任链。

## Attestation 模式

### AttestationMode 枚举

```rust
pub enum AttestationMode {
    /// TDX only (纯 TDX 环境，无 vTPM)
    Tdx,

    /// vTPM only (纯 vTPM 环境，无 TDX)
    VTpm,

    /// Both TDX and vTPM (GCP TDX 环境) ⭐
    TdxVtpm,
}
```

### 自动检测

```rust
pub fn detect() -> Result<Self> {
    let has_tdx = Path::new("/dev/tdx_guest").exists();
    let has_vtpm = Path::new("/dev/tpmrm0").exists();

    match (has_tdx, has_vtpm) {
        (true, true) => Ok(Self::TdxVtpm),  // GCP TDX
        (true, false) => Ok(Self::Tdx),     // TDX only
        (false, true) => Ok(Self::VTpm),    // vTPM only
        (false, false) => bail!("No device found"),
    }
}
```

## 证书扩展结构

### TdxVtpm 模式证书

```
X.509 Certificate Extensions:
├── ATTESTATION_MODE: "tdx+vtpm"
├── QUOTE: <TDX Quote binary>              # TDX DCAP quote
├── EVENT_LOG: <TDX Event Log>             # TDX RTMR3 event log
└── TPM_QUOTE: <TpmQuote JSON>         # vTPM quote + PCR values
```

**TpmQuote 内容**:
```json
{
  "message": "...",        // TPMS_ATTEST (hex)
  "signature": "...",      // TPM signature (hex)
  "pcr_values": [
    {"index": 0, "value": "0x0cca9ec..."},  // Firmware version
    {"index": 2, "value": "0x..."},         // UKI hash ⭐
    {"index": 4, "value": "0x7a94ffe..."},  // Boot sequence
    {"index": 7, "value": "0x..."}          // Secure Boot
  ],
  "ak_cert": "...",        // AK certificate (hex)
  "qualifying_data": "..." // Nonce (hex)
}
```

## 数据采集流程

### Guest 端 (TdxVtpm 模式)

```rust
fn local_tdx_vtpm() -> Result<Attestation> {
    // 1. Get TDX quote
    let tdx_quote = tdx_attest::get_quote(&[0u8; 64])?;

    // 2. Get TDX event log (for RTMR3)
    let event_log = tdx_attest::eventlog::read_event_logs()?;
    let raw_event_log = serde_json::to_vec(&event_log)?;

    // 3. Get vTPM quote (for PCR verification)
    let tpm_data = collect_vtpm_quote(&[
        0,  // PCR 0: firmware version
        2,  // PCR 2: UKI hash ⭐
        4,  // PCR 4: boot sequence
        7,  // PCR 7: Secure Boot
    ])?;

    Ok(Attestation {
        mode: AttestationMode::TdxVtpm,
        quote: tdx_quote,              // TDX quote
        raw_event_log,                  // TDX event log
        event_log,
        report: (),
        tpm_data: Some(tpm_data),      // vTPM quote
    })
}
```

### vTPM Quote 采集

```rust
fn collect_vtpm_quote(pcr_indices: &[u32]) -> Result<TpmQuote> {
    // 1. Generate nonce
    let nonce = generate_nonce();

    // 2. Build PCR selection
    let pcr_selection = pcr_indices
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let pcr_selection_arg = format!("sha256:{}", pcr_selection);

    // 3. Call tpm2_quote
    let output = Command::new("tpm2_quote")
        .args(&[
            "-c", "0x81010001",         // AK handle
            "-l", &pcr_selection_arg,   // PCR list
            "-q", "/tmp/nonce",         // Nonce
            "-m", "/tmp/quote.msg",     // Output message
            "-s", "/tmp/quote.sig",     // Output signature
            "-g", "sha256",
        ])
        .output()?;

    if !output.status.success() {
        bail!("tpm2_quote failed");
    }

    // 4. Read outputs
    let message = fs::read("/tmp/quote.msg")?;
    let signature = fs::read("/tmp/quote.sig")?;

    // 5. Read PCR values
    let pcr_values = read_pcr_values(pcr_indices)?;

    // 6. Read AK certificate
    let ak_cert = fs::read("/var/lib/dstack/ak_cert.der")?;

    Ok(TpmQuote {
        message,
        signature,
        pcr_values,
        ak_cert,
        qualifying_data: nonce,
    })
}

fn read_pcr_values(indices: &[u32]) -> Result<Vec<PcrValue>> {
    let mut values = Vec::new();

    for &index in indices {
        let output = Command::new("tpm2_pcrread")
            .args(&["sha256", &index.to_string()])
            .output()?;

        // Parse output to extract PCR value
        let value = parse_pcr_value(&output.stdout)?;

        values.push(PcrValue { index, value });
    }

    Ok(values)
}
```

## 验证流程

### Verifier 端 (TdxVtpm 模式)

```rust
async fn verify_tdx_vtpm(
    &self,
    attestation: &Attestation,
    vm_config: &VmConfig,
) -> Result<VerificationResponse> {
    let mut details = VerificationDetails::default();

    // ====== Step 1: Verify TDX Quote ======
    match verify_tdx_quote(attestation).await {
        Ok(report) => {
            details.quote_verified = true;
            details.tcb_status = Some(format!("{:?}", report.tcb_status));

            // Verify RTMR3 from event log
            let rtmr3 = attestation.replay_rtmr3(None)?;
            if rtmr3 != report.rt_mr3 {
                return Err(anyhow!("RTMR3 mismatch"));
            }
            details.event_log_verified = true;
        }
        Err(e) => {
            return Ok(VerificationResponse {
                is_valid: false,
                details,
                reason: Some(format!("TDX verification failed: {}", e)),
            });
        }
    }

    // ====== Step 2: Verify vTPM Quote ======
    let tpm_data = attestation.tpm_data.as_ref()
        .ok_or_else(|| anyhow!("TPM data missing in TdxVtpm mode"))?;

    // 2a. Verify TPM Quote signature and certificate chain
    match verify_tpm_quote_signature(tpm_data).await {
        Ok(_) => {
            details.quote_verified = true;  // Both quotes verified
        }
        Err(e) => {
            return Ok(VerificationResponse {
                is_valid: false,
                details,
                reason: Some(format!("vTPM signature failed: {}", e)),
            });
        }
    }

    // 2b. Verify PCR 2 matches UKI hash
    match verify_pcr2_uki_hash(tpm_data, vm_config).await {
        Ok(_) => {
            details.os_image_hash_verified = true;
        }
        Err(e) => {
            return Ok(VerificationResponse {
                is_valid: false,
                details,
                reason: Some(format!("PCR 2 verification failed: {}", e)),
            });
        }
    }

    // 2c. Optional: Verify PCR 0 (firmware), PCR 4 (boot), PCR 7 (Secure Boot)
    verify_pcr_baseline(tpm_data)?;

    Ok(VerificationResponse {
        is_valid: true,
        details,
        reason: None,
    })
}
```

### vTPM Quote 签名验证

```rust
async fn verify_tpm_quote_signature(tpm_data: &TpmQuote) -> Result<()> {
    use tpm_qvl::{TpmQuote, QuoteCollateral, verify_quote};

    // 1. Construct TpmQuote for tpm-qvl
    let quote = TpmQuote {
        message: tpm_data.message.clone(),
        signature: tpm_data.signature.clone(),
        pcr_values: tpm_data.pcr_values.clone(),
        ak_cert: tpm_data.ak_cert.clone(),
        qualifying_data: tpm_data.qualifying_data.clone(),
    };

    // 2. Build collateral
    let collateral = QuoteCollateral {
        cert_chain_pem: extract_cert_chain(&tpm_data.ak_cert)?,
        crls: vec![],           // GCP doesn't provide CRLs
        root_ca_crl: None,
    };

    // 3. GCP Root CA
    const GCP_ROOT_CA: &str = include_str!("gcp_root_ca.pem");

    // 4. Verify
    verify_quote(&quote, &collateral, GCP_ROOT_CA)?;

    Ok(())
}
```

### PCR 2 验证 (UKI Hash)

```rust
async fn verify_pcr2_uki_hash(
    tpm_data: &TpmQuote,
    vm_config: &VmConfig,
) -> Result<()> {
    // 1. Find PCR 2 in quote
    let pcr2 = tpm_data.pcr_values.iter()
        .find(|p| p.index == 2)
        .ok_or_else(|| anyhow!("PCR 2 not found"))?;

    // 2. Download UKI image
    let uki_path = download_image_component(
        vm_config,
        "kernel",  // UKI is stored as "kernel" in metadata
    ).await?;

    // 3. Calculate expected PCR 2
    let uki_data = fs::read(uki_path)?;
    let expected_pcr2 = calculate_pcr2_from_uki(&uki_data)?;

    // 4. Compare
    if pcr2.value != expected_pcr2 {
        bail!(
            "PCR 2 mismatch:\n  expected: {}\n  actual: {}",
            hex::encode(&expected_pcr2),
            hex::encode(&pcr2.value)
        );
    }

    Ok(())
}

/// Calculate PCR 2 from UKI binary
fn calculate_pcr2_from_uki(uki_data: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    // PCR 2 measurement for GCP UKI boot:
    // 1. PCR starts at zeros
    let mut pcr = vec![0u8; 32];

    // 2. Multiple separator events (result in known intermediate state)
    // Skip to the critical event...

    // 3. Extend with UKI hash
    // Event: EV_EFI_BOOT_SERVICES_APPLICATION
    let uki_hash = Sha256::digest(uki_data);

    let mut hasher = Sha256::new();
    hasher.update(&pcr);
    hasher.update(uki_hash);
    pcr = hasher.finalize().to_vec();

    // 4. Additional events may follow (need to research exact sequence)
    // TODO: Complete PCR 2 calculation based on GCP Event Log analysis

    Ok(pcr)
}
```

## 验证矩阵

| 验证项 | 来源 | 用途 | 优先级 |
|--------|------|------|--------|
| **TDX Quote 签名** | TDX | 证明 quote 来自真实 TDX | P0 |
| **TDX TCB 状态** | DCAP | Intel 平台安全版本 | P0 |
| **MRTD** | TDX Quote | 固件完整性 | P0 |
| **RTMR0-2** | TDX Quote | 系统镜像 (fw/kernel/initrd) | P0 |
| **RTMR3** | TDX Event Log | 应用层完整性 ⭐ | P0 |
| **vTPM Quote 签名** | vTPM | 证明 quote 来自真实 TPM | P0 |
| **vTPM AK Cert** | GCP | 证明 TPM 由 Google 管理 | P0 |
| **PCR 2** | vTPM | UKI hash ⭐ | P0 |
| **PCR 0** | vTPM | 固件版本基线 | P1 |
| **PCR 4** | vTPM | 启动序列 | P1 |
| **PCR 7** | vTPM | Secure Boot 策略 | P1 |

**关键发现**:
- **RTMR3**: 从 TDX event log 验证，包含应用运行时状态
- **PCR 2**: 从 vTPM 验证，是系统镜像 (UKI) 的唯一完整性指标

## 为什么需要两者？

### TDX 提供

✅ **运行时应用验证** - RTMR3 包含：
- app-id
- compose-hash
- instance-id
- rootfs-hash
- system-ready 事件

✅ **平台 TCB 状态** - Intel 签名的 quote
✅ **硬件隔离保证** - TDX Module

❌ **系统镜像完整性不完整** - RTMR1 只有部分 kernel 信息

### vTPM 提供

✅ **系统镜像完整性** - PCR 2 = 完整 UKI hash
- Kernel
- Initramfs
- Cmdline
- EFI stub

❌ **运行时应用状态** - PCR 不包含应用层信息
❌ **硬件隔离** - vTPM 可能被 hypervisor 访问

### 组合验证

```
完整信任链:
├─ TDX (硬件 + 运行时)
│  ├─ MRTD: GCP 固件
│  ├─ RTMR0: ACPI/配置
│  ├─ RTMR1: 部分 kernel 信息
│  ├─ RTMR2: kernel cmdline + initrd
│  └─ RTMR3: ⭐ 应用层 (app-id, compose-hash, etc.)
│
└─ vTPM (系统镜像)
   ├─ PCR 0: 固件版本
   ├─ PCR 2: ⭐ 完整 UKI hash (唯一镜像验证)
   ├─ PCR 4: 启动序列
   └─ PCR 7: Secure Boot 策略

结论: 两者互补，缺一不可
```

## 实现清单

### Phase 1: 基础设施 ✅
- [x] 添加 `TdxVtpm` 模式到 `AttestationMode`
- [x] 添加 `has_tdx()` / `has_vtpm()` 辅助方法
- [x] 修改 `detect()` 自动检测双模式
- [x] 修改 `local()` 支持 `local_tdx_vtpm()`
- [x] 修改 `from_ext_getter()` 提取双 quote

### Phase 2: vTPM Quote 采集
- [ ] 实现 `collect_vtpm_quote()`
- [ ] 实现 `generate_nonce()`
- [ ] 实现 `read_pcr_values()`
- [ ] 集成到 `local_tdx_vtpm()`

### Phase 3: 证书生成
- [ ] 修改 `cert.rs` 生成双模式证书
- [ ] 同时添加 TDX 和 vTPM 扩展

### Phase 4: Verifier 验证
- [ ] 实现 `verify_tdx_vtpm()`
- [ ] 实现 `verify_tpm_quote_signature()`
- [ ] 实现 `verify_pcr2_uki_hash()`
- [ ] 实现 `calculate_pcr2_from_uki()`
- [ ] 可选: `verify_pcr_baseline()`

### Phase 5: 测试
- [ ] testgcp 端到端测试
- [ ] PCR 不匹配测试
- [ ] 签名验证失败测试
- [ ] 性能测试

## 配置示例

### Verifier 策略

```yaml
# config.yaml
attestation:
  allowed_modes:
    - tdx+vtpm      # GCP TDX (required)
    - tdx           # Fallback for non-GCP TDX

  pcr_policy:
    pcr0:
      required: true
      expected: "0x0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802"

    pcr2:  # ⭐ Critical
      required: true
      verify_against_uki: true

    pcr4:
      required: false
      expected: "0x7a94ffe8a7729a566d3d3c577fcb4b6b1e671f31540375f80eae6382ab785e35"

    pcr7:
      required: false
```

## 安全考虑

### 双因素验证

类似于双因素认证，双模式验证提供：
1. **What you have** (TDX) - 硬件保证 + 运行时状态
2. **What you are** (vTPM) - 系统镜像身份

两者都通过才能信任。

### 降级攻击防护

- 不能只用 TDX（缺少完整镜像验证）
- 不能只用 vTPM（缺少运行时应用验证）
- 必须两者都验证通过

### Nonce 防重放

- vTPM quote 必须包含新 nonce
- TDX quote 也应包含 nonce（通过 report_data）

## 参考文档

- [RATLS_VTPM_DESIGN.md](RATLS_VTPM_DESIGN.md) - vTPM 单模式设计
- [GCP_PCR_ANALYSIS.md](tpm/GCP_PCR_ANALYSIS.md) - PCR 详细分析
- [PCR_POLICY_RECOMMENDATIONS.md](tpm/PCR_POLICY_RECOMMENDATIONS.md) - PCR 策略

---

**最后更新**: 2025-01-09
**适用于**: GCP TDX with vTPM
