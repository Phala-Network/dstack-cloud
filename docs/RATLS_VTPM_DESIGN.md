# RA-TLS vTPM Support Design

## 概述

为 ra-tls 添加 vTPM attestation 支持，使得 dstack 可以在 vTPM 和 TDX 两种模式下工作。

## 设计目标

1. **向后兼容** - 不影响现有 TDX quote 功能
2. **统一接口** - vTPM 和 TDX 使用相同的 API
3. **模式感知** - 自动检测或明确指定 attestation 模式
4. **PCR 验证** - 验证 PCR 2 (UKI hash) 以确保镜像完整性

## 架构变化

### 1. 新的 X.509 证书扩展 OID

在 `ra-tls/src/oids.rs` 中添加：

```rust
/// Attestation mode (vTPM or TDX)
pub const PHALA_RATLS_ATTESTATION_MODE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 5];

/// TPM Quote (for vTPM mode)
pub const PHALA_RATLS_TPM_QUOTE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 6];

/// TPM Event Log (optional, for vTPM mode)
pub const PHALA_RATLS_TPM_EVENT_LOG: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 7];
```

**字段用途**:
- `ATTESTATION_MODE`: 字符串，值为 "tdx" 或 "vtpm"
- `TPM_QUOTE`: vTPM Quote 二进制数据（tpm2_quote 输出）
- `TPM_EVENT_LOG`: 可选的 TPM Event Log（用于调试/审计）

### 2. Attestation 模式枚举

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    /// Intel TDX with DCAP quote
    Tdx,
    /// vTPM with TPM2.0 quote
    VTpm,
}

impl AttestationMode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tdx => "tdx",
            Self::VTpm => "vtpm",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "tdx" => Ok(Self::Tdx),
            "vtpm" => Ok(Self::VTpm),
            _ => bail!("Invalid attestation mode: {}", s),
        }
    }

    /// Detect attestation mode from system
    pub fn detect() -> Result<Self> {
        // Check if TDX is available
        if std::path::Path::new("/dev/tdx_guest").exists() {
            return Ok(Self::Tdx);
        }

        // Check if vTPM is available
        if std::path::Path::new("/dev/tpmrm0").exists() {
            return Ok(Self::VTpm);
        }

        bail!("No attestation device found (neither TDX nor vTPM)")
    }
}
```

### 3. TPM Quote 数据结构

```rust
/// TPM Quote data (for vTPM mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// TPM Quote (TPMS_ATTEST + signature)
    pub quote: Vec<u8>,

    /// PCR values included in quote
    pub pcr_values: Vec<PcrValue>,

    /// AK (Attestation Key) certificate (DER format)
    pub ak_cert: Vec<u8>,

    /// Qualifying data (nonce) used in quote
    pub qualifying_data: Vec<u8>,

    /// Optional: TPM Event Log
    pub event_log: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub index: u32,
    pub value: Vec<u8>,
}
```

### 4. 统一的 Attestation 结构

修改 `ra-tls/src/attestation.rs` 中的 `Attestation` 结构：

```rust
#[derive(Debug, Clone)]
pub struct Attestation<R = ()> {
    /// Attestation mode
    pub mode: AttestationMode,

    /// Quote data (TDX Quote 或 TPM Quote)
    pub quote: Vec<u8>,

    /// Raw event log (TDX event log 或 TPM event log)
    pub raw_event_log: Vec<u8>,

    /// Parsed event log (TDX specific)
    pub event_log: Vec<EventLog>,

    /// Verified report
    pub report: R,

    /// TPM specific data (only for vTPM mode)
    pub tpm_data: Option<TpmQuote>,
}
```

## 实现步骤

### Phase 1: 基础设施 ✅

1. **添加 OID 定义** (`ra-tls/src/oids.rs`)
   - `PHALA_RATLS_ATTESTATION_MODE`
   - `PHALA_RATLS_TPM_QUOTE`
   - `PHALA_RATLS_TPM_EVENT_LOG`

2. **添加模式枚举** (`ra-tls/src/attestation.rs`)
   - `AttestationMode` enum
   - `detect()` 自动检测方法

3. **修改 Attestation 结构** (`ra-tls/src/attestation.rs`)
   - 添加 `mode` 字段
   - 添加 `tpm_data` 可选字段

### Phase 2: 设备端采集 (ra-tls)

4. **实现 vTPM Quote 采集** (`ra-tls/src/attestation.rs`)

```rust
impl Attestation {
    /// Create an attestation for local machine (auto-detect mode)
    pub fn local() -> Result<Self> {
        let mode = AttestationMode::detect()?;
        match mode {
            AttestationMode::Tdx => Self::local_tdx(),
            AttestationMode::VTpm => Self::local_vtpm(),
        }
    }

    /// Create TDX attestation (existing impl)
    fn local_tdx() -> Result<Self> {
        let quote = tdx_attest::get_quote(&[0u8; 64])?;
        let event_log = tdx_attest::eventlog::read_event_logs()?;
        let raw_event_log = serde_json::to_vec(&event_log)?;
        Ok(Self {
            mode: AttestationMode::Tdx,
            quote,
            raw_event_log,
            event_log,
            report: (),
            tpm_data: None,
        })
    }

    /// Create vTPM attestation (NEW)
    fn local_vtpm() -> Result<Self> {
        // 1. Generate nonce (qualifying data)
        let nonce = generate_nonce();

        // 2. Select PCRs to quote (0, 2, 4, 7)
        let pcr_selection = "sha256:0,2,4,7";

        // 3. Get TPM quote using tpm2_quote
        let quote_output = tpm2_quote(&nonce, pcr_selection)?;

        // 4. Read AK certificate
        let ak_cert = read_ak_cert()?;

        // 5. Parse PCR values
        let pcr_values = parse_pcr_values(&quote_output)?;

        // 6. Optional: read event log
        let event_log = read_tpm_event_log().ok();

        let tpm_data = TpmQuote {
            quote: quote_output.quote,
            pcr_values,
            ak_cert,
            qualifying_data: nonce,
            event_log,
        };

        Ok(Self {
            mode: AttestationMode::VTpm,
            quote: tpm_data.quote.clone(),
            raw_event_log: vec![], // vTPM doesn't use same event log format
            event_log: vec![],
            report: (),
            tpm_data: Some(tpm_data),
        })
    }
}
```

5. **实现 TPM 辅助函数**

```rust
fn generate_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn tpm2_quote(nonce: &[u8], pcr_selection: &str) -> Result<QuoteOutput> {
    use std::process::Command;

    // Save nonce to temp file
    let nonce_file = "/tmp/tpm_nonce";
    std::fs::write(nonce_file, nonce)?;

    // Run tpm2_quote
    let output = Command::new("tpm2_quote")
        .args(&[
            "-c", "0x81010001",  // AK handle
            "-l", pcr_selection,
            "-q", nonce_file,
            "-m", "/tmp/tpm_quote.msg",
            "-s", "/tmp/tpm_quote.sig",
            "-o", "/tmp/tpm_quote.pcrs",
            "-g", "sha256",
        ])
        .output()?;

    if !output.status.success() {
        bail!("tpm2_quote failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Read quote output
    let msg = std::fs::read("/tmp/tpm_quote.msg")?;
    let sig = std::fs::read("/tmp/tpm_quote.sig")?;

    // Combine TPMS_ATTEST + signature
    let mut quote = msg;
    quote.extend_from_slice(&sig);

    Ok(QuoteOutput { quote })
}

fn read_ak_cert() -> Result<Vec<u8>> {
    // Read AK certificate from TPM NV or file
    std::fs::read("/var/lib/dstack/ak_cert.der")
        .context("Failed to read AK certificate")
}

fn parse_pcr_values(quote_output: &QuoteOutput) -> Result<Vec<PcrValue>> {
    // Parse PCR values from tpm2_quote output
    // Could use tpm2-tools or parse manually
    todo!("Parse PCR values from quote")
}
```

### Phase 3: 证书生成 (ra-tls/src/cert.rs)

6. **修改证书生成添加 attestation mode 扩展**

```rust
pub fn generate_ratls_cert(/* ... */) -> Result<rcgen::Certificate> {
    let attestation = Attestation::local()?;

    // Add attestation mode extension
    custom_extensions.push(CustomExtension::from_oid_content(
        oids::PHALA_RATLS_ATTESTATION_MODE,
        attestation.mode.as_str().as_bytes().to_vec(),
    ));

    match attestation.mode {
        AttestationMode::Tdx => {
            // Existing TDX logic
            custom_extensions.push(CustomExtension::from_oid_content(
                oids::PHALA_RATLS_QUOTE,
                attestation.quote,
            ));
            custom_extensions.push(CustomExtension::from_oid_content(
                oids::PHALA_RATLS_EVENT_LOG,
                compressed_event_log,
            ));
        }
        AttestationMode::VTpm => {
            let tpm_data = attestation.tpm_data.unwrap();

            // Add TPM quote
            custom_extensions.push(CustomExtension::from_oid_content(
                oids::PHALA_RATLS_TPM_QUOTE,
                serde_json::to_vec(&tpm_data)?,
            ));

            // Optional: add TPM event log
            if let Some(event_log) = tpm_data.event_log {
                custom_extensions.push(CustomExtension::from_oid_content(
                    oids::PHALA_RATLS_TPM_EVENT_LOG,
                    event_log,
                ));
            }
        }
    }

    // ... rest of cert generation
}
```

### Phase 4: 验证端实现 (dstack-verifier)

7. **添加 vTPM 验证逻辑** (`verifier/src/verification.rs`)

```rust
impl CvmVerifier {
    pub async fn verify(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
        // Extract attestation mode from request or cert
        let attestation_mode = self.detect_attestation_mode(request)?;

        match attestation_mode {
            AttestationMode::Tdx => self.verify_tdx(request).await,
            AttestationMode::VTpm => self.verify_vtpm(request).await,
        }
    }

    async fn verify_vtpm(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
        let quote_hex = &request.quote;
        let quote_json: TpmQuote = serde_json::from_str(quote_hex)?;

        let mut details = VerificationDetails {
            quote_verified: false,
            event_log_verified: false,
            os_image_hash_verified: false,
            report_data: None,
            tcb_status: Some("vTPM (no TCB status)".to_string()),
            advisory_ids: vec![],
            app_info: None,
            acpi_tables: None,
            rtmr_debug: None,
        };

        // Step 1: Verify TPM Quote signature and certificate chain
        match self.verify_tpm_quote(&quote_json).await {
            Ok(_) => {
                details.quote_verified = true;
            }
            Err(e) => {
                return Ok(VerificationResponse {
                    is_valid: false,
                    details,
                    reason: Some(format!("TPM quote verification failed: {}", e)),
                });
            }
        }

        // Step 2: Verify PCR 2 matches expected UKI hash
        let vm_config: VmConfig = serde_json::from_str(&request.vm_config)?;

        match self.verify_vtpm_pcr2(&vm_config, &quote_json, &mut details).await {
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

        Ok(VerificationResponse {
            is_valid: true,
            details,
            reason: None,
        })
    }

    async fn verify_tpm_quote(&self, tpm_data: &TpmQuote) -> Result<()> {
        // Use tpm-qvl crate
        use tpm_qvl::verify_quote;

        // 1. Parse quote
        let quote = TpmQuote::parse(&tpm_data.quote)?;

        // 2. Extract collateral (cert chain)
        let collateral = QuoteCollateral {
            cert_chain_pem: extract_cert_chain(&tpm_data.ak_cert)?,
            crls: vec![], // GCP doesn't provide CRLs for vTPM
            root_ca_crl: None,
        };

        // 3. Get GCP Root CA
        let root_ca_pem = GCP_VTPM_ROOT_CA;

        // 4. Verify quote
        verify_quote(&quote, &collateral, root_ca_pem)?;

        // 5. Verify qualifying data matches nonce
        if quote.qualifying_data != tpm_data.qualifying_data {
            bail!("Qualifying data mismatch");
        }

        Ok(())
    }

    async fn verify_vtpm_pcr2(
        &self,
        vm_config: &VmConfig,
        tpm_data: &TpmQuote,
        details: &mut VerificationDetails,
    ) -> Result<()> {
        // 1. Find PCR 2 in quote
        let pcr2 = tpm_data
            .pcr_values
            .iter()
            .find(|p| p.index == 2)
            .ok_or_else(|| anyhow!("PCR 2 not found in quote"))?;

        // 2. Download image and compute expected PCR 2
        let image_paths = self.ensure_image_downloaded(vm_config).await?;

        // 3. Calculate expected PCR 2 from UKI
        let uki_data = std::fs::read(&image_paths.kernel_path)?;  // UKI is stored as "kernel"
        let expected_pcr2 = calculate_pcr2_from_uki(&uki_data)?;

        // 4. Compare
        if pcr2.value != expected_pcr2 {
            bail!(
                "PCR 2 mismatch: expected={}, actual={}",
                hex::encode(&expected_pcr2),
                hex::encode(&pcr2.value)
            );
        }

        Ok(())
    }
}

/// Calculate PCR 2 value from UKI binary
fn calculate_pcr2_from_uki(uki_data: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    // PCR 2 calculation for UKI:
    // 1. Start with zeros
    let mut pcr = vec![0u8; 32];

    // 2. Extend with UKI hash
    // PCR_new = SHA256(PCR_old || SHA256(UKI))
    let uki_hash = Sha256::digest(uki_data);

    let mut hasher = Sha256::new();
    hasher.update(&pcr);
    hasher.update(uki_hash);
    pcr = hasher.finalize().to_vec();

    Ok(pcr)
}
```

## PCR 验证策略

### 必须验证 (P0)

- **PCR 0**: 固件版本基线
  - 预期值: `0x0CCA9EC161B09288802E5A112255D21340ED5B797F5FE29CECCCFD8F67B9F802` (GCP)
  - 用途: 检测固件版本变化

- **PCR 2**: UKI 完整性 ⭐ **最关键**
  - 预期值: 从构建的 UKI 二进制计算
  - 用途: 验证系统镜像完整性

### 可选验证 (P1)

- **PCR 4**: 启动序列
  - 预期值: `0x7A94FFE8A7729A566D3D3C577FCB4B6B1E671F31540375F80EAE6382AB785E35` (GCP UKI boot)
  - 用途: 检测启动序列异常

- **PCR 7**: Secure Boot 策略
  - 预期值: 根据 Secure Boot 配置计算
  - 用途: 监控 Secure Boot 策略变化

## 数据流

### 设备端 (Guest)

```
1. Attestation::local()
   ↓
2. 检测模式: /dev/tdx_guest 或 /dev/tpmrm0
   ↓
3a. TDX: tdx_attest::get_quote()
   ↓
3b. vTPM: tpm2_quote + AK cert
   ↓
4. 生成 RA-TLS 证书，添加扩展:
   - ATTESTATION_MODE = "vtpm"
   - TPM_QUOTE = TpmQuote (JSON)
   - TPM_EVENT_LOG (optional)
```

### 验证端 (Verifier)

```
1. 接收 RA-TLS 证书
   ↓
2. 提取 ATTESTATION_MODE
   ↓
3a. mode=tdx: 现有 TDX 验证流程
   ↓
3b. mode=vtpm:
   - 提取 TPM_QUOTE
   - 验证 quote 签名 (tpm-qvl)
   - 验证 AK 证书链 (GCP Root CA)
   - 验证 PCR 2 == UKI hash
   ↓
4. 返回验证结果
```

## 依赖项

### 新增 Crates

1. **tpm-qvl** (已存在) - TPM quote 验证
2. **serde_json** - TpmQuote 序列化

### 系统依赖 (Guest)

1. **tpm2-tools** - `tpm2_quote` 命令
2. **TPM 2.0 设备** - `/dev/tpmrm0` 或 `/dev/tpm0`

## 测试计划

### 单元测试

1. `AttestationMode::detect()` 检测逻辑
2. `calculate_pcr2_from_uki()` PCR 计算
3. OID 编码/解码

### 集成测试

1. testgcp (vTPM) 生成 RA-TLS 证书
2. testgcp (vTPM) 验证 quote
3. tdx-ubuntu-2404-test (TDX) 现有功能回归
4. 交叉验证: TDX cert 不能通过 vTPM 验证

### 端到端测试

1. vTPM guest → verifier 完整流程
2. PCR 2 不匹配时正确拒绝
3. 签名验证失败时正确拒绝

## 安全考虑

### 1. Nonce 防重放

- 每次 quote 使用新的 nonce (qualifying_data)
- Verifier 验证 nonce 包含在 quote 中

### 2. 证书链验证

- vTPM AK 证书必须链接到 GCP Root CA
- 使用 tpm-qvl 的 webpki 验证

### 3. PCR 2 验证

- **核心安全控制** - 必须验证 PCR 2
- 从可信的镜像源下载 UKI
- 计算并比较 PCR 2

### 4. 降级攻击防护

- Attestation mode 包含在证书中
- 不能用 TDX 要求验证 vTPM quote
- 策略明确指定允许的模式

## 兼容性

### 向后兼容

- 现有 TDX 代码路径不变
- 只在检测到 `ATTESTATION_MODE` OID 时使用新逻辑
- 默认行为: 检测 `/dev/tdx_guest` → TDX mode

### 向前兼容

- `AttestationMode` enum 可扩展
- 未来可添加 SEV-SNP, SGX 等模式

## 文件清单

### 需要修改的文件

1. `ra-tls/src/oids.rs` - 添加新 OID
2. `ra-tls/src/attestation.rs` - 添加 vTPM 支持
3. `ra-tls/src/cert.rs` - 证书生成添加 mode 扩展
4. `verifier/src/verification.rs` - 添加 vTPM 验证逻辑

### 新增文件

1. `ra-tls/src/vtpm.rs` - vTPM 特定实现
2. `docs/RATLS_VTPM_DESIGN.md` - 本设计文档

## 实施优先级

### P0 (必须)
- [x] OID 定义
- [ ] AttestationMode 枚举
- [ ] 基础 vTPM quote 采集
- [ ] PCR 2 验证

### P1 (应该)
- [ ] Event log 支持
- [ ] PCR 0, 4, 7 验证
- [ ] 完整测试覆盖

### P2 (可选)
- [ ] 性能优化
- [ ] 缓存机制
- [ ] 监控指标

## 参考资源

- [GCP_PCR_ANALYSIS.md](tpm/GCP_PCR_ANALYSIS.md) - GCP vTPM PCR 分析
- [PCR_POLICY_RECOMMENDATIONS.md](tpm/PCR_POLICY_RECOMMENDATIONS.md) - PCR 验证策略
- [tpm-qvl README](../tpm-qvl/README.md) - TPM quote 验证库
