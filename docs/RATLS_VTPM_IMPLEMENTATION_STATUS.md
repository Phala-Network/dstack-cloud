# RA-TLS Dual-Mode Attestation (TDX + vTPM) - Implementation Status

**重要变更**: 从单一模式改为双模式验证，支持在 GCP TDX 环境中同时验证 TDX 和 vTPM。

## 已完成工作 (Phase 1-2)

### 1. OID 定义 ✅

**文件**: `ra-tls/src/oids.rs`

添加了 3 个新的 X.509 证书扩展 OID：

```rust
/// OID for attestation mode (vTPM or TDX).
pub const PHALA_RATLS_ATTESTATION_MODE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 5];

/// OID for TPM Quote (vTPM mode).
pub const PHALA_RATLS_TPM_QUOTE: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 6];

/// OID for TPM Event Log (vTPM mode, optional).
pub const PHALA_RATLS_TPM_EVENT_LOG: &[u64] = &[1, 3, 6, 1, 4, 1, 62397, 1, 7];
```

### 2. AttestationMode 枚举 ✅

**文件**: `ra-tls/src/attestation.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    /// Intel TDX with DCAP quote only
    Tdx,
    /// vTPM with TPM 2.0 quote only
    VTpm,
    /// Both TDX and vTPM (GCP TDX with vTPM)
    #[serde(rename = "tdx+vtpm")]
    TdxVtpm,
}
```

**功能**:
- ✅ `as_str()` - 转换为字符串 ("tdx"/"vtpm"/"tdx+vtpm")
- ✅ `from_str()` - 从字符串解析，支持 "tdx+vtpm" 和 "tdxvtpm"
- ✅ `detect()` - 自动检测模式
  - 同时存在 `/dev/tdx_guest` + `/dev/tpmrm0` → **TdxVtpm** ⭐
  - 仅 `/dev/tdx_guest` → Tdx
  - 仅 `/dev/tpmrm0` 或 `/dev/tpm0` → VTpm
  - 否则返回错误
- ✅ `has_tdx()` - 检查是否包含 TDX (Tdx | TdxVtpm)
- ✅ `has_vtpm()` - 检查是否包含 vTPM (VTpm | TdxVtpm)

### 3. TPM 数据结构 ✅

**文件**: `ra-tls/src/attestation.rs`

```rust
/// PCR value in TPM quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub index: u32,
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

/// TPM Quote data (for vTPM mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,         // TPMS_ATTEST

    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,       // TPM signature

    pub pcr_values: Vec<PcrValue>, // PCR values

    #[serde(with = "hex_bytes")]
    pub ak_cert: Vec<u8>,         // AK certificate (DER)

    #[serde(with = "hex_bytes")]
    pub qualifying_data: Vec<u8>, // Nonce
}
```

### 4. Attestation 结构重构 ✅

**文件**: `ra-tls/src/attestation.rs`

```rust
#[derive(Debug, Clone)]
pub struct Attestation<R = ()> {
    pub mode: AttestationMode,     // NEW: 模式标识
    pub quote: Vec<u8>,
    pub raw_event_log: Vec<u8>,
    pub event_log: Vec<EventLog>,
    pub report: R,
    pub tpm_data: Option<TpmQuote>,  // NEW: vTPM 数据
}
```

**修改的方法**:
- ✅ `local()` - 自动检测模式并调用对应方法
- ✅ `local_tdx()` - TDX attestation（原有逻辑）
- ✅ `local_vtpm()` - vTPM attestation（**已实现**）✅
- ✅ `local_tdx_vtpm()` - 双模式 attestation（**已实现**）✅
- ✅ `collect_vtpm_quote()` - 采集 vTPM quote（**已实现**）✅
  - 生成 32 字节随机 nonce
  - 调用 `tpm2_quote` (PCR 0,2,4,7)
  - 读取 PCR 值
  - 读取 AK 证书（GCP metadata 或 NVRAM）
- ✅ `generate_nonce()` - 生成随机 nonce
- ✅ `read_pcr_values()` - 读取 PCR 值
- ✅ `read_ak_cert()` - 读取 AK 证书
- ✅ `new()` - 默认 TDX 模式（向后兼容）
- ✅ `from_ext_getter()` - 从证书提取，支持模式检测
  - 优先读取 `ATTESTATION_MODE` OID
  - 向后兼容：根据 quote OID 类型推断模式
  - TDX: 读取 `PHALA_RATLS_QUOTE` + `PHALA_RATLS_EVENT_LOG`
  - vTPM: 读取 `PHALA_RATLS_TPM_QUOTE`，反序列化 `TpmQuote`
  - **TdxVtpm**: 读取两种 quote 并验证都存在 ✅
- ✅ `verify()` - 更新以包含新字段

### 5. 编译状态 ✅

- ✅ ra-tls crate 编译通过
- ✅ 向后兼容性保持
- ✅ 所有现有 TDX 功能不受影响

### 6. 证书生成支持 ✅

**文件**: `ra-tls/src/cert.rs`

**已完成**:
- ✅ `CertRequest` 添加 `attestation_mode` 和 `tpm_quote_data` 字段
- ✅ `into_cert_params()` 添加 `PHALA_RATLS_ATTESTATION_MODE` 扩展
- ✅ `into_cert_params()` 添加 `PHALA_RATLS_TPM_QUOTE` 扩展（JSON 序列化）
- ✅ `generate_ra_cert()` 更新为支持多模式
  - 自动检测模式 (`Attestation::local()`)
  - TDX: 生成 TDX quote + event log
  - vTPM: 使用采集的 vTPM quote
  - TdxVtpm: 同时包含两种 quote ⭐

**代码示例**:
```rust
pub fn generate_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<CertPair> {
    let attestation = Attestation::local()?; // 自动检测并采集
    let mode = attestation.mode;

    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .key(&key)
        .maybe_attestation_mode(Some(mode))
        .maybe_quote(tdx_quote.as_deref())           // TDX quote if has_tdx()
        .maybe_event_log(tdx_event_log.as_deref())   // TDX event log
        .maybe_tpm_quote_data(attestation.tpm_data.as_ref()) // vTPM quote if has_vtpm()
        .build();
    // ...
}
```

### 7. 新增依赖 ✅

**文件**: `ra-tls/Cargo.toml`

- ✅ `rand` - 用于生成 nonce

## 下一步工作 (Phase 3-4)

### Phase 3: Verifier 验证逻辑 ✅

**优先级**: P0

**任务** (已完成):

1. **添加双模式验证** - `verifier/src/verification.rs`
   ```rust
   impl CvmVerifier {
       pub async fn verify(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
           let attestation = extract_attestation_from_request(request)?;

           match attestation.mode {
               AttestationMode::Tdx => self.verify_tdx(request).await,
               AttestationMode::VTpm => self.verify_vtpm(request).await,
               AttestationMode::TdxVtpm => self.verify_tdx_vtpm(request).await, // ⭐
           }
       }

       async fn verify_tdx_vtpm(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
           // 1. Verify TDX Quote (use existing logic)
           // 2. Verify RTMR3 from TDX event log
           // 3. Verify TPM Quote signature (use tpm-qvl)
           // 4. Verify AK certificate chain
           // 5. Verify PCR 2 == UKI hash ⭐
           // 6. Return combined result
       }

       async fn verify_vtpm(&self, request: &VerificationRequest) -> Result<VerificationResponse> {
           // 1. Verify TPM Quote (use tpm-qvl)
           // 2. Verify AK certificate chain
           // 3. Verify PCR 2 == UKI hash
           // 4. Return result
       }
   }
   ```

2. **PCR 2 计算和验证**
   ```rust
   fn calculate_pcr2_from_uki(uki_data: &[u8]) -> Result<Vec<u8>> {
       use sha2::{Digest, Sha256};

       // PCR starts at zeros
       let mut pcr = vec![0u8; 32];

       // Extend with UKI hash
       let uki_hash = Sha256::digest(uki_data);
       let mut hasher = Sha256::new();
       hasher.update(&pcr);
       hasher.update(uki_hash);
       pcr = hasher.finalize().to_vec();

       Ok(pcr)
   }
   ```

3. **使用 tpm-qvl 验证 quote**
   ```rust
   use tpm_qvl::verify_quote;

   let quote = TpmQuote {
       message: tpm_data.message,
       signature: tpm_data.signature,
       pcr_values: tpm_data.pcr_values,
       ak_cert: tpm_data.ak_cert,
       qualifying_data: tpm_data.qualifying_data,
   };

   let collateral = QuoteCollateral {
       cert_chain_pem: extract_cert_chain(&tpm_data.ak_cert)?,
       crls: vec![],
       root_ca_crl: None,
   };

   verify_quote(&quote, &collateral, GCP_ROOT_CA)?;
   ```

## 设计文档

详细设计见：
- **[RATLS_VTPM_DESIGN.md](RATLS_VTPM_DESIGN.md)** - 完整设计文档
  - 架构变化
  - 数据流
  - PCR 验证策略
  - 安全考虑

## PCR 验证策略

### 必须验证 (P0)

| PCR | 用途 | 预期值 | 动作 |
|-----|------|--------|------|
| PCR 0 | 固件版本 | `0x0CCA9EC...` (GCP) | 基线检查 |
| PCR 2 | UKI hash | `<from_build>` | ⭐ **拒绝不匹配** |

### 可选验证 (P1)

| PCR | 用途 | 预期值 | 动作 |
|-----|------|--------|------|
| PCR 4 | 启动序列 | `0x7A94FFE...` (GCP UKI) | 异常检测 |
| PCR 7 | Secure Boot | `<varies>` | 策略监控 |

## 测试计划

### 单元测试

- [x] `AttestationMode::detect()` - 自动检测
- [x] `AttestationMode::from_str()` - 字符串解析
- [x] `Attestation::from_ext_getter()` - 证书提取（TDX）
- [ ] `Attestation::from_ext_getter()` - 证书提取（vTPM）
- [ ] `calculate_pcr2_from_uki()` - PCR 计算

### 集成测试

- [ ] testgcp (vTPM) - 生成证书
- [ ] testgcp (vTPM) - 验证 quote
- [ ] testgcp (vTPM) - PCR 2 验证
- [x] 现有 TDX 测试回归

### 端到端测试

- [ ] vTPM guest → verifier - 完整流程
- [ ] PCR 不匹配时正确拒绝
- [ ] 签名验证失败时正确拒绝

## 文件变更总结

### 已修改

- ✅ `ra-tls/src/oids.rs` - 添加 3 个新 OID
- ✅ `ra-tls/src/attestation.rs` - 添加 vTPM 支持
  - `AttestationMode` enum
  - `PcrValue` struct
  - `TpmQuote` struct
  - 修改 `Attestation` 结构
  - 更新所有相关方法

### 待修改

- [ ] `dstack-util` - 添加命令显示 vTPM quote 和 PCR 值（可选）

### 已添加

- ✅ `verifier/certs/gcp-vtpm-root-ca.pem` - GCP vTPM root CA 证书
- ✅ `verifier/src/verification.rs` - 添加 vTPM/TdxVtpm 验证逻辑
  - `verify_vtpm()` - vTPM 验证
  - `verify_tdx_vtpm()` - 双模式验证
  - `verify_tpm_quote()` - TPM quote 签名验证
  - `verify_pcr2_uki_hash()` - PCR 2 与 UKI hash 验证
  - `calculate_pcr2_from_uki()` - PCR 2 计算

## 向后兼容性

### 保证的兼容性

- ✅ 现有 TDX quote 验证不受影响
- ✅ `Attestation::new()` 默认 TDX 模式
- ✅ 旧证书没有 `ATTESTATION_MODE` OID 时默认为 TDX
- ✅ 所有现有 API 签名保持不变

### 新功能

- ✅ 自动模式检测 (`AttestationMode::detect()`)
- ✅ 证书可包含模式标识
- ✅ 支持从证书提取 vTPM quote

## 依赖项

### 现有依赖

- ✅ `serde` / `serde_json` - 序列化
- ✅ `anyhow` - 错误处理
- ✅ `hex` - 编码
- ✅ `sha2` - 哈希
- ✅ `tpm-qvl` - TPM quote 验证（已存在）

### 系统依赖 (Guest)

- `tpm2-tools` - 用于 `tpm2_quote` 命令
- `/dev/tpmrm0` 或 `/dev/tpm0` - TPM 设备
- AK certificate 存储

## 下一步行动项

### 立即执行 (本周)

1. [x] 实现 `local_vtpm()` - vTPM quote 采集 ✅
2. [x] 实现 `local_tdx_vtpm()` - 双模式 quote 采集 ✅
3. [x] 修改 `cert.rs` - 添加 mode 扩展到证书 ✅
4. [ ] 在 testgcp 上测试基本流程（需要 tpm2-tools）⭐

### 短期 (下周)

5. [x] 实现 verifier vTPM 验证逻辑 ✅
6. [x] 实现 verifier TdxVtpm 双模式验证逻辑 ✅
7. [x] 实现 PCR 2 计算和验证 ✅
8. [ ] 端到端测试 ⭐
9. [ ] 获取真实的 GCP vTPM root CA 证书

### 中期 (2周)

9. [ ] 完整测试覆盖
10. [ ] 文档和示例
11. [ ] 性能测试

## 参考资源

- [RATLS_DUAL_MODE_DESIGN.md](RATLS_DUAL_MODE_DESIGN.md) - **双模式设计文档** ⭐
- [RATLS_VTPM_DESIGN.md](RATLS_VTPM_DESIGN.md) - vTPM 单模式设计（历史参考）
- [GCP_PCR_ANALYSIS.md](tpm/GCP_PCR_ANALYSIS.md) - PCR 分析
- [PCR_POLICY_RECOMMENDATIONS.md](tpm/PCR_POLICY_RECOMMENDATIONS.md) - PCR 策略
- [tpm-qvl README](../tpm-qvl/README.md) - TPM 验证库

## 重要变更记录

### 2025-01-10: 双模式支持

从单一模式（TDX 或 vTPM）改为支持三种模式：
- **Tdx**: TDX only (原有模式)
- **VTpm**: vTPM only (新增)
- **TdxVtpm**: 同时验证 TDX + vTPM (GCP 场景) ⭐

**原因**:
- GCP TDX VMs 同时提供 TDX 和 vTPM
- TDX 验证 RTMR3 (应用层完整性)
- vTPM 验证 PCR 2 (UKI 完整 hash)
- 两者互补，提供完整信任链

### 2025-01-10 (下午): Verifier 实现完成

完成 Phase 3 - Verifier 验证逻辑：
- ✅ 实现 `verify_tdx()` - TDX 验证（重构原有逻辑）
- ✅ 实现 `verify_vtpm()` - vTPM 验证
- ✅ 实现 `verify_tdx_vtpm()` - 双模式验证 ⭐
- ✅ 实现 `verify_tpm_quote()` - TPM quote 签名验证（使用 tpm-qvl）
- ✅ 实现 `verify_pcr2_uki_hash()` - PCR 2 验证
- ✅ 实现 `calculate_pcr2_from_uki()` - PCR 2 计算
- ✅ 添加 GCP vTPM root CA 证书（占位）
- ✅ 添加 `tpm-qvl` 和 `tpm-attest` 依赖到 verifier

**验证流程**:
1. **TdxVtpm 模式**: TDX quote → RTMR0-3 验证 → vTPM quote → PCR 2 验证
2. **VTpm 模式**: vTPM quote → PCR 2 验证
3. **Tdx 模式**: TDX quote → RTMR0-3 验证（原有逻辑）

---

**最后更新**: 2025-01-10
**状态**: Phase 1-3 完成 ✅ | Phase 4 测试待进行
