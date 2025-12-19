# GCP Firmware MRTD Reference

## 概述

对于 GCP Confidential VM (包括 AMD SEV-SNP 和 Intel TDX)，Google 提供了固件的参考测量值 (Reference Measurements)，用于验证虚拟机运行的 OVMF 固件的完整性。

## ⚠️ 重要发现：vTPM vs TDX/SEV-SNP

**关键区别**：

| 特性 | vTPM (当前 testgcp) | TDX/SEV-SNP |
|------|-------------------|-------------|
| 固件测量 | ❌ PCR 0 只有版本字符串 | ✅ MRTD 包含固件 hash |
| 参考值来源 | ❌ Google 不提供 | ✅ Google 提供 Cloud Storage |
| 验证能力 | ⚠️ 只能验证版本一致性 | ✅ 可以验证固件完整性 |

**结论**：
- **vTPM 无法获取固件 hash 参考值** - Google 不为 vTPM 提供固件 MRTD
- **TDX/SEV-SNP 可以验证固件** - Google 提供完整的参考测量值

## TDX/SEV-SNP Firmware Reference Measurements

### 1. Cloud Storage 位置

Google 在公开的 Cloud Storage bucket 中提供固件参考测量值：

**AMD SEV-SNP**:
```bash
gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/384_BIT_MEASUREMENT.binarypb
```

**Intel TDX**:
```bash
gs://gce_tcb_integrity/ovmf_x64_csm/tdx/384_BIT_MEASUREMENT.binarypb
```

**OVMF 固件二进制**:
```bash
gs://gce_tcb_integrity/ovmf_x64_csm/UEFI_BINARY_DIGEST.fd
```

其中 `UEFI_BINARY_DIGEST` 是固件的 SHA-384 哈希值（十六进制字符串）。

### 2. 访问方法

#### 列出所有可用的参考测量值

```bash
# 列出所有 TDX 参考测量
gsutil ls gs://gce_tcb_integrity/ovmf_x64_csm/tdx/

# 列出所有 SEV-SNP 参考测量
gsutil ls gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/

# 列出所有固件二进制
gsutil ls gs://gce_tcb_integrity/ovmf_x64_csm/*.fd
```

#### 下载特定的参考测量值

```bash
# 从 attestation report 中提取 MRTD (384-bit)
MRTD="<your_384_bit_measurement_in_hex>"

# 下载对应的 launch endorsement (TDX)
gsutil cp gs://gce_tcb_integrity/ovmf_x64_csm/tdx/${MRTD}.binarypb \
    ./launch_endorsement.binarypb

# 或 SEV-SNP
gsutil cp gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/${MRTD}.binarypb \
    ./launch_endorsement.binarypb
```

#### 下载固件二进制

```bash
# 从 launch endorsement 中提取 UEFI binary digest
UEFI_DIGEST="<sha384_of_uefi_binary>"

# 下载固件二进制
gsutil cp gs://gce_tcb_integrity/ovmf_x64_csm/${UEFI_DIGEST}.fd \
    ./ovmf_firmware.fd

# 验证下载的固件
sha384sum ovmf_firmware.fd
# 应该匹配 UEFI_DIGEST
```

### 3. 验证流程

#### 完整验证步骤

```bash
# 1. 获取 attestation report
# (根据平台不同，使用 TDX 或 SEV-SNP 的工具)

# For TDX:
# - Extract MRTD from attestation report at offset 0xb8 (TDX Module 1.5)
# - MRTD is 48 bytes (384 bits)

# For SEV-SNP:
# - Extract measurement from attestation report at offset 0x90
# - Measurement is 48 bytes (384 bits)

# 2. 下载 launch endorsement
gsutil cp gs://gce_tcb_integrity/ovmf_x64_csm/tdx/${MRTD}.binarypb \
    ./endorsement.binarypb

# 3. 解码 protocol buffer
# 使用 gce-tcb-verifier 工具或 protoc

# 4. 验证签名
# 下载 GCP root certificate
wget https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt

# 5. 验证 endorsement 签名链
# 使用 gce-tcb-verifier 的 verify 库

# 6. 提取 UEFI binary digest
# 从 endorsement 的 VMGoldenMeasurement 字段

# 7. 下载并验证固件二进制
gsutil cp gs://gce_tcb_integrity/ovmf_x64_csm/${UEFI_DIGEST}.fd \
    ./ovmf.fd
sha384sum ovmf.fd
```

## 使用 gce-tcb-verifier 工具

### 1. 安装

```bash
git clone https://github.com/google/gce-tcb-verifier.git
cd gce-tcb-verifier
go build ./cmd/gcetcbendorsement
```

### 2. 提取和验证 Endorsement

```bash
# 从 attestation 中提取 endorsement
./gcetcbendorsement extract \
    --attestation=attestation.bin \
    --out=endorsement.binarypb

# 验证 endorsement
./gcetcbendorsement verify \
    --endorsement=endorsement.binarypb \
    --root-cert=GCE-cc-tcb-root_1.crt
```

### 3. 计算预期的 MRTD (离线)

```bash
# 从 OVMF 二进制计算 MRTD
# 参考 gce-tcb-verifier/tdx/mrtd_from_ovmf.go
```

## Launch Endorsement 结构

Launch endorsement 是一个 Protocol Buffer 消息，包含：

```protobuf
message VMGoldenMeasurement {
  // SHA-384 digest of the UEFI binary
  bytes digest = 1;

  // Security version number
  uint32 svn = 2;

  // Expected launch measurement (MRTD for TDX, measurement for SEV-SNP)
  bytes measurement = 3;

  // Launch policy
  bytes policy = 4;

  // Additional metadata
  ...
}

message Endorsement {
  // Golden measurements for this firmware version
  repeated VMGoldenMeasurement golden_measurements = 1;

  // Signature (signed by GCP)
  bytes signature = 2;

  // Certificate chain
  repeated bytes certificates = 3;
}
```

## vTPM 情况说明

### 为什么 vTPM 没有固件 MRTD？

对于使用 vTPM 的 Confidential VM (不是 TDX/SEV-SNP)：

**原因分析**：
1. vTPM 使用的是传统的 TCG TPM 2.0 规范
2. PCR 0 按照 TCG PC Client 规范，应该测量固件代码
3. 但 GCP 选择了简化实现：
   - 只测量固件**版本字符串** (`"GCE Virtual Firmware v2"`)
   - 不测量固件**二进制内容**
4. Google 不为 vTPM 虚拟机提供固件参考测量值

**已有的数据**：
- ✅ PCR 0 固定值: `0x0CCA9EC161B09288802E5A112255D21340ED5B797F5FE29CECCCFD8F67B9F802`
- ✅ 可以验证固件版本一致性
- ❌ 无法验证固件二进制完整性
- ❌ 无法从 Google 获取固件 hash 参考值

**替代方案**：
1. **信任 GCP 的固件签名验证**（在 TPM 之外）
2. **依赖 PCR 2 (UKI) 验证** - 这是唯一可靠的测量
3. **记录已知的 PCR 0 值** - 用于检测版本变化

### vTPM vs TDX/SEV-SNP 安全模型对比

| 安全特性 | vTPM | TDX/SEV-SNP |
|---------|------|-------------|
| **固件完整性验证** | ❌ 无法验证 | ✅ MRTD 完整 hash |
| **固件参考值** | ❌ Google 不提供 | ✅ Cloud Storage 公开 |
| **启动镜像验证** | ✅ PCR 2 (UKI) | ✅ RTMR[0-2] |
| **硬件隔离** | ⚠️ Hypervisor 可见 | ✅ 加密内存 |
| **Attestation** | ✅ TPM Quote | ✅ TDX/SNP Report |

## 推荐做法

### 对于 vTPM Confidential VM (当前 dstack)

```yaml
验证策略:
  PCR 0:
    purpose: 固件版本基线检查
    expected: "0x0CCA9EC161B09288802E5A112255D21340ED5B797F5FE29CECCCFD8F67B9F802"
    action: 警告如果不匹配（表示 GCP 更新了固件版本）

  PCR 2:
    purpose: UKI 镜像完整性 ⭐ 核心安全控制
    expected: <calculated_from_build>
    action: 拒绝如果不匹配

  固件信任:
    model: 信任 GCP 的固件签名和分发
    rationale: vTPM 无法验证固件 hash
```

### 对于 TDX/SEV-SNP (未来迁移)

```yaml
验证策略:
  MRTD:
    purpose: 固件完整性
    source: gs://gce_tcb_integrity/ovmf_x64_csm/tdx/${MRTD}.binarypb
    verification: Google 签名的 launch endorsement
    action: 拒绝如果不匹配

  RTMR[1]:
    purpose: OS/UKI 完整性
    expected: <calculated_from_build>
    action: 拒绝如果不匹配
```

## 参考资源

### 官方文档
- [Verify Confidential VM Firmware](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware)
- [GCP Confidential Computing](https://cloud.google.com/confidential-computing)

### 工具和代码
- [gce-tcb-verifier](https://github.com/google/gce-tcb-verifier) - Google 的参考验证工具
- [go-sev-guest](https://github.com/google/go-sev-guest) - AMD SEV-SNP attestation
- [go-tdx-guest](https://github.com/google/go-tdx-guest) - Intel TDX attestation

### 证书和根密钥
- GCP Root Certificate: https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt
- Cloud Storage Bucket: gs://gce_tcb_integrity/

### 相关研究
- [Understanding TDX Attestation Reports](https://phala.network/posts/understanding-tdx-attestation-reports-a-developers-guide)
- [TCG PC Client Platform TPM Profile](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)

## 总结

### vTPM (当前方案)

- ❌ **无固件 MRTD** - Google 不提供 vTPM 固件参考值
- ⚠️ **PCR 0 只有版本** - 无法验证固件完整性
- ✅ **PCR 2 是关键** - 唯一可靠的镜像验证
- 📝 **信任模型** - 依赖 GCP 固件管理

### TDX/SEV-SNP (升级路径)

- ✅ **完整 MRTD** - 固件 hash 可验证
- ✅ **Google 提供参考值** - Cloud Storage 公开访问
- ✅ **端到端验证** - 固件 + OS 都可验证
- 🎯 **推荐未来迁移** - 更强的安全保证

---

*文档创建日期: 2025-01-09*
*适用于: GCP Confidential VM (vTPM, TDX, SEV-SNP)*
