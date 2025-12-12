# TPM Attestation 文档索引

本目录包含所有TPM (Trusted Platform Module) 相关的文档、脚本和证书文件。

## 📚 文档分类

### 0. GCP PCR Analysis and Security ⭐ 完整研究

**核心发现**: PCR 2 是唯一能唯一标识 dstack 系统镜像的 PCR

- **[PCR_RESEARCH_SUMMARY.md](PCR_RESEARCH_SUMMARY.md)** - 📖 **快速入门 - 从这里开始**
  - 研究问题和答案总结
  - 哪些 PCR 可用于镜像验证
  - ⚠️ 关键发现：OVMF hash 不在任何 PCR 中
  - 如何预计算 PCR 值
  - 安全模型和风险评估
  - 实施清单

- **[GCP_PCR_ANALYSIS.md](GCP_PCR_ANALYSIS.md)** - 📊 **技术深度分析**
  - 完整的 Event Log 分析
  - 每个 PCR 的详细测量内容
  - PCR 0: OVMF 固件版本（非固件 hash）
  - PCR 2: UKI 完整二进制 hash ⭐ **最关键**
  - PCR 4: 标准启动事件
  - 为什么 PCR 8 是零（UKI vs GRUB）
  - 预计算方法和验证

- **[PCR_POLICY_RECOMMENDATIONS.md](PCR_POLICY_RECOMMENDATIONS.md)** - 🔧 **实施指南**
  - PCR 验证策略（P0/P1/P2 优先级）
  - tpm-qvl 集成示例代码
  - Yocto 构建系统集成
  - 安全考虑和攻击场景
  - Secure Boot 分析

- **[pcr3_7_security_analysis.md](/tmp/pcr3_7_security_analysis.md)** - 🔒 **安全影响分析**
  - PCR 3-7 详细安全评估
  - Secure Boot 禁用的影响
  - 当前安全层级分析
  - 是否应启用 Secure Boot
  - 风险总结和建议

- **[GCP_FIRMWARE_MRTD_REFERENCE.md](GCP_FIRMWARE_MRTD_REFERENCE.md)** - 📦 **GCP 固件参考测量值**
  - ⚠️ 关键发现：vTPM 无固件 MRTD
  - TDX/SEV-SNP 固件参考值获取方法
  - Cloud Storage bucket 访问指南
  - gce-tcb-verifier 工具使用
  - vTPM vs TDX/SEV-SNP 安全对比

- **[calculate_pcr.py](calculate_pcr.py)** - 🛠️ **PCR 计算工具**
  - 从 Event Log 重放计算 PCR
  - 预计算 PCR 0（固件版本）
  - 预计算 PCR 2（UKI hash）⭐ 用于构建系统
  - 支持 verbose 模式查看详细步骤
  - 验证功能

### 1. TPM Quote 结构和验证

#### 核心文档
- **[TPM_QUOTE_STRUCTURE.md](TPM_QUOTE_STRUCTURE.md)** - TPM Quote结构详解
  - TPMS_ATTEST结构完整说明
  - 每个字段的含义和用途
  - 十六进制格式说明
  - 验证逻辑和安全注意事项

- **[TPM_QUOTE_QUICK_REF.txt](TPM_QUOTE_QUICK_REF.txt)** - TPM Quote快速参考
  - 可视化的字段说明
  - 验证流程总结
  - 常用命令速查
  - 安全陷阱提醒

#### 辅助文档
- **[tpm_quote_trust_chain.txt](tpm_quote_trust_chain.txt)** - TPM Quote信任链分析
  - 证书链结构（3个X.509证书）
  - 密钥对（AK - 无证书）
  - 签名数据（Quote）
  - 信任传递链详解

#### 脚本
- **[analyze_tpm_quote.sh](analyze_tpm_quote.sh)** - Quote结构分析脚本
  - 解析Quote.msg文件
  - 提取关键字段
  - 演示验证流程

### 2. Quote与Event Log关联验证

#### 核心文档
- **[QUOTE_EVENTLOG_VERIFICATION.md](QUOTE_EVENTLOG_VERIFICATION.md)** - 完整验证指南
  - 核心原理图解
  - 详细验证步骤
  - 安全性分析
  - Python和Bash代码示例
  - 攻击场景分析

- **[quote_eventlog_summary.txt](quote_eventlog_summary.txt)** - 可视化验证流程
  - 一图看懂验证原理
  - 启动时的测量过程
  - Quote生成过程
  - 验证步骤图示
  - 攻击场景分析

#### 脚本
- **[verify_quote_eventlog.sh](verify_quote_eventlog.sh)** - Quote和Event Log验证脚本
  - 生成Quote
  - 重放Event Log
  - 计算PCR Digest
  - 对比验证

### 3. GCP vTPM Attestation

#### CA证书文件
- **[gce_tpm_root_ca.pem](gce_tpm_root_ca.pem)** - Google Cloud vTPM Root CA证书
  - 大小: 2.1KB
  - 有效期: 2022-2122 (100年)
  - 用途: TPM EK证书专用 (OID 2.23.133.8.1)

- **[gce_tpm_intermediate_ca.pem](gce_tpm_intermediate_ca.pem)** - Google Cloud vTPM Intermediate CA
  - 大小: 2.5KB
  - Subject: CN=EK/AK CA Intermediate
  - 签发者: CN=EK/AK CA Root

- **[gcp_vtpm_ca_bundle.pem](gcp_vtpm_ca_bundle.pem)** - CA Bundle (Root + Intermediate)
  - 大小: 4.6KB
  - 包含完整的证书链

#### Attestation脚本
- **[gcp-vtpm-attest-minimal.sh](gcp-vtpm-attest-minimal.sh)** - ⭐ 推荐使用
  - 最小信任模型（只需Root CA）
  - 动态下载Intermediate CA
  - 完整的Quote验证
  - OS镜像验证

- **[gcp-vtpm-attest-secure.sh](gcp-vtpm-attest-secure.sh)** - CA Bundle模式
  - 需要预先提供CA Bundle
  - 完整的密码学验证
  - Quote生成和验证

#### 文档
- **[CERTIFICATE-PURPOSE-VALIDATION.md](CERTIFICATE-PURPOSE-VALIDATION.md)** - 证书用途验证
  - Extended Key Usage说明 (OID 2.23.133.8.1)
  - CA用途验证逻辑
  - 安全风险分析
  - 验证建议

- **[CA-TRUST-MODEL-COMPARISON.md](CA-TRUST-MODEL-COMPARISON.md)** - CA信任模型对比
  - Bundle模型 vs Minimal模型
  - Intermediate CA范围和有效期
  - 实施建议

#### 辅助脚本
- **[ca_purpose_check.sh](ca_purpose_check.sh)** - CA用途验证脚本
  - 检查Basic Constraints
  - 检查Key Usage
  - 检查Extended Key Usage
  - 验证Subject CN

- **[compare-ccel-tpm.sh](compare-ccel-tpm.sh)** - CCEL vs TPM Event Log对比
  - TDX CCEL分析
  - TPM Event Log分析
  - 对比测试

#### 证书详情文件
- **[root_ca_full.txt](root_ca_full.txt)** - Root CA完整证书内容
- **[intermediate_ca_full.txt](intermediate_ca_full.txt)** - Intermediate CA完整证书内容

## 🚀 快速开始

### 计算和验证 PCR 值 ⭐ 推荐

```bash
# 1. 从 testgcp 下载 Event Log
ssh testgcp 'tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements 2>/dev/null' > eventlog.yaml

# 2. 计算 PCR 0, 2, 4 值
./docs/tpm/calculate_pcr.py --eventlog eventlog.yaml --pcr 0,2,4

# 3. 查看详细计算过程
./docs/tpm/calculate_pcr.py --eventlog eventlog.yaml --pcr 0 --verbose

# 4. 从 bootloader 哈希计算 PCR 2（用于提前计算）
./docs/tpm/calculate_pcr.py --build-pcr2 \
    --bootloader build/tmp/deploy/images/*/grub-efi-bootx64.efi \
    --verbose
```

### 在GCP VM上进行vTPM Attestation

```bash
# 1. 使用最小信任模型（推荐）
./docs/tpm/gcp-vtpm-attest-minimal.sh

# 2. 或使用CA Bundle模式
./docs/tpm/gcp-vtpm-attest-secure.sh
```

### 验证Quote与Event Log关联

```bash
# 运行验证演示脚本
./docs/tpm/verify_quote_eventlog.sh
```

### 分析TPM Quote结构

```bash
# 在有TPM设备的系统上
./docs/tpm/analyze_tpm_quote.sh
```

## 📖 学习路径

### 初学者
1. 阅读 [TPM_QUOTE_QUICK_REF.txt](TPM_QUOTE_QUICK_REF.txt) 了解基本概念
2. 阅读 [quote_eventlog_summary.txt](quote_eventlog_summary.txt) 了解验证原理
3. 运行 [gcp-vtpm-attest-minimal.sh](gcp-vtpm-attest-minimal.sh) 体验实际attestation

### 进阶
1. ⭐ 阅读 [GCP_PCR_ANALYSIS.md](GCP_PCR_ANALYSIS.md) 了解 PCR 和系统镜像验证
2. 阅读 [TPM_QUOTE_STRUCTURE.md](TPM_QUOTE_STRUCTURE.md) 深入了解Quote结构
3. 阅读 [QUOTE_EVENTLOG_VERIFICATION.md](QUOTE_EVENTLOG_VERIFICATION.md) 理解安全性
4. 阅读 [CERTIFICATE-PURPOSE-VALIDATION.md](CERTIFICATE-PURPOSE-VALIDATION.md) 了解证书验证

### 开发者
1. ⭐ 使用 [calculate_pcr.py](calculate_pcr.py) 计算和验证 PCR 值
2. 研究验证脚本的实现
3. 参考Python/Bash代码示例
4. 根据需求定制验证逻辑
5. 在构建系统中集成 PCR 预计算

## 🔑 关键概念

### TPM Quote
- **定义**: TPM对PCR值的加密签名快照
- **内容**: PCR Digest + Nonce + 时钟信息 + 签名
- **用途**: 证明平台状态，防止重放攻击

### Event Log
- **定义**: 启动时所有测量事件的详细记录
- **内容**: 每个组件的哈希值和扩展操作
- **用途**: 提供OS镜像等详细信息

### PCR (Platform Configuration Register)
- **定义**: TPM内部的测量寄存器
- **特性**: 只能extend（单向操作），不能直接写入
- **用途**: 记录平台启动状态

### PCR Digest
- **定义**: 所有选中PCR值的组合哈希
- **计算**: SHA256(PCR[0] || PCR[1] || ... || PCR[n])
- **作用**: 连接Quote和Event Log的"桥梁"

### 验证原理
```
Quote (TPM签名，不可伪造)
  ↓
PCR Digest (Quote中包含)
  ↓
重放Event Log → 计算PCR值 → 计算Digest
  ↓
对比 → 相等则Event Log可信
```

## 🔒 安全要点

### 必须验证
1. ✅ Quote签名（用AK公钥）
2. ✅ Nonce匹配（防重放）
3. ✅ Magic值 (0xFF544347)
4. ✅ PCR Digest匹配
5. ✅ EK证书链（用Root CA）

### 不要做
1. ✗ 跳过nonce验证
2. ✗ 只检查证书issuer文本（可伪造）
3. ✗ 不验证Event Log
4. ✗ 信任clockInfo作为UTC时间

## 📝 常用命令

```bash
# 生成Quote
tpm2_quote -c ak.ctx -l sha256:0-7 -q $NONCE -m quote.msg -s quote.sig

# 验证Quote签名
tpm2_checkquote -u ak.pub -m quote.msg -s quote.sig -q $NONCE

# 解析Quote
tpm2_print -t TPMS_ATTEST quote.msg

# 读取PCR值
tpm2_pcrread sha256:0-7

# 读取Event Log
cat /sys/kernel/security/tpm0/binary_bios_measurements

# 解析Event Log
tpm2_eventlog binary_bios_measurements

# 验证证书链
openssl verify -CAfile root_ca.pem intermediate_ca.pem
```

## 🔗 相关资源

### TPM 2.0 规范
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [TCG PC Client Platform TPM Profile](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)

### 工具
- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) - TPM 2.0命令行工具
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) - TPM 2.0 Software Stack

### GCP文档
- [Google Cloud vTPM](https://cloud.google.com/compute/shielded-vm/docs/shielded-vm)
- [Confidential VM with vTPM](https://cloud.google.com/confidential-computing/confidential-vm/docs)

## 📂 文件列表

### 文档 (Markdown)
- ⭐ GCP_PCR_ANALYSIS.md (PCR 分析和预计算)
- ⭐ PCR_RESEARCH_SUMMARY.md (PCR 研究总结 - 快速参考)
- ⭐ PCR_POLICY_RECOMMENDATIONS.md (PCR 策略实施指南)
- ⭐ GCP_FIRMWARE_MRTD_REFERENCE.md (GCP 固件参考测量值)
- CERTIFICATE-PURPOSE-VALIDATION.md
- CA-TRUST-MODEL-COMPARISON.md
- TPM_QUOTE_STRUCTURE.md
- QUOTE_EVENTLOG_VERIFICATION.md
- README.md (本文件)

### 参考文本
- TPM_QUOTE_QUICK_REF.txt
- quote_eventlog_summary.txt
- tpm_quote_trust_chain.txt
- intermediate_ca_full.txt
- root_ca_full.txt

### 脚本 (可执行)
- ⭐ calculate_pcr.py (NEW - PCR 计算工具)
- analyze_tpm_quote.sh
- verify_quote_eventlog.sh
- gcp-vtpm-attest-minimal.sh ⭐ 推荐
- gcp-vtpm-attest-secure.sh
- ca_purpose_check.sh
- compare-ccel-tpm.sh

### 证书文件
- gce_tpm_root_ca.pem (2.1KB)
- gce_tpm_intermediate_ca.pem (2.5KB)
- gcp_vtpm_ca_bundle.pem (4.6KB)

## 🆘 故障排除

### 问题1: TPM设备不可用
```bash
# 检查TPM设备
ls -l /dev/tpm*

# 检查内核模块
lsmod | grep tpm
```

### 问题2: tpm2-tools未安装
```bash
# Ubuntu/Debian
sudo apt-get install tpm2-tools

# RHEL/CentOS
sudo yum install tpm2-tools
```

### 问题3: Quote验证失败
- 检查nonce是否匹配
- 检查AK公钥是否正确
- 检查PCR值是否被修改

### 问题4: 证书验证失败
- 检查Root CA是否正确
- 检查证书是否过期
- 检查证书用途（Extended Key Usage）

## 📧 反馈

如有问题或建议，请提交issue或PR。

---

*文档最后更新: 2025年*
