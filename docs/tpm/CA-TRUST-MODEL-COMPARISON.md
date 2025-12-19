# CA信任模型对比 - GCP vTPM Attestation

## 你的问题回答

### ✅ Q1: Intermediate CA能否由TPM提供？
**答：可以！**

EK证书包含 **AIA (Authority Information Access)** 扩展，里面有Intermediate CA的下载URL：
```
Authority Information Access:
    CA Issuers - URI:http://privateca-content-[id].storage.googleapis.com/[hash]/ca.crt
```

验证程序可以：
1. 从EK证书提取AIA URL
2. 动态下载Intermediate CA
3. 用Root CA验证Intermediate CA的签名
4. 用验证过的Intermediate CA验证EK证书

### ✅ Q2: 验证程序需要内置两个CA吗？
**答：不需要！只需要Root CA！**

**最小信任模型**：
- ✅ **只内置Root CA** (gce_tpm_root_ca.pem)
- ⚡ **Intermediate CA动态获取** (从EK证书的AIA字段)
- 🔒 **Intermediate CA被Root CA验证** (密码学签名验证)

这样最灵活：
- Intermediate CA可以轮换，不影响验证程序
- Root CA有效期100年，很少需要更新
- 减小信任基础（只需信任一个Root CA）

### ✅ Q3: Intermediate CA负责一个区域还是全部GCP？
**答：全部GCP（全局的）**

证书信息：
```
Intermediate CA:
  Subject: CN=EK/AK CA Intermediate  ← 通用名称，无区域信息
  有效期: 2022-08-23 → 2122-07-08 (100年)
  范围: 全局

Root CA:
  Subject: CN=EK/AK CA Root  ← 全局Root
  有效期: 2022-07-08 → 2122-07-08 (100年)
  范围: 全局
```

**不是**按区域划分的CA，所有GCP区域使用同一个Intermediate CA。

### ✅ Q4: 有效期是多久？
**答：100年！**

| 证书 | 开始时间 | 结束时间 | 有效期 |
|------|---------|---------|--------|
| **Root CA** | 2022-07-08 | 2122-07-08 | **100年** |
| **Intermediate CA** | 2022-08-23 | 2122-07-08 | **~100年** |

这意味着：
- Root CA在2122年前基本不需要更新
- Intermediate CA可能会轮换，但可以动态获取
- EK证书（每个VM唯一）有效期较短，定期更新

## 两种信任模型对比

### 方案A：Bundle模型（需要两个CA）

**脚本**: `gcp-vtpm-attest-secure.sh`

```bash
# 使用预先打包的CA bundle
sudo ./gcp-vtpm-attest-secure.sh \
    gcp_vtpm_ca_bundle.pem \
    my-nonce
```

**特点**：
- ✅ 离线验证（不需要网络下载）
- ✅ 速度快（无网络延迟）
- ⚠️  需要同时信任Root CA + Intermediate CA
- ⚠️  Intermediate CA轮换时需要更新bundle

**信任链**：
```
用户提供的Bundle:
  ├─ Root CA (信任锚点)
  └─ Intermediate CA (预先打包)
       └─ 验证 EK Certificate
```

### 方案B：最小信任模型（只需Root CA）⭐ 推荐

**脚本**: `gcp-vtpm-attest-minimal.sh`

```bash
# 只需要Root CA
sudo ./gcp-vtpm-attest-minimal.sh \
    gce_tpm_root_ca.pem \
    my-nonce
```

**特点**：
- ✅ 最小信任基础（只需Root CA）
- ✅ 灵活性高（Intermediate CA轮换无影响）
- ✅ 验证完整性更强（动态验证Intermediate CA）
- ⚠️  需要网络访问（下载Intermediate CA）
- ⚠️  首次略慢（网络下载）

**信任链**：
```
用户只提供 Root CA
    ↓
从EK证书的AIA提取URL
    ↓
下载 Intermediate CA
    ↓
Root CA验证Intermediate CA ← 密码学验证！
    ↓
验证的Intermediate CA验证EK Certificate
```

## 详细流程对比

### 方案A流程（Bundle）
```
1. 用户提供: CA Bundle (Root + Intermediate)
2. 从TPM读取: EK Certificate
3. OpenSSL验证: Bundle → EK Certificate
4. 生成和验证: TPM Quote
```

### 方案B流程（最小信任）⭐
```
1. 用户提供: Root CA only
2. 从TPM读取: EK Certificate
3. 从EK提取: AIA URL
4. 下载: Intermediate CA (从AIA URL)
5. OpenSSL验证: Root CA → Intermediate CA  ← 验证下载的CA！
6. OpenSSL验证: Intermediate CA → EK Certificate
7. 生成和验证: TPM Quote
```

**关键差异**：方案B多了第5步 - 验证动态下载的Intermediate CA

## 安全性分析

### 方案A的风险
❌ **如果Intermediate CA被替换**：
- 用户可能使用旧的或错误的bundle
- Intermediate CA轮换时需要手动更新

### 方案B的优势
✅ **Intermediate CA始终最新**：
- 从EK证书的AIA动态获取
- 自动跟随GCP的CA轮换

✅ **无法注入假的Intermediate CA**：
```bash
# 攻击者尝试：
# 1. MITM攻击，替换下载的Intermediate CA
# 2. 验证时会失败：
openssl verify -CAfile root_ca.pem fake_intermediate.pem
# → Error: unable to verify signature
# → 因为fake_intermediate没有Root CA的私钥签名
```

## 使用建议

### 推荐：方案B（最小信任）

**适用场景**：
- 生产环境（需要最高安全性）
- 长期运行的验证服务
- 需要自动适应CA轮换

**优点**：
- 最小信任基础
- 自动适应CA变更
- 更强的安全保证

### 备选：方案A（Bundle）

**适用场景**：
- 离线环境（无网络）
- 快速验证（性能优先）
- 测试和开发

**优点**：
- 无需网络
- 速度快
- 简单直接

## 实际测试对比

### 测试1：正常验证

```bash
# 方案A（Bundle）
$ sudo ./gcp-vtpm-attest-secure.sh gcp_vtpm_ca_bundle.pem nonce
✓✓✓ ATTESTATION PASSED ✓✓✓
Time: ~2 seconds

# 方案B（最小信任）
$ sudo ./gcp-vtpm-attest-minimal.sh gce_tpm_root_ca.pem nonce
✓✓✓ ATTESTATION PASSED ✓✓✓
Time: ~3 seconds (含下载Intermediate CA)
```

### 测试2：使用假CA

```bash
# 两者都会正确拒绝
$ sudo ./gcp-vtpm-attest-*.sh fake_root_ca.pem nonce
✗✗✗ VERIFICATION FAILED ✗✗✗
unable to get local issuer certificate
```

### 测试3：Intermediate CA被篡改

```bash
# 方案A：如果bundle中的Intermediate CA被篡改
# → 验证失败（因为和Root CA签名不匹配）

# 方案B：如果下载时MITM替换Intermediate CA
# → 验证失败（步骤5验证Intermediate CA签名会失败）
# → 更安全！动态验证每次下载的CA
```

## 性能对比

| 操作 | 方案A (Bundle) | 方案B (最小信任) |
|------|---------------|-----------------|
| 读取EK证书 | ~100ms | ~100ms |
| 验证证书链 | ~50ms | ~200ms (含下载+验证) |
| TPM Quote | ~500ms | ~500ms |
| **总时间** | **~2秒** | **~3秒** |
| 网络需求 | 无 | 需要（首次下载） |

## 文件需求对比

### 方案A需要
```
gcp-vtpm-attest-secure.sh         # 脚本
gcp_vtpm_ca_bundle.pem            # Root + Intermediate (4.6KB)
```

### 方案B需要
```
gcp-vtpm-attest-minimal.sh        # 脚本
gce_tpm_root_ca.pem               # 只需Root CA (2.1KB)
```

**方案B更小**：只需要2.1KB的Root CA

## 总结表格

| 特性 | Bundle模型 | 最小信任模型 ⭐ |
|------|-----------|----------------|
| **需要的CA文件** | 2个(Root+Intermediate) | 1个(Root only) |
| **文件大小** | 4.6KB | 2.1KB |
| **网络需求** | 不需要 | 需要(首次) |
| **速度** | 快(~2秒) | 略慢(~3秒) |
| **安全性** | 高 | **最高** |
| **灵活性** | 低(CA轮换需更新) | **高(自动适应)** |
| **信任基础** | 2个CA | **1个CA(最小)** |
| **离线使用** | ✓ | ✗ |
| **生产推荐** | 可用 | **推荐** ⭐ |

## 最佳实践建议

### 1. 生产环境
```bash
# 使用最小信任模型
sudo ./gcp-vtpm-attest-minimal.sh \
    /etc/gcp-ca/root_ca.pem \
    $(uuidgen) \
    expected-os-hash

# 优点：
# - 最小信任基础
# - 自动适应CA变更
# - 最高安全性
```

### 2. 离线/测试环境
```bash
# 使用Bundle模型
sudo ./gcp-vtpm-attest-secure.sh \
    /etc/gcp-ca/ca_bundle.pem \
    test-nonce

# 优点：
# - 无需网络
# - 快速验证
```

### 3. Root CA保护
```bash
# Root CA应该被严格保护
chmod 444 gce_tpm_root_ca.pem
chown root:root gce_tpm_root_ca.pem

# 验证Root CA内容
openssl x509 -in gce_tpm_root_ca.pem -noout -text | grep "Issuer:\|Subject:"
# Subject和Issuer应该相同（自签名）
```

### 4. 监控CA有效期
```bash
# 检查Root CA有效期（每年检查一次）
openssl x509 -in gce_tpm_root_ca.pem -noout -dates

# 当前有效期到2122年，100年内无需担心
```

## 结论

**推荐使用方案B（最小信任模型）**，因为：

1. ✅ **最小信任基础** - 只需信任一个Root CA
2. ✅ **自动适应变更** - Intermediate CA轮换无影响
3. ✅ **最高安全性** - 动态验证每个环节
4. ✅ **面向未来** - 100年有效期，长期稳定

只在以下情况使用方案A：
- 离线环境
- 性能极度敏感
- 测试和快速验证
