# 证书用途验证 - CA Purpose Validation

## 为什么需要验证证书用途？

### 问题场景

即使一个证书被可信的Root CA签名，如果不检查用途，可能会出现以下风险：

1. **CA被滥用**
   - Root CA可能签发多种用途的Intermediate CA
   - 如果不检查，可能接受非TPM用途的证书

2. **降低攻击面**
   - 限定CA只能用于特定目的（TPM EK）
   - 防止其他用途的证书被错误接受

3. **符合最小权限原则**
   - CA应该只被信任用于其声明的用途
   - 不应该给予超出必要的信任

## Google vTPM CA的用途限定

### Extended Key Usage分析

**Root CA和Intermediate CA都包含**：
```
X509v3 Extended Key Usage:
    2.23.133.8.1
```

**OID解析**：
```
2.23.133     = TCG (Trusted Computing Group)
  └─ .8      = TPM相关
     └─ .1   = tcg-kp-EKCertificate (EK Certificate Purpose)
```

**含义**：
- ✅ 该CA专门用于签发TPM的Endorsement Key (EK)证书
- ✅ 不能用于其他用途（如TLS服务器证书、代码签名等）
- ✅ 符合TCG规范要求

### 其他约束

```
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign

X509v3 Basic Constraints: critical
    CA:TRUE
```

- `Certificate Sign` - 可以签发证书
- `CRL Sign` - 可以签发吊销列表
- `CA:TRUE` - 这是CA证书
- `critical` - 这些约束是关键的，必须遵守

## 应该验证的内容

### 1. Intermediate CA的Extended Key Usage

**验证内容**：
```bash
# 检查Intermediate CA包含TPM EK用途
openssl x509 -in intermediate_ca.pem -noout -text | grep "2.23.133.8.1"
```

**预期结果**：
- ✅ 必须包含 `2.23.133.8.1` (tcg-kp-EKCertificate)
- ✗ 如果缺失或包含其他用途 → 拒绝

### 2. Intermediate CA的Subject CN

**验证内容**：
```bash
# 检查CN是否符合预期
openssl x509 -in intermediate_ca.pem -noout -subject
```

**预期结果**：
```
subject=C = US, ST = California, L = Mountain View, O = Google LLC,
        OU = Google Cloud, CN = EK/AK CA Intermediate
```

- ✅ CN应该是 "EK/AK CA Intermediate" 或类似的TPM相关名称
- ✗ 如果CN是其他用途（如"Web Server CA"） → 拒绝

### 3. Intermediate CA的Basic Constraints

**验证内容**：
```bash
# 确认是CA证书
openssl x509 -in intermediate_ca.pem -noout -text | grep -A 1 "Basic Constraints"
```

**预期结果**：
```
X509v3 Basic Constraints: critical
    CA:TRUE
```

- ✅ 必须是 `CA:TRUE`
- ✗ 如果是 `CA:FALSE` → 这不是CA证书，拒绝

### 4. Intermediate CA的Key Usage

**验证内容**：
```bash
openssl x509 -in intermediate_ca.pem -noout -text | grep -A 1 "Key Usage"
```

**预期结果**：
```
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
```

- ✅ 必须包含 `Certificate Sign`
- ✗ 如果包含 `Digital Signature, Key Encipherment` 等 → 可能是终端实体证书，拒绝

## 验证逻辑伪代码

```python
def validate_intermediate_ca(ca_cert, root_ca):
    # 1. 验证签名（已有）
    if not verify_signature(ca_cert, root_ca):
        return FAIL, "Signature verification failed"

    # 2. 检查是CA证书
    if not ca_cert.basic_constraints.ca:
        return FAIL, "Not a CA certificate"

    # 3. 检查Key Usage
    if "Certificate Sign" not in ca_cert.key_usage:
        return FAIL, "Cannot sign certificates"

    # 4. 检查Extended Key Usage (TPM EK专用)
    if "2.23.133.8.1" not in ca_cert.extended_key_usage:
        return FAIL, "Not authorized for TPM EK certificates"

    # 5. 检查Subject CN (可选但推荐)
    if "EK" not in ca_cert.subject.cn or "CA" not in ca_cert.subject.cn:
        return WARNING, "CN does not indicate TPM EK CA"

    # 6. 检查Issuer是否是提供的Root CA
    if ca_cert.issuer != root_ca.subject:
        return FAIL, "Issuer mismatch"

    return SUCCESS, "Valid TPM EK Intermediate CA"
```

## 实际风险案例

### 案例1：接受错误用途的CA

**场景**：
- Root CA签发了多个Intermediate CA：
  - Intermediate CA A: 用于TPM EK (2.23.133.8.1)
  - Intermediate CA B: 用于Web服务器 (serverAuth)
- 如果不检查Extended Key Usage，可能错误接受CA B

**风险**：
- 攻击者可能使用CA B签发假的EK证书
- 如果CA B被攻破，影响面更大

**防御**：
- 验证Extended Key Usage = 2.23.133.8.1
- 只接受专门用于TPM EK的CA

### 案例2：CA被替换

**场景**：
- MITM攻击者拦截Intermediate CA下载
- 替换为攻击者自己生成的CA（虽然无法通过Root CA验证）
- 但如果下载了另一个合法但用途不同的CA呢？

**防御**：
- 验证下载的CA的Extended Key Usage
- 验证CN包含"EK"或"TPM"等关键词

## 增强版验证建议

### 最小验证（必须）
```bash
# 1. 签名验证
openssl verify -CAfile root_ca.pem intermediate_ca.pem

# 2. Extended Key Usage验证
EKEYUSAGE=$(openssl x509 -in intermediate_ca.pem -noout -text | grep "2.23.133.8.1")
if [ -z "$EKEYUSAGE" ]; then
    echo "ERROR: CA not authorized for TPM EK certificates"
    exit 1
fi
```

### 推荐验证（完整）
```bash
# 1. 签名验证
openssl verify -CAfile root_ca.pem intermediate_ca.pem || exit 1

# 2. Basic Constraints
CA_TRUE=$(openssl x509 -in intermediate_ca.pem -noout -text | grep "CA:TRUE")
if [ -z "$CA_TRUE" ]; then
    echo "ERROR: Not a CA certificate"
    exit 1
fi

# 3. Key Usage
CERT_SIGN=$(openssl x509 -in intermediate_ca.pem -noout -text | grep "Certificate Sign")
if [ -z "$CERT_SIGN" ]; then
    echo "ERROR: Cannot sign certificates"
    exit 1
fi

# 4. Extended Key Usage (TPM EK)
EK_PURPOSE=$(openssl x509 -in intermediate_ca.pem -noout -text | grep "2.23.133.8.1")
if [ -z "$EK_PURPOSE" ]; then
    echo "ERROR: Not authorized for TPM EK certificates"
    exit 1
fi

# 5. Subject CN check (optional but recommended)
SUBJECT=$(openssl x509 -in intermediate_ca.pem -noout -subject)
if ! echo "$SUBJECT" | grep -q -E "(EK|TPM).*CA"; then
    echo "WARNING: Subject CN does not indicate TPM EK CA: $SUBJECT"
    # Don't exit, just warn
fi

echo "✓ Intermediate CA validation passed"
```

## Google vTPM CA的安全保证

### 当前配置分析

**Root CA**：
- Extended Key Usage: `2.23.133.8.1` (TPM EK专用)
- Key Usage: `Certificate Sign, CRL Sign`
- ✅ 专门用于TPM，范围受限

**Intermediate CA**：
- Extended Key Usage: `2.23.133.8.1` (TPM EK专用)
- Key Usage: `Certificate Sign, CRL Sign`
- Subject CN: "EK/AK CA Intermediate"
- ✅ 专门用于签发EK/AK证书

**安全保证**：
- 这个Root CA不会被用于签发TLS证书、代码签名证书等
- 即使Root CA被攻破，影响范围限定在TPM EK证书
- 符合最小权限原则

## 结论

### 回答原问题

**Q: 这个Root CA会签发哪些Intermediate CA？**

**A**: 只会签发用于TPM EK/AK证书的Intermediate CA，因为：
1. Root CA的Extended Key Usage限定为 `2.23.133.8.1`
2. 这是TCG标准定义的专用用途
3. Google可能会签发多个Intermediate CA（不同代、不同服务），但都是TPM EK用途

**Q: 是否需要检查Intermediate CA用途？**

**A**: 是的，建议检查：
1. ✅ **必须检查**：Extended Key Usage包含 `2.23.133.8.1`
2. ✅ **推荐检查**：Subject CN包含"EK"或"TPM"等关键词
3. ✅ **推荐检查**：Basic Constraints为 `CA:TRUE`
4. ✅ **推荐检查**：Key Usage包含 `Certificate Sign`

### 安全等级对比

| 验证级别 | 检查项 | 安全性 | 推荐度 |
|---------|-------|--------|--------|
| **基础** | 签名验证 | 中 | 最低要求 |
| **中级** | + Extended Key Usage | 高 | **推荐** ⭐ |
| **完整** | + CN + Constraints | 最高 | 生产环境 |

### 实施建议

1. **短期**：添加Extended Key Usage检查（最重要）
2. **长期**：实施完整验证逻辑
3. **监控**：记录所有CA验证结果，检测异常
