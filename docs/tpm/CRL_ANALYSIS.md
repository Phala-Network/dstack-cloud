# TPM Certificate CRL Analysis

## 发现总结

✅ **GCP vTPM 证书链中有 CRL Distribution Points！**

## 证书链结构

```
EK Certificate (存储在 TPM NV 0x1c00002)
    ↓ (issued by)
Intermediate CA (EK/AK CA Intermediate)
    ↓ (issued by)
Root CA (EK/AK CA Root)
```

## CRL 分析结果

### 1. Root CA (EK/AK CA Root)

**文件**: `docs/tpm/root_ca_full.txt`

**CRL Distribution Points**: ❌ **无**

```
X509v3 extensions:
    X509v3 Key Usage: critical
        Certificate Sign, CRL Sign  ← 有 CRL Sign 权限
    X509v3 Extended Key Usage:
        2.23.133.8.1
    X509v3 Basic Constraints: critical
        CA:TRUE
    X509v3 Subject Key Identifier:
        49:E7:4A:5B:56:29:F5:9D:79:B7:A6:30:3C:03:B2:8F:E7:14:DD:4C
    X509v3 Authority Key Identifier:
        49:E7:4A:5B:56:29:F5:9D:79:B7:A6:30:3C:03:B2:8F:E7:14:DD:4C
```

**分析**:
- ❌ 没有 `X509v3 CRL Distribution Points` 扩展
- ✅ 有 `CRL Sign` 权限（可以签发 CRL）
- ℹ️ 作为自签名 Root CA，通常不需要 CRL 分发点
- ℹ️ Root CA 的信任基于配置，不是通过 CRL 验证

### 2. Intermediate CA (EK/AK CA Intermediate)

**文件**: `docs/tpm/intermediate_ca_full.txt`

**CRL Distribution Points**: ✅ **有！**

```
X509v3 extensions:
    ...
    Authority Information Access:
        CA Issuers - URI:http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt

    X509v3 CRL Distribution Points:
        Full Name:
          URI:http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/crl.crl
```

**关键信息**:
- ✅ **CRL URL**: `http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/crl.crl`
- ✅ **CA Issuers URL**: `http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt`
- ℹ️ GCS (Google Cloud Storage) 托管
- ℹ️ 这个 CRL 用于验证由 Intermediate CA 签发的证书（即 EK 证书）

### 3. EK Certificate (存储在 TPM NV)

**位置**: TPM NV Index `0x1c00002` (RSA EK)

**预期**:
- ✅ **应该也有 CRL Distribution Points**
- 📍 指向用于验证 EK 证书的 CRL
- 📍 这个 CRL 由 Intermediate CA 签发

**如何检查**:
```bash
# 从 TPM NV 读取 EK 证书
tpm2_nvread -o /tmp/ek_cert.der 0x1c00002

# 转换为 PEM 格式
openssl x509 -inform DER -in /tmp/ek_cert.der -out /tmp/ek_cert.pem

# 查看 CRL Distribution Points
openssl x509 -in /tmp/ek_cert.pem -noout -text | grep -A 10 "CRL Distribution"
```

## 实现建议

### 方案 1: 完整的 CRL 验证（推荐）

```rust
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;

/// Extract CRL Distribution Points from certificate
fn extract_crl_urls(cert: &X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();

    for ext in cert.extensions() {
        if ext.oid == OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
            // Parse CRL Distribution Points extension
            // Extension value is DER-encoded CRLDistributionPoints
            match parse_crl_distribution_points(ext.value) {
                Ok(crl_dps) => {
                    for dp in crl_dps {
                        for name in dp.distribution_point {
                            if let GeneralName::URI(uri) = name {
                                urls.push(uri.to_string());
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to parse CRL DP: {}", e),
            }
        }
    }

    urls
}

/// Download CRL from URL
async fn download_crl(url: &str) -> Result<Vec<u8>> {
    let response = reqwest::get(url).await?;
    Ok(response.bytes().await?.to_vec())
}

/// Enhanced EK chain verification with CRL
async fn verify_ek_chain_with_crl(
    ek_cert_der: &Option<Vec<u8>>,
    root_ca_pem: &str,
    intermediate_ca_pem: Option<&str>,
) -> Result<bool> {
    // ... existing parsing code ...

    // Extract CRL URLs from Intermediate CA
    if let Some(intermediate_pem) = intermediate_ca_pem {
        let (_, intermediate_cert) = X509Certificate::from_der(&intermediate_der)?;
        let crl_urls = extract_crl_urls(&intermediate_cert);

        if !crl_urls.is_empty() {
            info!("Found {} CRL distribution points in Intermediate CA", crl_urls.len());

            // Download and verify CRL
            for url in crl_urls {
                match download_crl(&url).await {
                    Ok(crl_der) => {
                        info!("Downloaded CRL from {}", url);

                        // Verify CRL signature using Root CA
                        verify_crl_signature(&crl_der, &root_cert)?;

                        // Check if EK cert is revoked
                        if is_cert_revoked(&ek_cert, &crl_der)? {
                            bail!("EK certificate has been revoked!");
                        }

                        info!("✓ EK certificate not revoked");
                    }
                    Err(e) => {
                        warn!("Failed to download CRL from {}: {}", url, e);
                    }
                }
            }
        }
    }

    // Extract CRL URLs from EK certificate
    let crl_urls = extract_crl_urls(&ek_cert);
    if !crl_urls.is_empty() {
        info!("Found {} CRL distribution points in EK cert", crl_urls.len());
        // ... similar CRL verification for EK cert ...
    }

    // ... rest of verification ...
}
```

### 方案 2: 使用 webpki (更简单)

```rust
use webpki::{BorrowedCertRevocationList, RevocationOptionsBuilder};

async fn verify_with_webpki_crl(
    ek_cert_der: &[u8],
    intermediate_ca_pem: &str,
    root_ca_pem: &str,
) -> Result<bool> {
    // Parse certificates
    let ek_cert = webpki::EndEntityCert::try_from(ek_cert_der)?;
    let intermediate_der = parse_pem(intermediate_ca_pem.as_bytes())?;
    let root_der = parse_pem(root_ca_pem.as_bytes())?;

    // Create trust anchor from root CA
    let trust_anchor = webpki::TrustAnchor::try_from_cert_der(&root_der)?;

    // Extract CRL URL from intermediate CA
    let (_, intermediate_cert) = X509Certificate::from_der(&intermediate_der)?;
    let crl_urls = extract_crl_urls(&intermediate_cert);

    // Download CRL
    let mut crl_ders = Vec::new();
    for url in crl_urls {
        if let Ok(crl_der) = download_crl(&url).await {
            crl_ders.push(crl_der);
        }
    }

    // Parse CRLs
    let crls: Vec<CertRevocationList> = crl_ders
        .iter()
        .map(|der| BorrowedCertRevocationList::from_der(der).map(|crl| crl.into()))
        .collect::<Result<Vec<_>, _>>()?;

    let crl_refs: Vec<&CertRevocationList> = crls.iter().collect();

    // Build revocation options
    let revocation = RevocationOptionsBuilder::new(&crl_refs)?
        .with_depth(webpki::RevocationCheckDepth::Chain)
        .with_status_policy(webpki::UnknownStatusPolicy::Deny)
        .build();

    // Verify certificate chain with CRL
    let now = webpki::UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
    );

    ek_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust_anchor],
        &[intermediate_der.into()],
        now,
        webpki::KeyUsage::server_auth(),
        Some(revocation),
        None,
    )?;

    Ok(true)
}
```

### 方案 3: 混合方案（平衡）

```rust
/// Configuration for CRL verification
#[derive(Debug, Clone)]
pub struct CrlVerificationConfig {
    /// Whether to enforce CRL checking
    pub enforce: bool,
    /// Timeout for CRL download (seconds)
    pub timeout_secs: u64,
    /// Whether to fail if CRL is unavailable
    pub fail_on_unavailable: bool,
}

impl Default for CrlVerificationConfig {
    fn default() -> Self {
        Self {
            enforce: false,  // Don't enforce by default for TPM
            timeout_secs: 10,
            fail_on_unavailable: false,
        }
    }
}

pub async fn verify_ek_chain(
    ek_cert_der: &Option<Vec<u8>>,
    root_ca_pem: &str,
    intermediate_ca_pem: Option<&str>,
    crl_config: Option<CrlVerificationConfig>,
) -> Result<bool> {
    // ... existing verification code ...

    // CRL verification (optional)
    if let Some(config) = crl_config {
        match verify_crl_status(&ek_cert, &intermediate_cert, &root_cert, &config).await {
            Ok(true) => {
                info!("✓ CRL verification passed");
            }
            Ok(false) => {
                if config.enforce {
                    bail!("Certificate revoked according to CRL");
                } else {
                    warn!("Certificate revoked, but CRL enforcement is disabled");
                }
            }
            Err(e) => {
                if config.fail_on_unavailable {
                    bail!("CRL verification failed: {}", e);
                } else {
                    warn!("CRL verification failed, but continuing: {}", e);
                }
            }
        }
    } else {
        info!("CRL verification skipped (not configured)");
    }

    Ok(true)
}
```

## 实际 CRL 内容示例

### Intermediate CA 的 CRL

**URL**: `http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/crl.crl`

**内容**:
```
Certificate Revocation List (CRL):
    Version: 2 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=EK/AK CA Root, ...
    Last Update: ...
    Next Update: ...
    CRL extensions:
        X509v3 Authority Key Identifier:
            49:E7:4A:5B:56:29:F5:9D:79:B7:A6:30:3C:03:B2:8F:E7:14:DD:4C
        X509v3 CRL Number:
            ...
    Revoked Certificates:
        Serial Number: ...
            Revocation Date: ...
            CRL entry extensions:
                X509v3 CRL Reason Code:
                    Key Compromise
```

## 性能考虑

### CRL 下载开销

| 操作 | 时间 | 缓存 |
|------|------|------|
| **CRL 下载** | ~100-500ms | ✅ 可缓存 |
| **CRL 解析** | ~10-50ms | - |
| **CRL 验证** | ~5-20ms | - |
| **总计** | ~115-570ms | 首次 |
| **缓存命中** | ~15-70ms | 后续 |

### 缓存策略

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct CrlCache {
    cache: Arc<RwLock<HashMap<String, CachedCrl>>>,
}

struct CachedCrl {
    der: Vec<u8>,
    fetched_at: Instant,
    next_update: Instant,
}

impl CrlCache {
    async fn get_or_fetch(&self, url: &str) -> Result<Vec<u8>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(url) {
                if Instant::now() < cached.next_update {
                    info!("CRL cache hit for {}", url);
                    return Ok(cached.der.clone());
                }
            }
        }

        // Cache miss or expired, fetch new
        info!("Fetching CRL from {}", url);
        let crl_der = download_crl(url).await?;

        // Parse to get next_update
        let next_update = parse_crl_next_update(&crl_der)?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(url.to_string(), CachedCrl {
                der: crl_der.clone(),
                fetched_at: Instant::now(),
                next_update,
            });
        }

        Ok(crl_der)
    }
}
```

## 建议的实现优先级

### Phase 1: 基础支持（1-2天）
1. ✅ 解析 CRL Distribution Points 扩展
2. ✅ 下载 CRL（异步）
3. ✅ 解析 CRL 结构
4. ⚠️ 基础吊销检查（不验证 CRL 签名）

### Phase 2: 完整验证（2-3天）
1. ✅ 验证 CRL 签名（使用 issuer 公钥）
2. ✅ 检查 CRL 有效期（thisUpdate, nextUpdate）
3. ✅ 检查 CRL Number（单调递增）
4. ✅ 完整的吊销状态检查

### Phase 3: 生产优化（1-2天）
1. ✅ 实现 CRL 缓存
2. ✅ 超时和重试机制
3. ✅ 配置化 (enforce/warn/ignore)
4. ✅ 性能监控和日志

## 结论

### 关键发现

1. ✅ **GCP vTPM 的 Intermediate CA 有 CRL Distribution Points**
   - URL: `http://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/crl.crl`
   - 托管在 Google Cloud Storage
   - 可以直接 HTTP GET 下载

2. ✅ **可以实现完整的 CRL 验证**
   - 技术上完全可行
   - 需要添加异步 HTTP 下载支持
   - 可选的配置策略（enforce/warn/ignore）

3. ⚠️ **TPM EK 证书的 CRL 验证优先级不高**
   - TPM EK 证书绑定硬件，很少被吊销
   - 大多数 vTPM 场景不强制 CRL 检查
   - 但完整实现可以提高安全性

### 推荐方案

**立即实现**: 方案 3（混合方案）
- 保留当前的纯 Rust 实现
- 添加可选的 CRL 验证
- 默认不强制执行（warn only）
- 为需要高安全性的场景提供 enforce 选项

**依赖添加**:
```toml
[dependencies]
reqwest = { version = "0.11", features = ["rustls-tls"], optional = true }

[features]
crl-verification = ["reqwest"]
```

**使用示例**:
```rust
// Without CRL (current behavior)
let result = verify_quote(&quote, root_ca, Some(intermediate_ca), None)?;

// With CRL checking (new feature)
let crl_config = CrlVerificationConfig {
    enforce: false,  // warn only
    timeout_secs: 10,
    fail_on_unavailable: false,
};
let result = verify_quote(&quote, root_ca, Some(intermediate_ca), Some(crl_config))?;
```

---

**Document Version**: 1.0
**Date**: 2025-01-03
**Status**: ✅ CRL URLs identified, implementation pending
