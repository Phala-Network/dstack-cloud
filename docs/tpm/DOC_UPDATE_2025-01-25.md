# 基于GCP VM实测的文档更新

## 测试结果总结

### ✓ 符合文档的部分
1. Magic值: 0xFF544347 ✓
2. Type: 0x8018 (TPM_ST_ATTEST_QUOTE) ✓  
3. quote.msg大小: 145 bytes (在118-200范围内) ✓
4. Quote签名验证: 通过 ✓
5. 所有字段结构: 与文档一致 ✓

### ⚠ 需要更新的部分

#### 1. quote.sig文件大小说明不够准确

**当前文档说法**:
- quote.sig: 256 bytes (RSA-2048) 或 384 bytes (RSA-3072)

**实际情况**:
- quote.sig: 262 bytes (RSA-2048) 或 390 bytes (RSA-3072)

**原因**:
tpm2_quote生成的不是纯签名，而是完整的TPMT_SIGNATURE结构：

```
TPMT_SIGNATURE结构 (262 bytes for RSA-2048):
  +0: sigAlg (2 bytes)       - 签名算法ID (0x0014 = TPM_ALG_RSASSA)
  +2: hash (2 bytes)         - 哈希算法ID (0x000B = TPM_ALG_SHA256)
  +4: sig_size (2 bytes)     - 签名大小 (0x0100 = 256 big-endian)
  +6: signature (256 bytes)  - 实际RSA签名数据
  ─────────────────────────
  Total: 262 bytes
```

**十六进制证据**:
```
00000000: 0014 000b 0100 1adb 2725 87b4 a6a5 e06b
          ^^^^ ^^^^ ^^^^
          sigAlg hash size(256)
```

#### 2. 文档结构示例图需要更新

**当前**:
```
quote.sig (256 bytes) - AK的RSA签名（对quote.msg的签名）
```

**应改为**:
```
quote.sig (262 bytes) - TPMT_SIGNATURE结构
  ├─ sigAlg: 2 bytes (签名算法)
  ├─ hash: 2 bytes (哈希算法)
  ├─ size: 2 bytes (签名大小)
  └─ signature: 256 bytes (实际RSA-2048签名)
```

#### 3. PCR Digest提取的grep命令需要优化

**问题**: 当前grep提取PCR Digest的命令有时会失败（返回空字符串）

**当前命令**:
```bash
QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST quote.msg | grep -A 2 "pcrDigest:" | grep "buffer:" | awk '{print $2}')
```

**问题**: 
- YAML输出中pcrDigest直接在冒号后，没有"buffer:"子字段
- 实际输出是: `pcrDigest: 96badccfa6d5db99...`

**改进后的命令**:
```bash
# 方法1: 直接提取pcrDigest行
QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST quote.msg | grep "pcrDigest:" | awk '{print $2}')

# 方法2: 使用sed
QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST quote.msg | sed -n 's/.*pcrDigest: \(.*\)/\1/p')
```

## 实际测试数据

### Quote.msg内容 (145 bytes)
```
00000000: ff54 4347 8018 0022 000b 507a ac10 14ab  .TCG..."..Pz....
00000010: f70b 6193 09fd 6a4a 935d 6b28 56eb 2dfd  ..a...jJ.]k(V.-.
00000020: 6f87 d705 3dbe a9a0 3122 0020 dead beef  o...=...1". ....
00000030: cafe babe 1234 5678 90ab cdef 1234 5678  .....4Vx.....4Vx
00000040: 90ab cdef dead beef cafe babe 0000 0000  ................
00000050: 05ea d340 0000 0010 0000 0000 0120 1605  ...@......... ..
00000060: 1100 1628 0000 0000 0100 0b03 ff00 0000  ...(............
00000070: 2096 badc cfa6 d5db 99d4 230a caf3 d932   .........#....2
00000080: 620a 637b c8ae 6e26 0408 aff1 f8c2 8d43  b.c{..n&.......C
00000090: b2                                       .
```

### Quote.sig内容 (262 bytes)
```
00000000: 0014 000b 0100 1adb 2725 87b4 a6a5 e06b  ........'%.....k
          ^^^^ ^^^^ ^^^^
          sigAlg hash size
00000010: bfa9 f4e6 8dc1 8d42 fd3b 8441 9e12 0932  .......B.;.A...2
... (256 bytes signature data)
```

### 解析后的YAML
```yaml
magic: ff544347
type: 8018
qualifiedSigner: 000b507aac1014abf70b619309fd6a4a935d6b2856eb2dfd6f87d7053dbea9a03122
extraData: deadbeefcafebabe1234567890abcdef1234567890abcdefdeadbeefcafebabe
clockInfo:
  clock: 99275584
  resetCount: 16
  restartCount: 0
  safe: 1
firmwareVersion: 0028160011051620
attested:
  quote:
    pcrSelect:
      count: 1
      pcrSelections:
        0:
          hash: 11 (sha256)
          sizeofSelect: 3
          pcrSelect: ff0000
    pcrDigest: 96badccfa6d5db99d4230acaf3d932620a637bc8ae6e260408aff1f8c28d43b2
```


## 已更新的文件

### 1. TPM_QUOTE_STRUCTURE.md
- ✓ 更新quote.msg大小范围: 100-200 bytes (原118-200 bytes)
- ✓ 更新quote.sig大小说明: 262 bytes with TPMT_SIGNATURE结构
- ✓ 添加nonce长度对quote.msg大小的影响说明
- ✓ 添加"附录：GCP vTPM实测数据"章节

### 2. TPM_QUOTE_QUICK_REF.txt
- ✓ 更新quote.msg大小: 100-200 bytes
- ✓ 更新quote.sig说明: 262 bytes TPMT_SIGNATURE结构
- ✓ 添加TPMT_SIGNATURE结构详细说明
- ✓ 添加nonce格式说明（必须是十六进制）

## 测试验证

所有更新都基于在GCP TDX Confidential VM (c3-standard-4) 上的实际测试：
- TPM 2.0 (vTPM)
- Ubuntu 24.04
- tpm2-tools
- 测试日期: 2025-01-25

## 下一步建议

可选的后续工作：
1. 更新相关脚本中的PCR Digest提取命令
2. 在README.md中添加"实测验证"章节的引用
3. 考虑添加更多不同环境的测试数据对比

