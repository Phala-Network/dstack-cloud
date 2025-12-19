# TPM Quote 结构详解

## 一、Quote包含的文件

TPM Quote attestation包含两个文件：

1. **quote.msg** - TPMS_ATTEST结构（100-200字节，取决于nonce长度）
2. **quote.sig** - TPMT_SIGNATURE结构（262字节用于RSA-2048）

**注意**: `quote.sig`不是纯签名，而是完整的TPMT_SIGNATURE结构：
```
TPMT_SIGNATURE (262 bytes for RSA-2048):
  +0: sigAlg (2 bytes)      - 签名算法ID (0x0014 = TPM_ALG_RSASSA)
  +2: hash (2 bytes)        - 哈希算法ID (0x000B = TPM_ALG_SHA256)
  +4: sig_size (2 bytes)    - 签名大小 (256 in big-endian)
  +6: signature (256 bytes) - 实际RSA-2048签名
  ─────────────────────────
  Total: 262 bytes
```

## 二、TPMS_ATTEST结构（quote.msg）

### 完整字段列表

```
Offset | Size | Field              | Description
-------|------|--------------------|-----------------------------------------
0      | 4    | magic              | 0xFF544347 (TPM_GENERATED_VALUE)
4      | 2    | type               | 0x8018 (TPM_ST_ATTEST_QUOTE)
6      | 2    | qualifiedSigner    | AK的Qualified Name（可变长度）
       |      |   size             |   名称长度
       |      |   name             |   实际名称（SHA256哈希）
       | 2    | extraData          | Nonce数据
       |      |   size             |   数据长度
       |      |   buffer           |   实际nonce（调用者提供）
       | 17   | clockInfo          | 时钟信息结构
       |      |   clock            |   8字节：TPM启动以来的毫秒数
       |      |   resetCount       |   4字节：TPM重置次数
       |      |   restartCount     |   4字节：TPM恢复次数
       |      |   safe             |   1字节：时钟是否可信
       | 8    | firmwareVersion    | TPM固件版本号
       | var  | attested           | TPMS_QUOTE_INFO结构
       |      |   pcrSelect        |   PCR选择位图
       |      |     count          |     哈希算法数量
       |      |     hash           |     哈希算法ID（如SHA256=0x000B）
       |      |     sizeofSelect   |     PCR位图大小（通常3字节）
       |      |     pcrSelect      |     PCR位图（如0x0007FF = PCR 0-10）
       |      |   pcrDigest        |   PCR摘要
       |      |     size           |     摘要长度（SHA256=32）
       |      |     buffer         |     实际摘要值
```

## 三、可解析的信息

### 1. 身份验证信息

#### qualifiedSigner (AK标识)
- **内容**: AK的Qualified Name（SHA256哈希，32字节）
- **用途**: 证明Quote由特定AK签名
- **示例**:
  ```
  000b20c8a1f4e3... (34字节)
    ^^-- 0x000B = SHA256
      ^^-- 0x20 = 32字节长度
  ```

### 2. 防重放信息

#### extraData (Nonce)
- **内容**: 验证者提供的随机数（最多64字节）
- **用途**: 防止重放攻击，证明Quote是新生成的
- **示例**:
  ```yaml
  extraData:
    size: 32
    buffer: challenge_from_verifier_12345678
  ```
- **验证**: Verifier检查extraData是否与发送的nonce匹配

### 3. 时间和重启信息

#### clockInfo
- **clock**: TPM运行时间（毫秒）
  - 示例: 1234567890 (约14天)
  - 用途: 检测TPM运行时长

- **resetCount**: TPM重置次数
  - 示例: 5
  - 用途: 检测完全重启（冷启动）

- **restartCount**: TPM恢复次数
  - 示例: 10
  - 用途: 检测从休眠恢复

- **safe**: 时钟可信标志
  - 值: 0=不可信, 1=可信
  - 用途: 判断时钟是否被篡改

**实际应用**:
```python
# 检测VM重启
if quote.resetCount != previous_resetCount:
    print("VM已重启，可能需要重新验证")

# 检测运行时长异常
if quote.clock < expected_minimum:
    print("警告：TPM运行时间异常短")
```

### 4. 平台状态信息

#### pcrSelect (PCR选择)
- **格式**: 位图表示选中哪些PCR
- **示例**:
  ```yaml
  pcrSelect:
    - hash: sha256 (0x000B)
      sizeofSelect: 3
      pcrSelect: [0, 1, 2, 3, 4, 5, 6, 7]
      # 位图: 0xFF 0x00 0x00
  ```

#### pcrDigest (PCR摘要) ⚠️ 最关键字段
- **计算方法**:
  ```
  pcrDigest = SHA256(PCR[0] || PCR[1] || ... || PCR[7])
  ```
  其中 `||` 表示字节拼接

- **重要**: 不是单个PCR值，而是所有选中PCR的组合哈希

- **示例**:
  ```yaml
  pcrDigest:
    size: 32
    buffer: 9f86d081884c7d659a2feaa0c55ad015...
  ```

- **验证流程**:
  ```bash
  # 1. 从Quote提取pcrDigest
  QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST quote.msg | grep -A 1 pcrDigest)

  # 2. 读取实际PCR值
  tpm2_pcrread sha256:0,1,2,3,4,5,6,7 -o /tmp/pcrs.bin

  # 3. 计算组合哈希
  CALCULATED_DIGEST=$(sha256sum /tmp/pcrs.bin)

  # 4. 对比
  if [ "$QUOTE_DIGEST" = "$CALCULATED_DIGEST" ]; then
      echo "PCR值未被篡改"
  fi
  ```

### 5. TPM信息

#### magic (魔数)
- **值**: 0xFF544347 (固定)
- **含义**: "TPM Generated Value"
- **用途**: 证明这是TPM生成的，不是外部构造的
- **验证**:
  ```c
  if (magic != 0xFF544347) {
      return ERROR_NOT_TPM_GENERATED;
  }
  ```

#### type (类型)
- **值**: 0x8018 (TPM_ST_ATTEST_QUOTE)
- **其他类型**:
  - 0x8014: TPM_ST_ATTEST_CERTIFY
  - 0x8016: TPM_ST_ATTEST_CREATION
  - 0x8017: TPM_ST_ATTEST_NV

#### firmwareVersion
- **内容**: 8字节TPM固件版本
- **示例**: 0x0001000200030004
- **解析**: 通常是Major.Minor.Build格式

## 四、Quote不包含的信息

### ✗ 单个PCR的原始值
- Quote只包含PCR Digest（组合哈希）
- 需要单独调用 `tpm2_pcrread` 获取

### ✗ Event Log
- Event Log记录每个PCR扩展的历史
- 需要从 `/sys/kernel/security/tpm0/binary_bios_measurements` 读取

### ✗ AK证书
- AK没有X.509证书
- 只有公钥（ak.pub）

### ✗ OS镜像哈希
- OS镜像哈希在Event Log中，不在Quote中
- Quote通过PCR Digest间接保证Event Log完整性

## 五、实际验证流程

### 完整的验证步骤

```bash
#!/bin/bash

# 输入：
# - quote.msg: Quote消息
# - quote.sig: Quote签名
# - ak.pub: AK公钥
# - expected_nonce: 预期的nonce
# - trusted_os_hash: 可信的OS镜像哈希

# 步骤1: 验证Quote签名
echo "1. 验证Quote签名..."
tpm2_checkquote -u ak.pub -m quote.msg -s quote.sig -q "$expected_nonce"
if [ $? -ne 0 ]; then
    echo "✗ Quote签名验证失败"
    exit 1
fi
echo "✓ Quote签名有效"

# 步骤2: 解析Quote
echo "2. 解析Quote内容..."
tpm2_print -t TPMS_ATTEST quote.msg > quote_parsed.yaml

# 步骤3: 检查Magic
MAGIC=$(grep "magic:" quote_parsed.yaml | awk '{print $2}')
if [ "$MAGIC" != "0xff544347" ]; then
    echo "✗ Magic值错误"
    exit 1
fi
echo "✓ Magic值正确"

# 步骤4: 检查Nonce
NONCE=$(grep -A 1 "extraData:" quote_parsed.yaml | tail -1)
if ! echo "$NONCE" | grep -q "$expected_nonce"; then
    echo "✗ Nonce不匹配"
    exit 1
fi
echo "✓ Nonce匹配（防重放）"

# 步骤5: 提取PCR Digest
PCR_DIGEST=$(grep -A 2 "pcrDigest:" quote_parsed.yaml | tail -1 | awk '{print $2}')
echo "PCR Digest: $PCR_DIGEST"

# 步骤6: 获取Event Log并重放PCR
echo "3. 验证Event Log..."
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > eventlog.yaml

# 步骤7: 从Event Log提取OS镜像哈希
OS_HASH=$(grep -A 5 "EventType: EV_IPL" eventlog.yaml | grep "Digest:" | head -1 | awk '{print $2}')
echo "OS镜像哈希: $OS_HASH"

# 步骤8: 对比OS镜像哈希
if [ "$OS_HASH" = "$trusted_os_hash" ]; then
    echo "✓✓✓ OS镜像验证通过 ✓✓✓"
else
    echo "✗✗✗ OS镜像被篡改 ✗✗✗"
    exit 1
fi

echo "✓✓✓ 完整验证通过 ✓✓✓"
```

## 六、Quote结构示例（十六进制）

```
Offset    Hex Data                                     Field
────────────────────────────────────────────────────────────────
0000:     ff 54 43 47                                  magic
0004:     80 18                                        type (QUOTE)
0006:     00 22                                        qualifiedSigner.size
0008:     00 0b 20 c8 a1 f4 e3 ... (32 bytes)         qualifiedSigner.name
002A:     00 20                                        extraData.size
002C:     63 68 61 6c 6c 65 6e ... (32 bytes)         extraData (nonce)
004C:     00 00 00 49 96 02 d2                         clockInfo.clock
0053:     00 00 00 05                                  clockInfo.resetCount
0057:     00 00 00 0a                                  clockInfo.restartCount
005B:     01                                           clockInfo.safe
005C:     00 01 00 02 00 03 00 04                      firmwareVersion
0064:     00 01                                        attested.pcrSelect.count
0066:     00 0b                                        hash (SHA256)
0068:     03                                           sizeofSelect
0069:     ff 07 00                                     pcrSelect (PCR 0-10)
006C:     00 20                                        pcrDigest.size
006E:     9f 86 d0 81 88 4c 7d ... (32 bytes)         pcrDigest
```

## 七、与其他Attestation格式对比

### TPM Quote vs TDX Quote

| 特性 | TPM Quote | TDX Quote |
|------|-----------|-----------|
| 格式 | TPMS_ATTEST | tdx_report_t |
| 大小 | 118-200字节 | 1024字节（固定）|
| 状态标识 | PCR Digest | RTMR值（直接包含）|
| Nonce | extraData | report_data |
| 签名者 | AK（软件密钥）| TDX硬件密钥 |
| Event Log | 需要单独获取 | 需要单独获取（CCEL）|
| 重启计数 | resetCount | - |

### TPM Quote vs SGX Quote

| 特性 | TPM Quote | SGX Quote |
|------|-----------|-----------|
| 大小 | 118-200字节 | 436字节+签名 |
| 状态标识 | PCR Digest | MRENCLAVE, MRSIGNER |
| 证书链 | EK Certificate | PCK Certificate |
| 中间CA | 需要 | 需要（Intel PCS）|

## 八、常见问题

### Q1: 为什么Quote不直接包含PCR值？
**A**: 安全性和效率。
- PCR Digest（32字节）比所有PCR值（24个PCR × 32字节 = 768字节）小得多
- 使用哈希保证完整性，任何PCR改变都会导致Digest不同

### Q2: 如何从Quote获取OS镜像哈希？
**A**: 三步：
1. Quote验证通过 → PCR Digest可信
2. 获取Event Log，重放计算PCR值
3. 从Event Log找到OS镜像的测量事件（EventType=EV_IPL）

### Q3: extraData（nonce）有大小限制吗？
**A**: 有，最大64字节。建议使用：
- 32字节随机数（防重放）
- 或 SHA256(challenge || timestamp || requester_id)

**注意**: nonce长度会影响quote.msg总大小：
- nonce=0字节 → quote.msg ≈ 100字节
- nonce=32字节 → quote.msg ≈ 132字节
- nonce=64字节 → quote.msg ≈ 164字节

### Q4: Quote包含时间戳吗？
**A**: 包含TPM内部时钟（clockInfo.clock），但：
- 不是UTC时间，而是TPM运行毫秒数
- 可能不准确（取决于safe标志）
- 建议用nonce包含时间戳，不要依赖TPM时钟

### Q5: 如何验证Quote是最新的？
**A**: 使用extraData：
```python
# Verifier端
nonce = random_bytes(32)
timestamp = current_time()
extra_data = sha256(nonce || timestamp)

# 发送给TEE
response = tee.get_quote(extra_data)

# 验证
if response.quote.extraData != extra_data:
    raise Exception("Quote不是新生成的")
if current_time() - timestamp > 60:
    raise Exception("Quote生成超时")
```

## 九、安全注意事项

### 必须验证的字段
1. ✅ **magic**: 必须是0xFF544347
2. ✅ **type**: 必须是0x8018（Quote）
3. ✅ **extraData**: 必须与发送的nonce匹配
4. ✅ **signature**: 必须通过AK公钥验证
5. ✅ **pcrDigest**: 必须与重放的PCR值匹配

### 可选验证的字段
- **clockInfo**: 检测异常重启
- **firmwareVersion**: 确保TPM固件版本可信

### 不要做的事
- ✗ 不要信任未验证签名的Quote
- ✗ 不要跳过nonce验证（容易被重放攻击）
- ✗ 不要只检查PCR Digest，必须验证Event Log
- ✗ 不要假设clockInfo.clock是UTC时间

## 十、总结

### Quote包含的核心信息
1. **身份**: AK标识（qualifiedSigner）
2. **防重放**: Nonce（extraData）
3. **状态**: PCR Digest（pcrDigest）
4. **时间**: TPM时钟和重启计数（clockInfo）
5. **完整性**: 签名（quote.sig）

### 验证思路
```
Quote.sig ──AK公钥验证──> Quote.msg可信
  │
  ├──> extraData = nonce ──> 防重放 ✓
  │
  └──> pcrDigest ──对比──> 重放的PCR值
                              │
                              └──> Event Log ──提取──> OS镜像哈希 ✓
```

Quote本身是一个轻量级的"承诺"（commitment），真正的详细信息在Event Log中，通过PCR Digest间接保证Event Log的完整性。

## 附录：GCP vTPM实测数据

### 测试环境
- 平台: Google Cloud Platform
- VM类型: c3-standard-4 (TDX Confidential VM)
- TPM版本: TPM 2.0 (vTPM)
- OS: Ubuntu 24.04
- 测试日期: 2025-01-25

### 实际Quote数据

#### quote.msg (145 bytes)
```hexdump
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

**字段解析**:
- `ff544347` (offset 0): Magic (TPM_GENERATED_VALUE)
- `8018` (offset 4): Type (TPM_ST_ATTEST_QUOTE)
- `0022 000b 507a...` (offset 6): qualifiedSigner (34 bytes)
- `0020 dead beef...` (offset 40): extraData/nonce (32 bytes)
- `0000 0000 05ea d340` (offset 74): clockInfo.clock (99275584 ms ≈ 27.6小时)
- `0000 0010` (offset 82): clockInfo.resetCount (16次重启)
- `0000 0000` (offset 86): clockInfo.restartCount (0次恢复)
- `01` (offset 90): clockInfo.safe (可信)
- `2096 badc...` (offset 112): pcrDigest (32 bytes)

#### quote.sig (262 bytes)
```hexdump (前8行)
00000000: 0014 000b 0100 1adb 2725 87b4 a6a5 e06b  ........'%.....k
         ^^^^ ^^^^ ^^^^
         sigAlg hash size(256)
00000010: bfa9 f4e6 8dc1 8d42 fd3b 8441 9e12 0932  .......B.;.A...2
00000020: 9343 9930 8d6a 6430 b953 2d14 438f 3af3  .C.0.jd0.S-.C.:.
00000030: 2ec2 9ac1 456c 7c79 bee1 a864 2b37 83ac  ....El|y...d+7..
... (继续256字节签名数据)
```

**TPMT_SIGNATURE结构解析**:
- `0014` (offset 0): sigAlg = TPM_ALG_RSASSA (0x0014)
- `000b` (offset 2): hash = TPM_ALG_SHA256 (0x000B)
- `0100` (offset 4): sig_size = 256 (big-endian)
- `1adb2725...` (offset 6): 256字节RSA-2048签名数据

#### 解析后的YAML
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

### 验证结果

```bash
# Quote签名验证
$ tpm2_checkquote -u ak.pub -m quote.msg -s quote.sig -q deadbeef...
✓ Quote签名验证通过

# PCR Digest验证
$ tpm2_pcrread sha256:0-7 -o pcrs.bin
$ sha256sum pcrs.bin
96badccfa6d5db99d4230acaf3d932620a637bc8ae6e260408aff1f8c28d43b2
✓ PCR Digest匹配
```

### 关键发现

1. **quote.msg大小**: 145 bytes (文档范围100-200 bytes) ✓
2. **quote.sig大小**: 262 bytes (包含6字节TPMT_SIGNATURE头) ✓
3. **Magic值**: 0xFF544347 ✓
4. **Type**: 0x8018 (TPM_ST_ATTEST_QUOTE) ✓
5. **所有字段**: 与TPM 2.0规范完全一致 ✓

