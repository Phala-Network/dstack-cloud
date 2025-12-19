#!/bin/bash

echo "=== TPM Quote结构分析 ==="
echo

# TPM Quote是一个TPM2_ATTEST结构，包含以下字段

cat << 'STRUCTURE'
TPM2_ATTEST结构（quote.msg）:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Magic (4 bytes)
   值: 0xFF544347 ("TPM_GENERATED_VALUE")
   用途: 证明这是TPM生成的，不是外部构造的

2. Type (2 bytes)
   值: TPM_ST_ATTEST_QUOTE (0x8018)
   用途: 标识这是Quote类型的attestation

3. Qualified Signer (variable)
   内容: AK的Qualified Name
   用途: 标识是哪个密钥签名的

4. Extra Data (variable)
   内容: Caller提供的nonce（最多64字节）
   用途: 防重放攻击，证明Quote是freshly生成的

5. Clock Info (结构体)
   - Clock: TPM内部时钟（毫秒）
   - ResetCount: TPM重启次数
   - RestartCount: TPM恢复次数
   - Safe: TPM时钟是否可信

6. Firmware Version (8 bytes)
   内容: TPM固件版本号

7. PCR Selection (结构体)
   内容: 包含哪些PCR的列表
   示例: PCR 0,1,2,3,4,5,6,7

8. PCR Digest (32 bytes for SHA256)
   内容: 所有选中PCR值的哈希
   计算: SHA256(PCR[0] || PCR[1] || ... || PCR[7])
   ⚠️ 注意: 不是单个PCR值！

STRUCTURE

echo
echo "=== 实际解析示例 ==="
echo

# 检查是否在GCP VM上
if [ -c /dev/tpm0 ]; then
    echo "✓ 检测到TPM设备，生成示例Quote..."
    echo
    
    # 清理旧文件
    rm -f /tmp/ak.ctx /tmp/ak.pub /tmp/ak.name /tmp/quote.msg /tmp/quote.sig /tmp/ek.ctx 2>/dev/null
    
    # 1. 创建EK
    echo "[1/4] 创建Endorsement Key..."
    tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub 2>/dev/null
    
    # 2. 创建AK
    echo "[2/4] 创建Attestation Key..."
    tpm2_createak -C /tmp/ek.ctx -c /tmp/ak.ctx -G rsa -g sha256 -s rsassa -u /tmp/ak.pub -n /tmp/ak.name 2>/dev/null
    
    # 3. 生成Quote（包含一个nonce）
    echo "[3/4] 生成TPM Quote..."
    NONCE="deadbeefcafebabe1234567890abcdef"
    tpm2_quote -c /tmp/ak.ctx -l sha256:0,1,2,3,4,5,6,7 -q $NONCE -m /tmp/quote.msg -s /tmp/quote.sig -g sha256 2>/dev/null
    
    echo "[4/4] 解析Quote内容..."
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "原始Quote文件:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ls -lh /tmp/quote.msg /tmp/quote.sig
    echo
    
    # 解析Quote消息
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Quote消息内容（十六进制）:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    xxd /tmp/quote.msg | head -20
    echo "..."
    echo
    
    # 手动解析关键字段
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "解析的字段:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Magic (前4字节应该是 FF544347)
    MAGIC=$(xxd -p -l 4 /tmp/quote.msg | tr -d '\n')
    echo "1. Magic: 0x$MAGIC"
    if [ "$MAGIC" = "ff544347" ]; then
        echo "   ✓ 验证通过: TPM_GENERATED_VALUE"
    fi
    echo
    
    # Type (字节4-5)
    TYPE=$(xxd -p -s 4 -l 2 /tmp/quote.msg | tr -d '\n')
    echo "2. Type: 0x$TYPE"
    if [ "$TYPE" = "8018" ]; then
        echo "   ✓ 这是ATTEST_QUOTE类型"
    fi
    echo
    
    # 使用tpm2_print解析完整结构
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "完整Quote结构（YAML格式）:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    tpm2_print -t TPMS_ATTEST /tmp/quote.msg
    echo
    
    # 提取PCR Digest
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "PCR Digest（关键信息）:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    tpm2_print -t TPMS_ATTEST /tmp/quote.msg | grep -A 5 "pcrDigest"
    echo
    
    # 验证Quote
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "验证Quote签名:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if tpm2_checkquote -u /tmp/ak.pub -m /tmp/quote.msg -s /tmp/quote.sig -g sha256 -q $NONCE 2>&1; then
        echo "✓✓✓ Quote签名验证通过 ✓✓✓"
    else
        echo "✗ Quote签名验证失败"
    fi
    echo
    
    # 读取实际PCR值进行对比
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "当前PCR值（用于对比）:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    tpm2_pcrread sha256:0,1,2,3,4,5,6,7
    
else
    echo "✗ 未检测到TPM设备"
    echo
    echo "在没有TPM的环境中，这里是Quote包含的信息类型："
    echo
    cat << 'INFO'
Quote中可解析的信息：

✓ 身份信息
  - Qualified Signer: 签名密钥的标识
  - 证明这是特定AK签名的

✓ 时间信息
  - Clock: TPM运行时间（毫秒）
  - ResetCount: TPM重启次数
  - RestartCount: TPM恢复次数
  - 可用于检测VM重启

✓ 防重放
  - ExtraData: 包含调用者提供的nonce
  - 验证者可以确认Quote是新生成的

✓ 平台状态
  - PCR Selection: 包含了哪些PCR
  - PCR Digest: 所有选中PCR的组合哈希
  - 可用于验证启动状态、OS镜像等

✓ TPM信息
  - Firmware Version: TPM固件版本
  - Magic: 证明是TPM生成的

✓ 签名
  - quote.sig文件包含AK对quote.msg的签名
  - 验证者用AK公钥验证

Quote不包含的信息：
✗ 单个PCR的原始值（只有组合哈希）
✗ Event Log（需要单独获取）
✗ AK证书（AK没有证书）
✗ 具体的OS镜像哈希（需要从PCR反推）

INFO
fi

echo
echo "=== 如何使用Quote验证OS镜像 ==="
echo
cat << 'USAGE'
步骤:
1. 获取Quote中的PCR Digest
2. 获取TPM Event Log（记录了每个PCR的扩展历史）
3. 从Event Log重放计算PCR值
4. 对比重放的PCR值和Quote中的PCR Digest
5. 从Event Log中找到OS镜像的哈希值
6. 对比OS镜像哈希和预期值

重要概念:
- Quote本身不直接包含OS镜像哈希
- OS镜像哈希在Event Log中
- Quote保证Event Log的完整性（通过PCR Digest）

验证流程:
  Event Log ──计算──> PCR值 ──组合哈希──> PCR Digest
                                            │
                                            ↓
  Quote.msg ───包含───> PCR Digest ─────对比验证
                        Nonce
                        Clock Info
       │
       ↓
  Quote.sig ───AK签名──> 验证整体真实性

USAGE

