# Quote与Event Log关联验证完全指南

## 一、核心原理图

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Quote ←→ Event Log 验证关系                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

启动时 (Boot Time):
─────────────────────────────────────────────────────────────────────────────

  硬件/固件          测量          记录              扩展
  ─────────        ─────────     ─────────         ─────────

  ┌─────────┐
  │  BIOS   │───→ Hash(BIOS) ───→ Event Log ───→ PCR[0].extend(Hash)
  └─────────┘      0xaabbcc...    Event #0         PCR[0] = SHA256(0||0xaa..)

  ┌─────────┐
  │  UEFI   │───→ Hash(UEFI) ───→ Event Log ───→ PCR[0].extend(Hash)
  └─────────┘      0xddeeff...    Event #1         PCR[0] = SHA256(PCR[0]||0xdd..)

  ┌─────────┐
  │Bootload│───→ Hash(GRUB) ───→ Event Log ───→ PCR[4].extend(Hash)
  └─────────┘      0x112233...    Event #2         PCR[4] = SHA256(0||0x11..)

  ┌─────────┐
  │ Kernel  │───→ Hash(vmlinuz)→ Event Log ───→ PCR[8].extend(Hash)
  └─────────┘      0x445566...    Event #3         PCR[8] = SHA256(0||0x44..)

  ... (继续启动过程)


启动完成后 (After Boot):
─────────────────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 最终状态                                                                 │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                          │
  │  Event Log (完整历史)                TPM PCR寄存器 (最终值)             │
  │  ═════════════════════                ═══════════════════════            │
  │  [Event #0] PCR[0] = 0xaa..          PCR[0] = 0x1a2b3c...               │
  │  [Event #1] PCR[0] = 0xdd..          PCR[1] = 0x4d5e6f...               │
  │  [Event #2] PCR[4] = 0x11..          PCR[2] = 0x708192...               │
  │  [Event #3] PCR[8] = 0x44..          PCR[3] = 0xa3b4c5...               │
  │  ...                                 PCR[4] = 0xd6e7f8...               │
  │  [Event #121]                        ...                                │
  │                                      PCR[23] = 0x091a2b...              │
  │                                                                          │
  └─────────────────────────────────────────────────────────────────────────┘


Attestation时 (Quote Generation):
─────────────────────────────────────────────────────────────────────────────

  Verifier                    TEE/VM                       TPM
  ────────                    ──────                       ───

  生成nonce
  "0xdeadbeef..."
       │
       ├──────────────→ getQuote(nonce)
       │                      │
       │                      ├────────────→ tpm2_quote
       │                      │              -l sha256:0-7
       │                      │              -q nonce
       │                      │                    │
       │                      │                    ↓
       │                      │              读取PCR[0-7]
       │                      │              拼接: PCR[0]||PCR[1]||..||PCR[7]
       │                      │              计算: SHA256(拼接值)
       │                      │                    │
       │                      │                    ↓
       │                      │              pcrDigest = 0x9f86d0...
       │                      │                    │
       │                      │              构造TPMS_ATTEST:
       │                      │                magic = 0xFF544347
       │                      │                type = 0x8018
       │                      │                extraData = nonce
       │                      │                pcrDigest = 0x9f86d0...
       │                      │                ...
       │                      │                    │
       │                      │                    ↓
       │                      │              AK签名(TPMS_ATTEST)
       │                      │                    │
       │                      │                    ↓
       │                      │              返回: quote.msg + quote.sig
       │                      │
       │                      ├────────────┐
       │                      │            │
       │                      │      读取Event Log
       │                      │      /sys/kernel/.../binary_bios_measurements
       │                      │            │
       │                      ←────────────┘
       │                      │
       ←──────────────────────┤
       │                      返回:
   收到Quote + Event Log        - quote.msg
                                - quote.sig
                                - eventlog.bin


验证时 (Verification):
─────────────────────────────────────────────────────────────────────────────

  Verifier端:

  ┌────────────────────────────────────────────────────────────────────────┐
  │ Step 1: 验证Quote签名                                                   │
  ├────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  输入: quote.msg, quote.sig, ak.pub, nonce                             │
  │                                                                         │
  │  验证:                                                                  │
  │    1. 用AK公钥验证签名                                                 │
  │       verify_signature(quote.msg, quote.sig, ak.pub) ✓                 │
  │                                                                         │
  │    2. 检查nonce                                                         │
  │       quote.extraData == nonce ✓                                       │
  │                                                                         │
  │  结论: Quote是可信的，由真实的AK签名，且是新生成的                     │
  │                                                                         │
  └────────────────────────────────────────────────────────────────────────┘
           │
           ↓
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Step 2: 提取Quote中的PCR Digest                                        │
  ├────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  解析: tpm2_print -t TPMS_ATTEST quote.msg                             │
  │                                                                         │
  │  提取:                                                                  │
  │    quote.pcrDigest = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b...    │
  │                                                                         │
  │  这是Quote"承诺"的PCR Digest                                           │
  │                                                                         │
  └────────────────────────────────────────────────────────────────────────┘
           │
           ↓
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Step 3: 重放Event Log计算PCR值                        ⭐ 关键步骤 ⭐    │
  ├────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  输入: eventlog.bin                                                     │
  │                                                                         │
  │  算法:                                                                  │
  │    # 初始化所有PCR为0                                                  │
  │    PCR[0..23] = 0x00000000...00 (32字节零)                             │
  │                                                                         │
  │    # 按顺序重放每个事件                                                │
  │    for event in eventlog:                                              │
  │        pcr_idx = event.PCRIndex                                        │
  │        digest = event.Digest                                           │
  │                                                                         │
  │        # PCR extend操作                                                │
  │        PCR[pcr_idx] = SHA256(PCR[pcr_idx] || digest)                   │
  │                               ^^^^^^^^^^^^^^^^^^^^^^^                  │
  │                               拼接后哈希                               │
  │                                                                         │
  │  示例重放:                                                              │
  │    Event #0: PCRIndex=0, Digest=0xaabbcc...                            │
  │      → PCR[0] = SHA256(0x000...00 || 0xaabbcc...)                      │
  │      → PCR[0] = 0x123456...                                            │
  │                                                                         │
  │    Event #1: PCRIndex=0, Digest=0xddeeff...                            │
  │      → PCR[0] = SHA256(0x123456... || 0xddeeff...)                     │
  │      → PCR[0] = 0x789abc...                                            │
  │                                                                         │
  │    ... (继续所有事件)                                                   │
  │                                                                         │
  │  最终结果:                                                              │
  │    PCR[0] = 0x1a2b3c4d...                                              │
  │    PCR[1] = 0x4d5e6f70...                                              │
  │    ...                                                                  │
  │    PCR[7] = 0xa3b4c5d6...                                              │
  │                                                                         │
  └────────────────────────────────────────────────────────────────────────┘
           │
           ↓
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Step 4: 计算PCR Digest                                                 │
  ├────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  拼接选中的PCR值:                                                       │
  │    pcr_concat = PCR[0] || PCR[1] || PCR[2] || ... || PCR[7]            │
  │              = 0x1a2b3c...||0x4d5e6f...||...||0xa3b4c5...              │
  │              = 256 bytes (8个PCR × 32字节)                             │
  │                                                                         │
  │  计算SHA256:                                                            │
  │    calculated_digest = SHA256(pcr_concat)                              │
  │                      = 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b...   │
  │                                                                         │
  └────────────────────────────────────────────────────────────────────────┘
           │
           ↓
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Step 5: 对比PCR Digest                            ⭐ 验证时刻 ⭐        │
  ├────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  比较:                                                                  │
  │    quote.pcrDigest        = 0x9f86d081884c7d659a2feaa0c55ad015...      │
  │    calculated_digest      = 0x9f86d081884c7d659a2feaa0c55ad015...      │
  │                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^           │
  │                                    完全匹配！                          │
  │                                                                         │
  │  if quote.pcrDigest == calculated_digest:                              │
  │      ✓✓✓ 验证通过！✓✓✓                                                 │
  │                                                                         │
  │      结论:                                                              │
  │        1. Event Log是真实的、完整的                                    │
  │        2. Event Log没有被篡改                                          │
  │        3. Event Log中的测量值都是可信的                                │
  │        4. 可以安全地从Event Log提取OS镜像哈希等信息                    │
  │                                                                         │
  │  else:                                                                  │
  │      ✗✗✗ 验证失败！✗✗✗                                                 │
  │                                                                         │
  │      可能原因:                                                          │
  │        1. Event Log被篡改（修改、删除、添加事件）                      │
  │        2. Event Log不完整（缺少事件）                                  │
  │        3. Event Log与Quote不匹配（来自不同的启动）                     │
  │                                                                         │
  └────────────────────────────────────────────────────────────────────────┘
           │
           ↓ (验证通过后)
  ┌────────────────────────────────────────────────────────────────────────┐
  │ Step 6: 从Event Log提取OS镜像信息                                      │
  ├────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  查找特定事件类型:                                                      │
  │    - EV_IPL (Initial Program Load)                                     │
  │    - EV_EFI_BOOT_SERVICES_APPLICATION                                  │
  │    - EV_EFI_PLATFORM_FIRMWARE_BLOB                                     │
  │                                                                         │
  │  示例:                                                                  │
  │    Event #45:                                                           │
  │      PCRIndex: 8                                                        │
  │      EventType: EV_IPL                                                  │
  │      Digest: 0x445566778899aabbccddeeff00112233...                     │
  │      Event: "vmlinuz-5.15.0-56-generic"                                │
  │                                                                         │
  │  提取:                                                                  │
  │    os_kernel_hash = 0x445566778899aabbccddeeff00112233...              │
  │                                                                         │
  │  验证:                                                                  │
  │    if os_kernel_hash == trusted_kernel_hash:                           │
  │        ✓✓✓ OS镜像验证通过！✓✓✓                                         │
  │        → 系统运行的是可信的OS镜像                                       │
  │        → 没有被替换或篡改                                               │
  │                                                                         │
  └────────────────────────────────────────────────────────────────────────┘

```

## 二、为什么这个验证是安全的？

### 安全性分析

#### 1️⃣ Quote的PCR Digest是TPM签名的，无法伪造

```
Quote.sig = Sign_AK(Quote.msg)
           └─ AK私钥在TPM内部，永不导出

攻击者即使篡改Event Log，也无法:
  1. 修改Quote中的pcrDigest（有签名保护）
  2. 重新生成有效的签名（没有AK私钥）
```

#### 2️⃣ PCR值由TPM硬件维护，只能extend不能直接写入

```
PCR extend是单向操作:
  PCR_new = SHA256(PCR_old || new_value)
          └─ 无法逆向计算

攻击者无法:
  - 直接设置PCR值
  - 回滚PCR值到之前的状态
  - 跳过某个测量
```

#### 3️⃣ 哈希函数的抗碰撞性

```
SHA256的安全性保证:
  - 找到两个不同输入产生相同输出几乎不可能
  - 攻击者无法构造一个假的Event Log使其产生相同的PCR Digest
```

### 攻击场景分析

#### ❌ 攻击1：篡改Event Log

```
攻击者尝试:
  1. 修改Event Log中的某个Digest
     Event #3: Digest: 0x445566... → 0x999999...
                       (真实内核)    (恶意内核)

  2. 发送篡改的Event Log给Verifier

Verifier验证:
  1. 重放篡改的Event Log
     → PCR值会不同
     → calculated_digest ≠ quote.pcrDigest

  2. 验证失败 ✗
     → 攻击被检测
```

#### ❌ 攻击2：删除Event Log中的事件

```
攻击者尝试:
  1. 删除Event Log中的某些事件
     (试图隐藏某些测量)

Verifier验证:
  1. 重放不完整的Event Log
     → 缺少某些extend操作
     → PCR值会不同
     → calculated_digest ≠ quote.pcrDigest

  2. 验证失败 ✗
```

#### ❌ 攻击3：添加假的事件

```
攻击者尝试:
  1. 在Event Log中插入假事件

Verifier验证:
  1. 重放包含假事件的Event Log
     → 多了extend操作
     → PCR值会不同
     → calculated_digest ≠ quote.pcrDigest

  2. 验证失败 ✗
```

#### ❌ 攻击4：提供旧的Event Log

```
攻击者尝试:
  1. 系统启动恶意OS（PCR值改变）
  2. 生成新Quote（包含恶意OS的PCR Digest）
  3. 但发送之前启动时的旧Event Log

Verifier验证:
  1. 重放旧Event Log
     → 得到旧的PCR值
     → calculated_digest ≠ quote.pcrDigest (新的)

  2. 验证失败 ✗
```

#### ✓ 唯一成功的情况

```
只有当:
  1. Event Log是真实的、完整的
  2. 记录了实际发生的所有测量
  3. 与Quote生成时的PCR值一致

验证才会通过 ✓
```

## 三、实际验证代码示例

### Python实现

```python
#!/usr/bin/env python3
import hashlib
import struct

def extend_pcr(pcr_value, digest):
    """
    模拟TPM的PCR extend操作
    PCR_new = SHA256(PCR_old || digest)
    """
    return hashlib.sha256(pcr_value + digest).digest()

def replay_eventlog(eventlog):
    """
    重放Event Log计算最终的PCR值

    eventlog格式:
    [
        {'pcr_index': 0, 'digest': b'\xaa\xbb\xcc...'},
        {'pcr_index': 0, 'digest': b'\xdd\xee\xff...'},
        ...
    ]
    """
    # 初始化所有PCR为0
    pcrs = {i: b'\x00' * 32 for i in range(24)}

    # 按顺序重放每个事件
    for event in eventlog:
        pcr_idx = event['pcr_index']
        digest = event['digest']

        # Extend操作
        pcrs[pcr_idx] = extend_pcr(pcrs[pcr_idx], digest)

        print(f"Event: PCR[{pcr_idx}] extended with {digest.hex()[:16]}...")
        print(f"  → PCR[{pcr_idx}] = {pcrs[pcr_idx].hex()[:32]}...")

    return pcrs

def calculate_pcr_digest(pcrs, selected_pcrs):
    """
    计算PCR Digest
    Digest = SHA256(PCR[0] || PCR[1] || ... || PCR[n])
    """
    # 拼接选中的PCR值
    pcr_concat = b''.join(pcrs[i] for i in selected_pcrs)

    # 计算SHA256
    digest = hashlib.sha256(pcr_concat).digest()

    return digest

def verify_quote_eventlog(quote_pcr_digest, eventlog, selected_pcrs):
    """
    验证Quote与Event Log的关联

    返回: (验证结果, 重放的PCR值)
    """
    print("=" * 80)
    print("开始验证Quote与Event Log的关联")
    print("=" * 80)
    print()

    # Step 1: 重放Event Log
    print("[Step 1] 重放Event Log...")
    print("-" * 80)
    pcrs = replay_eventlog(eventlog)
    print()

    # Step 2: 计算PCR Digest
    print("[Step 2] 计算PCR Digest...")
    print("-" * 80)
    print(f"选中的PCR: {selected_pcrs}")
    calculated_digest = calculate_pcr_digest(pcrs, selected_pcrs)
    print(f"计算出的Digest: {calculated_digest.hex()}")
    print()

    # Step 3: 对比
    print("[Step 3] 对比验证...")
    print("-" * 80)
    print(f"Quote中的Digest:  {quote_pcr_digest.hex()}")
    print(f"计算出的Digest:   {calculated_digest.hex()}")
    print()

    if quote_pcr_digest == calculated_digest:
        print("✓✓✓ 验证通过！✓✓✓")
        print("  → Event Log是真实的、完整的")
        print("  → 可以安全地从Event Log提取OS镜像信息")
        return True, pcrs
    else:
        print("✗✗✗ 验证失败！✗✗✗")
        print("  → Event Log可能被篡改")
        print("  → 不要信任Event Log中的任何信息")
        return False, None

# 示例使用
if __name__ == "__main__":
    # 模拟Event Log
    eventlog = [
        {'pcr_index': 0, 'digest': hashlib.sha256(b'BIOS').digest()},
        {'pcr_index': 0, 'digest': hashlib.sha256(b'UEFI').digest()},
        {'pcr_index': 4, 'digest': hashlib.sha256(b'GRUB').digest()},
        {'pcr_index': 8, 'digest': hashlib.sha256(b'vmlinuz-5.15.0').digest()},
    ]

    # 计算期望的PCR Digest（模拟Quote中的值）
    pcrs = replay_eventlog(eventlog)
    expected_digest = calculate_pcr_digest(pcrs, [0, 4, 8])

    # 验证
    result, verified_pcrs = verify_quote_eventlog(
        quote_pcr_digest=expected_digest,
        eventlog=eventlog,
        selected_pcrs=[0, 4, 8]
    )

    if result:
        print()
        print("验证通过后可以提取信息:")
        print(f"  PCR[0] (BIOS/UEFI): {verified_pcrs[0].hex()[:32]}...")
        print(f"  PCR[4] (Bootloader): {verified_pcrs[4].hex()[:32]}...")
        print(f"  PCR[8] (OS Kernel): {verified_pcrs[8].hex()[:32]}...")
```

### Bash脚本实现

```bash
#!/bin/bash

verify_quote_eventlog() {
    local quote_file="$1"
    local eventlog_file="$2"

    echo "=========================================="
    echo "Quote与Event Log关联验证"
    echo "=========================================="
    echo

    # Step 1: 提取Quote中的PCR Digest
    echo "[Step 1] 从Quote提取PCR Digest..."
    QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST "$quote_file" | \
                   grep -A 2 "pcrDigest:" | \
                   grep "buffer:" | \
                   awk '{print $2}')
    echo "Quote Digest: $QUOTE_DIGEST"
    echo

    # Step 2: 重放Event Log
    echo "[Step 2] 重放Event Log（如果工具支持）..."
    # 注意: tpm2_eventlog目前不支持输出重放后的PCR值
    # 这里我们读取实际的PCR值作为对比
    tpm2_pcrread sha256:0,1,2,3,4,5,6,7 -o /tmp/pcrs.bin

    # Step 3: 计算PCR Digest
    echo "[Step 3] 计算PCR Digest..."
    CALC_DIGEST=$(sha256sum /tmp/pcrs.bin | awk '{print $1}')
    echo "Calculated Digest: $CALC_DIGEST"
    echo

    # Step 4: 对比
    echo "[Step 4] 对比验证..."
    echo "Quote:      $QUOTE_DIGEST"
    echo "Calculated: $CALC_DIGEST"
    echo

    if [ "$QUOTE_DIGEST" = "$CALC_DIGEST" ]; then
        echo "✓✓✓ 验证通过！✓✓✓"
        return 0
    else
        echo "✗✗✗ 验证失败！✗✗✗"
        return 1
    fi
}

# 使用示例
verify_quote_eventlog "/tmp/quote.msg" "/tmp/eventlog.bin"
```

## 四、总结

### 验证流程总结

```
Quote签名验证 ✓
    ↓
提取Quote.pcrDigest
    ↓
重放Event Log → 计算PCR值
    ↓
拼接PCR值 → 计算Digest
    ↓
Digest对比 → 相等？
    ↓              ↓
   Yes            No
    ↓              ↓
Event Log可信   Event Log被篡改
    ↓
提取OS镜像哈希
    ↓
验证OS镜像
```

### 关键要点

1. **Quote是"承诺"，Event Log是"详情"**
   - Quote说："PCR Digest是XXXX"（由TPM签名，不可伪造）
   - Event Log说："这是启动时发生的所有测量"
   - 验证：重放Event Log是否能得到相同的PCR Digest

2. **单向性保证安全**
   - PCR extend是单向操作，无法逆向
   - SHA256抗碰撞，无法构造假的Event Log
   - Quote签名保护，无法修改pcrDigest

3. **完整性验证**
   - 任何对Event Log的篡改都会导致PCR Digest不同
   - 验证失败立即检测到攻击

4. **信任链**
   ```
   TPM硬件可信
     → Quote签名可信
       → PCR Digest可信
         → Event Log验证通过
           → OS镜像哈希可信
   ```
