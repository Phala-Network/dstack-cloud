#!/bin/bash

cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║            Quote与Event Log关联验证原理与实践                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

一、核心概念
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Quote和Event Log的关系：

  ┌─────────────────────────────────────────────────────────────┐
  │ Event Log (详细的测量历史)                                 │
  │ ─────────────────────────────────────────────────────       │
  │ Event 1: BIOS启动，测量值=0xaabbcc... → extend到PCR[0]    │
  │ Event 2: UEFI启动，测量值=0xddeeff... → extend到PCR[0]    │
  │ Event 3: Bootloader，测量值=0x112233... → extend到PCR[4] │
  │ Event 4: OS Kernel，测量值=0x445566... → extend到PCR[8]  │
  │ ...                                                         │
  │ Event N: 最后一个事件                                      │
  └─────────────────────────────────────────────────────────────┘
           │
           │ 重放（Replay）每个extend操作
           ↓
  ┌─────────────────────────────────────────────────────────────┐
  │ 计算出的PCR值                                               │
  │ ─────────────────────────────────────────────────────       │
  │ PCR[0] = SHA256(SHA256(...SHA256(0 || Event1) || Event2))  │
  │ PCR[4] = SHA256(0 || Event3)                                │
  │ PCR[8] = SHA256(0 || Event4)                                │
  │ ...                                                          │
  └─────────────────────────────────────────────────────────────┘
           │
           │ 拼接所有选中的PCR值
           ↓
  ┌─────────────────────────────────────────────────────────────┐
  │ 计算PCR Digest                                              │
  │ ─────────────────────────────────────────────────────       │
  │ Calculated_Digest = SHA256(PCR[0] || PCR[1] || ... || PCR[7])│
  └─────────────────────────────────────────────────────────────┘
           │
           │ 对比
           ↓
  ┌─────────────────────────────────────────────────────────────┐
  │ Quote中的PCR Digest                                         │
  │ ─────────────────────────────────────────────────────       │
  │ Quote_Digest = 从quote.msg解析出的pcrDigest字段            │
  └─────────────────────────────────────────────────────────────┘
           │
           ↓
    Quote_Digest == Calculated_Digest ?
           │
    ┌──────┴───────┐
    ↓              ↓
   相等          不相等
    ✓              ✗
  验证通过      Event Log被篡改


二、为什么这样可以验证？
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Quote的PCR Digest是TPM签名的，无法伪造
  → 如果Event Log被篡改，重放后的PCR值会不同
    → PCR Digest会不同
      → 验证失败 ✗

只有当Event Log是真实的、完整的，重放后才能得到相同的PCR Digest
  → 验证通过 ✓


三、验证步骤详解
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

步骤1: 获取Quote
───────────────────────────────────────────────────────────────────
命令:
  tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7 \
             -q $NONCE -m quote.msg -s quote.sig

获得:
  - quote.msg: 包含pcrDigest
  - quote.sig: AK的签名

步骤2: 提取Quote中的PCR Digest
───────────────────────────────────────────────────────────────────
命令:
  tpm2_print -t TPMS_ATTEST quote.msg | grep -A 2 pcrDigest

输出示例:
  pcrDigest:
    size: 32
    buffer: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0abe8318363958dc89e8e3
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           这就是Quote承诺的PCR Digest

步骤3: 获取Event Log
───────────────────────────────────────────────────────────────────
命令:
  # 二进制格式
  cat /sys/kernel/security/tpm0/binary_bios_measurements > eventlog.bin

  # 解析为YAML
  tpm2_eventlog eventlog.bin > eventlog.yaml

Event Log内容示例:
  ---
  events:
    - EventNum: 0
      PCRIndex: 0
      EventType: EV_S_CRTM_VERSION
      DigestCount: 1
      Digests:
        - AlgorithmId: sha256
          Digest: "d3b07384d113edec49eaa6238ad5ff00"
      EventSize: 32
      Event: "BIOS Version 1.2.3"

    - EventNum: 1
      PCRIndex: 0
      EventType: EV_EFI_PLATFORM_FIRMWARE_BLOB
      Digests:
        - AlgorithmId: sha256
          Digest: "c157a79031e1c40f85931829bc5fc552"
      Event: "UEFI Firmware"

    ... (更多事件)

步骤4: 重放Event Log计算PCR值
───────────────────────────────────────────────────────────────────
这是关键步骤！

PCR初始值都是0（32字节的零）:
  PCR[0] = 0x000000...00 (32个零)

然后按照Event Log的顺序，逐个extend:

伪代码:
  for event in eventlog:
      pcr_index = event.PCRIndex
      digest = event.Digest

      # PCR extend操作
      PCR[pcr_index] = SHA256(PCR[pcr_index] || digest)
                                    ^^^^^^^^^^^^^^^^^^
                                    拼接后计算哈希

实际命令（tpm2-tools已经实现了重放）:
  # 方法1: 使用tpm2_eventlog的重放功能（如果支持）
  tpm2_eventlog eventlog.bin --pcr-replay

  # 方法2: 手动重放（更可靠）
  # 提取每个事件的Digest，按顺序extend

步骤5: 读取实际PCR值（对比用）
───────────────────────────────────────────────────────────────────
命令:
  tpm2_pcrread sha256:0,1,2,3,4,5,6,7 -o pcrs.bin

这会读取TPM中当前的PCR值

注意: 如果系统启动后没有新的extend，实际PCR值应该等于重放的值

步骤6: 计算PCR Digest
───────────────────────────────────────────────────────────────────
拼接所有选中的PCR值，然后计算哈希:

命令:
  # 读取PCR值到文件
  tpm2_pcrread sha256:0,1,2,3,4,5,6,7 -o pcrs.bin

  # 计算SHA256
  PCR_DIGEST=$(sha256sum pcrs.bin | awk '{print $1}')

  echo "计算出的PCR Digest: $PCR_DIGEST"

步骤7: 对比
───────────────────────────────────────────────────────────────────
比较两个Digest:
  - Quote中的PCR Digest（从quote.msg提取）
  - 计算出的PCR Digest（从PCR值或重放Event Log计算）

命令:
  QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST quote.msg | \
                 grep -A 2 pcrDigest | tail -1 | awk '{print $2}')

  if [ "$QUOTE_DIGEST" = "$PCR_DIGEST" ]; then
      echo "✓✓✓ 验证通过！Event Log与Quote一致 ✓✓✓"
  else
      echo "✗✗✗ 验证失败！Event Log可能被篡改 ✗✗✗"
  fi


四、实际验证示例（需要TPM设备）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

# 检查是否有TPM
if [ ! -c /dev/tpm0 ]; then
    echo "✗ 未检测到TPM设备 (/dev/tpm0)"
    echo
    echo "如果在GCP VM上，可以这样测试："
    echo "  gcloud compute ssh <instance-name> -- 'bash -s' < $0"
    exit 0
fi

echo "✓ 检测到TPM设备，开始验证演示..."
echo

# 清理旧文件
rm -f /tmp/{ek,ak}.{ctx,pub,name} /tmp/quote.{msg,sig} /tmp/eventlog.{bin,yaml} /tmp/pcrs.bin 2>/dev/null

# 1. 创建EK和AK
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤1: 创建密钥"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  创建EK..."
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub 2>/dev/null
echo "  创建AK..."
tpm2_createak -C /tmp/ek.ctx -c /tmp/ak.ctx -G rsa -g sha256 -s rsassa -u /tmp/ak.pub -n /tmp/ak.name 2>/dev/null
echo "  ✓ 密钥创建完成"
echo

# 2. 生成Quote
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤2: 生成Quote"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
NONCE="test_nonce_12345678"
echo "  使用nonce: $NONCE"
echo "  包含PCR: 0,1,2,3,4,5,6,7"
tpm2_quote -c /tmp/ak.ctx -l sha256:0,1,2,3,4,5,6,7 -q $NONCE \
           -m /tmp/quote.msg -s /tmp/quote.sig -g sha256 2>/dev/null
echo "  ✓ Quote生成完成"
echo "  文件: /tmp/quote.msg ($(stat -c%s /tmp/quote.msg) bytes)"
echo "        /tmp/quote.sig ($(stat -c%s /tmp/quote.sig) bytes)"
echo

# 3. 提取Quote中的PCR Digest
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤3: 从Quote提取PCR Digest"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  解析Quote..."
tpm2_print -t TPMS_ATTEST /tmp/quote.msg > /tmp/quote_parsed.yaml
echo "  PCR Digest字段:"
tpm2_print -t TPMS_ATTEST /tmp/quote.msg | grep -A 3 pcrDigest | head -4
QUOTE_DIGEST=$(tpm2_print -t TPMS_ATTEST /tmp/quote.msg | grep -A 2 pcrDigest | grep "buffer:" | awk '{print $2}')
echo
echo "  Quote承诺的PCR Digest: $QUOTE_DIGEST"
echo

# 4. 读取实际PCR值
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤4: 读取当前PCR值"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  读取PCR 0-7的值..."
tpm2_pcrread sha256:0,1,2,3,4,5,6,7 -o /tmp/pcrs.bin
echo
echo "  当前PCR值:"
tpm2_pcrread sha256:0,1,2,3,4,5,6,7 | head -12
echo

# 5. 计算PCR Digest
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤5: 计算PCR Digest"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  计算方式: SHA256(PCR[0] || PCR[1] || ... || PCR[7])"
CALCULATED_DIGEST=$(sha256sum /tmp/pcrs.bin | awk '{print $1}')
echo "  计算出的PCR Digest: $CALCULATED_DIGEST"
echo

# 6. 对比
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤6: 对比验证"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Quote中的Digest:  $QUOTE_DIGEST"
echo "  计算出的Digest:   $CALCULATED_DIGEST"
echo

if [ "$QUOTE_DIGEST" = "$CALCULATED_DIGEST" ]; then
    echo "  ✓✓✓ 验证通过！✓✓✓"
    echo "      → PCR值与Quote一致"
    echo "      → Quote承诺的平台状态是真实的"
else
    echo "  ✗✗✗ 验证失败！✗✗✗"
    echo "      → PCR值与Quote不一致"
    echo "      → 可能的原因："
    echo "        1. PCR值在Quote生成后被修改"
    echo "        2. Quote被篡改"
fi
echo

# 7. 获取Event Log
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤7: 分析Event Log"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    cp /sys/kernel/security/tpm0/binary_bios_measurements /tmp/eventlog.bin
    EVENT_COUNT=$(tpm2_eventlog /tmp/eventlog.bin 2>/dev/null | grep -c "EventNum:")
    echo "  Event Log位置: /sys/kernel/security/tpm0/binary_bios_measurements"
    echo "  大小: $(stat -c%s /tmp/eventlog.bin) bytes"
    echo "  事件数量: $EVENT_COUNT"
    echo
    echo "  前5个事件:"
    tpm2_eventlog /tmp/eventlog.bin 2>/dev/null | head -40
    echo "  ..."
    echo
    echo "  Event Log包含的信息:"
    echo "    - 每个PCR扩展的详细历史"
    echo "    - 启动时测量的每个组件（BIOS, UEFI, Bootloader, Kernel等）"
    echo "    - 每个组件的哈希值"
    echo
    echo "  验证思路:"
    echo "    1. 重放Event Log，计算每个PCR的最终值"
    echo "    2. 拼接所有PCR值，计算SHA256"
    echo "    3. 对比计算结果与Quote中的pcrDigest"
    echo "    4. 如果一致 → Event Log是真实的、完整的"
    echo "    5. 从Event Log中提取OS镜像哈希进行验证"
else
    echo "  ✗ Event Log不可用"
    echo "    位置: /sys/kernel/security/tpm0/binary_bios_measurements"
fi
echo

# 8. 验证Quote签名
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "步骤8: 验证Quote签名（完整性）"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if tpm2_checkquote -u /tmp/ak.pub -m /tmp/quote.msg -s /tmp/quote.sig -g sha256 -q "$NONCE" 2>&1; then
    echo
    echo "  ✓✓✓ Quote签名验证通过 ✓✓✓"
    echo "      → Quote确实由AK签名"
    echo "      → Nonce匹配（防重放）"
    echo "      → Quote内容未被篡改"
else
    echo "  ✗ Quote签名验证失败"
fi
echo

cat << 'SUMMARY'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
总结：Quote与Event Log的关联验证
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

完整的验证链:

  1. 验证Quote签名
     tpm2_checkquote ✓
     → Quote是AK签名的，可信

  2. 提取Quote中的PCR Digest
     pcrDigest = XXXX
     → Quote承诺的平台状态

  3. 读取实际PCR值
     tpm2_pcrread
     → 当前的平台状态

  4. 计算PCR Digest
     SHA256(PCR拼接)
     → 验证Quote承诺是否真实

  5. 对比PCR Digest
     Quote中的 == 计算出的 ?
     → ✓ 平台状态可信

  6. 重放Event Log
     计算每个PCR的值
     → 验证Event Log完整性

  7. 从Event Log提取OS镜像哈希
     找到EV_IPL或类似事件
     → 验证OS镜像

关键点:
  ✓ Quote的PCR Digest由TPM签名，无法伪造
  ✓ Event Log重放后必须得到相同的PCR值
  ✓ 只有Event Log真实完整，才能通过验证
  ✓ 从验证通过的Event Log中提取的OS哈希是可信的

SUMMARY

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "临时文件位置:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ls -lh /tmp/quote.* /tmp/ak.pub /tmp/eventlog.* /tmp/pcrs.bin 2>/dev/null || echo "  (部分文件未生成)"
