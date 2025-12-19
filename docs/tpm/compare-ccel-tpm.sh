#!/bin/bash
set -euo pipefail

echo "=== TDX CCEL vs TPM Event Log Comparison ==="
echo

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

# Check for required tools
for tool in tpm2_eventlog xxd; do
    if ! command -v "$tool" &> /dev/null; then
        echo "Error: $tool not found. Please install tpm2-tools."
        exit 1
    fi
done

CCEL_ACPI="/sys/firmware/acpi/tables/CCEL"
CCEL_DATA="/sys/firmware/acpi/tables/data/CCEL"
TPM_EVENTLOG="/sys/kernel/security/tpm0/binary_bios_measurements"
CCEL_SYSFS="/sys/kernel/config/tsm/report/tdx-guest-*/eventlog"

echo "[1] Checking available event logs..."
echo

# Check CCEL availability
CCEL_AVAILABLE=0
CCEL_SOURCE=""
if [ -f "$CCEL_ACPI" ]; then
    echo "✓ CCEL ACPI table found: $CCEL_ACPI"
    CCEL_AVAILABLE=1
    CCEL_SOURCE="$CCEL_ACPI"
elif [ -f "$CCEL_DATA" ]; then
    echo "✓ CCEL data found: $CCEL_DATA"
    CCEL_AVAILABLE=1
    CCEL_SOURCE="$CCEL_DATA"
elif ls $CCEL_SYSFS 2>/dev/null | head -1 | read -r ccel_path; then
    echo "✓ CCEL found via tsm: $ccel_path"
    CCEL_AVAILABLE=1
    CCEL_SOURCE="$ccel_path"
else
    echo "✗ CCEL not found (not a TDX guest or kernel doesn't support CCEL)"
fi

# Check TPM event log availability
TPM_AVAILABLE=0
if [ -f "$TPM_EVENTLOG" ]; then
    echo "✓ TPM event log found: $TPM_EVENTLOG"
    TPM_AVAILABLE=1
else
    echo "✗ TPM event log not found"
fi

echo

if [ $CCEL_AVAILABLE -eq 0 ] && [ $TPM_AVAILABLE -eq 0 ]; then
    echo "Error: Neither CCEL nor TPM event log available"
    exit 1
fi

# Parse CCEL if available
if [ $CCEL_AVAILABLE -eq 1 ]; then
    echo "[2] Parsing CCEL (TDX Event Log)..."
    echo

    # Get CCEL size and basic info
    CCEL_SIZE=$(stat -c%s "$CCEL_SOURCE" 2>/dev/null || echo "unknown")
    echo "CCEL source: $CCEL_SOURCE (size: $CCEL_SIZE bytes)"
    echo

    # Try to parse with tpm2_eventlog, but it may crash on CCEL format
    CCEL_PARSED=0
    if timeout 5 tpm2_eventlog "$CCEL_SOURCE" > /tmp/ccel_parsed.yaml 2>/dev/null; then
        CCEL_PARSED=1
        echo "✓ CCEL parsed successfully with tpm2_eventlog"
    else
        echo "⚠ tpm2_eventlog cannot parse CCEL (format may differ from TPM log)"
        echo "  CCEL uses CC Event Log format (TCG spec), not standard TPM format"
    fi
    echo

    if [ $CCEL_PARSED -eq 1 ] && [ -f /tmp/ccel_parsed.yaml ] && [ -s /tmp/ccel_parsed.yaml ]; then
        echo "CCEL Event Summary:"
        echo "-------------------"

        # Count events by PCR/RTMR
        echo "Events by Register (RTMR for TDX):"
        grep "PCRIndex:" /tmp/ccel_parsed.yaml | sort | uniq -c | sort -rn | head -20
        echo

        # Show event types
        echo "Event Types:"
        grep "EventType:" /tmp/ccel_parsed.yaml | sort | uniq -c | sort -rn | head -10
        echo

        # Extract some sample events
        echo "Sample CCEL Events (first 3):"
        grep -A 10 "^- " /tmp/ccel_parsed.yaml | head -40
        echo
    else
        # Dump raw CCEL header
        echo "Raw CCEL Header (first 512 bytes):"
        echo "-----------------------------------"
        xxd -l 512 "$CCEL_SOURCE" > /tmp/ccel_raw.txt
        cat /tmp/ccel_raw.txt
        echo

        # Parse CCEL ACPI table structure
        if [ -f "$CCEL_SOURCE" ]; then
            echo "ACPI/CCEL Table Structure:"
            echo "--------------------------"
            # First 4 bytes: "CCEL" signature
            SIGNATURE=$(xxd -p -l 4 "$CCEL_SOURCE" | xxd -r -p 2>/dev/null || echo "")
            echo "  Signature: $SIGNATURE"

            # Bytes 4-7: table length (little endian)
            TABLE_LEN=$(xxd -p -s 4 -l 4 "$CCEL_SOURCE" | tac -rs .. | tr -d '\n')
            echo "  ACPI Table Length: 0x$TABLE_LEN ($(printf "%d" "0x$TABLE_LEN") bytes)"

            # Bytes 0x24-0x27 (36-39): LAML - Log Area Minimum Length
            LAML=$(xxd -p -s 36 -l 4 "$CCEL_SOURCE" 2>/dev/null | tac -rs .. | tr -d '\n')
            if [ -n "$LAML" ]; then
                echo "  LAML (Log Area Min Length): 0x$LAML ($(printf "%d" "0x$LAML") bytes)"
            fi

            # Bytes 0x28-0x2F (40-47): LASA - Log Area Start Address
            LASA=$(xxd -p -s 40 -l 8 "$CCEL_SOURCE" 2>/dev/null | tac -rs .. | tr -d '\n')
            if [ -n "$LASA" ]; then
                echo "  LASA (Log Area Start Addr): 0x$LASA"
                echo
                echo "  → Actual CCEL event log is at physical address 0x$LASA"
                echo "  → Not directly accessible from userspace without kernel support"
                echo

                # Check if there's a /dev/mem or kernel interface to read it
                if [ -c /dev/mem ]; then
                    echo "  Note: /dev/mem exists but reading physical memory requires special access"
                fi

                # Check for kernel-provided CCEL data
                if [ -d /sys/kernel/config/tsm ]; then
                    echo "  Checking TSM (Trusted Security Module) interface..."
                    find /sys/kernel/config/tsm -name "*eventlog*" -o -name "*ccel*" 2>/dev/null | while read -r f; do
                        echo "    Found: $f"
                    done
                fi
            fi
            echo
        fi
    fi
fi

# Parse TPM event log if available
if [ $TPM_AVAILABLE -eq 1 ]; then
    echo "[3] Parsing TPM Event Log..."
    echo

    tpm2_eventlog "$TPM_EVENTLOG" > /tmp/tpm_parsed.yaml 2>/dev/null

    if [ -f /tmp/tpm_parsed.yaml ]; then
        echo "TPM Event Summary:"
        echo "------------------"

        # Count events by PCR
        echo "Events by PCR:"
        grep "PCRIndex:" /tmp/tpm_parsed.yaml | sort | uniq -c | sort -rn | head -20
        echo

        # Show event types
        echo "Event Types:"
        grep "EventType:" /tmp/tpm_parsed.yaml | sort | uniq -c | sort -rn | head -10
        echo

        # Extract some sample events
        echo "Sample TPM Events (first 3):"
        grep -A 10 "^- " /tmp/tpm_parsed.yaml | head -40
        echo
    fi
fi

# Compare if both available
if [ $CCEL_AVAILABLE -eq 1 ] && [ $TPM_AVAILABLE -eq 1 ]; then
    echo "[4] Comparison: CCEL vs TPM Event Log"
    echo "======================================"
    echo

    echo "Key Differences:"
    echo "----------------"
    echo
    echo "1. Register Names:"
    echo "   CCEL: Uses RTMR (Runtime Measurement Registers) 0-3"
    echo "   TPM:  Uses PCR (Platform Configuration Registers) 0-23"
    echo

    echo "2. Event Counts:"
    CCEL_COUNT=$(grep -c "^- " /tmp/ccel_parsed.yaml 2>/dev/null || echo "0")
    TPM_COUNT=$(grep -c "^- " /tmp/tpm_parsed.yaml 2>/dev/null || echo "0")
    echo "   CCEL: $CCEL_COUNT events"
    echo "   TPM:  $TPM_COUNT events"
    echo

    echo "3. Digest Algorithms:"
    echo "   CCEL digests:"
    grep "AlgorithmId:" /tmp/ccel_parsed.yaml 2>/dev/null | sort -u | head -5 | sed 's/^/     /'
    echo "   TPM digests:"
    grep "AlgorithmId:" /tmp/tpm_parsed.yaml 2>/dev/null | sort -u | head -5 | sed 's/^/     /'
    echo

    echo "4. Common Event Types (overlap):"
    comm -12 \
        <(grep "EventType:" /tmp/ccel_parsed.yaml 2>/dev/null | awk '{print $2}' | sort -u) \
        <(grep "EventType:" /tmp/tpm_parsed.yaml 2>/dev/null | awk '{print $2}' | sort -u) \
        2>/dev/null | sed 's/^/   - /' || echo "   (none)"
    echo

    echo "5. CCEL-only Event Types:"
    comm -23 \
        <(grep "EventType:" /tmp/ccel_parsed.yaml 2>/dev/null | awk '{print $2}' | sort -u) \
        <(grep "EventType:" /tmp/tpm_parsed.yaml 2>/dev/null | awk '{print $2}' | sort -u) \
        2>/dev/null | sed 's/^/   - /' || echo "   (none)"
    echo

    echo "6. TPM-only Event Types:"
    comm -13 \
        <(grep "EventType:" /tmp/ccel_parsed.yaml 2>/dev/null | awk '{print $2}' | sort -u) \
        <(grep "EventType:" /tmp/tpm_parsed.yaml 2>/dev/null | awk '{print $2}' | sort -u) \
        2>/dev/null | sed 's/^/   - /' || echo "   (none)"
    echo

    # Check for similar digests (same measurements in both logs)
    echo "7. Checking for Matching Digests (same measurements):"
    echo

    # Extract all SHA256 digests from both logs
    grep -A 1 "AlgorithmId: sha256" /tmp/ccel_parsed.yaml 2>/dev/null | grep "Digest:" | awk '{print $2}' | tr -d '"' | sort -u > /tmp/ccel_digests.txt
    grep -A 1 "AlgorithmId: sha256" /tmp/tpm_parsed.yaml 2>/dev/null | grep "Digest:" | awk '{print $2}' | tr -d '"' | sort -u > /tmp/tpm_digests.txt

    COMMON_DIGESTS=$(comm -12 /tmp/ccel_digests.txt /tmp/tpm_digests.txt | wc -l)
    CCEL_UNIQUE=$(comm -23 /tmp/ccel_digests.txt /tmp/tpm_digests.txt | wc -l)
    TPM_UNIQUE=$(comm -13 /tmp/ccel_digests.txt /tmp/tpm_digests.txt | wc -l)

    echo "   Common digests (appear in both): $COMMON_DIGESTS"
    echo "   CCEL-only digests: $CCEL_UNIQUE"
    echo "   TPM-only digests: $TPM_UNIQUE"
    echo

    if [ "$COMMON_DIGESTS" -gt 0 ]; then
        echo "   Sample common digests (first 5):"
        comm -12 /tmp/ccel_digests.txt /tmp/tpm_digests.txt | head -5 | nl | sed 's/^/     /'
        echo
    fi
fi

# Explanation section
echo "[5] Understanding the Relationship"
echo "==================================="
echo
echo "CCEL (CC Event Log) - TDX Specific:"
echo "  • Records measurements made by TDX firmware/VMM"
echo "  • Events are extended into RTMR 0-3 (TDX runtime registers)"
echo "  • RTMR values are part of TDX quote (TD Quote)"
echo "  • Used for TDX-specific attestation"
echo "  • Measures: UEFI, kernel, initrd, kernel cmdline, etc."
echo
echo "TPM Event Log - Virtual TPM:"
echo "  • Records measurements made by vTPM"
echo "  • Events are extended into PCR 0-23 (TPM registers)"
echo "  • PCR values are part of TPM quote"
echo "  • Used for traditional TPM attestation"
echo "  • May measure similar or different components"
echo
echo "In a TDX VM with vTPM:"
echo "  • Both logs may coexist"
echo "  • They may measure some of the same components (e.g., kernel)"
echo "  • But extend to different registers (RTMR vs PCR)"
echo "  • TDX provides hardware-level isolation guarantees"
echo "  • vTPM provides compatibility with existing TPM tools"
echo
echo "For attestation:"
echo "  • TDX Quote: Proves code running in hardware-protected TD"
echo "  • TPM Quote: Proves measurements recorded by vTPM"
echo "  • Can use both for defense-in-depth"
echo

echo "Full parsed logs saved to:"
echo "  CCEL: /tmp/ccel_parsed.yaml"
echo "  TPM:  /tmp/tpm_parsed.yaml"
echo "  Digests: /tmp/ccel_digests.txt, /tmp/tpm_digests.txt"
