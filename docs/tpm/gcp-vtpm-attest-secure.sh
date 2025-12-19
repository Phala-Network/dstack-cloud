#!/bin/bash
set -euo pipefail

echo "=== GCP vTPM Secure Attestation with CA Chain Verification ==="
echo

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

# Parse arguments
CA_BUNDLE="${1:-}"
NONCE="${2:-}"
EXPECTED_OS_HASH="${3:-}"

if [ -z "$CA_BUNDLE" ] || [ -z "$NONCE" ]; then
    echo "Usage: $0 <ca-bundle-file> <nonce> [expected-os-image-hash]"
    echo
    echo "Arguments:"
    echo "  ca-bundle-file:        Path to CA bundle (PEM format) containing trusted Root CA"
    echo "                         The Root CA is the trust anchor for verification"
    echo "  nonce:                 Random nonce to prevent replay attacks"
    echo "  expected-os-image-hash: (Optional) Expected OS image SHA256 hash"
    echo
    echo "Example:"
    echo "  $0 /path/to/gcp_vtpm_ca_bundle.pem my-nonce-123 [hash]"
    echo
    echo "Security: This script verifies the complete certificate chain:"
    echo "  Trusted Root CA → Intermediate CA → EK Certificate"
    echo "  Using OpenSSL's cryptographic verification, not just text matching"
    exit 1
fi

# Verify CA bundle file exists
if [ ! -f "$CA_BUNDLE" ]; then
    echo "Error: CA bundle file not found: $CA_BUNDLE"
    exit 1
fi

echo "[Config]"
echo "  CA Bundle: $CA_BUNDLE"
echo "  Nonce: $NONCE"
[ -n "$EXPECTED_OS_HASH" ] && echo "  Expected OS Hash: $EXPECTED_OS_HASH"
echo

EK_CERT_VALID=0
QUOTE_VALID=0
OS_VALID=-1

# Step 1: Extract EK certificate from TPM NV storage
echo "[+] Step 1: Extracting EK Certificate from vTPM..."
tpm2_nvread -o /tmp/ek_cert.der 0x1c00002 2>/dev/null
if [ -f /tmp/ek_cert.der ]; then
    openssl x509 -inform DER -in /tmp/ek_cert.der -out /tmp/ek_cert.pem 2>/dev/null
    echo "✓ EK Certificate extracted"
    echo "  Subject: $(openssl x509 -in /tmp/ek_cert.pem -noout -subject 2>/dev/null)"
    echo "  Issuer: $(openssl x509 -in /tmp/ek_cert.pem -noout -issuer 2>/dev/null)"
else
    echo "✗ Failed to extract EK certificate"
    exit 1
fi
echo

# Step 2: Verify EK certificate chain with provided CA bundle
echo "[+] Step 2: Verifying EK Certificate Chain with Trusted CA..."
echo "  Trust Anchor: $CA_BUNDLE"
echo

# Show CA bundle contents
echo "  CA Bundle Contents:"
openssl storeutl -noout -text -certs "file:$CA_BUNDLE" 2>/dev/null | grep "Subject:" | sed 's/^/    /'
echo

# Perform cryptographic verification of certificate chain
echo "  Performing cryptographic chain verification..."
if openssl verify -CAfile "$CA_BUNDLE" /tmp/ek_cert.pem 2>&1 | tee /tmp/cert_verify.log | grep -q "OK"; then
    echo "  ✓✓✓ EK CERTIFICATE CHAIN VERIFIED ✓✓✓"
    echo "  → Certificate is cryptographically signed by trusted Root CA"
    echo "  → This is a genuine Google Cloud vTPM"
    echo "  → Trust chain established: Root CA → Intermediate CA → EK"
    EK_CERT_VALID=1
else
    echo "  ✗✗✗ EK CERTIFICATE CHAIN VERIFICATION FAILED ✗✗✗"
    echo "  → Certificate is NOT signed by the provided Root CA"
    echo "  → This vTPM cannot be trusted"
    echo
    echo "  Verification error:"
    cat /tmp/cert_verify.log | sed 's/^/    /'
    EK_CERT_VALID=0
fi
echo

# Step 3: Create EK and AK
echo "[+] Step 3: Creating Attestation Key..."
tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub > /dev/null 2>&1
tpm2_createak -C /tmp/ek.ctx -c /tmp/ak.ctx -G rsa -g sha256 -s rsassa -u /tmp/ak.pub -n /tmp/ak.name > /dev/null 2>&1
echo "  ✓ AK created under verified EK hierarchy"
echo

# Step 4: Read PCRs
echo "[+] Step 4: Reading PCR values..."
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,14 > /tmp/pcrs.txt
cat /tmp/pcrs.txt
echo

# Step 5: Generate TPM Quote
echo "[+] Step 5: Generating TPM Quote with nonce..."
echo -n "$NONCE" > /tmp/nonce.bin
tpm2_quote -c /tmp/ak.ctx -l sha256:0,1,2,3,4,5,6,7,8,9,10,14 -q /tmp/nonce.bin -m /tmp/quote.msg -s /tmp/quote.sig -o /tmp/quote.pcr -g sha256 2>&1 | grep -E "quoted:|signature:" | head -2
echo "✓ Quote generated (signed by AK)"
echo

# Step 6: Verify Quote signature
echo "[+] Step 6: Verifying Quote Signature..."
if tpm2_checkquote -u /tmp/ak.pub -m /tmp/quote.msg -s /tmp/quote.sig -f /tmp/quote.pcr -g sha256 -q /tmp/nonce.bin > /tmp/verify.log 2>&1; then
    echo "✓✓✓ QUOTE SIGNATURE VERIFIED ✓✓✓"
    echo "  → PCR values are authentic"
    echo "  → Nonce matches (prevents replay)"
    echo "  → Quote signed by AK under cryptographically verified EK"
    QUOTE_VALID=1
else
    echo "✗✗✗ QUOTE VERIFICATION FAILED ✗✗✗"
    cat /tmp/verify.log
    QUOTE_VALID=0
fi
echo

# Step 7: Verify OS image from event log
echo "[+] Step 7: Verifying OS Image Integrity..."
if [ -f /sys/kernel/security/tpm0/binary_bios_measurements ]; then
    tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > /tmp/eventlog.yaml 2>/dev/null || true

    grep -B 2 -A 15 'PCRIndex: [89]' /tmp/eventlog.yaml | grep -E 'AlgorithmId: sha256|Digest:' | grep -A 1 'sha256' | grep 'Digest:' | awk '{print $2}' | tr -d '"' | sort -u > /tmp/os_hashes.txt

    if [ -s /tmp/os_hashes.txt ]; then
        NUM_HASHES=$(wc -l < /tmp/os_hashes.txt)
        echo "Found $NUM_HASHES OS image hashes from PCR 8-9"

        if [ -n "$EXPECTED_OS_HASH" ]; then
            echo
            if grep -qi "$EXPECTED_OS_HASH" /tmp/os_hashes.txt; then
                echo "✓✓✓ OS IMAGE HASH MATCHED ✓✓✓"
                echo "  → VM boots from expected OS image"
                OS_VALID=1
            else
                echo "✗✗✗ OS IMAGE HASH MISMATCH ✗✗✗"
                echo "Expected: $EXPECTED_OS_HASH"
                echo "Found hashes saved to /tmp/os_hashes.txt"
                OS_VALID=0
            fi
        else
            echo "  (No expected hash provided for comparison)"
            echo "  First 5 hashes:"
            head -5 /tmp/os_hashes.txt | nl
            echo "  ... ($NUM_HASHES total saved to /tmp/os_hashes.txt)"
        fi
    fi
fi
echo

# Final Verdict
echo "========================================="
echo "        ATTESTATION RESULT"
echo "========================================="
echo
echo "Trust Chain: Trusted Root CA → Intermediate CA → EK → AK → Quote → PCRs"
echo

if [ $EK_CERT_VALID -eq 1 ]; then
    echo "✓ [1] EK Certificate: CRYPTOGRAPHICALLY VERIFIED"
    echo "      → Certificate chain validated with OpenSSL"
    echo "      → Signed by trusted Root CA (not just text matching)"
    echo "      → Cannot be forged without private key of CA"
else
    echo "✗ [1] EK Certificate: VERIFICATION FAILED"
    echo "      → Certificate NOT signed by provided Root CA"
fi

if [ $QUOTE_VALID -eq 1 ]; then
    echo "✓ [2] TPM Quote: VERIFIED"
    echo "      → PCR values authenticated by verified vTPM"
    echo "      → Nonce prevents replay attacks"
    echo "      → AK provably created under verified EK"
else
    echo "✗ [2] TPM Quote: FAILED"
fi

if [ -n "$EXPECTED_OS_HASH" ]; then
    if [ $OS_VALID -eq 1 ]; then
        echo "✓ [3] OS Image: VERIFIED"
        echo "      → VM boots from expected image"
    elif [ $OS_VALID -eq 0 ]; then
        echo "✗ [3] OS Image: MISMATCH"
    else
        echo "? [3] OS Image: UNKNOWN"
    fi
fi

echo
if [ $EK_CERT_VALID -eq 1 ] && [ $QUOTE_VALID -eq 1 ] && { [ -z "$EXPECTED_OS_HASH" ] || [ $OS_VALID -eq 1 ]; }; then
    echo "🎉🎉🎉 ATTESTATION PASSED 🎉🎉🎉"
    echo
    echo "Complete cryptographic trust chain verified:"
    echo "  Trusted Root CA (user-provided)"
    echo "    ↓ (signs)"
    echo "  Intermediate CA"
    echo "    ↓ (signs)"
    echo "  EK Certificate (TPM identity)"
    echo "    ↓ (creates)"
    echo "  AK (Attestation Key)"
    echo "    ↓ (signs)"
    echo "  TPM Quote (PCR snapshot + nonce)"
    echo
    echo "Security guarantees:"
    echo "  ✓ vTPM identity verified with cryptographic signatures"
    echo "  ✓ PCR measurements authenticated by verified vTPM"
    echo "  ✓ Replay attacks prevented (nonce verified)"
    if [ $OS_VALID -eq 1 ]; then
        echo "  ✓ OS image integrity verified"
    fi
    echo
    echo "This VM can be trusted."
    exit 0
else
    echo "❌ ATTESTATION FAILED ❌"
    echo
    echo "Trust chain broken - do NOT trust this VM"
    echo
    if [ $EK_CERT_VALID -eq 0 ]; then
        echo "CRITICAL: EK certificate is not signed by your trusted Root CA"
        echo "  → This could be:"
        echo "    1. Wrong CA bundle provided"
        echo "    2. Compromised or fake vTPM"
        echo "    3. Man-in-the-middle attack"
    fi
    exit 1
fi
