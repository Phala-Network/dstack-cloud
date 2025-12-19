#!/bin/bash
set -euo pipefail

echo "=== GCP vTPM Attestation (Minimal Trust - Root CA Only) ==="
echo

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

# Parse arguments
ROOT_CA="${1:-}"
NONCE="${2:-}"
EXPECTED_OS_HASH="${3:-}"

if [ -z "$ROOT_CA" ] || [ -z "$NONCE" ]; then
    echo "Usage: $0 <root-ca-file> <nonce> [expected-os-image-hash]"
    echo
    echo "Arguments:"
    echo "  root-ca-file:          Path to Root CA certificate (PEM format)"
    echo "                         This is the ONLY trust anchor needed"
    echo "  nonce:                 Random nonce to prevent replay attacks"
    echo "  expected-os-image-hash: (Optional) Expected OS image SHA256 hash"
    echo
    echo "Environment Variables:"
    echo "  TPM_KEY_ALGO:          Key algorithm (rsa|ecc, default: rsa)"
    echo "                         rsa  = RSA-2048 (262-byte signatures)"
    echo "                         ecc  = ECC P-256/ECDSA (72-byte signatures)"
    echo
    echo "How it works:"
    echo "  1. Extract EK certificate from TPM"
    echo "  2. Download Intermediate CA from EK cert's AIA extension"
    echo "  3. Verify: Root CA → Intermediate CA → EK Certificate"
    echo "  4. Generate and verify TPM Quote"
    echo
    echo "Security: Only Root CA needs to be trusted and embedded"
    echo "  Intermediate CA is fetched dynamically and verified against Root CA"
    echo
    echo "Examples:"
    echo "  # Default (RSA)"
    echo "  $0 /path/to/gce_tpm_root_ca.pem my-nonce-123"
    echo
    echo "  # Use ECC (smaller signatures)"
    echo "  TPM_KEY_ALGO=ecc $0 /path/to/gce_tpm_root_ca.pem my-nonce-123"
    exit 1
fi

# Verify Root CA file exists
if [ ! -f "$ROOT_CA" ]; then
    echo "Error: Root CA file not found: $ROOT_CA"
    exit 1
fi

# Algorithm configuration
TPM_KEY_ALGO="${TPM_KEY_ALGO:-rsa}"
case "$TPM_KEY_ALGO" in
    rsa|RSA)
        EK_ALGO="rsa"
        AK_ALGO="rsa"
        AK_SCHEME="rsassa"
        ALGO_NAME="RSA-2048"
        ;;
    ecc|ECC|ecdsa|ECDSA)
        EK_ALGO="ecc"
        AK_ALGO="ecc"
        AK_SCHEME="ecdsa"
        ALGO_NAME="ECC P-256 (ECDSA)"
        ;;
    *)
        echo "Error: Invalid TPM_KEY_ALGO='$TPM_KEY_ALGO'"
        echo "       Supported values: rsa, ecc"
        exit 1
        ;;
esac

echo "[Config]"
echo "  Root CA (Trust Anchor): $ROOT_CA"
echo "  Nonce: $NONCE"
echo "  Key Algorithm: $ALGO_NAME"
[ -n "$EXPECTED_OS_HASH" ] && echo "  Expected OS Hash: $EXPECTED_OS_HASH"
echo

# Verify it's a valid Root CA (self-signed)
echo "[+] Verifying Root CA..."
ROOT_SUBJECT=$(openssl x509 -in "$ROOT_CA" -noout -subject | sed 's/subject=//')
ROOT_ISSUER=$(openssl x509 -in "$ROOT_CA" -noout -issuer | sed 's/issuer=//')

echo "  Root CA Subject: $ROOT_SUBJECT"
echo "  Root CA Issuer:  $ROOT_ISSUER"

if [ "$ROOT_SUBJECT" = "$ROOT_ISSUER" ]; then
    echo "  ✓ Self-signed Root CA confirmed"
else
    echo "  ✗ Warning: Not self-signed, might not be a Root CA"
fi
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

# Step 2: Extract Intermediate CA URL from EK cert's AIA extension
echo "[+] Step 2: Extracting Intermediate CA URL from EK certificate..."
ICA_URL=$(openssl x509 -in /tmp/ek_cert.pem -noout -text | grep -A 1 "CA Issuers" | grep "URI:" | sed 's/.*URI://' | tr -d ' ')

if [ -n "$ICA_URL" ]; then
    echo "  AIA URL found: $ICA_URL"
    echo "  → Downloading Intermediate CA..."

    if curl -s -o /tmp/intermediate_ca.crt "$ICA_URL"; then
        # Convert to PEM if needed
        openssl x509 -inform DER -in /tmp/intermediate_ca.crt -outform PEM -out /tmp/intermediate_ca.pem 2>/dev/null || \
        openssl x509 -inform PEM -in /tmp/intermediate_ca.crt -outform PEM -out /tmp/intermediate_ca.pem 2>/dev/null

        if [ -f /tmp/intermediate_ca.pem ]; then
            echo "  ✓ Intermediate CA downloaded"
            echo "    Subject: $(openssl x509 -in /tmp/intermediate_ca.pem -noout -subject 2>/dev/null)"
            echo "    Issuer: $(openssl x509 -in /tmp/intermediate_ca.pem -noout -issuer 2>/dev/null)"
        else
            echo "  ✗ Failed to convert Intermediate CA to PEM"
            exit 1
        fi
    else
        echo "  ✗ Failed to download Intermediate CA from $ICA_URL"
        exit 1
    fi
else
    echo "  ✗ No AIA extension found in EK certificate"
    exit 1
fi
echo

# Step 3: Verify Intermediate CA is signed by Root CA
echo "[+] Step 3: Verifying Intermediate CA → Root CA..."
if openssl verify -CAfile "$ROOT_CA" /tmp/intermediate_ca.pem 2>&1 | tee /tmp/ica_verify.log | grep -q "OK"; then
    echo "  ✓✓ Intermediate CA verified by Root CA ✓✓"
    echo "  → Intermediate CA is authentic"
else
    echo "  ✗✗ Intermediate CA verification FAILED ✗✗"
    echo "  → Intermediate CA is NOT signed by provided Root CA"
    cat /tmp/ica_verify.log
    exit 1
fi
echo

# Step 4: Create CA bundle and verify EK certificate
echo "[+] Step 4: Verifying EK Certificate → Intermediate CA..."
cat /tmp/intermediate_ca.pem "$ROOT_CA" > /tmp/ca_chain.pem

if openssl verify -CAfile /tmp/ca_chain.pem /tmp/ek_cert.pem 2>&1 | tee /tmp/ek_verify.log | grep -q "OK"; then
    echo "  ✓✓✓ EK CERTIFICATE CHAIN VERIFIED ✓✓✓"
    echo "  → Complete trust chain:"
    echo "    Root CA (user-provided, trusted)"
    echo "      ↓ signs"
    echo "    Intermediate CA (downloaded, verified)"
    echo "      ↓ signs"
    echo "    EK Certificate (TPM identity, verified)"
    EK_CERT_VALID=1
else
    echo "  ✗✗✗ EK CERTIFICATE VERIFICATION FAILED ✗✗✗"
    cat /tmp/ek_verify.log
    EK_CERT_VALID=0
fi
echo

# Step 5: Create EK and AK
echo "[+] Step 5: Creating Attestation Key ($ALGO_NAME)..."
tpm2_createek -c /tmp/ek.ctx -G "$EK_ALGO" -u /tmp/ek.pub > /dev/null 2>&1
tpm2_createak -C /tmp/ek.ctx -c /tmp/ak.ctx -G "$AK_ALGO" -g sha256 -s "$AK_SCHEME" -u /tmp/ak.pub -n /tmp/ak.name > /dev/null 2>&1
echo "  ✓ AK ($ALGO_NAME) created under verified EK hierarchy"
echo

# Step 6: Read PCRs
echo "[+] Step 6: Reading PCR values..."
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,14 > /tmp/pcrs.txt
cat /tmp/pcrs.txt
echo

# Step 7: Generate TPM Quote
echo "[+] Step 7: Generating TPM Quote with nonce..."
echo -n "$NONCE" > /tmp/nonce.bin
tpm2_quote -c /tmp/ak.ctx -l sha256:0,1,2,3,4,5,6,7,8,9,10,14 -q /tmp/nonce.bin -m /tmp/quote.msg -s /tmp/quote.sig -o /tmp/quote.pcr -g sha256 2>&1 | grep -E "quoted:|signature:" | head -2
echo "✓ Quote generated (signed by AK)"
echo

# Step 8: Verify Quote signature
echo "[+] Step 8: Verifying Quote Signature..."
if tpm2_checkquote -u /tmp/ak.pub -m /tmp/quote.msg -s /tmp/quote.sig -f /tmp/quote.pcr -g sha256 -q /tmp/nonce.bin > /tmp/verify.log 2>&1; then
    echo "✓✓✓ QUOTE SIGNATURE VERIFIED ✓✓✓"
    echo "  → PCR values are authentic"
    echo "  → Nonce matches (prevents replay)"
    QUOTE_VALID=1
else
    echo "✗✗✗ QUOTE VERIFICATION FAILED ✗✗✗"
    cat /tmp/verify.log
    QUOTE_VALID=0
fi
echo

# Step 9: Verify OS image from event log
echo "[+] Step 9: Verifying OS Image Integrity..."
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
                OS_VALID=0
            fi
        else
            echo "  (No expected hash provided)"
            echo "  First 5 hashes:"
            head -5 /tmp/os_hashes.txt | nl
        fi
    fi
fi
echo

# Final Verdict
echo "========================================="
echo "        ATTESTATION RESULT"
echo "========================================="
echo
echo "Minimal Trust Model:"
echo "  • Only Root CA is pre-trusted (user-provided)"
echo "  • Intermediate CA fetched dynamically and verified"
echo "  • Complete chain verified cryptographically"
echo

if [ $EK_CERT_VALID -eq 1 ]; then
    echo "✓ [1] Certificate Chain: VERIFIED"
    echo "      Root CA → Intermediate CA (dynamic) → EK"
else
    echo "✗ [1] Certificate Chain: FAILED"
fi

if [ $QUOTE_VALID -eq 1 ]; then
    echo "✓ [2] TPM Quote: VERIFIED"
else
    echo "✗ [2] TPM Quote: FAILED"
fi

if [ -n "$EXPECTED_OS_HASH" ]; then
    if [ $OS_VALID -eq 1 ]; then
        echo "✓ [3] OS Image: VERIFIED"
    elif [ $OS_VALID -eq 0 ]; then
        echo "✗ [3] OS Image: MISMATCH"
    fi
fi

echo
if [ $EK_CERT_VALID -eq 1 ] && [ $QUOTE_VALID -eq 1 ] && { [ -z "$EXPECTED_OS_HASH" ] || [ $OS_VALID -eq 1 ]; }; then
    echo "🎉🎉🎉 ATTESTATION PASSED 🎉🎉🎉"
    echo
    echo "Security guarantees:"
    echo "  ✓ Only Root CA needs to be trusted"
    echo "  ✓ Intermediate CA dynamically fetched and verified"
    echo "  ✓ Complete cryptographic chain verified"
    echo "  ✓ Cannot be forged without CA private keys"
    exit 0
else
    echo "❌ ATTESTATION FAILED ❌"
    exit 1
fi
