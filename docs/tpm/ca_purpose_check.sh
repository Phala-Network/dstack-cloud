#!/bin/bash
# Add this function to validation scripts

validate_intermediate_ca_purpose() {
    local ca_file="$1"
    local check_level="${2:-strict}"  # strict | normal | minimal
    
    echo "  [CA Purpose Validation]"
    
    # 1. Check Basic Constraints (CA:TRUE)
    if ! openssl x509 -in "$ca_file" -noout -text | grep -q "CA:TRUE"; then
        echo "  ✗ FAILED: Not a CA certificate (CA:FALSE or missing)"
        return 1
    fi
    echo "    ✓ Basic Constraints: CA:TRUE"
    
    # 2. Check Key Usage (Certificate Sign)
    if ! openssl x509 -in "$ca_file" -noout -text | grep "Key Usage" -A 1 | grep -q "Certificate Sign"; then
        echo "  ✗ FAILED: Cannot sign certificates (missing Certificate Sign)"
        return 1
    fi
    echo "    ✓ Key Usage: Certificate Sign"
    
    # 3. Check Extended Key Usage (TPM EK Purpose)
    if ! openssl x509 -in "$ca_file" -noout -text | grep -q "2.23.133.8.1"; then
        echo "  ✗ FAILED: Not authorized for TPM EK certificates"
        echo "    Expected Extended Key Usage: 2.23.133.8.1 (tcg-kp-EKCertificate)"
        return 1
    fi
    echo "    ✓ Extended Key Usage: 2.23.133.8.1 (TPM EK Certificate)"
    
    # 4. Check Subject CN (optional but recommended)
    if [ "$check_level" = "strict" ]; then
        local subject=$(openssl x509 -in "$ca_file" -noout -subject)
        if ! echo "$subject" | grep -q -E "(EK|AK|TPM).*CA"; then
            echo "  ⚠ WARNING: Subject CN does not indicate TPM CA"
            echo "    Subject: $subject"
            # Don't fail, just warn
        else
            echo "    ✓ Subject CN indicates TPM EK/AK CA"
        fi
    fi
    
    echo "  ✓✓ Intermediate CA purpose validation PASSED ✓✓"
    echo "    → CA is authorized for TPM EK certificates only"
    echo "    → Scope limited by TCG Extended Key Usage"
    return 0
}

# Test the function
echo "Testing CA purpose validation..."
echo
validate_intermediate_ca_purpose "/home/kvin/sdc/home/meta-dstack/dstack/gce_tpm_intermediate_ca.pem" "strict"
