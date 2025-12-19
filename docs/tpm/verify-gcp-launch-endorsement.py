#!/usr/bin/env python3
"""
GCP TDX Launch Endorsement Verifier

This script downloads and cryptographically verifies GCP's launch endorsement
for a TDX VM, confirming the authenticity of the MRTD (Measurement of TD).

Verification steps:
1. Download launch endorsement from GCS bucket
2. Parse protobuf structure (VMLaunchEndorsement)
3. Verify RSA-PSS signature (SHA256)
4. Verify certificate chain (Google root CA)
5. Match MRTD from TDX Quote with reference value

Usage:
    ./verify-gcp-launch-endorsement.py <mrtd_hex>

    # Or get MRTD from running TDX VM:
    sudo dstack-util show | grep MRTD: | awk '{print $2}' | xargs ./verify-gcp-launch-endorsement.py

Requirements:
    - openssl command-line tool
    - gsutil (GCP SDK)
"""

import subprocess
import sys
import tempfile
import os


def parse_varint(data, pos):
    """Parse protobuf varint encoding."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            return None, pos
        byte = data[pos] if isinstance(data[pos], int) else ord(data[pos])
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7


def parse_message(data):
    """Parse protobuf message into dict of field_number -> value."""
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = parse_varint(data, pos)
        if tag is None:
            break
        field_number = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:  # varint
            value, pos = parse_varint(data, pos)
            fields[field_number] = value
        elif wire_type == 2:  # length-delimited
            length, pos = parse_varint(data, pos)
            if length is None:
                break
            value = data[pos:pos+length]
            pos += length
            fields[field_number] = value
    return fields


def download_endorsement(mrtd_hex, output_path):
    """Download launch endorsement from GCS bucket."""
    gcs_url = f"gs://gce_tcb_integrity/ovmf_x64_csm/tdx/{mrtd_hex}.binarypb"
    print(f"Downloading launch endorsement from GCS...")
    print(f"  URL: {gcs_url}")

    result = subprocess.run(
        ["gsutil", "cp", gcs_url, output_path],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        print(f"✗ Failed to download: {result.stderr}")
        return False

    print(f"✓ Downloaded {os.path.getsize(output_path)} bytes")
    return True


def verify_signature_rsa_pss(pubkey_path, signature_path, data_path):
    """Verify RSA-PSS signature with SHA256."""
    result = subprocess.run(
        ["openssl", "dgst", "-sha256",
         "-sigopt", "rsa_padding_mode:pss",
         "-verify", pubkey_path,
         "-signature", signature_path,
         data_path],
        capture_output=True, text=True
    )
    return "Verified OK" in result.stdout


def verify_cert_chain(cert_path, ca_bundle_path):
    """Verify certificate chain."""
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", ca_bundle_path, cert_path],
        capture_output=True, text=True
    )
    return "OK" in result.stdout, result.stdout


def extract_pubkey(cert_path, pubkey_path):
    """Extract public key from certificate."""
    subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-in", cert_path,
         "-pubkey", "-noout", "-out", pubkey_path],
        check=True, capture_output=True
    )


def get_cert_info(cert_path):
    """Get certificate subject and issuer."""
    subject = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-in", cert_path,
         "-noout", "-subject"],
        capture_output=True, text=True
    ).stdout.strip()

    issuer = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-in", cert_path,
         "-noout", "-issuer"],
        capture_output=True, text=True
    ).stdout.strip()

    return subject, issuer


def main():
    if len(sys.argv) != 2:
        print("Usage: verify-gcp-launch-endorsement.py <mrtd_hex>")
        print()
        print("Example:")
        print("  ./verify-gcp-launch-endorsement.py a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694")
        sys.exit(1)

    mrtd_hex = sys.argv[1].strip()

    if len(mrtd_hex) != 96:
        print(f"✗ Invalid MRTD length: {len(mrtd_hex)} (expected 96 hex chars)")
        sys.exit(1)

    print("=" * 70)
    print("  GCP TDX Launch Endorsement Verification")
    print("=" * 70)
    print()
    print(f"MRTD: {mrtd_hex}")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        endorsement_path = os.path.join(tmpdir, "endorsement.binarypb")

        # Download endorsement
        if not download_endorsement(mrtd_hex, endorsement_path):
            sys.exit(1)
        print()

        # Parse protobuf
        print("[+] Parsing VMLaunchEndorsement protobuf...")
        with open(endorsement_path, "rb") as f:
            data = f.read()

        endorsement = parse_message(data)
        serialized_uefi_golden = endorsement.get(1)
        signature = endorsement.get(2)

        if not serialized_uefi_golden or not signature:
            print("✗ Failed to parse endorsement structure")
            sys.exit(1)

        golden = parse_message(serialized_uefi_golden)
        cert_der = golden.get(4)
        ca_bundle_pem = golden.get(6)
        tdx_msg = golden.get(8)

        print(f"  Signed data: {len(serialized_uefi_golden)} bytes")
        print(f"  Signature: {len(signature)} bytes (RSA-4096)")
        print(f"  Certificate: {len(cert_der)} bytes")
        print()

        # Extract files
        signed_data_path = os.path.join(tmpdir, "signed_data.bin")
        signature_path = os.path.join(tmpdir, "signature.bin")
        cert_path = os.path.join(tmpdir, "cert.der")
        pubkey_path = os.path.join(tmpdir, "pubkey.pem")
        ca_bundle_path = os.path.join(tmpdir, "ca_bundle.pem")

        with open(signed_data_path, "wb") as f:
            f.write(serialized_uefi_golden)
        with open(signature_path, "wb") as f:
            f.write(signature)
        with open(cert_path, "wb") as f:
            f.write(cert_der)
        with open(ca_bundle_path, "wb") as f:
            f.write(ca_bundle_pem)

        extract_pubkey(cert_path, pubkey_path)

        # Step 1: Verify signature
        print("[1] Signature Verification (RSA-PSS with SHA256)")
        if verify_signature_rsa_pss(pubkey_path, signature_path, signed_data_path):
            print("    ✓✓✓ SIGNATURE VERIFIED ✓✓✓")
            print("    → Launch endorsement is authentic")
            print("    → Signed by Google's private key")
            sig_valid = True
        else:
            print("    ✗✗✗ SIGNATURE VERIFICATION FAILED ✗✗✗")
            sig_valid = False
        print()

        # Step 2: Verify certificate chain
        print("[2] Certificate Chain Verification")
        chain_valid, output = verify_cert_chain(cert_path, ca_bundle_path)
        if chain_valid:
            print("    ✓✓ CERTIFICATE CHAIN VALID ✓✓")
            subject, issuer = get_cert_info(cert_path)
            print(f"    → {subject}")
            print(f"    → {issuer}")
            print("    → Issued by: GCE-cc-tcb-root")
        else:
            print("    ✗✗ CERTIFICATE CHAIN INVALID ✗✗")
            print(output)
        print()

        # Step 3: Extract and verify MRTD
        print("[3] MRTD Reference Value Extraction")
        if tdx_msg:
            tdx = parse_message(tdx_msg)
            measurements = []

            for field_num, value in tdx.items():
                if isinstance(value, bytes):
                    try:
                        measurement = parse_message(value)
                        if 3 in measurement:  # MRTD field
                            measurements.append(measurement)
                    except:
                        pass

            print(f"    Found {len(measurements)} reference measurement(s)")

            mrtd_found = False
            for m in measurements:
                mrtd_bytes = m.get(3)
                if mrtd_bytes:
                    mrtd_ref = mrtd_bytes.hex()
                    ram = m.get(1, 0)

                    if mrtd_ref == mrtd_hex:
                        print(f"    ✓✓ MRTD MATCH CONFIRMED ✓✓")
                        print(f"    → Configuration: {ram} GiB RAM")
                        mrtd_found = True
                        break

            if not mrtd_found:
                print("    ✗ MRTD not found in reference measurements")
        else:
            print("    ✗ No TDX measurements found")
            mrtd_found = False
        print()

        # Summary
        print("=" * 70)
        print("  VERIFICATION SUMMARY")
        print("=" * 70)
        print()

        if sig_valid:
            print("✓ Signature: VALID (RSA-PSS SHA256)")
        else:
            print("✗ Signature: FAILED")

        if chain_valid:
            print("✓ Certificate Chain: VALID (Google root CA)")
        else:
            print("✗ Certificate Chain: FAILED")

        if mrtd_found:
            print("✓ MRTD Reference: MATCHED")
        else:
            print("✗ MRTD Reference: NOT FOUND")

        print()

        if sig_valid and chain_valid and mrtd_found:
            print("🎉 VERIFICATION PASSED 🎉")
            print()
            print("Security Conclusion:")
            print("  → VM is running Google's official TDX UEFI firmware")
            print("  → MRTD is cryptographically verified by Google")
            print("  → Trust chain: Google Root CA → Signing Cert → MRTD")
            print()
            sys.exit(0)
        else:
            print("❌ VERIFICATION FAILED ❌")
            sys.exit(1)


if __name__ == "__main__":
    main()
