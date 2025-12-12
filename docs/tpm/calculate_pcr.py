#!/usr/bin/env python3
"""
TPM PCR Calculator

This script calculates TPM PCR values by replaying Event Log events or from component hashes.
Useful for pre-calculating expected PCR values for image verification.

Usage:
    # From Event Log file
    ./calculate_pcr.py --eventlog /sys/kernel/security/tpm0/binary_bios_measurements --pcr 0,2,4

    # From UKI binary (calculates PE/COFF Authenticode hash)
    ./calculate_pcr.py --build-pcr2 \
        --bootloader build/tmp/deploy/images/*/dstack-uki.efi \
        --gpt-hash 00b8a357e652623798d1bbd16c375ec90fbed802b4269affa3e78e6eb19386cf \
        --verbose

    # From pre-calculated hashes
    ./calculate_pcr.py --build-pcr2 \
        --bootloader-hash 9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f \
        --gpt-hash 00b8a357e652623798d1bbd16c375ec90fbed802b4269affa3e78e6eb19386cf

    # Show detailed replay
    ./calculate_pcr.py --eventlog eventlog.yaml --pcr 0 --verbose
"""

import argparse
import hashlib
import sys
from typing import List, Optional

try:
    import yaml
except ImportError:
    print("Error: pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


def tpm_extend(pcr_value: bytes, digest: bytes) -> bytes:
    """
    TPM PCR extend operation: PCR_new = SHA256(PCR_old || digest)

    Args:
        pcr_value: Current PCR value (32 bytes)
        digest: Digest to extend with (32 bytes)

    Returns:
        New PCR value (32 bytes)
    """
    if len(pcr_value) != 32:
        raise ValueError(f"PCR value must be 32 bytes, got {len(pcr_value)}")
    if len(digest) != 32:
        raise ValueError(f"Digest must be 32 bytes, got {len(digest)}")

    return hashlib.sha256(pcr_value + digest).digest()


def get_sha256_digest(event: dict) -> Optional[bytes]:
    """Extract SHA256 digest from event"""
    if 'Digests' in event:
        for d in event['Digests']:
            if d.get('AlgorithmId') == 'sha256':
                digest_hex = d.get('Digest', '')
                if digest_hex:
                    return bytes.fromhex(digest_hex)
    return None


def calculate_pcr_from_eventlog(events: List[dict], pcr_index: int, verbose: bool = False) -> bytes:
    """
    Calculate PCR value by replaying events from Event Log

    Args:
        events: List of events from TPM Event Log
        pcr_index: PCR index to calculate (0-23)
        verbose: Print detailed replay information

    Returns:
        Final PCR value (32 bytes)
    """
    pcr = b'\x00' * 32  # PCRs start at zero

    pcr_events = [e for e in events if e.get('PCRIndex') == pcr_index]

    if verbose:
        print(f"\n=== PCR {pcr_index} Calculation ===")
        print(f"Initial PCR: {pcr.hex()}")
        print(f"Found {len(pcr_events)} events\n")

    for e in pcr_events:
        # Skip EV_NO_ACTION events - they don't extend PCRs
        event_type = e.get('EventType', 'UNKNOWN')
        if event_type == 'EV_NO_ACTION':
            if verbose:
                event_num = e.get('EventNum', '?')
                print(f"Event {event_num:3d} ({event_type:35s}) [SKIPPED - no PCR extend]")
            continue

        digest = get_sha256_digest(e)
        if digest:
            pcr = tpm_extend(pcr, digest)
            if verbose:
                event_num = e.get('EventNum', '?')
                print(f"Event {event_num:3d} ({event_type:35s})")
                print(f"  Digest:  {digest.hex()}")
                print(f"  PCR:     {pcr.hex()}\n")

    return pcr


def calculate_pcr0_from_firmware_version(
    firmware_version: str = "GCE Virtual Firmware v2",
    nonhost_info: bytes = b'GCE NonHostInfo\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    separator_hash: str = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
    verbose: bool = False
) -> bytes:
    """
    Calculate PCR 0 from known GCP OVMF firmware version strings

    Args:
        firmware_version: OVMF firmware version string (UTF-16LE encoded)
        nonhost_info: GCE NonHostInfo metadata bytes
        separator_hash: EV_SEPARATOR digest (standard value)
        verbose: Print detailed calculation

    Returns:
        PCR 0 value (32 bytes)
    """
    pcr = b'\x00' * 32

    if verbose:
        print("\n=== PCR 0 Calculation (From Firmware Version) ===")
        print(f"Initial PCR: {pcr.hex()}\n")

    # Event 3: EV_S_CRTM_VERSION - Firmware version string (UTF-16LE + null terminator)
    firmware_utf16le = firmware_version.encode('utf-16-le') + b'\x00\x00'
    digest = hashlib.sha256(firmware_utf16le).digest()
    pcr = tpm_extend(pcr, digest)
    if verbose:
        print(f"EV_S_CRTM_VERSION: '{firmware_version}'")
        print(f"  UTF-16LE bytes: {firmware_utf16le.hex()}")
        print(f"  Digest:  {digest.hex()}")
        print(f"  PCR:     {pcr.hex()}\n")

    # Event 4: EV_NONHOST_INFO - GCE NonHostInfo metadata
    digest = hashlib.sha256(nonhost_info).digest()
    pcr = tpm_extend(pcr, digest)
    if verbose:
        print(f"EV_NONHOST_INFO")
        print(f"  Bytes:   {nonhost_info.hex()}")
        print(f"  Digest:  {digest.hex()}")
        print(f"  PCR:     {pcr.hex()}\n")

    # Event 20: EV_SEPARATOR - Standard separator
    digest = bytes.fromhex(separator_hash)
    pcr = tpm_extend(pcr, digest)
    if verbose:
        print(f"EV_SEPARATOR")
        print(f"  Digest:  {digest.hex()}")
        print(f"  PCR:     {pcr.hex()}\n")

    return pcr


def calculate_pcr2_from_components(
    bootloader_hash: str,
    gpt_hash: Optional[str] = None,
    separator_hash: str = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
    verbose: bool = False
) -> bytes:
    """
    Calculate PCR 2 from known component hashes (for pre-calculation)

    Args:
        bootloader_hash: PE/COFF Authenticode SHA256 hash of bootloader (e.g., UKI)
        gpt_hash: SHA256 of UEFI_GPT_DATA structure (optional)
        separator_hash: EV_SEPARATOR digest (standard value)
        verbose: Print detailed calculation

    Returns:
        PCR 2 value (32 bytes)
    """
    pcr = b'\x00' * 32

    if verbose:
        print("\n=== PCR 2 Calculation (From Components) ===")
        print(f"Initial PCR: {pcr.hex()}\n")

    # Event 1: EV_SEPARATOR (end of firmware phase)
    digest = bytes.fromhex(separator_hash)
    pcr = tpm_extend(pcr, digest)
    if verbose:
        print(f"EV_SEPARATOR")
        print(f"  Digest:  {digest.hex()}")
        print(f"  PCR:     {pcr.hex()}\n")

    # Event 2: EV_EFI_GPT_EVENT (GPT partition table) - if provided
    if gpt_hash:
        digest = bytes.fromhex(gpt_hash)
        pcr = tpm_extend(pcr, digest)
        if verbose:
            print(f"EV_EFI_GPT_EVENT")
            print(f"  Digest:  {digest.hex()}")
            print(f"  PCR:     {pcr.hex()}\n")

    # Event 3: EV_EFI_BOOT_SERVICES_APPLICATION (bootloader)
    digest = bytes.fromhex(bootloader_hash)
    pcr = tpm_extend(pcr, digest)
    if verbose:
        print(f"EV_EFI_BOOT_SERVICES_APPLICATION (bootloader)")
        print(f"  Digest:  {digest.hex()}")
        print(f"  PCR:     {pcr.hex()}\n")

    return pcr


def hash_file(filepath: str) -> str:
    """Calculate SHA256 hash of a file"""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def read_le_u16(data: bytes, offset: int) -> int:
    """Read little-endian uint16 from bytes"""
    import struct
    return struct.unpack('<H', data[offset:offset+2])[0]


def read_le_u32(data: bytes, offset: int) -> int:
    """Read little-endian uint32 from bytes"""
    import struct
    return struct.unpack('<I', data[offset:offset+4])[0]


def authenticode_hash(filepath: str) -> str:
    """
    Calculate PE/COFF Authenticode SHA256 hash (TPM Event Log compatible)

    This implements the PE/COFF image hashing specified in:
    "PE/COFF Specification 8.0 Appendix A" (Authenticode)

    Based on dstack-mr/src/kernel.rs::authenticode_sha384_hash
    Converted to SHA256 for TPM Event Log compatibility.

    Args:
        filepath: Path to PE/COFF file (e.g., UKI .efi file)

    Returns:
        Hex-encoded SHA256 digest
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    # Read DOS header
    lfanew_offset = 0x3c
    lfanew = read_le_u32(data, lfanew_offset)

    # Verify PE signature
    pe_sig_offset = lfanew
    pe_sig = read_le_u32(data, pe_sig_offset)
    IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
    if pe_sig != IMAGE_NT_SIGNATURE:
        raise ValueError(f"Invalid PE signature in {filepath}")

    # Read COFF header
    coff_header_offset = pe_sig_offset + 4
    optional_header_size = read_le_u16(data, coff_header_offset + 16)

    # Read Optional header magic
    optional_header_offset = coff_header_offset + 20
    magic = read_le_u16(data, optional_header_offset)

    is_pe32_plus = (magic == 0x20b)

    # Calculate offsets for excluded regions (checksum and cert directory)
    checksum_offset = optional_header_offset + 64
    checksum_end = checksum_offset + 4

    data_dir_offset = optional_header_offset + (112 if is_pe32_plus else 96)
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    cert_dir_offset = data_dir_offset + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8)
    cert_dir_end = cert_dir_offset + 8

    size_of_headers_offset = optional_header_offset + 60
    size_of_headers = read_le_u32(data, size_of_headers_offset)

    # Hash header (excluding checksum and cert directory)
    hasher = hashlib.sha256()
    hasher.update(data[0:checksum_offset])
    hasher.update(data[checksum_end:cert_dir_offset])
    hasher.update(data[cert_dir_end:size_of_headers])

    sum_of_bytes_hashed = size_of_headers

    # Read section table
    num_sections_offset = coff_header_offset + 2
    num_sections = read_le_u16(data, num_sections_offset)

    section_table_offset = optional_header_offset + optional_header_size
    section_size = 40

    sections = []
    for i in range(num_sections):
        section_offset = section_table_offset + (i * section_size)

        ptr_raw_data_offset = section_offset + 20
        ptr_raw_data = read_le_u32(data, ptr_raw_data_offset)

        size_raw_data_offset = section_offset + 16
        size_raw_data = read_le_u32(data, size_raw_data_offset)

        if size_raw_data > 0:
            sections.append((ptr_raw_data, size_raw_data))

    # Sort sections by offset
    sections.sort(key=lambda x: x[0])

    # Hash sections
    for offset, size in sections:
        start = offset
        end = start + size

        if end <= len(data):
            hasher.update(data[start:end])
        else:
            available_size = max(0, len(data) - start)
            if available_size > 0:
                hasher.update(data[start:start + available_size])

        sum_of_bytes_hashed += size

    file_size = len(data)

    # Read certificate table info
    cert_table_addr = read_le_u32(data, cert_dir_offset)
    cert_table_size = read_le_u32(data, cert_dir_offset + 4)

    # Hash trailing data (excluding certificate table)
    if cert_table_addr > 0 and cert_table_size > 0 and file_size > sum_of_bytes_hashed:
        trailing_data_len = file_size - sum_of_bytes_hashed

        if trailing_data_len > cert_table_size:
            hashed_trailing_len = trailing_data_len - cert_table_size
            trailing_start = sum_of_bytes_hashed

            if trailing_start + hashed_trailing_len <= len(data):
                hasher.update(data[trailing_start:trailing_start + hashed_trailing_len])

    # Add padding to align to 8 bytes
    remainder = file_size % 8
    if remainder != 0:
        padding = bytes([0] * (8 - remainder))
        hasher.update(padding)

    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Calculate TPM PCR values from Event Log or component hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Event Log mode
    parser.add_argument('--eventlog', metavar='FILE',
                        help='Path to Event Log YAML file (from tpm2_eventlog)')
    parser.add_argument('--pcr', metavar='LIST',
                        help='Comma-separated list of PCR indices (e.g., "0,2,4")')

    # Pre-calculation modes
    parser.add_argument('--build-pcr0', action='store_true',
                        help='Calculate PCR 0 from GCP OVMF firmware version')
    parser.add_argument('--firmware-version', metavar='STRING',
                        default='GCE Virtual Firmware v2',
                        help='OVMF firmware version string (default: "GCE Virtual Firmware v2")')

    parser.add_argument('--build-pcr2', action='store_true',
                        help='Calculate PCR 2 from build artifacts')
    parser.add_argument('--bootloader', metavar='FILE',
                        help='Path to PE/COFF bootloader binary (e.g., UKI .efi file)')
    parser.add_argument('--bootloader-hash', metavar='SHA256',
                        help='PE/COFF Authenticode SHA256 hash of bootloader binary')
    parser.add_argument('--gpt-hash', metavar='SHA256',
                        help='SHA256 hash of GPT partition table (optional)')

    # Output options
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed calculation steps')
    parser.add_argument('--format', choices=['hex', 'json'], default='hex',
                        help='Output format (default: hex)')

    args = parser.parse_args()

    # Validate arguments
    if not args.eventlog and not args.build_pcr0 and not args.build_pcr2:
        parser.error("Must specify either --eventlog, --build-pcr0, or --build-pcr2")

    results = {}

    # Pre-calculate PCR 0
    if args.build_pcr0:
        pcr_value = calculate_pcr0_from_firmware_version(
            firmware_version=args.firmware_version,
            verbose=args.verbose
        )
        results[0] = pcr_value.hex()

    # Event Log mode
    if args.eventlog:
        if not args.pcr:
            parser.error("--eventlog requires --pcr")

        # Load Event Log
        try:
            with open(args.eventlog) as f:
                data = yaml.safe_load(f)
                events = data['events']
        except Exception as e:
            print(f"Error loading Event Log: {e}", file=sys.stderr)
            sys.exit(1)

        # Calculate each requested PCR
        pcr_list = [int(p.strip()) for p in args.pcr.split(',')]
        for pcr_idx in pcr_list:
            pcr_value = calculate_pcr_from_eventlog(events, pcr_idx, args.verbose)
            results[pcr_idx] = pcr_value.hex()

    # Build artifact mode
    if args.build_pcr2:
        # Get bootloader hash (PE/COFF Authenticode hash)
        if args.bootloader:
            bootloader_hash = authenticode_hash(args.bootloader)
            if args.verbose:
                print(f"Calculated PE/COFF Authenticode hash: {bootloader_hash}")
        elif args.bootloader_hash:
            bootloader_hash = args.bootloader_hash
        else:
            parser.error("--build-pcr2 requires --bootloader or --bootloader-hash")

        pcr_value = calculate_pcr2_from_components(
            bootloader_hash=bootloader_hash,
            gpt_hash=args.gpt_hash,
            verbose=args.verbose
        )
        results[2] = pcr_value.hex()

    # Output results
    if args.format == 'hex':
        print("\n=== Final PCR Values ===")
        for pcr_idx in sorted(results.keys()):
            print(f"PCR {pcr_idx}: 0x{results[pcr_idx].upper()}")
    elif args.format == 'json':
        import json
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
