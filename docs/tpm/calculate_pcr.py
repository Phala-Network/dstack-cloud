#!/usr/bin/env python3
"""
TPM PCR Calculator

This script calculates TPM PCR values by replaying Event Log events or from component hashes.
Useful for pre-calculating expected PCR values for image verification.

Usage:
    # From Event Log file
    ./calculate_pcr.py --eventlog /sys/kernel/security/tpm0/binary_bios_measurements --pcr 0,2,4

    # From component hashes (build artifacts)
    ./calculate_pcr.py --build-pcr2 \
        --bootloader-hash <sha256> \
        --gpt-hash <sha256>

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
        bootloader_hash: SHA256 of bootloader binary (e.g., GRUB EFI)
        gpt_hash: SHA256 of GPT partition table (optional)
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
                        help='Path to bootloader binary (e.g., grub-efi-bootx64.efi)')
    parser.add_argument('--bootloader-hash', metavar='SHA256',
                        help='SHA256 hash of bootloader binary')
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
        # Get bootloader hash
        if args.bootloader:
            bootloader_hash = hash_file(args.bootloader)
            if args.verbose:
                print(f"Calculated bootloader hash: {bootloader_hash}")
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
