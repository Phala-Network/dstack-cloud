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

import os
import runpy
import sys


def main() -> None:
    here = os.path.dirname(__file__)
    target = os.path.abspath(
        os.path.join(here, "..", "..", "..", "scripts", "bin", "calculate_pcr.py")
    )

    if not os.path.exists(target):
        print(
            f"Error: calculate_pcr.py was moved but target not found: {target}",
            file=sys.stderr,
        )
        sys.exit(1)

    runpy.run_path(target, run_name="__main__")


if __name__ == '__main__':
    main()
