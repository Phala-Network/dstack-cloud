// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Integration test: verify Nitro Enclave attestation end-to-end

use dstack_attest::attestation::{DstackVerifiedReport, VersionedAttestation};
use futures::executor::block_on;
use std::time::{Duration, SystemTime};

// Real Nitro Enclave attestation captured from an enclave
const NITRO_ATTESTATION_BIN: &[u8] = include_bytes!("nitro_attestation.bin");

#[test]
fn verify_nitro_attestation_bin() {
    // Decode VersionedAttestation from SCALE
    let versioned = VersionedAttestation::from_scale(NITRO_ATTESTATION_BIN)
        .expect("decode VersionedAttestation");
    let attestation = versioned.into_inner();

    let app_info = attestation.decode_app_info(false).unwrap();
    let app_info_str = serde_json::to_string_pretty(&app_info).unwrap();

    println!("App Info: {app_info_str}");
    insta::assert_snapshot!("app_info", app_info_str);

    // Perform full verification (COSE signature + cert chain + user_data)
    // Use a fixed historical time to tolerate expired certs in this captured sample
    // just before not_after
    let fixed_now = SystemTime::UNIX_EPOCH + Duration::from_secs(1766678656);
    let verified = block_on(attestation.verify_with_time(None, Some(fixed_now))).unwrap();
    let DstackVerifiedReport::DstackNitroEnclave(report) = verified.report else {
        panic!("Nitro attestation verification failed");
    };
    println!("✓ Nitro attestation verified successfully");
    insta::assert_snapshot!(
        "nitro_report",
        serde_json::to_string_pretty(&report).unwrap()
    );
}
