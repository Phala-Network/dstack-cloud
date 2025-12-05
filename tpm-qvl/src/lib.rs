// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM Quote Verification Library (QVL)
//!
//! This module provides quote verification and collateral management for TPM attestation.
//! It follows the dcap-qvl architecture for Intel TDX verification.
//!
//! # Architecture
//! - **Step 1**: `get_collateral()` - Extract cert chain and download CRLs
//! - **Step 2**: `verify_quote()` - Verify quote with collateral
//!
//! This crate is designed to run on the verifier side, while tpm-attest runs on the device side.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteCollateral {
    /// Intermediate certificate chain (PEM format) from device
    /// Does NOT include root CA (which must be provided independently by verifier)
    pub cert_chain_pem: String,
    /// All CRLs extracted from device-provided cert chain
    pub crls: Vec<Vec<u8>>,
    /// Root CA CRL extracted from verifier-provided root CA
    pub root_ca_crl: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub ak_verified: bool,
    pub signature_verified: bool,
    pub pcr_verified: bool,
    pub qualifying_data_verified: bool,
    pub error_message: Option<String>,
}

impl VerificationResult {
    pub fn success(&self) -> bool {
        self.ak_verified
            && self.signature_verified
            && self.pcr_verified
            && self.qualifying_data_verified
    }
}

#[cfg(feature = "crl-download")]
pub use collateral::get_collateral;

pub use verify::verify_quote;

mod verify;

#[cfg(feature = "crl-download")]
mod collateral;
