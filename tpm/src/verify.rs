// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM Quote Verification Module
//!
//! This module provides pure Rust implementation of TPM quote verification
//! without relying on external command-line tools.

use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use x509_parser::{extensions::DistributionPointName, prelude::*};

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{BorrowedCertRevocationList, CertRevocationList, EndEntityCert};

use crate::{PcrValue, TpmQuote};

/// Public key type (RSA or ECC)
#[derive(Debug)]
enum PublicKey {
    Rsa(RsaPublicKey),
    Ecc(VerifyingKey),
}

/// Result of TPM quote verification
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

/// Verify a TPM quote with full cryptographic verification and conditional CRL checking
///
/// This is the second step of dcap-qvl architecture. Use `get_collateral()` first
/// to fetch certificates and CRLs, then pass the collateral to this function.
///
/// # Arguments
/// * `quote` - The TPM quote to verify
/// * `collateral` - Quote collateral containing cert chain and CRLs (from `get_collateral()`)
///
/// # Verification Steps
/// 1. Parse TPMS_ATTEST structure
/// 2. Verify qualifying data matches
/// 3. **Verify PCR selection in pcr_values matches TPMS_ATTEST**
/// 4. Verify PCR digest matches computed digest
/// 5. **Extract AK public key from AK certificate**
/// 6. Verify signature (RSA or ECC) using AK public key from certificate
/// 7. **Verify AK certificate chain with CRL checking (webpki) - CRL verified if present**
///
/// # Returns
/// A `VerificationResult` containing the results of all verification steps
///
/// # Example
/// ```ignore
/// let collateral = get_collateral(&quote, root_ca_pem)?;
/// let result = verify_quote(&quote, &collateral)?;
/// assert!(result.success());
/// ```
pub fn verify_quote(
    quote: &TpmQuote,
    collateral: &crate::QuoteCollateral,
) -> Result<VerificationResult> {
    let mut result = VerificationResult {
        ak_verified: false,
        signature_verified: false,
        pcr_verified: false,
        qualifying_data_verified: false,
        error_message: None,
    };

    // Step 1: Parse and verify TPMS_ATTEST structure
    let attest = match parse_tpms_attest(&quote.message) {
        Ok(a) => a,
        Err(e) => {
            result.error_message = Some(format!("failed to parse TPMS_ATTEST: {e}"));
            return Ok(result);
        }
    };

    // Step 2: Verify qualifying data matches
    if attest.extra_data != quote.qualifying_data {
        result.error_message = Some(format!(
            "qualifying data mismatch: expected {} bytes, got {} bytes",
            quote.qualifying_data.len(),
            attest.extra_data.len()
        ));
        return Ok(result);
    }
    result.qualifying_data_verified = true;

    // Step 3: Verify PCR selection matches TPMS_ATTEST
    debug!(
        "parsing PCR selection from TPMS_ATTEST ({} bytes)",
        attest.attested_quote_info.pcr_select.len()
    );
    debug!(
        "pcr_select hex: {}",
        hex::encode(&attest.attested_quote_info.pcr_select)
    );
    let attested_pcr_indices = parse_pcr_selection(&attest.attested_quote_info.pcr_select)?;
    let provided_pcr_indices: Vec<u32> = quote.pcr_values.iter().map(|p| p.index).collect();

    if attested_pcr_indices != provided_pcr_indices {
        result.error_message = Some(format!(
            "PCR selection mismatch: TPMS_ATTEST has {:?}, but pcr_values has {:?}",
            attested_pcr_indices, provided_pcr_indices
        ));
        return Ok(result);
    }

    // Step 4: Verify PCR digest in TPMS_ATTEST matches our PCR values
    let computed_pcr_digest = compute_pcr_digest(&quote.pcr_values)?;
    if attest.attested_quote_info.pcr_digest != computed_pcr_digest {
        result.error_message = Some("PCR digest mismatch".to_string());
        return Ok(result);
    }
    result.pcr_verified = true;

    // Step 5: Extract AK public key from certificate
    let ak_public_key = match extract_ak_public_key_from_cert(&quote.ak_cert) {
        Ok(key) => {
            debug!("extracted AK public key from certificate");
            key
        }
        Err(e) => {
            result.error_message = Some(format!(
                "failed to extract AK public key from certificate: {}",
                e
            ));
            return Ok(result);
        }
    };

    // Step 6: Verify signature (RSA or ECC) of TPMS_ATTEST using AK public key from certificate
    match verify_signature_with_key(&quote.message, &quote.signature, &ak_public_key) {
        Ok(true) => result.signature_verified = true,
        Ok(false) => {
            warn!("signature verification failed, continuing to certificate chain verification");
            result.error_message = Some("signature verification failed".to_string());
            // DON'T return here - continue to check certificate chain
        }
        Err(e) => {
            warn!(
                "signature verification error: {}, continuing to certificate chain verification",
                e
            );
            result.error_message = Some(format!("signature verification error: {e}"));
            // DON'T return here - continue to check certificate chain
        }
    }

    // Step 7: Verify AK certificate chain with conditional CRL checking (webpki)
    // Following dcap-qvl architecture: CRL verification is enforced when CRL DP is present
    match verify_ak_chain_with_collateral(&quote.ak_cert, collateral) {
        Ok(true) => result.ak_verified = true,
        Ok(false) => {
            result.error_message =
                Some("AK certificate chain verification failed (webpki)".to_string());
        }
        Err(e) => {
            result.error_message = Some(format!("AK certificate chain verification error: {}", e));
        }
    }

    Ok(result)
}

/// Get quote collateral - certificates and CRLs required for verification
///
/// This function implements the first step of dcap-qvl architecture:
/// given a quote, extract and download all necessary certificates and CRLs.
///
/// # Architecture (dcap-qvl pattern)
/// - **Step 1**: `get_collateral()` - Extract certificate chain info and download CRLs
/// - **Step 2**: `verify()` - Verify quote with collateral and enforce CRL checking
///
/// # Process
/// 1. Extract AK certificate from quote
/// 2. Extract CRL URLs from AK certificate
/// 3. Extract intermediate CA certificate URL (AIA extension)
/// 4. Download intermediate CA certificate
/// 5. Extract CRL URLs from intermediate CA
/// 6. Download all CRLs (root CA, intermediate CA, AK cert)
///
/// # Arguments
/// * `quote` - TPM quote containing AK certificate
/// * `root_ca_pem` - Root CA certificate in PEM format (provided by user)
///
/// # Returns
/// `QuoteCollateral` containing all certificates and CRLs
///
/// # Errors
/// Returns error if:
/// - AK certificate not present in quote
/// - CRL download fails (when crl-download feature enabled)
/// - Certificate parsing fails
///
/// # Feature Requirements
/// - Requires `crl-download` feature for automatic CRL downloading
/// - Without feature, URLs are logged but CRLs are not downloaded
#[cfg(feature = "crl-download")]
pub fn get_collateral(quote: &TpmQuote, root_ca_pem: &str) -> Result<crate::QuoteCollateral> {
    use crate::QuoteCollateral;

    debug!("fetching quote collateral (cert chain + CRLs)");

    // Step 1: Extract AK certificate (leaf cert) from quote
    let ak_cert_der = &quote.ak_cert;
    debug!("AK certificate (leaf) found: {} bytes", ak_cert_der.len());

    // Step 2: Download intermediate CA from AK's AIA extension
    let intermediate_ca_url = extract_aia_ca_issuers(ak_cert_der)?
        .ok_or_else(|| anyhow::anyhow!("no AIA CA Issuers URL in AK certificate"))?;
    debug!("downloading intermediate CA from: {}", intermediate_ca_url);
    let intermediate_ca_der = download_cert(&intermediate_ca_url)?;
    let intermediate_ca_pem = der_to_pem(&intermediate_ca_der, "CERTIFICATE")?;

    // Step 3: Build cert chain (intermediate + root)
    let cert_chain_pem = format!("{}{}", intermediate_ca_pem, root_ca_pem);
    debug!("cert chain built: intermediate + root CA");

    // Step 4: Extract CRL URLs from all certs
    // Use pem crate to parse root CA (handles multi-line base64 correctly)
    let root_ca_certs = extract_certs_webpki(root_ca_pem.as_bytes())?;
    if root_ca_certs.is_empty() {
        bail!("failed to parse root CA PEM - no certificates found");
    }
    let root_ca_der = root_ca_certs[0].as_ref();

    let all_crl_urls = vec![
        ("root", extract_crl_urls(root_ca_der)?),
        ("intermediate", extract_crl_urls(&intermediate_ca_der)?),
        ("ak", extract_crl_urls(ak_cert_der)?),
    ];

    // Step 5: Download all CRLs in chain order
    // CRL verification is conditional: only verify if CRL DP is present
    debug!("downloading CRLs (conditional: verify if CRL DP present)...");
    let mut crls = Vec::new();

    'outter: for (name, cert_crl_urls) in all_crl_urls {
        if cert_crl_urls.is_empty() {
            debug!("  {name} cert has no CRL DP");
            continue;
        }
        for url in cert_crl_urls {
            match download_crl(&url) {
                Ok(crl) => {
                    debug!("  {name} CRL: {} bytes", crl.len());
                    crls.push(crl);
                    continue 'outter;
                }
                Err(e) => {
                    warn!("✗ failed to download CRL from {url}: {e:?}");
                    continue;
                }
            };
        }
        bail!("failed to download CRL for {name}");
    }

    debug!("✓ collateral fetched: {} CRLs downloaded", crls.len());

    Ok(QuoteCollateral {
        cert_chain_pem,
        crls,
    })
}

/// TPMS_ATTEST structure parsed
#[derive(Debug)]
pub(crate) struct TpmsAttest {
    pub magic: u32,
    pub type_: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
    pub attested_quote_info: QuoteInfo,
}

#[derive(Debug)]
pub(crate) struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: u8,
}

#[derive(Debug)]
pub(crate) struct QuoteInfo {
    pub pcr_select: Vec<u8>,
    pub pcr_digest: Vec<u8>,
}

/// Parse TPMS_ATTEST structure (TPM 2.0 Part 2, Section 10.12.8)
fn parse_tpms_attest(data: &[u8]) -> Result<TpmsAttest> {
    use nom::bytes::complete::take;
    use nom::number::complete::{be_u16, be_u32, be_u64, be_u8};
    use nom::IResult;

    fn parse_sized_buffer(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let (input, size) = be_u16(input)?;
        let (input, data) = take(size)(input)?;
        Ok((input, data.to_vec()))
    }

    fn parse_attest(input: &[u8]) -> IResult<&[u8], TpmsAttest> {
        let (input, magic) = be_u32(input)?;
        let (input, type_) = be_u16(input)?;
        let (input, qualified_signer) = parse_sized_buffer(input)?;
        let (input, extra_data) = parse_sized_buffer(input)?;

        // Clock info
        let (input, clock) = be_u64(input)?;
        let (input, reset_count) = be_u32(input)?;
        let (input, restart_count) = be_u32(input)?;
        let (input, safe) = be_u8(input)?;

        let (input, firmware_version) = be_u64(input)?;

        // Attested structure (TPMS_QUOTE_INFO for type TPM_ST_ATTEST_QUOTE = 0x8018)
        // pcrSelect is TPML_PCR_SELECTION (not TPM2B, no size prefix)
        // We need to parse it as raw data, so we'll extract it by parsing count first
        let (input, pcr_select_count) = be_u32(input)?;

        // For each TPMS_PCR_SELECTION, we need hash (2 bytes) + sizeofSelect (1 byte) + pcrSelect bytes
        // Since we don't know the total size upfront, we'll parse each one
        let mut pcr_select_data = Vec::new();
        pcr_select_data.extend_from_slice(&pcr_select_count.to_be_bytes());

        let mut current_input = input;
        for _ in 0..pcr_select_count {
            let (input, hash_alg) = be_u16(current_input)?;
            let (input, sizeof_select) = be_u8(input)?;
            let (input, pcr_bitmap) = take(sizeof_select)(input)?;

            pcr_select_data.extend_from_slice(&hash_alg.to_be_bytes());
            pcr_select_data.push(sizeof_select);
            pcr_select_data.extend_from_slice(pcr_bitmap);

            current_input = input;
        }

        let input = current_input;
        let (input, pcr_digest) = parse_sized_buffer(input)?;

        Ok((
            input,
            TpmsAttest {
                magic,
                type_,
                qualified_signer,
                extra_data,
                clock_info: ClockInfo {
                    clock,
                    reset_count,
                    restart_count,
                    safe,
                },
                firmware_version,
                attested_quote_info: QuoteInfo {
                    pcr_select: pcr_select_data,
                    pcr_digest,
                },
            },
        ))
    }

    let (_, attest) = parse_attest(data).map_err(|e| anyhow::anyhow!("parse error: {e}"))?;

    // Verify magic number (TPM_GENERATED_VALUE = 0xff544347)
    if attest.magic != 0xff544347 {
        bail!("invalid magic number: 0x{:08x}", attest.magic);
    }

    // Verify type is TPM_ST_ATTEST_QUOTE (0x8018)
    if attest.type_ != 0x8018 {
        bail!("invalid attest type: 0x{:04x}", attest.type_);
    }

    Ok(attest)
}

/// Test helper: expose parse_tpms_attest for testing
#[cfg(test)]
pub(crate) fn parse_tpms_attest_for_test(data: &[u8]) -> Result<TpmsAttest> {
    parse_tpms_attest(data)
}

/// Parse TPML_PCR_SELECTION to extract PCR indices
///
/// TPML_PCR_SELECTION structure (TPM 2.0 Part 2, Section 10.7.2):
/// - count: UINT32 (4 bytes) - number of TPMS_PCR_SELECTION elements
/// - For each TPMS_PCR_SELECTION:
///   - hash: TPM_ALG_ID (2 bytes) - hash algorithm
///   - sizeofSelect: UINT8 (1 byte) - size of pcrSelect in bytes (typically 3)
///   - pcrSelect: BYTE[sizeofSelect] - PCR bitmap
///
/// Returns sorted list of PCR indices
fn parse_pcr_selection(data: &[u8]) -> Result<Vec<u32>> {
    use nom::bytes::complete::take;
    use nom::number::complete::{be_u16, be_u32, be_u8};
    use nom::IResult;

    fn parse_selection(input: &[u8]) -> IResult<&[u8], Vec<u32>> {
        let (input, count) = be_u32(input)?;

        let mut all_pcrs = Vec::new();
        let mut current_input = input;

        for _ in 0..count {
            let (input, _hash_alg) = be_u16(current_input)?;
            let (input, sizeof_select) = be_u8(input)?;
            let (input, pcr_bitmap) = take(sizeof_select)(input)?;

            // Extract PCR indices from bitmap
            for (byte_idx, &byte) in pcr_bitmap.iter().enumerate() {
                for bit_idx in 0..8 {
                    if (byte & (1 << bit_idx)) != 0 {
                        let pcr_index = (byte_idx * 8 + bit_idx) as u32;
                        all_pcrs.push(pcr_index);
                    }
                }
            }

            current_input = input;
        }

        Ok((current_input, all_pcrs))
    }

    let (_, mut pcr_indices) =
        parse_selection(data).map_err(|e| anyhow::anyhow!("failed to parse PCR selection: {e}"))?;

    // Sort PCR indices for comparison
    pcr_indices.sort_unstable();

    Ok(pcr_indices)
}

/// Compute PCR digest from PCR values
fn compute_pcr_digest(pcr_values: &[PcrValue]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for pcr in pcr_values {
        hasher.update(&pcr.value);
    }
    Ok(hasher.finalize().to_vec())
}

/// Extract AK public key from AK certificate
///
/// This function extracts the public key (RSA or ECC) from the AK certificate in DER format.
/// The AK certificate is signed by a trusted CA (e.g., Google Private CA on GCP).
///
/// # Arguments
/// * `ak_cert_der` - AK certificate in DER format (from quote)
///
/// # Returns
/// Public key (RSA or ECC) extracted from the certificate
fn extract_ak_public_key_from_cert(ak_cert_der: &[u8]) -> Result<PublicKey> {
    // Parse X.509 certificate
    let (_, cert) =
        X509Certificate::from_der(ak_cert_der).context("failed to parse AK certificate")?;

    // Extract SubjectPublicKeyInfo
    let spki = cert.public_key();

    // Get algorithm OID
    let algo_oid = &spki.algorithm.algorithm;

    // RSA: 1.2.840.113549.1.1.1
    const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    // ECC: 1.2.840.10045.2.1
    const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];

    let oid_bytes: Vec<u64> = algo_oid
        .iter()
        .ok_or_else(|| anyhow::anyhow!("invalid OID"))?
        .collect();

    if oid_bytes == OID_RSA_ENCRYPTION {
        // Parse RSA public key
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::traits::PublicKeyParts;

        let public_key = RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
            .context("failed to decode RSA public key from certificate")?;

        debug!(
            "extracted RSA AK public key from certificate ({} bits)",
            public_key.size() * 8
        );

        Ok(PublicKey::Rsa(public_key))
    } else if oid_bytes == OID_EC_PUBLIC_KEY {
        // Parse ECC public key
        // The subjectPublicKey for ECC is an uncompressed point (0x04 || x || y)
        let public_key_bytes = spki.subject_public_key.data.as_ref();

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
            .context("failed to decode ECC public key from certificate")?;

        debug!("extracted ECC P-256 AK public key from certificate");

        Ok(PublicKey::Ecc(verifying_key))
    } else {
        bail!("unsupported public key algorithm: {:?}", oid_bytes);
    }
}

/// Verify signature using public key (RSA or ECC)
///
/// This function verifies the signature of the TPMS_ATTEST message using the provided
/// public key (RSA or ECC) extracted from AK certificate.
fn verify_signature_with_key(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    // Parse TPMT_SIGNATURE structure
    // TPM 2.0 Part 2, Section 11.2.3 - TPMT_SIGNATURE
    //
    // Structure depends on sigAlg:
    //
    // For RSASSA (0x0014):
    //   +0: sigAlg (2 bytes) = 0x0014
    //   +2: signature: TPMS_SIGNATURE_RSASSA {
    //         hash (2 bytes)
    //         sig: TPM2B_PUBLIC_KEY_RSA (2 bytes size + N bytes signature)
    //       }
    //
    // For ECDSA (0x0018):
    //   +0: sigAlg (2 bytes) = 0x0018
    //   +2: signature: TPMS_SIGNATURE_ECDSA {
    //         hash (2 bytes)
    //         signatureR: TPM2B_ECC_PARAMETER (2 bytes size + R bytes)
    //         signatureS: TPM2B_ECC_PARAMETER (2 bytes size + S bytes)
    //       }
    if signature.len() < 4 {
        bail!("signature too short: {} bytes", signature.len());
    }

    let sig_alg = u16::from_be_bytes([signature[0], signature[1]]);
    let hash_alg = u16::from_be_bytes([signature[2], signature[3]]);

    // Verify hash algorithm is SHA256
    if hash_alg != 0x000B {
        bail!("unsupported hash algorithm: 0x{:04x}", hash_alg);
    }

    // Extract actual signature bytes (after sigAlg + hash)
    let actual_signature = &signature[4..];

    debug!(
        "message ({} bytes): {}",
        message.len(),
        hex::encode(message)
    );
    debug!(
        "signature ({} bytes): {}",
        actual_signature.len(),
        hex::encode(actual_signature)
    );

    // Compute SHA256 hash of message
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    debug!("message hash: {}", hex::encode(message_hash));

    match public_key {
        PublicKey::Rsa(rsa_key) => {
            // Verify signature algorithm is RSASSA
            if sig_alg != 0x0014 {
                bail!("expected RSASSA (0x0014), got 0x{:04x}", sig_alg);
            }

            // Parse TPM2B_PUBLIC_KEY_RSA structure
            // The actual_signature points to: [size (2 bytes)] [signature data]
            if actual_signature.len() < 2 {
                bail!("RSA signature too short for size field");
            }
            let rsa_sig_size =
                u16::from_be_bytes([actual_signature[0], actual_signature[1]]) as usize;
            if actual_signature.len() < 2 + rsa_sig_size {
                bail!("RSA signature too short for signature data");
            }
            let rsa_sig_data = &actual_signature[2..2 + rsa_sig_size];

            debug!("RSA signature parsed: {} bytes", rsa_sig_size);

            // Verify using PKCS#1 v1.5 signature scheme with SHA256
            // TPM2 RSASSA signatures use standard PKCS#1 v1.5 padding with hash
            // Reference: TPM 2.0 Library Spec Part 1, Section 18.2.3.6 (RSASSA)
            let padding = rsa::Pkcs1v15Sign::new::<Sha256>();
            match rsa_key.verify(padding, &message_hash, rsa_sig_data) {
                Ok(_) => {
                    debug!("✓ RSA signature verification successful");
                    Ok(true)
                }
                Err(e) => {
                    warn!("RSA signature verification failed: {e}");
                    Ok(false)
                }
            }
        }
        PublicKey::Ecc(ecc_key) => {
            // Verify signature algorithm is ECDSA
            if sig_alg != 0x0018 {
                bail!("expected ECDSA (0x0018), got 0x{sig_alg:04x}");
            }

            // Parse TPMS_SIGNATURE_ECDSA structure (TPM 2.0 Part 2, Section 11.2.3.2)
            // After TPMT_SIGNATURE header, we have:
            //   signatureR: TPM2B_ECC_PARAMETER (2 bytes size + r bytes)
            //   signatureS: TPM2B_ECC_PARAMETER (2 bytes size + s bytes)
            //
            // But sig_size in TPMT_SIGNATURE only covers the first TPM2B (signatureR)!
            // We need to parse both TPM2B structures to get r || s

            // actual_signature points to: [signatureR (TPM2B)] [signatureS (TPM2B)] ...
            // Parse signatureR
            if actual_signature.len() < 2 {
                bail!("ECDSA signature too short for signatureR size");
            }
            let r_size = u16::from_be_bytes([actual_signature[0], actual_signature[1]]) as usize;
            if actual_signature.len() < 2 + r_size {
                bail!("ECDSA signature too short for signatureR data");
            }
            let r_data = &actual_signature[2..2 + r_size];

            // Parse signatureS
            let s_offset = 2 + r_size;
            if actual_signature.len() < s_offset + 2 {
                bail!("ECDSA signature too short for signatureS size");
            }
            let s_size =
                u16::from_be_bytes([actual_signature[s_offset], actual_signature[s_offset + 1]])
                    as usize;
            if actual_signature.len() < s_offset + 2 + s_size {
                bail!("ECDSA signature too short for signatureS data");
            }
            let s_data = &actual_signature[s_offset + 2..s_offset + 2 + s_size];

            // Concatenate r || s for p256 signature format
            let mut sig_bytes = Vec::with_capacity(r_size + s_size);
            sig_bytes.extend_from_slice(r_data);
            sig_bytes.extend_from_slice(s_data);

            debug!(
                "ECDSA signature parsed: r={} bytes, s={} bytes",
                r_size, s_size
            );

            // Parse as ECDSA signature (r || s format)
            let signature =
                Signature::from_slice(&sig_bytes).context("failed to parse ECDSA signature")?;

            // Verify ECDSA signature using prehash verifier
            // TPM signs the SHA256 hash of the message, so we use verify_prehash
            match ecc_key.verify_prehash(&message_hash, &signature) {
                Ok(_) => {
                    debug!("✓ ECC signature verification successful");
                    Ok(true)
                }
                Err(e) => {
                    warn!("ECC signature verification failed: {e}");
                    Ok(false)
                }
            }
        }
    }
}

//
// ========== webpki-based certificate verification (with CRL support) ==========
//
// The following functions are adapted from dcap-qvl to provide industrial-strength
// certificate chain verification with CRL revocation checking using the webpki library.
//

/// Extract PEM certificates and convert to webpki CertificateDer format
///
/// This helper function parses PEM-encoded certificates and converts them to
/// the DER format expected by webpki.
fn extract_certs_webpki(cert_pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    use ::pem::parse_many;

    let pem_items =
        parse_many(cert_pem).map_err(|e| anyhow::anyhow!("failed to parse PEM: {}", e))?;

    let certs = pem_items
        .into_iter()
        .map(|pem| CertificateDer::from(pem.into_contents()))
        .collect();

    Ok(certs)
}

/// Verify AK certificate chain with collateral (conditional CRL checking)
///
/// This function implements webpki-based verification following dcap-qvl architecture.
/// CRL verification is conditional: enforced if CRL Distribution Points are present in certs.
///
/// # Arguments
/// * `ak_cert_der` - AK certificate in DER format (from quote)
/// * `collateral` - Quote collateral containing cert chain and CRLs
///
/// # Returns
/// `Ok(true)` if verification succeeds, `Ok(false)` if it fails
fn verify_ak_chain_with_collateral(
    ak_cert_der: &[u8],
    collateral: &crate::QuoteCollateral,
) -> Result<bool> {
    debug!(
        "verifying AK certificate chain with webpki ({} bytes leaf, {} CRLs)",
        ak_cert_der.len(),
        collateral.crls.len()
    );

    // Parse leaf cert (AK certificate) as webpki EndEntityCert
    let ak_cert_der_owned = CertificateDer::from(ak_cert_der.to_vec());
    let ak_cert = EndEntityCert::try_from(&ak_cert_der_owned)
        .map_err(|e| anyhow::anyhow!("failed to parse AK certificate: {:?}", e))?;

    // Parse cert chain (intermediate CAs + root CA)
    let chain_certs = extract_certs_webpki(collateral.cert_chain_pem.as_bytes())?;
    if chain_certs.is_empty() {
        bail!("no certificates found in cert chain");
    }

    debug!("loaded {} certificate(s) from chain", chain_certs.len());

    // Last cert in chain is root CA (trust anchor)
    let root_cert_der = chain_certs
        .last()
        .ok_or_else(|| anyhow::anyhow!("empty cert chain"))?;
    let trust_anchor = webpki::anchor_from_trusted_cert(root_cert_der)
        .map_err(|e| anyhow::anyhow!("failed to create trust anchor from root CA: {:?}", e))?;

    // All certs except last are intermediates
    let intermediate_certs = if chain_certs.len() > 1 {
        &chain_certs[..chain_certs.len() - 1]
    } else {
        &[]
    };

    debug!(
        "trust anchor created, {} intermediate(s)",
        intermediate_certs.len()
    );

    // Get current time for validation
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("failed to get current time")?;
    let time = UnixTime::since_unix_epoch(now);

    // Create trust anchor array
    let trust_anchors = [trust_anchor];

    // Check root CA against CRL (if CRLs available)
    // Because the original rustls-webpki doesn't check the ROOT CA against the CRL,
    // we use dcap-qvl-webpki to check it separately (following dcap-qvl pattern)
    if !collateral.crls.is_empty() {
        debug!("checking root CA against CRL (dcap-qvl-webpki)");
        let crl_refs: Vec<&[u8]> = collateral.crls.iter().map(|c| c.as_slice()).collect();
        dcap_qvl_webpki::check_single_cert_crl(root_cert_der.as_ref(), &crl_refs, time)?;
        debug!("✓ root CA CRL check passed");
    }

    // Parse CRLs and verify (conditional: only verify with CRL if CRLs are present)
    // Following user guidance: CRL verification is required if CRL DP is present in certs
    let result = if !collateral.crls.is_empty() {
        debug!(
            "parsing {} CRL(s) for revocation checking",
            collateral.crls.len()
        );
        let crls: Vec<CertRevocationList> = collateral
            .crls
            .iter()
            .enumerate()
            .map(|(i, der)| {
                BorrowedCertRevocationList::from_der(der)
                    .map(|crl| crl.into())
                    .map_err(|e| anyhow::anyhow!("failed to parse CRL #{}: {:?}", i, e))
            })
            .collect::<Result<Vec<_>>>()?;
        let crl_refs: Vec<&CertRevocationList> = crls.iter().collect();

        debug!("creating revocation options (CRL enforcement)");
        let revocation_builder = webpki::RevocationOptionsBuilder::new(&crl_refs)
            .map_err(|_| anyhow::anyhow!("failed to create RevocationOptionsBuilder"))?;

        // Following dcap-qvl: check entire chain, allow unknown status, enforce expiration
        // Note: UnknownStatusPolicy::Allow is used because:
        // - AK leaf cert has NO CRL DP (Intermediate CA doesn't publish CRL for AK certs)
        // - Only Intermediate CA has CRL (signed by Root CA)
        // - If cert has no CRL DP, we don't require revocation check for that cert
        let revocation = revocation_builder
            .with_depth(webpki::RevocationCheckDepth::Chain)
            .with_status_policy(webpki::UnknownStatusPolicy::Allow)
            .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
            .build();

        debug!("verifying certificate chain with CRL revocation checking");

        // Verify with CRL checking
        // TPM Attestation: Intermediate CA has EKU = tcg-kp-AIKCertificate (2.23.133.8.1)
        // This is defined by TCG (Trusted Computing Group) for TPM AIK certificates
        // AK leaf cert has no EKU, but intermediate CA does, so we must specify this
        const TCG_KP_AIK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01]; // OID 2.23.133.8.1
        let key_usage = webpki::KeyUsage::required_if_present(TCG_KP_AIK_CERTIFICATE);

        ak_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &trust_anchors,
                intermediate_certs,
                time,
                key_usage,
                Some(revocation), // CRL checking
                None,
            )
            .map_err(|e| anyhow::anyhow!("certificate chain verification failed: {:?}", e))
    } else {
        debug!("no CRLs available (no certificates have CRL Distribution Points)");
        debug!("verifying certificate chain WITHOUT CRL checking");

        // Verify without CRL checking
        // TPM Attestation: use TCG AIK Certificate EKU
        const TCG_KP_AIK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01]; // OID 2.23.133.8.1
        let key_usage = webpki::KeyUsage::required_if_present(TCG_KP_AIK_CERTIFICATE);

        ak_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &trust_anchors,
                intermediate_certs,
                time,
                key_usage,
                None, // No CRL checking
                None,
            )
            .map_err(|e| anyhow::anyhow!("certificate chain verification failed: {:?}", e))
    };

    match result {
        Ok(_) => {
            if collateral.crls.is_empty() {
                debug!("✓ AK certificate chain verification successful (webpki, no CRLs)");
            } else {
                debug!(
                    "✓ AK certificate chain verification successful (webpki + {} CRL(s))",
                    collateral.crls.len()
                );
            }
            Ok(true)
        }
        Err(e) => {
            warn!("✗ AK certificate chain verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Download CRL from URL (requires crl-download feature)
///
/// This function downloads a CRL from the given URL using reqwest.
/// It's used to fetch CRLs referenced in certificate CRL Distribution Points.
#[cfg(feature = "crl-download")]
fn download_crl(url: &str) -> Result<Vec<u8>> {
    debug!("downloading CRL from {}", url);

    let response =
        reqwest::blocking::get(url).context(format!("failed to download CRL from {}", url))?;

    if !response.status().is_success() {
        bail!("CRL download failed with status: {}", response.status());
    }

    let crl_bytes = response
        .bytes()
        .context("failed to read CRL response body")?
        .to_vec();

    debug!("downloaded {} bytes CRL from {}", crl_bytes.len(), url);

    Ok(crl_bytes)
}

/// Extract CRL Distribution Points from X.509 certificate
///
/// Parses the CRL Distribution Points extension from a certificate to find
/// CRL download URLs. These URLs can then be used with `download_crl()` to
/// fetch the actual CRL data.
///
/// # Arguments
/// * `cert_der` - Certificate in DER format
///
/// # Returns
/// Vector of CRL URLs found in the certificate
fn extract_crl_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    use x509_parser::extensions::ParsedExtension;

    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;

    let mut crl_urls = Vec::new();

    // Look for CRL Distribution Points extension
    for ext in cert.extensions() {
        let ParsedExtension::CRLDistributionPoints(crl_dist_points) = ext.parsed_extension() else {
            continue;
        };
        for dist_point in crl_dist_points.points.iter() {
            let Some(dist_point_name) = &dist_point.distribution_point else {
                continue;
            };

            let DistributionPointName::FullName(names) = dist_point_name else {
                continue;
            };
            for name in names.iter() {
                let x509_parser::extensions::GeneralName::URI(uri) = name else {
                    continue;
                };
                crl_urls.push(uri.to_string());
                debug!("found CRL URL: {uri}");
            }
        }
    }

    if crl_urls.is_empty() {
        debug!("no CRL Distribution Points found in certificate");
    }

    Ok(crl_urls)
}

/// Extract Authority Information Access (AIA) CA Issuers URLs from X.509 certificate
///
/// Parses the AIA extension from a certificate to find the intermediate CA
/// certificate download URL. This is used to automatically download the
/// intermediate CA certificate referenced by the EK certificate.
///
/// # Arguments
/// * `cert_der` - Certificate in DER format
///
/// # Returns
/// First CA Issuers URL found in the certificate, or None if not present
#[cfg(feature = "crl-download")]
fn extract_aia_ca_issuers(cert_der: &[u8]) -> Result<Option<String>> {
    use x509_parser::extensions::ParsedExtension;

    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;

    // Look for Authority Information Access extension
    for ext in cert.extensions() {
        let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
            continue;
        };

        for access_desc in &aia.accessdescs {
            // Check if this is CA Issuers (OID 1.3.6.1.5.5.7.48.2)
            const OID_CA_ISSUERS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
            let oid_bytes: Vec<u64> = match access_desc.access_method.iter() {
                Some(iter) => iter.collect(),
                None => continue,
            };

            if oid_bytes == OID_CA_ISSUERS {
                // Extract URL from access location
                if let x509_parser::extensions::GeneralName::URI(uri) = &access_desc.access_location
                {
                    debug!("found AIA CA Issuers URL: {}", uri);
                    return Ok(Some(uri.to_string()));
                }
            }
        }
    }

    debug!("no AIA CA Issuers URL found in certificate");
    Ok(None)
}

/// Download certificate from URL (requires crl-download feature)
///
/// This function downloads a certificate from the given URL using reqwest.
/// It's used to fetch intermediate CA certificates referenced in EK certificate AIA extension.
#[cfg(feature = "crl-download")]
fn download_cert(url: &str) -> Result<Vec<u8>> {
    debug!("downloading certificate from {}", url);

    let response = reqwest::blocking::get(url)
        .context(format!("failed to download certificate from {}", url))?;

    if !response.status().is_success() {
        bail!(
            "certificate download failed with status: {}",
            response.status()
        );
    }

    let cert_bytes = response
        .bytes()
        .context("failed to read certificate response body")?
        .to_vec();

    debug!(
        "downloaded {} bytes certificate from {}",
        cert_bytes.len(),
        url
    );

    Ok(cert_bytes)
}

/// Convert DER-encoded certificate to PEM format
///
/// # Arguments
/// * `der` - Certificate in DER format
/// * `label` - PEM label (e.g., "CERTIFICATE")
///
/// # Returns
/// Certificate in PEM format
#[cfg(feature = "crl-download")]
fn der_to_pem(der: &[u8], label: &str) -> Result<String> {
    use base64::Engine;

    let b64 = base64::engine::general_purpose::STANDARD.encode(der);

    // Format as PEM with 64-character lines
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk)?);
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));

    Ok(pem)
}
