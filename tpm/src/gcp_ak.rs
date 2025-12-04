//! GCP vTPM pre-provisioned AK loading using tss-esapi
//!
//! This module provides native Rust implementation for loading GCP's
//! pre-provisioned Attestation Key using the TSS2 ESAPI.

#[cfg(feature = "gcp-vtpm")]
use anyhow::{Context as _, Result};
#[cfg(feature = "gcp-vtpm")]
use tss_esapi::{
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        resource_handles::{Hierarchy, NvAuth},
    },
    structures::Public,
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::UnMarshall,
    Context as TssContext,
};
#[cfg(feature = "gcp-vtpm")]
use tracing::info;

/// GCP vTPM NV indices for pre-provisioned AK
#[cfg(feature = "gcp-vtpm")]
pub mod gcp_nv_index {
    /// RSA AK certificate (DER format)
    pub const AK_RSA_CERT: u32 = 0x01C10000;
    /// RSA AK template (TPM2B_PUBLIC format)
    pub const AK_RSA_TEMPLATE: u32 = 0x01C10001;
    /// ECC AK certificate (DER format)
    pub const AK_ECC_CERT: u32 = 0x01C10002;
    /// ECC AK template (TPM2B_PUBLIC format)
    pub const AK_ECC_TEMPLATE: u32 = 0x01C10003;
}

/// Load GCP pre-provisioned RSA AK using tss-esapi
///
/// This function:
/// 1. Reads the AK template from NV index 0x01C10001
/// 2. Creates a primary key under Endorsement hierarchy with the template
/// 3. TPM deterministically recreates the same key pair (same template + same parent)
///
/// # Parameters
/// - `tcti_path`: Path to TPM device (e.g., "/dev/tpmrm0" or None for default)
///
/// # Returns
/// - `Ok((TssContext, KeyHandle))` - TSS context and handle to the loaded AK
/// - `Err(_)` - Failed to load AK (not on GCP vTPM, or access error)
#[cfg(feature = "gcp-vtpm")]
pub fn load_gcp_ak_rsa(tcti_path: Option<&str>) -> Result<(TssContext, KeyHandle)> {
    info!("loading GCP pre-provisioned RSA AK with tss-esapi...");

    // Create TSS context
    use std::str::FromStr;
    // Strip "device:" prefix if present (from TpmContext tcti format)
    let tcti_str = tcti_path.unwrap_or("/dev/tpmrm0");
    let device_path = tcti_str.strip_prefix("device:").unwrap_or(tcti_str);
    let device_config = DeviceConfig::from_str(device_path)
        .context("failed to parse device config")?;
    let tcti = TctiNameConf::Device(device_config);
    let mut context = TssContext::new(tcti).context("failed to create TSS context")?;

    // Read AK template from NV
    let template_bytes = read_nv_data(&mut context, gcp_nv_index::AK_RSA_TEMPLATE)
        .context("failed to read AK template from NV 0x01C10001")?;

    info!("read AK template from NV: {} bytes", template_bytes.len());

    // Parse template as TPM2B_PUBLIC
    let public = Public::unmarshall(&template_bytes)
        .context("failed to parse AK template as TPM2B_PUBLIC")?;

    // Create primary key under Endorsement hierarchy with null auth session
    // This recreates the pre-provisioned AK because TPM CreatePrimary is deterministic
    let ak_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Endorsement,
                public,
                None,  // auth_value
                None,  // sensitive_data
                None,  // outside_info
                None,  // creation_pcr
            )
        })
        .context("failed to create primary AK")?
        .key_handle;

    info!("✓ successfully loaded GCP pre-provisioned AK (handle: {:?})", ak_handle);

    Ok((context, ak_handle))
}

/// Generate a TPM quote using GCP pre-provisioned AK
///
/// This function:
/// 1. Loads the GCP pre-provisioned RSA AK
/// 2. Reads the specified PCR values
/// 3. Generates a quote signed by the AK
/// 4. Reads the AK certificate from NV
/// 5. Returns a complete TpmQuote structure
///
/// # Parameters
/// - `tcti_path`: Path to TPM device (e.g., "/dev/tpmrm0" or None for default)
/// - `qualifying_data`: Nonce/challenge data to include in quote
/// - `pcr_selection`: PCR registers to include in quote
///
/// # Returns
/// - `Ok(TpmQuote)` - Complete quote with signature and certificate
/// - `Err(_)` - Failed to generate quote
#[cfg(feature = "gcp-vtpm")]
pub fn create_quote_with_gcp_ak(
    tcti_path: Option<&str>,
    qualifying_data: &[u8],
    pcr_selection: &crate::PcrSelection,
) -> Result<crate::TpmQuote> {
    use tss_esapi::structures::{Data, PcrSelectionListBuilder, PcrSlot, SignatureScheme};
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::traits::Marshall;

    info!("generating TPM quote with GCP pre-provisioned AK...");

    // Load GCP pre-provisioned AK
    let (mut context, ak_handle) = load_gcp_ak_rsa(tcti_path)?;

    // Build PCR selection list for tss-esapi
    let mut pcr_selection_list = PcrSelectionListBuilder::new();

    // Convert hash algorithm string to HashingAlgorithm enum
    let hash_alg = match pcr_selection.bank.as_str() {
        "sha256" => HashingAlgorithm::Sha256,
        "sha384" => HashingAlgorithm::Sha384,
        "sha512" => HashingAlgorithm::Sha512,
        _ => anyhow::bail!("unsupported hash algorithm: {}", pcr_selection.bank),
    };

    // Add each PCR to the selection
    // PcrSlot uses bit mask representation: PCR 0 = bit 0 (0x1), PCR 1 = bit 1 (0x2), etc.
    for pcr_idx in &pcr_selection.pcrs {
        let bit_mask = 1u32 << pcr_idx;
        let pcr_slot = PcrSlot::try_from(bit_mask)
            .with_context(|| format!("invalid PCR index: {}", pcr_idx))?;
        pcr_selection_list = pcr_selection_list
            .with_selection(hash_alg, &[pcr_slot]);
    }

    let pcr_selection_list = pcr_selection_list.build()
        .context("failed to build PCR selection list")?;

    // Create qualifying data structure
    let qual_data = Data::try_from(qualifying_data.to_vec())
        .context("failed to create qualifying data")?;

    // Use default signing scheme (RSASSA with SHA256)
    let signing_scheme = SignatureScheme::Null;

    // Generate quote
    info!("calling TPM Quote command...");
    let (attest, signature) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.quote(ak_handle, qual_data, signing_scheme, pcr_selection_list.clone())
        })
        .context("failed to generate quote")?;

    info!("✓ quote generated successfully");

    // Marshall attest structure to bytes (TPMS_ATTEST)
    let message = attest.marshall().context("failed to marshall attest")?;

    // Marshall signature to bytes (TPMT_SIGNATURE)
    let signature = signature.marshall().context("failed to marshall signature")?;

    // Read PCR values - read each PCR individually to ensure correct mapping
    let mut pcr_values = Vec::new();
    for pcr_idx in &pcr_selection.pcrs {
        // Build selection for single PCR
        let bit_mask = 1u32 << pcr_idx;
        let pcr_slot = PcrSlot::try_from(bit_mask)
            .with_context(|| format!("invalid PCR index: {}", pcr_idx))?;

        let single_pcr_sel = PcrSelectionListBuilder::new()
            .with_selection(hash_alg, &[pcr_slot])
            .build()
            .context("failed to build single PCR selection")?;

        let (_update_counter, _pcr_sel_out, digest_list) = context
            .execute_without_session(|ctx| {
                ctx.pcr_read(single_pcr_sel)
            })
            .context("failed to read PCR value")?;

        // Get the first (and only) digest
        if let Some(digest) = digest_list.value().first() {
            pcr_values.push(crate::PcrValue {
                index: *pcr_idx,
                algorithm: pcr_selection.bank.clone(),
                value: digest.value().to_vec(),
            });
        }
    }

    // Read AK certificate from NV
    let ak_cert = read_nv_data(&mut context, gcp_nv_index::AK_RSA_CERT)
        .context("failed to read AK certificate from NV")?;

    info!("✓ AK certificate read from NV: {} bytes", ak_cert.len());

    Ok(crate::TpmQuote {
        message,
        signature,
        pcr_values,
        qualifying_data: qualifying_data.to_vec(),
        ak_cert,
    })
}

/// Read data from TPM NV index
#[cfg(feature = "gcp-vtpm")]
fn read_nv_data(context: &mut TssContext, nv_index: u32) -> Result<Vec<u8>> {
    use tss_esapi::abstraction::nv;

    // Create NV index TPM handle
    let nv_idx = NvIndexTpmHandle::new(nv_index)
        .context("invalid NV index")?;

    // Get NV index handle from TPM
    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context
        .execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(nv_auth_handle)
                .map(|v| NvAuth::NvIndex(v.into()))
        })
        .context("failed to get NV index handle")?;

    // Read NV data with null auth session
    let data = context
        .execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))
        .context("failed to read NV data")?;

    Ok(data.to_vec())
}
