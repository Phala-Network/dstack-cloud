// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure tss-esapi implementation of TPM operations
//!
//! This module provides a clean implementation using only tss-esapi,
//! without relying on tpm2-tools command-line utilities.

use anyhow::{bail, Context as _, Result};
use std::convert::TryFrom;
use tracing::{info, warn};
use tss_esapi::{
    abstraction::nv,
    handles::{NvIndexTpmHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::Hierarchy,
    },
    structures::{
        PcrSelectionListBuilder, PcrSlot,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    Context as TssContext,
};

use crate::{PcrSelection, PcrValue};

/// TPM context using tss-esapi
pub struct EsapiContext {
    context: TssContext,
}

impl EsapiContext {
    /// Create a new ESAPI context with the given TCTI path
    pub fn new(tcti_path: Option<&str>) -> Result<Self> {
        use std::str::FromStr;

        let tcti_str = tcti_path.unwrap_or("/dev/tpmrm0");

        // Strip "device:" prefix if present (tss-esapi expects path without prefix)
        let device_path = tcti_str.strip_prefix("device:").unwrap_or(tcti_str);

        let device_config = DeviceConfig::from_str(device_path)
            .context("failed to parse device config")?;
        let tcti = TctiNameConf::Device(device_config);

        let context = TssContext::new(tcti)
            .context("failed to create TSS context")?;

        Ok(Self { context })
    }

    // ==================== NV Operations ====================

    /// Check if an NV index exists
    pub fn nv_exists(&mut self, index: u32) -> Result<bool> {
        let handle = NvIndexTpmHandle::new(index)
            .context("invalid NV index")?;
        let nv_index = self.context.tr_from_tpm_public(TpmHandle::NvIndex(handle));

        match nv_index {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Read data from an NV index
    pub fn nv_read(&mut self, index: u32) -> Result<Option<Vec<u8>>> {
        use tss_esapi::interface_types::resource_handles::NvAuth;

        let handle = NvIndexTpmHandle::new(index)
            .context("invalid NV index")?;

        // Get NV index handle from TPM
        let nv_auth_handle = TpmHandle::NvIndex(handle);
        let nv_auth_handle = match self.context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(nv_auth_handle)
                .map(|v| NvAuth::NvIndex(v.into()))
        }) {
            Ok(h) => h,
            Err(e) => {
                warn!("failed to get NV index handle for 0x{:08x}: {}", index, e);
                return Ok(None);
            }
        };

        // Read NV data with null auth session
        match self.context.execute_with_nullauth_session(|ctx| {
            nv::read_full(ctx, nv_auth_handle, handle)
        }) {
            Ok(data) => Ok(Some(data.to_vec())),
            Err(e) => {
                warn!("nv_read failed for index 0x{:08x}: {}", index, e);
                Ok(None)
            }
        }
    }

    /// Write data to an NV index
    pub fn nv_write(&mut self, _index: u32, _data: &[u8]) -> Result<bool> {
        // TODO: Implement NV write with correct nv API
        // Note: Not needed for quote generation (read-only operation)
        warn!("nv_write not yet implemented - not needed for quote generation");
        Ok(false)
    }

    /// Define a new NV index
    pub fn nv_define(&mut self, index: u32, size: usize, owner_read_write: bool) -> Result<bool> {
        use tss_esapi::attributes::NvIndexAttributesBuilder;
        use tss_esapi::structures::{NvPublicBuilder, Auth};
        use tss_esapi::interface_types::resource_handles::Provision;

        let handle = NvIndexTpmHandle::new(index)
            .context("invalid NV index")?;

        // Build NV index attributes
        let mut attributes = NvIndexAttributesBuilder::new();
        if owner_read_write {
            attributes = attributes
                .with_owner_write(true)
                .with_owner_read(true);
        }
        let attributes = attributes.build().context("failed to build NV attributes")?;

        // Build NV public structure
        let nv_public = NvPublicBuilder::new()
            .with_nv_index(handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attributes)
            .with_data_area_size(size)
            .build()
            .context("failed to build NV public")?;

        // Define NV space
        match self.context.execute_with_nullauth_session(|ctx| {
            ctx.nv_define_space(Provision::Owner, None, nv_public)
        }) {
            Ok(_) => {
                info!("defined NV index 0x{:08x} with size {}", index, size);
                Ok(true)
            }
            Err(e) => {
                warn!("nv_define failed for index 0x{:08x}: {}", index, e);
                Ok(false)
            }
        }
    }

    /// Undefine (delete) an NV index
    pub fn nv_undefine(&mut self, index: u32) -> Result<bool> {
        use tss_esapi::handles::NvIndexHandle;
        use tss_esapi::interface_types::resource_handles::Provision;

        let handle = NvIndexTpmHandle::new(index)
            .context("invalid NV index")?;

        // Get NV index handle
        let nv_idx = match self.context.tr_from_tpm_public(TpmHandle::NvIndex(handle)) {
            Ok(h) => NvIndexHandle::from(h),
            Err(e) => {
                warn!("failed to get NV index handle for 0x{:08x}: {}", index, e);
                return Ok(false);
            }
        };

        // Undefine NV space
        match self.context.execute_with_nullauth_session(|ctx| {
            ctx.nv_undefine_space(Provision::Owner, nv_idx)
        }) {
            Ok(_) => {
                info!("undefined NV index 0x{:08x}", index);
                Ok(true)
            }
            Err(e) => {
                warn!("nv_undefine failed for index 0x{:08x}: {}", index, e);
                Ok(false)
            }
        }
    }

    // ==================== PCR Operations ====================

    /// Read PCR values for the given selection
    pub fn pcr_read(&mut self, pcr_selection: &PcrSelection) -> Result<Vec<PcrValue>> {
        let hash_alg = match pcr_selection.bank.as_str() {
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => bail!("unsupported hash algorithm: {}", pcr_selection.bank),
        };

        let mut pcr_values = Vec::new();

        // Read each PCR individually to ensure correct index mapping
        for pcr_idx in &pcr_selection.pcrs {
            let bit_mask = 1u32 << pcr_idx;
            let pcr_slot = PcrSlot::try_from(bit_mask)
                .with_context(|| format!("invalid PCR index: {}", pcr_idx))?;

            let pcr_selection_list = PcrSelectionListBuilder::new()
                .with_selection(hash_alg, &[pcr_slot])
                .build()
                .context("failed to build PCR selection list")?;

            let (_update_counter, _pcr_sel_out, digest_list) = self
                .context
                .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))
                .context("failed to read PCR")?;

            if let Some(digest) = digest_list.value().first() {
                pcr_values.push(PcrValue {
                    index: *pcr_idx,
                    algorithm: pcr_selection.bank.clone(),
                    value: digest.value().to_vec(),
                });
            }
        }

        Ok(pcr_values)
    }

    /// Extend a PCR with a hash value
    pub fn pcr_extend(&mut self, _pcr: u32, _hash: &[u8], _bank: &str) -> Result<()> {
        // TODO: Implement PCR extend with correct PcrHandle API
        // Note: PCR extend is not needed for quote generation (read-only operation)
        bail!("pcr_extend not yet implemented - not needed for quote generation")
    }

    // ==================== Random Number Generation ====================

    /// Generate random bytes using the TPM's hardware RNG
    pub fn get_random<const N: usize>(&mut self) -> Result<[u8; N]> {
        let random_bytes = self
            .context
            .get_random(N)
            .context("failed to get random bytes from TPM")?;

        let bytes: [u8; N] = random_bytes
            .as_slice()
            .try_into()
            .context("insufficient random bytes from TPM")?;

        Ok(bytes)
    }

    // ==================== Primary Key Operations ====================

    /// Check if a persistent handle exists
    pub fn handle_exists(&mut self, handle: u32) -> Result<bool> {
        let persistent = PersistentTpmHandle::new(handle)
            .context("invalid persistent handle")?;

        match self.context.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create a primary key in the owner hierarchy
    pub fn create_primary(&mut self) -> Result<tss_esapi::handles::KeyHandle> {
        // TODO: Implement create_primary with correct DecodedKey API
        // Note: Not needed for quote generation (uses pre-provisioned GCP AK)
        bail!("create_primary not yet implemented - not needed for quote generation")
    }

    /// Make a key persistent at a given handle
    pub fn evict_control(
        &mut self,
        _transient_handle: tss_esapi::handles::KeyHandle,
        _persistent_handle: u32,
    ) -> Result<bool> {
        // TODO: Implement evict_control with correct Provision API
        // Note: Not needed for quote generation
        warn!("evict_control not yet implemented");
        Ok(false)
    }

    /// Ensure a persistent primary key exists at the given handle
    pub fn ensure_primary_key(&mut self, handle: u32) -> Result<bool> {
        if self.handle_exists(handle)? {
            return Ok(true);
        }

        info!("creating TPM primary key at 0x{:08x}...", handle);
        let transient = self.create_primary()?;
        self.evict_control(transient, handle)
    }
}
