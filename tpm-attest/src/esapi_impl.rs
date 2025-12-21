// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure tss-esapi implementation of TPM operations
//!
//! This module provides a clean implementation using only tss-esapi,
//! without relying on tpm2-tools command-line utilities.

use anyhow::{bail, Context as _, Result};
use std::convert::TryFrom;
use tracing::{debug, warn};
use tss_esapi::{
    abstraction::nv,
    constants::SessionType,
    handles::{NvIndexTpmHandle, PersistentTpmHandle, SessionHandle, TpmHandle},
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
    structures::{DigestValues, PcrSelectionListBuilder, PcrSlot, SymmetricDefinition},
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::{Marshall, UnMarshall},
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

        let device_config =
            DeviceConfig::from_str(device_path).context("failed to parse device config")?;
        let tcti = TctiNameConf::Device(device_config);

        let context = TssContext::new(tcti).context("failed to create TSS context")?;

        Ok(Self { context })
    }

    // ==================== NV Operations ====================

    /// Check if an NV index exists
    pub fn nv_exists(&mut self, index: u32) -> Result<bool> {
        let handle = NvIndexTpmHandle::new(index).context("invalid NV index")?;
        let nv_index = self.context.tr_from_tpm_public(TpmHandle::NvIndex(handle));

        match nv_index {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Read data from an NV index
    pub fn nv_read(&mut self, index: u32) -> Result<Option<Vec<u8>>> {
        use tss_esapi::interface_types::resource_handles::NvAuth;

        let handle = NvIndexTpmHandle::new(index).context("invalid NV index")?;

        // Get NV index handle from TPM
        let nv_auth_handle = TpmHandle::NvIndex(handle);
        let nv_auth_handle = match self.context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(nv_auth_handle)
                .map(|v| NvAuth::NvIndex(v.into()))
        }) {
            Ok(h) => h,
            Err(e) => {
                warn!("failed to get NV index handle for 0x{index:08x}: {e}");
                return Ok(None);
            }
        };

        // Read NV data with null auth session
        match self
            .context
            .execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, handle))
        {
            Ok(data) => Ok(Some(data.to_vec())),
            Err(e) => {
                warn!("nv_read failed for index 0x{index:08x}: {e}");
                Ok(None)
            }
        }
    }

    /// Write data to an NV index
    pub fn nv_write(&mut self, index: u32, data: &[u8]) -> Result<bool> {
        use tss_esapi::handles::NvIndexHandle;
        use tss_esapi::interface_types::resource_handles::NvAuth;
        use tss_esapi::structures::MaxNvBuffer;

        let handle = NvIndexTpmHandle::new(index).context("invalid NV index")?;

        // Get NV index handle from TPM
        let nv_index = self
            .context
            .tr_from_tpm_public(TpmHandle::NvIndex(handle))
            .context("failed to get NV index handle")?;
        let nv_index_handle = NvIndexHandle::from(nv_index);
        let nv_auth = NvAuth::NvIndex(nv_index.into());

        // Write data in chunks (TPM has max buffer size)
        let max_chunk = 1024usize; // Conservative chunk size
        let mut offset = 0u16;

        while offset < data.len() as u16 {
            let chunk_end = ((offset as usize) + max_chunk).min(data.len());
            let chunk = &data[(offset as usize)..chunk_end];

            let nv_data =
                MaxNvBuffer::try_from(chunk.to_vec()).context("data exceeds NV buffer size")?;

            self.context
                .execute_with_nullauth_session(|ctx| {
                    ctx.nv_write(nv_auth, nv_index_handle, nv_data, offset)
                })
                .with_context(|| {
                    format!("failed to write to NV index 0x{index:08x} at offset {offset}")
                })?;

            offset = chunk_end as u16;
        }

        debug!("wrote {} bytes to NV index 0x{index:08x}", data.len());
        Ok(true)
    }

    /// Define a new NV index
    pub fn nv_define(&mut self, index: u32, size: usize, owner_read_write: bool) -> Result<bool> {
        use tss_esapi::attributes::NvIndexAttributesBuilder;
        use tss_esapi::interface_types::resource_handles::Provision;
        use tss_esapi::structures::NvPublicBuilder;

        let handle = NvIndexTpmHandle::new(index).context("invalid NV index")?;

        // Build NV index attributes
        let mut attributes = NvIndexAttributesBuilder::new();
        if owner_read_write {
            attributes = attributes.with_owner_write(true).with_owner_read(true);
        }
        let attributes = attributes
            .build()
            .context("failed to build NV attributes")?;

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
                debug!("defined NV index 0x{index:08x} with size {size}");
                Ok(true)
            }
            Err(e) => {
                warn!("nv_define failed for index 0x{index:08x}: {e}");
                Ok(false)
            }
        }
    }

    /// Undefine (delete) an NV index
    pub fn nv_undefine(&mut self, index: u32) -> Result<bool> {
        use tss_esapi::handles::NvIndexHandle;
        use tss_esapi::interface_types::resource_handles::Provision;

        let handle = NvIndexTpmHandle::new(index).context("invalid NV index")?;

        // Get NV index handle
        let nv_idx = match self.context.tr_from_tpm_public(TpmHandle::NvIndex(handle)) {
            Ok(h) => NvIndexHandle::from(h),
            Err(e) => {
                warn!("failed to get NV index handle for 0x{index:08x}: {e}");
                return Ok(false);
            }
        };

        // Undefine NV space
        match self
            .context
            .execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(Provision::Owner, nv_idx))
        {
            Ok(_) => {
                debug!("undefined NV index 0x{index:08x}");
                Ok(true)
            }
            Err(e) => {
                warn!("nv_undefine failed for index 0x{index:08x}: {e}");
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
            _ => bail!(
                "unsupported hash algorithm: {bank}",
                bank = pcr_selection.bank
            ),
        };

        let mut pcr_values = Vec::new();

        // Read each PCR individually to ensure correct index mapping
        for pcr_idx in &pcr_selection.pcrs {
            let bit_mask = 1u32 << pcr_idx;
            let pcr_slot = PcrSlot::try_from(bit_mask)
                .with_context(|| format!("invalid PCR index: {pcr_idx}"))?;

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
    pub fn pcr_extend(&mut self, pcr: u32, hash: &[u8], bank: &str) -> Result<()> {
        use tss_esapi::handles::PcrHandle;
        use tss_esapi::structures::Digest;

        let hash_alg = match bank {
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => bail!("unsupported hash algorithm: {bank}"),
        };

        // PCR handles are pre-defined; do not resolve via ReadPublic.
        let pcr_handle =
            PcrHandle::try_from(pcr).with_context(|| format!("invalid PCR index: {pcr}"))?;

        // Create digest from hash bytes
        let digest =
            Digest::try_from(hash.to_vec()).context("failed to create digest from hash")?;

        // Create DigestValues with the hash algorithm
        let mut digest_values = DigestValues::new();
        digest_values.set(hash_alg, digest);

        self.context
            .execute_with_nullauth_session(|ctx| ctx.pcr_extend(pcr_handle, digest_values))
            .with_context(|| format!("failed to extend PCR {pcr} with {bank}"))?;

        debug!("extended PCR {pcr} with {bank} hash");
        Ok(())
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
        let persistent = PersistentTpmHandle::new(handle).context("invalid persistent handle")?;

        match self
            .context
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create a primary key in the owner hierarchy
    /// Uses RSA 2048 storage key template for sealing operations
    pub fn create_primary(&mut self) -> Result<tss_esapi::handles::KeyHandle> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::{algorithm::PublicAlgorithm, key_bits::RsaKeyBits};
        use tss_esapi::structures::{
            PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
            SymmetricDefinitionObject,
        };

        // Build RSA 2048 storage key template (standard SRK template)
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .context("failed to build object attributes")?;

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(Default::default()) // Use default RSA exponent (65537)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .context("failed to build RSA parameters")?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .context("failed to build public structure")?;

        // Create primary key in owner hierarchy
        let primary_key = self
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Owner,
                    public,
                    None, // auth_value
                    None, // sensitive_data
                    None, // outside_info
                    None, // creation_pcr
                )
            })
            .context("failed to create primary key")?;

        debug!("created primary key in owner hierarchy");
        Ok(primary_key.key_handle)
    }

    /// Make a key persistent at a given handle
    pub fn evict_control(
        &mut self,
        transient_handle: tss_esapi::handles::KeyHandle,
        persistent_handle: u32,
    ) -> Result<bool> {
        use tss_esapi::interface_types::resource_handles::Provision;

        let persistent =
            PersistentTpmHandle::new(persistent_handle).context("invalid persistent handle")?;

        self.context
            .execute_with_nullauth_session(|ctx| {
                ctx.evict_control(Provision::Owner, transient_handle.into(), persistent.into())
            })
            .context("failed to make key persistent")?;

        debug!("made key persistent at 0x{persistent_handle:08x}");
        Ok(true)
    }

    /// Ensure a persistent primary key exists at the given handle
    pub fn ensure_primary_key(&mut self, handle: u32) -> Result<bool> {
        if self.handle_exists(handle)? {
            return Ok(true);
        }

        debug!("creating TPM primary key at 0x{handle:08x}...");
        let transient = self.create_primary()?;
        self.evict_control(transient, handle)
    }

    // ==================== Seal/Unseal Operations ====================

    /// Seal data to TPM with PCR policy
    pub fn seal(
        &mut self,
        data: &[u8],
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::PublicAlgorithm;
        use tss_esapi::structures::{PublicBuilder, SensitiveData};

        // Get parent key handle
        let parent = PersistentTpmHandle::new(parent_handle).context("invalid parent handle")?;
        let parent_key = self
            .context
            .tr_from_tpm_public(TpmHandle::Persistent(parent))
            .context("failed to get parent key handle")?;

        // Build PCR policy
        let hash_alg = match pcr_selection.bank.as_str() {
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => bail!(
                "unsupported hash algorithm: {bank}",
                bank = pcr_selection.bank
            ),
        };

        // Build PCR selection list
        let pcr_slots: Result<Vec<PcrSlot>> = pcr_selection
            .pcrs
            .iter()
            .map(|&idx| {
                let bit_mask = 1u32 << idx;
                PcrSlot::try_from(bit_mask).with_context(|| format!("invalid PCR index: {idx}"))
            })
            .collect();
        let pcr_slots = pcr_slots?;

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(hash_alg, &pcr_slots)
            .build()
            .context("failed to build PCR selection list")?;

        // Create session for PCR policy
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                hash_alg,
            )
            .context("failed to start policy session")?
            .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

        let policy_session = session.try_into()?;

        // Apply PCR policy - requires digest of current PCR values
        let (_update_counter, _pcr_sel_out, digest_list) = self
            .context
            .pcr_read(pcr_selection_list.clone())
            .context("failed to read PCR values")?;

        // Calculate PCR digest
        let pcr_digest = if let Some(digest) = digest_list.value().first() {
            digest.clone()
        } else {
            bail!("no PCR digest found");
        };

        self.context
            .policy_pcr(policy_session, pcr_digest, pcr_selection_list.clone())
            .context("failed to set PCR policy")?;

        // Get policy digest
        let policy_digest = self
            .context
            .policy_get_digest(policy_session)
            .context("failed to get policy digest")?;

        // Flush session
        let session_handle: SessionHandle = session.into();
        self.context
            .flush_context(session_handle.into())
            .context("failed to flush policy session")?;

        // Build sealed data object attributes
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(false)
            .with_admin_with_policy(true)
            .build()
            .context("failed to build object attributes")?;

        // Build public structure for sealed object
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(object_attributes)
            .with_auth_policy(policy_digest)
            .build()
            .context("failed to build public structure")?;

        // Create sealed data (sensitive data)
        let sensitive_data =
            SensitiveData::try_from(data.to_vec()).context("failed to create sensitive data")?;

        // Create sealed object
        let create_result = self
            .context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(
                    parent_key.into(),
                    public,
                    None, // auth_value
                    Some(sensitive_data),
                    None, // outside_info
                    None, // creation_pcr
                )
            })
            .context("failed to seal data")?;

        debug!("sealed {} bytes to TPM with PCR policy", data.len());

        // Marshal public and private parts
        let pub_bytes = create_result
            .out_public
            .marshall()
            .context("failed to marshal public part")?;
        let priv_bytes = create_result.out_private.value().to_vec();

        Ok((pub_bytes, priv_bytes))
    }

    /// Unseal data from TPM with PCR policy
    pub fn unseal(
        &mut self,
        pub_bytes: &[u8],
        priv_bytes: &[u8],
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Vec<u8>> {
        use tss_esapi::structures::{Private, Public, SymmetricDefinition};

        // Get parent key handle
        let parent = PersistentTpmHandle::new(parent_handle).context("invalid parent handle")?;
        let parent_key = self
            .context
            .tr_from_tpm_public(TpmHandle::Persistent(parent))
            .context("failed to get parent key handle")?;

        // Unmarshal public and private parts
        let public = Public::unmarshall(pub_bytes).context("failed to unmarshal public part")?;
        let private =
            Private::try_from(priv_bytes.to_vec()).context("failed to create private structure")?;

        // Load sealed object
        let sealed_handle = self
            .context
            .execute_with_nullauth_session(|ctx| ctx.load(parent_key.into(), private, public))
            .context("failed to load sealed object")?;

        // Build PCR policy for unsealing
        let hash_alg = match pcr_selection.bank.as_str() {
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => bail!(
                "unsupported hash algorithm: {bank}",
                bank = pcr_selection.bank
            ),
        };

        let pcr_slots: Result<Vec<PcrSlot>> = pcr_selection
            .pcrs
            .iter()
            .map(|&idx| {
                let bit_mask = 1u32 << idx;
                PcrSlot::try_from(bit_mask).with_context(|| format!("invalid PCR index: {idx}"))
            })
            .collect();
        let pcr_slots = pcr_slots?;

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(hash_alg, &pcr_slots)
            .build()
            .context("failed to build PCR selection list")?;

        // Create policy session
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_128_CFB,
                hash_alg,
            )
            .context("failed to start policy session")?
            .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

        let policy_session = session.try_into()?;

        // Apply PCR policy - requires digest of current PCR values
        let (_update_counter, _pcr_sel_out, digest_list) = self
            .context
            .pcr_read(pcr_selection_list.clone())
            .context("failed to read PCR values")?;

        let pcr_digest = if let Some(digest) = digest_list.value().first() {
            digest.clone()
        } else {
            bail!("no PCR digest found");
        };

        self.context
            .policy_pcr(policy_session, pcr_digest, pcr_selection_list)
            .context("failed to set PCR policy")?;

        // Unseal with policy session
        let unsealed = self
            .context
            .execute_with_session(Some(session), |ctx| ctx.unseal(sealed_handle.into()))
            .context("failed to unseal data (PCR values may have changed)")?;

        // Flush handles
        self.context
            .flush_context(sealed_handle.into())
            .context("failed to flush sealed object handle")?;
        let session_handle: SessionHandle = session.into();
        self.context
            .flush_context(session_handle.into())
            .context("failed to flush policy session")?;

        let data = unsealed.to_vec();
        debug!("unsealed {} bytes from TPM", data.len());

        Ok(data)
    }
}
