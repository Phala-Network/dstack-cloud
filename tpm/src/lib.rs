// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 command-line wrapper library
//!
//! This module provides a clean Rust API for TPM 2.0 operations by wrapping
//! the `tpm2-tools` command-line utilities. It handles PCR operations, sealing,
//! unsealing, and NV storage.

use std::{
    io::{ErrorKind, Write as _},
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use tempfile::TempDir;
use tracing::{info, warn};

/// Primary key handle for sealing operations
pub const PRIMARY_KEY_HANDLE: u32 = 0x81000100;
/// NV index for sealed root key storage
pub const SEALED_NV_INDEX: u32 = 0x01801101;
/// App identity PCR number
pub const APP_PCR: u32 = 14;

/// Default PCR selection for dstack (boot chain PCR 0-9 + app PCR 15)
pub fn default_pcr_policy() -> PcrSelection {
    PcrSelection::sha256(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, APP_PCR])
}

/// Structured TPM quote containing all verification materials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// TPM quote message (TPMS_ATTEST structure)
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,
    /// Quote signature by Attestation Key
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// PCR values at the time of quote generation
    pub pcr_values: Vec<PcrValue>,
    /// Qualifying data (nonce) used in the quote
    #[serde(with = "hex_bytes")]
    pub qualifying_data: Vec<u8>,
    /// Attestation Key (AK) certificate (DER format)
    /// On GCP, this is stored in TPM NV index 0x01C10000 (RSA) or 0x01C10002 (ECC)
    /// and is signed by Google Private CA (GCE Intermediate CA)
    #[serde(with = "hex_bytes")]
    pub ak_cert: Vec<u8>,
}

/// Quote collateral - certificates and CRLs required for verification
///
/// Following dcap-qvl architecture, this structure contains all the external
/// data needed to verify a TPM quote certificate chain.
///
/// # Architecture (dcap-qvl pattern)
/// - **Step 1**: `get_collateral()` - Extract cert chain and download CRLs (if CRL DP present)
/// - **Step 2**: `verify_quote()` - Verify quote with collateral (CRL verification is conditional)
///
/// # Certificate Chain
/// The TPM AK certificate chain follows this structure:
/// - **Leaf cert**: AK (Attestation Key) certificate from TPM
/// - **Cert chain**: Intermediate CA(s) + Root CA (PEM format, concatenated)
/// - **CRLs**: Certificate Revocation Lists for all certs (DER format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteCollateral {
    /// Certificate chain in PEM format (intermediate CA(s) + root CA concatenated)
    /// This serves as the trust anchor for verification
    pub cert_chain_pem: String,
    /// Certificate Revocation Lists in DER format (conditional)
    /// Order: CRLs for certificates that have CRL Distribution Points
    /// CRL verification is enforced only for certs that provide CRL DP
    pub crls: Vec<Vec<u8>>,
}

/// PCR value for a specific PCR register
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR index
    pub index: u32,
    /// Hash algorithm (e.g., "sha256")
    pub algorithm: String,
    /// PCR value (hash)
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

/// TPM context for managing a connection to a TPM device
#[derive(Debug)]
pub struct TpmContext {
    tcti: String,
    work_dir: Arc<TempDir>,
}

impl TpmContext {
    fn work_dir(&self) -> &Path {
        self.work_dir.path()
    }
}

/// Result of a TPM command execution
#[derive(Debug)]
pub struct TpmOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl TpmOutput {
    fn from_output(output: Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }

    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

/// PCR (Platform Configuration Register) selection for policy binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSelection {
    pub bank: String,
    pub pcrs: Vec<u32>,
}

impl PcrSelection {
    pub fn new(bank: &str, pcrs: &[u32]) -> Self {
        Self {
            bank: bank.to_string(),
            pcrs: pcrs.to_vec(),
        }
    }

    pub fn sha256(pcrs: &[u32]) -> Self {
        Self::new("sha256", pcrs)
    }

    pub fn to_arg(&self) -> String {
        let pcr_list: Vec<String> = self.pcrs.iter().map(|p| p.to_string()).collect();
        format!("{}:{}", self.bank, pcr_list.join(","))
    }
}

impl Default for PcrSelection {
    fn default() -> Self {
        Self::sha256(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    }
}

/// Sealed data blob containing public and private parts
#[derive(Debug, Clone)]
pub struct SealedBlob {
    pub data: Vec<u8>,
}

impl SealedBlob {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_parts(pub_data: &[u8], priv_data: &[u8]) -> Self {
        let mut data = Vec::with_capacity(pub_data.len() + priv_data.len());
        data.extend_from_slice(pub_data);
        data.extend_from_slice(priv_data);
        Self { data }
    }

    pub fn split(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.data.len() < 4 {
            bail!("sealed blob too small");
        }

        let pub_size = u16::from_be_bytes([self.data[0], self.data[1]]) as usize;
        if self.data.len() < 2 + pub_size + 2 {
            bail!("sealed blob truncated at pub");
        }

        let priv_offset = 2 + pub_size;
        let priv_size =
            u16::from_be_bytes([self.data[priv_offset], self.data[priv_offset + 1]]) as usize;
        if self.data.len() < priv_offset + 2 + priv_size {
            bail!("sealed blob truncated at priv");
        }

        let pub_data = self.data[..2 + pub_size].to_vec();
        let priv_data = self.data[priv_offset..priv_offset + 2 + priv_size].to_vec();

        Ok((pub_data, priv_data))
    }
}

impl TpmContext {
    /// Open a TPM context with optional TCTI string (auto-detect if None)
    pub fn open(tcti: Option<&str>) -> Result<Self> {
        match tcti {
            Some(t) => Self::new(t),
            None => Self::detect(),
        }
    }

    /// Detect and connect to an available TPM device
    pub fn detect() -> Result<Self> {
        let tcti = if Path::new("/dev/tpmrm0").exists() {
            "device:/dev/tpmrm0"
        } else if Path::new("/dev/tpm0").exists() {
            "device:/dev/tpm0"
        } else {
            bail!("TPM device not found");
        };
        Self::new(tcti)
    }

    /// Create a new TPM context with a specific TCTI string
    pub fn new(tcti: &str) -> Result<Self> {
        let work_dir = TempDir::new().context("failed to create TPM work directory")?;
        Ok(Self {
            tcti: tcti.to_string(),
            work_dir: Arc::new(work_dir),
        })
    }

    /// Run a tpm2 command
    fn run_cmd(&self, cmd: &str, args: &[&str]) -> Result<Option<TpmOutput>> {
        let mut command = Command::new(cmd);
        command.env("TPM2TOOLS_TCTI", &self.tcti).args(args);
        match command.output() {
            Ok(output) => Ok(Some(TpmOutput::from_output(output))),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context("failed to run tpm2 command"),
        }
    }

    /// Run a tpm2 command with stdin data
    fn run_cmd_with_stdin(
        &self,
        cmd: &str,
        args: &[&str],
        stdin_data: &[u8],
    ) -> Result<Option<TpmOutput>> {
        let mut command = Command::new(cmd);
        command
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        child
            .stdin
            .as_mut()
            .context("failed to open stdin")?
            .write_all(stdin_data)?;

        let output = child
            .wait_with_output()
            .context("failed to wait for command")?;
        Ok(Some(TpmOutput::from_output(output)))
    }

    // ==================== NV Operations ====================

    /// Check if an NV index exists
    pub fn nv_exists(&self, index: u32) -> Result<bool> {
        let index_str = format!("0x{:08x}", index);
        let Some(output) = self.run_cmd("tpm2_nvreadpublic", &[&index_str])? else {
            return Ok(false);
        };
        Ok(output.success)
    }

    /// Define a new NV index
    pub fn nv_define(&self, index: u32, size: usize, attributes: &str) -> Result<bool> {
        let index_str = format!("0x{:08x}", index);
        let size_str = size.to_string();
        let Some(output) = self.run_cmd(
            "tpm2_nvdefine",
            &["-C", "o", "-s", &size_str, "-a", attributes, &index_str],
        )?
        else {
            return Ok(false);
        };
        if !output.success {
            warn!("tpm2_nvdefine failed: {}", output.stderr_string());
        }
        Ok(output.success)
    }

    /// Undefine (delete) an NV index
    pub fn nv_undefine(&self, index: u32) -> Result<bool> {
        let index_str = format!("0x{:08x}", index);
        let Some(output) = self.run_cmd("tpm2_nvundefine", &["-C", "o", &index_str])? else {
            return Ok(false);
        };
        Ok(output.success)
    }

    /// Read data from an NV index
    pub fn nv_read(&self, index: u32) -> Result<Option<Vec<u8>>> {
        if !self.nv_exists(index)? {
            return Ok(None);
        }
        let index_str = format!("0x{:08x}", index);
        let Some(output) = self.run_cmd("tpm2_nvread", &["-C", "o", &index_str])? else {
            return Ok(None);
        };
        if !output.success {
            warn!("tpm2_nvread failed: {}", output.stderr_string());
            return Ok(None);
        }
        Ok(Some(output.stdout))
    }

    /// Write data to an NV index
    pub fn nv_write(&self, index: u32, data: &[u8]) -> Result<bool> {
        let index_str = format!("0x{:08x}", index);
        let Some(output) =
            self.run_cmd_with_stdin("tpm2_nvwrite", &["-C", "o", "-i", "-", &index_str], data)?
        else {
            return Ok(false);
        };
        if !output.success {
            warn!("tpm2_nvwrite failed: {}", output.stderr_string());
        }
        Ok(output.success)
    }

    // ==================== Handle Operations ====================

    /// Check if a handle (persistent or transient) exists
    pub fn handle_exists(&self, handle: u32) -> Result<bool> {
        let handle_str = format!("0x{:08x}", handle);
        let Some(output) = self.run_cmd("tpm2_readpublic", &["-c", &handle_str])? else {
            return Ok(false);
        };
        Ok(output.success)
    }

    /// Create a primary key in the owner hierarchy
    pub fn create_primary(&self, output_ctx: &Path) -> Result<bool> {
        let ctx_str = output_ctx.to_string_lossy();
        let Some(output) = self.run_cmd("tpm2_createprimary", &["-C", "o", "-c", &ctx_str])? else {
            return Ok(false);
        };
        if !output.success {
            warn!("tpm2_createprimary failed: {}", output.stderr_string());
        }
        Ok(output.success)
    }

    /// Make a key persistent at a given handle
    pub fn evict_control(&self, ctx_file: &Path, persistent_handle: u32) -> Result<bool> {
        let ctx_str = ctx_file.to_string_lossy();
        let handle_str = format!("0x{:08x}", persistent_handle);
        let Some(output) = self.run_cmd(
            "tpm2_evictcontrol",
            &["-C", "o", "-c", &ctx_str, &handle_str],
        )?
        else {
            return Ok(false);
        };
        if !output.success {
            warn!("tpm2_evictcontrol failed: {}", output.stderr_string());
        }
        Ok(output.success)
    }

    /// Ensure a persistent primary key exists at the given handle
    pub fn ensure_primary_key(&self, handle: u32) -> Result<bool> {
        if self.handle_exists(handle)? {
            return Ok(true);
        }

        info!("creating TPM primary key at 0x{:08x}...", handle);
        let primary_ctx = self.work_dir().join("primary.ctx");
        if !self.create_primary(&primary_ctx)? {
            return Ok(false);
        }

        self.evict_control(&primary_ctx, handle)
    }

    // ==================== PCR Operations ====================

    /// Extend a PCR with a hash value
    pub fn pcr_extend(&self, pcr: u32, hash: &[u8], bank: &str) -> Result<()> {
        let pcr_arg = format!("{}:{}={}", pcr, bank, hex::encode(hash));
        let output = self
            .run_cmd("tpm2_pcrextend", &[&pcr_arg])?
            .context("tpm2_pcrextend not found")?;
        if !output.success {
            bail!(
                "tpm2_pcrextend PCR {pcr} failed: {}",
                output.stderr_string()
            );
        }
        info!("extended PCR {pcr} with hash");
        Ok(())
    }

    /// Extend a PCR with a SHA256 hash
    pub fn pcr_extend_sha256(&self, pcr: u32, hash: &[u8; 32]) -> Result<()> {
        self.pcr_extend(pcr, hash, "sha256")
    }

    /// Read PCR values (returns raw output)
    pub fn pcr_read(&self, selection: &PcrSelection) -> Result<Option<Vec<u8>>> {
        let sel_str = selection.to_arg();
        let Some(output) = self.run_cmd("tpm2_pcrread", &[&sel_str])? else {
            return Ok(None);
        };
        if !output.success {
            warn!("tpm2_pcrread failed: {}", output.stderr_string());
            return Ok(None);
        }
        Ok(Some(output.stdout))
    }

    /// Dump PCR values to log for debugging
    pub fn dump_pcr_values(&self, selection: &PcrSelection) {
        let sel_str = selection.to_arg();
        match self.run_cmd("tpm2_pcrread", &[&sel_str]) {
            Ok(Some(output)) if output.success => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                info!("PCR values ({}):\n{}", sel_str, stdout);
            }
            Ok(Some(output)) => {
                warn!("tpm2_pcrread failed: {}", output.stderr_string());
            }
            Ok(None) => {
                warn!("tpm2_pcrread not found");
            }
            Err(e) => {
                warn!("failed to read PCR values: {}", e);
            }
        }
    }

    // ==================== Session Operations ====================

    /// Start a trial policy session and compute PCR policy digest
    fn compute_pcr_policy(&self, selection: &PcrSelection) -> Result<Option<Vec<u8>>> {
        let work_dir = self.work_dir();
        let session_ctx = work_dir.join("session.ctx");
        let policy_digest = work_dir.join("policy.digest");
        let session_ctx_str = session_ctx.to_string_lossy();
        let policy_digest_str = policy_digest.to_string_lossy();
        let sel_str = selection.to_arg();

        // Start trial session
        let Some(output) = self.run_cmd("tpm2_startauthsession", &["-S", &session_ctx_str])? else {
            return Ok(None);
        };
        if !output.success {
            warn!("tpm2_startauthsession failed: {}", output.stderr_string());
            return Ok(None);
        }

        // Create PCR policy
        let result = self.run_cmd(
            "tpm2_policypcr",
            &[
                "-S",
                &session_ctx_str,
                "-l",
                &sel_str,
                "-L",
                &policy_digest_str,
            ],
        );
        let _ = self.run_cmd("tpm2_flushcontext", &[&session_ctx_str]);

        let Some(output) = result? else {
            return Ok(None);
        };
        if !output.success {
            warn!("tpm2_policypcr failed: {}", output.stderr_string());
            return Ok(None);
        }

        match std::fs::read(&policy_digest) {
            Ok(digest) => Ok(Some(digest)),
            Err(e) => {
                warn!("failed to read policy digest: {}", e);
                Ok(None)
            }
        }
    }

    // ==================== Sealing Operations ====================

    /// Seal data to the TPM bound to current PCR values
    pub fn seal_to_blob(
        &self,
        data: &[u8],
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Option<SealedBlob>> {
        // Ensure primary key exists
        if !self.ensure_primary_key(parent_handle)? {
            return Ok(None);
        }

        info!("sealing data with PCR policy {}...", pcr_selection.to_arg());

        // Compute PCR policy digest
        let Some(_policy_digest) = self.compute_pcr_policy(pcr_selection)? else {
            return Ok(None);
        };

        let work_dir = self.work_dir();
        let seal_pub = work_dir.join("seal.pub");
        let seal_priv = work_dir.join("seal.priv");
        let policy_digest_file = work_dir.join("policy.digest");
        let handle_str = format!("0x{:08x}", parent_handle);
        let seal_pub_str = seal_pub.to_string_lossy();
        let seal_priv_str = seal_priv.to_string_lossy();
        let policy_digest_str = policy_digest_file.to_string_lossy();

        // Create sealed object
        let Some(output) = self.run_cmd_with_stdin(
            "tpm2_create",
            &[
                "-C",
                &handle_str,
                "-u",
                &seal_pub_str,
                "-r",
                &seal_priv_str,
                "-L",
                &policy_digest_str,
                "-i",
                "-",
            ],
            data,
        )?
        else {
            return Ok(None);
        };
        if !output.success {
            warn!(
                "tpm2_create sealed object failed: {}",
                output.stderr_string()
            );
            return Ok(None);
        }

        // Read pub and priv data
        let pub_data = std::fs::read(&seal_pub).context("failed to read seal.pub")?;
        let priv_data = std::fs::read(&seal_priv).context("failed to read seal.priv")?;

        info!("data sealed successfully");
        Ok(Some(SealedBlob::from_parts(&pub_data, &priv_data)))
    }

    /// Unseal data from the TPM (requires PCR values to match)
    pub fn unseal_blob(
        &self,
        sealed: &SealedBlob,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Option<Vec<u8>>> {
        // Split sealed blob into pub/priv parts
        let (pub_data, priv_data) = sealed.split()?;

        let work_dir = self.work_dir();
        let seal_pub = work_dir.join("seal.pub");
        let seal_priv = work_dir.join("seal.priv");
        let seal_ctx = work_dir.join("seal.ctx");
        let session_ctx = work_dir.join("session.ctx");
        let unsealed = work_dir.join("unsealed.bin");

        std::fs::write(&seal_pub, &pub_data)?;
        std::fs::write(&seal_priv, &priv_data)?;

        let handle_str = format!("0x{:08x}", parent_handle);
        let seal_pub_str = seal_pub.to_string_lossy();
        let seal_priv_str = seal_priv.to_string_lossy();
        let seal_ctx_str = seal_ctx.to_string_lossy();
        let session_ctx_str = session_ctx.to_string_lossy();
        let unsealed_str = unsealed.to_string_lossy();
        let sel_str = pcr_selection.to_arg();

        // Load sealed object
        let Some(output) = self.run_cmd(
            "tpm2_load",
            &[
                "-C",
                &handle_str,
                "-u",
                &seal_pub_str,
                "-r",
                &seal_priv_str,
                "-c",
                &seal_ctx_str,
            ],
        )?
        else {
            return Ok(None);
        };
        if !output.success {
            warn!("tpm2_load sealed object failed: {}", output.stderr_string());
            return Ok(None);
        }

        // Start policy session
        let Some(output) = self.run_cmd(
            "tpm2_startauthsession",
            &["-S", &session_ctx_str, "--policy-session"],
        )?
        else {
            return Ok(None);
        };
        if !output.success {
            warn!("tpm2_startauthsession failed: {}", output.stderr_string());
            return Ok(None);
        }

        // Apply PCR policy
        let result = self.run_cmd("tpm2_policypcr", &["-S", &session_ctx_str, "-l", &sel_str]);
        if let Ok(Some(output)) = &result {
            if !output.success {
                warn!("tpm2_policypcr failed: {}", output.stderr_string());
                let _ = self.run_cmd("tpm2_flushcontext", &[&session_ctx_str]);
                return Ok(None);
            }
        } else {
            let _ = self.run_cmd("tpm2_flushcontext", &[&session_ctx_str]);
            return Ok(None);
        }

        // Unseal
        let policy_auth = format!("session:{}", session_ctx_str);
        let result = self.run_cmd(
            "tpm2_unseal",
            &["-c", &seal_ctx_str, "-p", &policy_auth, "-o", &unsealed_str],
        );
        let _ = self.run_cmd("tpm2_flushcontext", &[&session_ctx_str]);

        let Some(output) = result? else {
            return Ok(None);
        };
        if !output.success {
            // This is expected when PCR values don't match
            warn!(
                "tpm2_unseal failed (PCR mismatch?): {}",
                output.stderr_string()
            );
            return Ok(None);
        }

        // Read unsealed data
        match std::fs::read(&unsealed) {
            Ok(data) => Ok(Some(data)),
            Err(e) => {
                warn!("failed to read unsealed data: {}", e);
                Ok(None)
            }
        }
    }

    // ==================== Random Number Generation ====================

    /// Generate random bytes using the TPM's hardware RNG
    pub fn get_random<const N: usize>(&self) -> Result<[u8; N]> {
        let size_str = N.to_string();
        let output = self
            .run_cmd("tpm2_getrandom", &[&size_str])?
            .context("tpm2_getrandom not found")?;
        if !output.success {
            bail!("tpm2_getrandom failed: {}", output.stderr_string());
        }
        let bytes = output
            .stdout
            .try_into()
            .ok()
            .context("insufficient random bytes")?;
        Ok(bytes)
    }

    // ==================== High-Level Convenience Methods ====================

    /// Seal data and store in NV storage
    pub fn seal(
        &self,
        data: &[u8],
        nv_index: u32,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<()> {
        let sealed = self
            .seal_to_blob(data, parent_handle, pcr_selection)?
            .context("failed to seal data")?;

        // Delete existing NV index if present
        if self.nv_exists(nv_index)? {
            self.nv_undefine(nv_index)?;
        }

        self.nv_define(nv_index, sealed.data.len(), "ownerread|ownerwrite")?
            .then_some(())
            .context("failed to define NV index")?;

        self.nv_write(nv_index, &sealed.data)?
            .then_some(())
            .context("failed to write sealed blob to NV")?;

        info!("data sealed and stored to NV index 0x{:08x}", nv_index);
        Ok(())
    }

    /// Read and unseal data from NV storage
    pub fn unseal_to_vec(
        &self,
        nv_index: u32,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Option<Vec<u8>>> {
        let Some(blob_data) = self.nv_read(nv_index)? else {
            return Ok(None);
        };

        let sealed = SealedBlob::new(blob_data);
        self.unseal_blob(&sealed, parent_handle, pcr_selection)
    }

    /// Read and unseal fixed-size data from NV storage
    pub fn unseal<const N: usize>(
        &self,
        nv_index: u32,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Option<[u8; N]>> {
        let Some(data) = self.unseal_to_vec(nv_index, parent_handle, pcr_selection)? else {
            return Ok(None);
        };
        Ok(Some(
            data.try_into()
                .ok()
                .context("unsealed data size mismatch")?,
        ))
    }

    // ==================== Quote Operations ====================

    /// Read PCR values for the given selection
    fn read_pcr_values(&self, pcr_selection: &PcrSelection) -> Result<Vec<PcrValue>> {
        let work_dir = self.work_dir();
        let pcr_output = work_dir.join("pcr_values.bin");
        let pcr_output_str = pcr_output.to_string_lossy();
        let sel_str = pcr_selection.to_arg();

        let Some(output) = self.run_cmd("tpm2_pcrread", &["-o", &pcr_output_str, &sel_str])? else {
            bail!("tpm2_pcrread not found");
        };
        if !output.success {
            bail!("tpm2_pcrread failed: {}", output.stderr_string());
        }

        // Parse PCR values from binary output
        let pcr_data = std::fs::read(&pcr_output)?;
        let mut pcr_values = Vec::new();

        // Each PCR value is 32 bytes for SHA256
        let hash_size = 32;
        for (i, pcr_idx) in pcr_selection.pcrs.iter().enumerate() {
            let offset = i * hash_size;
            if offset + hash_size <= pcr_data.len() {
                let value = pcr_data[offset..offset + hash_size].to_vec();
                pcr_values.push(PcrValue {
                    index: *pcr_idx,
                    algorithm: pcr_selection.bank.clone(),
                    value,
                });
            }
        }

        Ok(pcr_values)
    }

    /// Generate a TPM quote with the given qualifying data and PCR selection
    pub fn create_quote(
        &self,
        qualifying_data: &[u8],
        pcr_selection: &PcrSelection,
    ) -> Result<TpmQuote> {
        // Try native GCP AK implementation first (if feature enabled)
        #[cfg(feature = "gcp-vtpm")]
        {
            match create_quote_with_gcp_ak(Some(&self.tcti), qualifying_data, pcr_selection) {
                Ok(quote) => {
                    info!("✓ quote generated using GCP pre-provisioned AK (native)");
                    return Ok(quote);
                }
                Err(e) => {
                    warn!("failed to use GCP AK, falling back to temporary AK: {}", e);
                }
            }
        }

        // Fall back to temporary AK (tpm2-tools)
        self.create_quote_with_temp_ak(qualifying_data, pcr_selection)
    }

    /// Generate a TPM quote using temporary AK (via tpm2-tools)
    fn create_quote_with_temp_ak(
        &self,
        qualifying_data: &[u8],
        pcr_selection: &PcrSelection,
    ) -> Result<TpmQuote> {
        let work_dir = self.work_dir();
        let ak_ctx = work_dir.join("ak.ctx");
        let ak_pub = work_dir.join("ak.pub");
        let quote_msg = work_dir.join("quote.msg");
        let quote_sig = work_dir.join("quote.sig");
        let ak_ctx_str = ak_ctx.to_string_lossy();
        let ak_pub_str = ak_pub.to_string_lossy();
        let quote_msg_str = quote_msg.to_string_lossy();
        let quote_sig_str = quote_sig.to_string_lossy();
        let sel_str = pcr_selection.to_arg();

        // Create Endorsement Key (EK) first
        let ek_ctx = work_dir.join("ek.ctx");
        let ek_ctx_str = ek_ctx.to_string_lossy();

        let Some(output) = self.run_cmd("tpm2_createek", &["-c", &ek_ctx_str, "-G", "rsa"])? else {
            bail!("tpm2_createek not found");
        };
        if !output.success {
            bail!("tpm2_createek failed: {}", output.stderr_string());
        }

        // Create Attestation Key (AK) as a child of EK
        let Some(output) = self.run_cmd(
            "tpm2_createak",
            &[
                "-C",
                &ek_ctx_str,
                "-c",
                &ak_ctx_str,
                "-u",
                &ak_pub_str,
                "-G",
                "rsa",
                "-g",
                "sha256",
            ],
        )?
        else {
            bail!("tpm2_createak not found");
        };
        if !output.success {
            bail!("tpm2_createak failed: {}", output.stderr_string());
        }

        // Read PCR values before generating quote
        let pcr_values = self.read_pcr_values(pcr_selection)?;

        // Write qualifying data to file
        let qual_data_file = work_dir.join("qual_data.bin");
        std::fs::write(&qual_data_file, qualifying_data)?;
        let qual_data_str = qual_data_file.to_string_lossy();

        // Generate quote with qualifying data
        let Some(output) = self.run_cmd(
            "tpm2_quote",
            &[
                "-c",
                &ak_ctx_str,
                "-l",
                &sel_str,
                "-m",
                &quote_msg_str,
                "-s",
                &quote_sig_str,
                "-q",
                &qual_data_str,
            ],
        )?
        else {
            bail!("tpm2_quote not found");
        };
        if !output.success {
            bail!("tpm2_quote failed: {}", output.stderr_string());
        }

        // Read all the quote materials
        let message = std::fs::read(&quote_msg)?;
        let signature = std::fs::read(&quote_sig)?;

        // Read AK certificate from TPM NV (REQUIRED - must have pre-provisioned AK)
        let ak_cert = self.read_ak_cert()?.context(
            "AK certificate not found in TPM NV storage - TPM quote requires pre-provisioned AK certificate for trust chain verification"
        )?;

        Ok(TpmQuote {
            message,
            signature,
            pcr_values,
            qualifying_data: qualifying_data.to_vec(),
            ak_cert,
        })
    }

    // ==================== AK (Attestation Key) Certificate Operations ====================

    /// Read the Attestation Key certificate from TPM NV
    ///
    /// On GCP vTPM, the AK certificate is stored in NV index:
    /// - 0x01C10000 (RSA AK cert)
    /// - 0x01C10002 (ECC AK cert)
    ///
    /// The AK certificate is signed by Google Private CA (GCE Intermediate CA)
    /// which establishes the trust chain: Google Root CA → GCE Intermediate CA → AK
    ///
    /// Returns None if not available (e.g., on non-GCP TPMs or hardware TPMs without pre-provisioning).
    pub fn read_ak_cert(&self) -> Result<Option<Vec<u8>>> {
        // GCP vTPM AK certificate NV indices (from go-tpm-tools)
        const AK_RSA_CERT_NV_INDEX: u32 = 0x01C10000;
        const AK_ECC_CERT_NV_INDEX: u32 = 0x01C10002;

        if let Some(cert) = self.nv_read(AK_RSA_CERT_NV_INDEX)? {
            info!(
                "read AK certificate from NV index 0x{:08x} ({} bytes)",
                AK_RSA_CERT_NV_INDEX,
                cert.len()
            );
            return Ok(Some(cert));
        }

        if let Some(cert) = self.nv_read(AK_ECC_CERT_NV_INDEX)? {
            info!(
                "read AK certificate from NV index 0x{:08x} ({} bytes)",
                AK_ECC_CERT_NV_INDEX,
                cert.len()
            );
            return Ok(Some(cert));
        }

        warn!("AK certificate not found in TPM NV storage (expected on GCP vTPM)");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_selection_to_string() {
        let sel = PcrSelection::sha256(&[0, 1, 2, 7]);
        assert_eq!(sel.to_arg(), "sha256:0,1,2,7");
    }

    #[test]
    fn test_sealed_blob_split() {
        // Create a mock sealed blob: 2-byte pub_size + pub_data + 2-byte priv_size + priv_data
        let pub_data = vec![0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]; // size=5
        let priv_data = vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]; // size=3
        let mut blob_data = Vec::new();
        blob_data.extend_from_slice(&pub_data);
        blob_data.extend_from_slice(&priv_data);

        let blob = SealedBlob::new(blob_data);
        let (pub_part, priv_part) = blob.split().unwrap();

        assert_eq!(pub_part, pub_data);
        assert_eq!(priv_part, priv_data);
    }

    #[test]
    fn test_default_pcr_policy() {
        let policy = default_pcr_policy();
        assert_eq!(policy.to_arg(), "sha256:0,1,2,3,4,5,6,7,8,9,14");
    }
}

// ==================== Pure Rust Verification ====================

mod verify;
pub use verify::{verify_quote, VerificationResult};

#[cfg(feature = "crl-download")]
pub use verify::get_collateral;

// ==================== GCP vTPM Support ====================

#[cfg(feature = "gcp-vtpm")]
mod gcp_ak;
#[cfg(feature = "gcp-vtpm")]
pub use gcp_ak::{create_quote_with_gcp_ak, gcp_nv_index, load_gcp_ak_rsa};
