// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Attestation functions

use std::borrow::Cow;

use anyhow::{anyhow, bail, Context, Result};
use dcap_qvl::quote::Quote;
use qvl::{
    quote::{EnclaveReport, Report, TDReport10, TDReport15},
    verify::VerifiedReport,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use x509_parser::parse_x509_certificate;

use crate::{oids, traits::CertExt};
use cc_eventlog::TdxEventLogEntry as EventLog;
use or_panic::ResultOrPanic;
use serde_human_bytes as hex_bytes;

/// Attestation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    /// Intel TDX with DCAP quote only
    Tdx,
    /// TPM 2.0 quote only
    Tpm,
    /// Both TDX and TPM (dual mode)
    #[serde(rename = "tdx+tpm")]
    TdxTpm,
}

impl AttestationMode {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tdx => "tdx",
            Self::Tpm => "tpm",
            Self::TdxTpm => "tdx+tpm",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "tdx" => Ok(Self::Tdx),
            "tpm" => Ok(Self::Tpm),
            "tdx+tpm" => Ok(Self::TdxTpm),
            _ => bail!("Invalid attestation mode: {s}"),
        }
    }

    /// Detect attestation mode from system
    pub fn detect() -> Result<Self> {
        // First, try to detect platform from DMI board name
        if let Ok(board_name) = std::fs::read_to_string("/sys/class/dmi/id/board_name") {
            let board_name = board_name.trim();
            match board_name {
                "dstack" => {
                    // dstack platform: TDX only (no TPM)
                    return Ok(Self::Tdx);
                }
                "Google Compute Engine" => {
                    // GCP platform: TDX + TPM dual mode
                    return Ok(Self::TdxTpm);
                }
                _ => {
                    // Unknown board name, fall through to device detection
                }
            }
        }

        // Fallback: detect from available devices
        let has_tdx = std::path::Path::new("/dev/tdx_guest").exists();
        let has_tpm = std::path::Path::new("/dev/tpmrm0").exists()
            || std::path::Path::new("/dev/tpm0").exists();

        match (has_tdx, has_tpm) {
            (true, true) => Ok(Self::TdxTpm),  // Both available
            (true, false) => Ok(Self::Tdx),    // TDX only
            (false, true) => Ok(Self::Tpm),    // TPM only
            (false, false) => bail!("No attestation device found"),
        }
    }

    /// Check if TDX quote is included
    pub fn has_tdx(&self) -> bool {
        matches!(self, Self::Tdx | Self::TdxTpm)
    }

    /// Check if TPM quote is included
    pub fn has_tpm(&self) -> bool {
        matches!(self, Self::Tpm | Self::TdxTpm)
    }
}

/// The content type of a quote. A CVM should only generate quotes for these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContentType<'a> {
    /// The public key of KMS root CA
    KmsRootCa,
    /// The public key of the RA-TLS certificate
    RaTlsCert,
    /// App defined data
    AppData,
    /// The custom content type
    Custom(&'a str),
}

/// The default hash algorithm used to hash the report data.
pub const DEFAULT_HASH_ALGORITHM: &str = "sha512";

impl QuoteContentType<'_> {
    /// The tag of the content type used in the report data.
    pub fn tag(&self) -> &str {
        match self {
            Self::KmsRootCa => "kms-root-ca",
            Self::RaTlsCert => "ratls-cert",
            Self::AppData => "app-data",
            Self::Custom(tag) => tag,
        }
    }

    /// Convert the content to the report data.
    pub fn to_report_data(&self, content: &[u8]) -> [u8; 64] {
        self.to_report_data_with_hash(content, "")
            .or_panic("sha512 hash should not fail")
    }

    /// Convert the content to the report data with a specific hash algorithm.
    pub fn to_report_data_with_hash(&self, content: &[u8], hash: &str) -> Result<[u8; 64]> {
        macro_rules! do_hash {
            ($hash: ty) => {{
                // The format is:
                // hash(<tag>:<content>)
                let mut hasher = <$hash>::new();
                hasher.update(self.tag().as_bytes());
                hasher.update(b":");
                hasher.update(content);
                let output = hasher.finalize();

                let mut padded = [0u8; 64];
                padded[..output.len()].copy_from_slice(&output);
                padded
            }};
        }
        let hash = if hash.is_empty() {
            DEFAULT_HASH_ALGORITHM
        } else {
            hash
        };
        let output = match hash {
            "sha256" => do_hash!(sha2::Sha256),
            "sha384" => do_hash!(sha2::Sha384),
            "sha512" => do_hash!(sha2::Sha512),
            "sha3-256" => do_hash!(sha3::Sha3_256),
            "sha3-384" => do_hash!(sha3::Sha3_384),
            "sha3-512" => do_hash!(sha3::Sha3_512),
            "keccak256" => do_hash!(sha3::Keccak256),
            "keccak384" => do_hash!(sha3::Keccak384),
            "keccak512" => do_hash!(sha3::Keccak512),
            "raw" => content.try_into().ok().context("invalid content length")?,
            _ => bail!("invalid hash algorithm"),
        };
        Ok(output)
    }
}

/// PCR value in TPM quote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR index
    pub index: u32,
    /// PCR value (32 bytes for SHA256)
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

/// TPM Quote data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuoteData {
    /// TPM Quote message (TPMS_ATTEST)
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,

    /// TPM Quote signature
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,

    /// PCR values included in quote
    pub pcr_values: Vec<PcrValue>,

    /// AK (Attestation Key) certificate (DER format)
    #[serde(with = "hex_bytes")]
    pub ak_cert: Vec<u8>,

    /// Qualifying data (nonce) used in quote
    #[serde(with = "hex_bytes")]
    pub qualifying_data: Vec<u8>,

    /// Platform where quote was generated
    pub platform: dstack_types::Platform,
}

/// Represents a verified attestation
pub type VerifiedAttestation = Attestation<VerifiedReport>;

/// Attestation data
#[derive(Debug, Clone)]
pub struct Attestation<R = ()> {
    /// Attestation mode
    pub mode: AttestationMode,

    /// Quote (TDX Quote or TPM Quote message)
    pub quote: Vec<u8>,

    /// Raw event log (TDX event log or empty for TPM mode)
    pub raw_event_log: Vec<u8>,

    /// Event log (TDX specific)
    pub event_log: Vec<EventLog>,

    /// Verified report
    pub report: R,

    /// TPM specific data (only for TPM mode)
    pub tpm_data: Option<TpmQuoteData>,
}

impl<T> Attestation<T> {
    /// Decode the quote
    pub fn decode_quote(&self) -> Result<Quote> {
        Quote::parse(&self.quote)
    }

    fn find_event(&self, imr: u32, name: &str) -> Result<EventLog> {
        for event in &self.event_log {
            if event.imr == 3 && event.event == "system-ready" {
                break;
            }
            if event.imr == imr && event.event == name {
                return Ok(event.clone());
            }
        }
        Err(anyhow!("event {name} not found"))
    }

    /// Replay event logs
    pub fn replay_rtmr3(&self, to_event: Option<&str>) -> Result<[u8; 48]> {
        cc_eventlog::replay_event_logs(&self.event_log, to_event, 3)
    }

    fn find_event_payload(&self, event: &str) -> Result<Vec<u8>> {
        self.find_event(3, event).map(|event| event.event_payload)
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event(3, "app-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event(3, "instance-id")
            .map(|event| hex::encode(&event.event_payload))
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_compose_hash(&self) -> Result<String> {
        let event = self.find_event(3, "compose-hash").or_else(|_| {
            // Old images use this event name
            self.find_event(3, "upgraded-app-id")
        })?;
        Ok(hex::encode(&event.event_payload))
    }

    /// Decode the app info from the event log
    pub fn decode_app_info(&self, boottime_mr: bool) -> Result<AppInfo> {
        let rtmr3 = self
            .replay_rtmr3(boottime_mr.then_some("boot-mr-done"))
            .context("Failed to replay event logs")?;
        let quote = self.decode_quote()?;
        let device_id = sha256(&[&quote.header.user_data]).to_vec();
        let td_report = quote.report.as_td10().context("TDX report not found")?;
        let key_provider_info = if boottime_mr {
            vec![]
        } else {
            self.find_event_payload("key-provider").unwrap_or_default()
        };
        let mr_key_provider = if key_provider_info.is_empty() {
            [0u8; 32]
        } else {
            sha256(&[&key_provider_info])
        };
        let mr_system = sha256(&[
            &td_report.mr_td,
            &td_report.rt_mr0,
            &td_report.rt_mr1,
            &td_report.rt_mr2,
            &mr_key_provider,
        ]);
        let mr_aggregated = {
            use sha2::{Digest as _, Sha256};
            let mut hasher = Sha256::new();
            for d in [
                &td_report.mr_td,
                &td_report.rt_mr0,
                &td_report.rt_mr1,
                &td_report.rt_mr2,
                &rtmr3,
            ] {
                hasher.update(d);
            }
            // For backward compatibility. Don't include mr_config_id, mr_owner, mr_owner_config if they are all 0.
            if td_report.mr_config_id != [0u8; 48]
                || td_report.mr_owner != [0u8; 48]
                || td_report.mr_owner_config != [0u8; 48]
            {
                hasher.update(td_report.mr_config_id);
                hasher.update(td_report.mr_owner);
                hasher.update(td_report.mr_owner_config);
            }
            hasher.finalize().into()
        };
        Ok(AppInfo {
            app_id: self.find_event_payload("app-id").unwrap_or_default(),
            compose_hash: self.find_event_payload("compose-hash").unwrap_or_default(),
            instance_id: self.find_event_payload("instance-id").unwrap_or_default(),
            device_id,
            mrtd: td_report.mr_td,
            rtmr0: td_report.rt_mr0,
            rtmr1: td_report.rt_mr1,
            rtmr2: td_report.rt_mr2,
            rtmr3,
            os_image_hash: self.find_event_payload("os-image-hash").unwrap_or_default(),
            mr_system,
            mr_aggregated,
            key_provider_info,
        })
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event(3, "rootfs-hash")
            .map(|event| hex::encode(event.digest()))
    }

    /// Decode the report data in the quote
    pub fn decode_report_data(&self) -> Result<[u8; 64]> {
        match self.decode_quote()?.report {
            Report::SgxEnclave(report) => Ok(report.report_data),
            Report::TD10(report) => Ok(report.report_data),
            Report::TD15(report) => Ok(report.base.report_data),
        }
    }
}

impl Attestation {
    /// Create an attestation for local machine (auto-detect mode)
    pub fn local() -> Result<Self> {
        let mode = AttestationMode::detect()?;
        match mode {
            AttestationMode::Tdx => Self::local_tdx(),
            AttestationMode::Tpm => Self::local_tpm(),
            AttestationMode::TdxTpm => Self::local_tdx_tpm(),
        }
    }

    /// Create TDX attestation only
    fn local_tdx() -> Result<Self> {
        let quote = tdx_attest::get_quote(&[0u8; 64]).context("Failed to get quote")?;
        let event_log =
            tdx_attest::eventlog::read_event_logs().context("Failed to read event logs")?;
        let raw_event_log =
            serde_json::to_vec(&event_log).context("Failed to serialize event log")?;
        Ok(Self {
            mode: AttestationMode::Tdx,
            quote,
            raw_event_log,
            event_log,
            report: (),
            tpm_data: None,
        })
    }

    /// Create TPM attestation only
    #[cfg(feature = "tpm-quote")]
    fn local_tpm() -> Result<Self> {
        let tpm_data = Self::collect_tpm_quote(&[0, 2, 4, 7])?;
        Ok(Self {
            mode: AttestationMode::Tpm,
            quote: tpm_data.message.clone(),
            raw_event_log: vec![],
            event_log: vec![],
            report: (),
            tpm_data: Some(tpm_data),
        })
    }

    /// Create TPM attestation only (without tpm-quote feature)
    #[cfg(not(feature = "tpm-quote"))]
    fn local_tpm() -> Result<Self> {
        bail!("TPM quote collection requires 'tpm-quote' feature")
    }

    /// Create both TDX and TPM attestation (dual mode)
    #[cfg(feature = "tpm-quote")]
    fn local_tdx_tpm() -> Result<Self> {
        // Get TDX quote and event log
        let quote = tdx_attest::get_quote(&[0u8; 64]).context("Failed to get TDX quote")?;
        let event_log =
            tdx_attest::eventlog::read_event_logs().context("Failed to read TDX event logs")?;
        let raw_event_log =
            serde_json::to_vec(&event_log).context("Failed to serialize event log")?;

        // Get TPM quote
        let tpm_data = Self::collect_tpm_quote(&[0, 2, 4, 7])?;

        Ok(Self {
            mode: AttestationMode::TdxTpm,
            quote,
            raw_event_log,
            event_log,
            report: (),
            tpm_data: Some(tpm_data),
        })
    }

    /// Create both TDX and TPM attestation (without tpm-quote feature)
    #[cfg(not(feature = "tpm-quote"))]
    fn local_tdx_tpm() -> Result<Self> {
        bail!("TPM quote collection requires 'tpm-quote' feature")
    }

    /// Collect TPM quote with specified PCR indices
    #[cfg(feature = "tpm-quote")]
    fn collect_tpm_quote(pcr_indices: &[u32]) -> Result<TpmQuoteData> {
        use tpm_attest::{TpmContext, PcrSelection};

        // Generate nonce for replay protection (32 bytes random)
        let nonce = Self::generate_nonce()?;

        // Create TPM context
        let tpm_ctx = TpmContext::open(None)
            .context("Failed to open TPM context")?;

        // Create PCR selection
        let pcr_sel = PcrSelection::sha256(pcr_indices);

        // Generate quote using pre-provisioned AK
        let quote = tpm_ctx.create_quote(&nonce, &pcr_sel)
            .context("Failed to create TPM quote")?;

        // Convert tpm-attest format to ra-tls format
        let pcr_values = quote.pcr_values.iter().map(|p| PcrValue {
            index: p.index,
            value: p.value.clone(),
        }).collect();

        Ok(TpmQuoteData {
            message: quote.message,
            signature: quote.signature,
            pcr_values,
            ak_cert: quote.ak_cert,
            qualifying_data: quote.qualifying_data,
            platform: dstack_types::Platform::detect(),
        })
    }

    /// Generate cryptographic nonce for replay protection
    #[cfg(feature = "tpm-quote")]
    fn generate_nonce() -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Create a new attestation from full event log format (defaults to TDX mode for backward compat)
    pub fn new(quote: Vec<u8>, mut raw_event_log: Vec<u8>) -> Result<Self> {
        let event_log: Vec<EventLog> = if !raw_event_log.is_empty() {
            // Decompress if needed (handles both compressed and uncompressed formats)
            raw_event_log = crate::cert::decompress_event_log(&raw_event_log)
                .context("failed to decompress event log")?;
            serde_json::from_slice(&raw_event_log).context("invalid event log")?
        } else {
            vec![]
        };
        Ok(Self {
            mode: AttestationMode::Tdx,  // Default to TDX for backward compatibility
            quote,
            raw_event_log,
            event_log,
            report: (),
            tpm_data: None,
        })
    }

    /// Extract attestation data from a certificate
    pub fn from_cert(cert: &impl CertExt) -> Result<Option<Self>> {
        Self::from_ext_getter(|oid| cert.get_extension_bytes(oid))
    }

    /// From an extension getter
    pub fn from_ext_getter(
        get_ext: impl Fn(&[u64]) -> Result<Option<Vec<u8>>>,
    ) -> Result<Option<Self>> {
        // Try to detect attestation mode from certificate extension
        let mode = if let Some(mode_bytes) = get_ext(oids::PHALA_RATLS_ATTESTATION_MODE)? {
            let mode_str = std::str::from_utf8(&mode_bytes)
                .context("Invalid attestation mode encoding")?;
            AttestationMode::from_str(mode_str)?
        } else {
            // Backward compatibility: if no mode specified, check which quote type exists
            let has_tdx = get_ext(oids::PHALA_RATLS_QUOTE)?.is_some();
            let has_tpm = get_ext(oids::PHALA_RATLS_TPM_QUOTE)?.is_some();

            match (has_tdx, has_tpm) {
                (true, true) => AttestationMode::TdxTpm,
                (true, false) => AttestationMode::Tdx,
                (false, true) => AttestationMode::Tpm,
                (false, false) => return Ok(None),
            }
        };

        match mode {
            AttestationMode::Tdx => {
                let quote = match get_ext(oids::PHALA_RATLS_QUOTE)? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                let raw_event_log = get_ext(oids::PHALA_RATLS_EVENT_LOG)?.unwrap_or_default();
                let mut attestation = Self::new(quote, raw_event_log)?;
                attestation.mode = AttestationMode::Tdx;
                Ok(Some(attestation))
            }
            AttestationMode::Tpm => {
                let tpm_quote_json = match get_ext(oids::PHALA_RATLS_TPM_QUOTE)? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                let tpm_data: TpmQuoteData = serde_json::from_slice(&tpm_quote_json)
                    .context("Failed to parse TPM quote data")?;

                Ok(Some(Self {
                    mode: AttestationMode::Tpm,
                    quote: tpm_data.message.clone(),
                    raw_event_log: vec![],
                    event_log: vec![],
                    report: (),
                    tpm_data: Some(tpm_data),
                }))
            }
            AttestationMode::TdxTpm => {
                // Both TDX and TPM quotes
                let tdx_quote = match get_ext(oids::PHALA_RATLS_QUOTE)? {
                    Some(v) => v,
                    None => bail!("TDX quote missing in TdxTpm mode"),
                };
                let raw_event_log = get_ext(oids::PHALA_RATLS_EVENT_LOG)?.unwrap_or_default();

                let tpm_quote_json = match get_ext(oids::PHALA_RATLS_TPM_QUOTE)? {
                    Some(v) => v,
                    None => bail!("TPM quote missing in TdxTpm mode"),
                };
                let tpm_data: TpmQuoteData = serde_json::from_slice(&tpm_quote_json)
                    .context("Failed to parse TPM quote data")?;

                let mut attestation = Self::new(tdx_quote, raw_event_log)?;
                attestation.mode = AttestationMode::TdxTpm;
                attestation.tpm_data = Some(tpm_data);
                Ok(Some(attestation))
            }
        }
    }

    /// Extract attestation from x509 certificate
    pub fn from_der(cert: &[u8]) -> Result<Option<Self>> {
        let (_, cert) = parse_x509_certificate(cert).context("Failed to parse certificate")?;
        Self::from_cert(&cert)
    }

    /// Extract attestation from x509 certificate in PEM format
    pub fn from_pem(cert: &[u8]) -> Result<Option<Self>> {
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(cert).context("Failed to parse certificate")?;
        let cert = pem.parse_x509().context("Failed to parse certificate")?;
        Self::from_cert(&cert)
    }

    /// Verify the quote
    pub async fn verify_with_ra_pubkey(
        self,
        ra_pubkey_der: &[u8],
        pccs_url: Option<&str>,
    ) -> Result<VerifiedAttestation> {
        self.verify(
            &QuoteContentType::RaTlsCert.to_report_data(ra_pubkey_der),
            pccs_url,
        )
        .await
    }

    /// Verify the quote
    pub async fn verify(
        self,
        report_data: &[u8; 64],
        pccs_url: Option<&str>,
    ) -> Result<VerifiedAttestation> {
        let quote = &self.quote;
        if &self.decode_report_data()? != report_data {
            bail!("report data mismatch");
        }
        let mut pccs_url = Cow::Borrowed(pccs_url.unwrap_or_default());
        if pccs_url.is_empty() {
            // try to read from PCCS_URL env var
            pccs_url = match std::env::var("PCCS_URL") {
                Ok(url) => Cow::Owned(url),
                Err(_) => Cow::Borrowed(""),
            };
        }
        let report = qvl::collateral::get_collateral_and_verify(quote, Some(pccs_url.as_ref()))
            .await
            .context("Failed to get collateral")?;
        if let Some(report) = report.report.as_td10() {
            // Replay the event logs
            let rtmr3 = self
                .replay_rtmr3(None)
                .context("Failed to replay event logs")?;
            if rtmr3 != report.rt_mr3 {
                bail!(
                    "RTMR3 mismatch, quoted: {}, replayed: {}",
                    hex::encode(report.rt_mr3),
                    hex::encode(rtmr3),
                );
            }
        }
        validate_tcb(&report)?;
        Ok(VerifiedAttestation {
            mode: self.mode,
            quote: self.quote,
            raw_event_log: self.raw_event_log,
            event_log: self.event_log,
            report,
            tpm_data: self.tpm_data,
        })
    }
}

impl Attestation<VerifiedReport> {}

/// Validate the TCB attributes
pub fn validate_tcb(report: &VerifiedReport) -> Result<()> {
    fn validate_td10(report: &TDReport10) -> Result<()> {
        let is_debug = report.td_attributes[0] & 0x01 != 0;
        if is_debug {
            bail!("Debug mode is not allowed");
        }
        if report.mr_signer_seam != [0u8; 48] {
            bail!("Invalid mr signer seam");
        }
        Ok(())
    }
    fn validate_td15(report: &TDReport15) -> Result<()> {
        if report.mr_service_td != [0u8; 48] {
            bail!("Invalid mr service td");
        }
        validate_td10(&report.base)
    }
    fn validate_sgx(report: &EnclaveReport) -> Result<()> {
        let is_debug = report.attributes[0] & 0x02 != 0;
        if is_debug {
            bail!("Debug mode is not allowed");
        }
        Ok(())
    }
    match &report.report {
        Report::TD15(report) => validate_td15(report),
        Report::TD10(report) => validate_td10(report),
        Report::SgxEnclave(report) => validate_sgx(report),
    }
}

/// Information about the app extracted from event log
#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    /// App ID
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    /// SHA256 of the app compose file
    #[serde(with = "hex_bytes")]
    pub compose_hash: Vec<u8>,
    /// ID of the CVM instance
    #[serde(with = "hex_bytes")]
    pub instance_id: Vec<u8>,
    /// ID of the device
    #[serde(with = "hex_bytes")]
    pub device_id: Vec<u8>,
    /// TCB info
    #[serde(with = "hex_bytes")]
    pub mrtd: [u8; 48],
    /// Runtime MR0
    #[serde(with = "hex_bytes")]
    pub rtmr0: [u8; 48],
    /// Runtime MR1
    #[serde(with = "hex_bytes")]
    pub rtmr1: [u8; 48],
    /// Runtime MR2
    #[serde(with = "hex_bytes")]
    pub rtmr2: [u8; 48],
    /// Runtime MR3
    #[serde(with = "hex_bytes")]
    pub rtmr3: [u8; 48],
    /// Measurement of everything except the app info
    #[serde(with = "hex_bytes")]
    pub mr_system: [u8; 32],
    /// Measurement of the entire vm execution environment
    #[serde(with = "hex_bytes")]
    pub mr_aggregated: [u8; 32],
    /// Measurement of the app image
    #[serde(with = "hex_bytes")]
    pub os_image_hash: Vec<u8>,
    /// Key provider info
    #[serde(with = "hex_bytes")]
    pub key_provider_info: Vec<u8>,
}

fn sha256(data: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    for d in data {
        hasher.update(d);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_report_data_with_hash() {
        let content_type = QuoteContentType::AppData;
        let content = b"test content";

        let report_data = content_type.to_report_data(content);
        assert_eq!(hex::encode(report_data), "7ea0b744ed5e9c0c83ff9f575668e1697652cd349f2027cdf26f918d4c53e8cd50b5ea9b449b4c3d50e20ae00ec29688d5a214e8daff8a10041f5d624dae8a01");

        // Test SHA-256
        let result = content_type
            .to_report_data_with_hash(content, "sha256")
            .unwrap();
        assert_eq!(result[32..], [0u8; 32]); // Check padding
        assert_ne!(result[..32], [0u8; 32]); // Check hash is non-zero

        // Test SHA-384
        let result = content_type
            .to_report_data_with_hash(content, "sha384")
            .unwrap();
        assert_eq!(result[48..], [0u8; 16]); // Check padding
        assert_ne!(result[..48], [0u8; 48]); // Check hash is non-zero

        // Test default
        let result = content_type.to_report_data_with_hash(content, "").unwrap();
        assert_ne!(result, [0u8; 64]); // Should fill entire buffer

        // Test raw content
        let exact_content = [42u8; 64];
        let result = content_type
            .to_report_data_with_hash(&exact_content, "raw")
            .unwrap();
        assert_eq!(result, exact_content);

        // Test invalid raw content length
        let invalid_content = [42u8; 65];
        assert!(content_type
            .to_report_data_with_hash(&invalid_content, "raw")
            .is_err());

        // Test invalid hash algorithm
        assert!(content_type
            .to_report_data_with_hash(content, "invalid")
            .is_err());
    }
}
