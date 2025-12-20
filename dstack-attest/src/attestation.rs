// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Attestation functions

use std::{borrow::Cow, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::{RuntimeEvent, TdxEvent};
use dcap_qvl::{
    quote::{EnclaveReport, Quote, Report, TDReport10, TDReport15},
    verify::VerifiedReport as TdxVerifiedReport,
};
use dstack_types::Platform;
use ez_hash::{sha256, Hasher, Sha256, Sha384};
use or_panic::ResultOrPanic;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use sha2::Digest as _;
use tpm_qvl::verify::VerifiedReport as TpmVerifiedReport;

// Re-export TpmQuote from tpm-types
pub use tpm_types::TpmQuote;

/// Attestation mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum AttestationMode {
    /// Intel TDX with DCAP quote only
    #[serde(rename = "dstack-tdx")]
    #[default]
    DstackTdx,
    /// GCP TDX with DCAP quote only
    #[serde(rename = "gcp-tdx")]
    GcpTdx,
    /// Dstack attestation SDK in AWS Nitro Enclave
    #[serde(rename = "dstack-nitro")]
    DstackNitro,
}

impl FromStr for AttestationMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "dstack-tdx" => Ok(Self::DstackTdx),
            "gcp-tdx" => Ok(Self::GcpTdx),
            "dstack-nitro" => Ok(Self::DstackNitro),
            _ => bail!("Invalid attestation mode: {s}"),
        }
    }
}

impl AttestationMode {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            Self::DstackTdx => "dstack-tdx",
            Self::GcpTdx => "gcp-tdx",
            Self::DstackNitro => "dstack-nitro",
        }
    }

    /// Detect attestation mode from system
    pub fn detect() -> Result<Self> {
        let has_tdx = std::path::Path::new("/dev/tdx_guest").exists();

        // First, try to detect platform from DMI product name
        let platform = Platform::detect_or_dstack();
        match platform {
            Platform::Dstack => {
                if has_tdx {
                    return Ok(Self::DstackTdx);
                }
                bail!("Unsupported platform: Dstack(-tdx)");
            }
            Platform::Gcp => {
                // GCP platform: TDX + TPM dual mode
                if has_tdx {
                    return Ok(Self::GcpTdx);
                }
                bail!("Unsupported platform: GCP(-tdx)");
            }
        }
    }

    /// Check if TDX quote should be included
    pub fn has_tdx(&self) -> bool {
        match self {
            Self::DstackTdx => true,
            Self::GcpTdx => true,
            Self::DstackNitro => false,
        }
    }

    /// Check if TPM quote should be included
    pub fn has_tpm(&self) -> bool {
        match self {
            Self::DstackTdx => false,
            Self::GcpTdx => true,
            Self::DstackNitro => true,
        }
    }

    /// Get TPM runtime event PCR index
    pub fn tpm_runtime_pcr(&self) -> Option<u32> {
        match self {
            Self::GcpTdx => Some(14),
            Self::DstackTdx => None,
            Self::DstackNitro => None,
        }
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

/// Represents a verified attestation
#[derive(Clone)]
pub struct DstackVerifiedReport {
    /// The attestation mode
    pub mode: AttestationMode,
    /// The verified TDX report
    pub tdx_report: Option<TdxVerifiedReport>,
    /// The verified TPM report
    pub tpm_report: Option<TpmVerifiedReport>,
}

fn get_report_data(report: &TdxVerifiedReport) -> [u8; 64] {
    match report.report {
        Report::SgxEnclave(enclave_report) => enclave_report.report_data,
        Report::TD10(tdreport10) => tdreport10.report_data,
        Report::TD15(tdreport15) => tdreport15.base.report_data,
    }
}

impl DstackVerifiedReport {
    /// Check if the report is empty
    pub fn is_empty(&self) -> bool {
        self.tdx_report.is_none() && self.tpm_report.is_none()
    }
}

/// Represents a verified attestation
pub type VerifiedAttestation = Attestation<DstackVerifiedReport>;

/// Represents a TDX quote
#[derive(Clone, Encode, Decode)]
pub struct TdxQuote {
    /// The quote gererated by Intel QE
    pub quote: Vec<u8>,
    /// The event log
    pub event_log: Vec<TdxEvent>,
}

/// Represents a versioned attestation
#[derive(Clone, Encode, Decode)]
pub enum VersionedAttestation {
    /// Version 0
    V0 {
        /// The attestation report
        attestation: Attestation,
    },
}

impl VersionedAttestation {
    /// Decode VerifiedAttestation from scale encoded bytes
    pub fn from_scale(scale: &[u8]) -> Result<Self> {
        Self::decode(&mut &scale[..]).context("Failed to decode VersionedAttestation")
    }

    /// Encode to scale encoded bytes
    pub fn to_scale(&self) -> Vec<u8> {
        self.encode()
    }

    /// Turn into latest version of attestation
    pub fn into_inner(self) -> Attestation {
        match self {
            Self::V0 { attestation } => attestation,
        }
    }

    /// Strip data for certificate embedding (e.g. keep RTMR3 event logs only).
    pub fn into_stripped(mut self) -> Self {
        let VersionedAttestation::V0 { attestation } = &mut self;
        if let Some(tdx_quote) = &mut attestation.tdx_quote {
            tdx_quote.event_log = tdx_quote
                .event_log
                .iter()
                .filter(|e| e.imr == 3)
                .map(|e| e.stripped())
                .collect();
        }
        self
    }
}

/// Attestation data
#[derive(Clone, Encode, Decode)]
pub struct Attestation<R = ()> {
    /// Attestation mode
    pub mode: AttestationMode,

    /// TDX quote (only for TDX mode)
    pub tdx_quote: Option<TdxQuote>,

    /// TPM quote (only for TPM mode)
    pub tpm_quote: Option<TpmQuote>,

    /// Runtime events (only for TDX mode)
    pub runtime_events: Vec<RuntimeEvent>,

    /// The report data
    pub report_data: [u8; 64],

    /// The configuration of the VM
    pub config: String,

    /// Verified report
    pub report: R,
}

impl<T> Attestation<T> {
    /// Get TDX quote bytes
    pub fn get_tdx_quote_bytes(&self) -> Option<Vec<u8>> {
        self.tdx_quote.as_ref().map(|q| q.quote.clone())
    }

    /// Get TDX event log bytes
    pub fn get_tdx_event_log_bytes(&self) -> Option<Vec<u8>> {
        self.tdx_quote
            .as_ref()
            .map(|q| serde_json::to_vec(&q.event_log).unwrap_or_default())
    }

    /// Get TDX event log string
    pub fn get_tdx_event_log_string(&self) -> Option<String> {
        self.tdx_quote
            .as_ref()
            .map(|q| serde_json::to_string(&q.event_log).unwrap_or_default())
    }
}

pub trait GetPpid {
    fn get_ppid(&self) -> Vec<u8>;
}

impl GetPpid for () {
    fn get_ppid(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl GetPpid for DstackVerifiedReport {
    fn get_ppid(&self) -> Vec<u8> {
        let Some(tdx_report) = &self.tdx_report else {
            return Vec::new();
        };
        tdx_report.ppid.clone()
    }
}

struct Mrs {
    mr_system: [u8; 32],
    mr_aggregated: [u8; 32],
}

impl<T: GetPpid> Attestation<T> {
    fn decode_mr_tpm(&self, boottime_mr: bool, mr_key_provider: &[u8]) -> Result<Mrs> {
        let os_image_hash = self.find_event_payload("os-image-hash").unwrap_or_default();
        let mr_system = sha256([&os_image_hash, mr_key_provider]);
        let tpm_quote = self.tpm_quote.as_ref().context("TPM quote not found")?;
        let pcr0 = tpm_quote
            .pcr_values
            .iter()
            .find(|p| p.index == 0)
            .context("PCR 0 not found")?;
        let pcr2 = tpm_quote
            .pcr_values
            .iter()
            .find(|p| p.index == 2)
            .context("PCR 2 not found")?;
        let runtime_pcr =
            self.replay_runtime_events::<Sha256>(boottime_mr.then_some("boot-mr-done"));
        let mr_aggregated = sha256([&pcr0.value[..], &pcr2.value, &runtime_pcr]);
        Ok(Mrs {
            mr_system,
            mr_aggregated,
        })
    }

    fn decode_mr_tdx(&self, boottime_mr: bool, mr_key_provider: &[u8]) -> Result<Mrs> {
        let quote = self.decode_tdx_quote()?;
        let rtmr3 = self.replay_runtime_events::<Sha384>(boottime_mr.then_some("boot-mr-done"));
        let td_report = quote.report.as_td10().context("TDX report not found")?;
        let mr_system = sha256([
            &td_report.mr_td[..],
            &td_report.rt_mr0,
            &td_report.rt_mr1,
            &td_report.rt_mr2,
            mr_key_provider,
        ]);
        let mr_aggregated = {
            let mut hasher = sha2::Sha256::new();
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
        Ok(Mrs {
            mr_system,
            mr_aggregated,
        })
    }

    /// Decode the app info from the event log
    pub fn decode_app_info(&self, boottime_mr: bool) -> Result<AppInfo> {
        let key_provider_info = if boottime_mr {
            vec![]
        } else {
            self.find_event_payload("key-provider").unwrap_or_default()
        };
        let mr_key_provider = if key_provider_info.is_empty() {
            [0u8; 32]
        } else {
            sha256(&key_provider_info)
        };
        let mrs = match self.mode {
            AttestationMode::DstackTdx => self.decode_mr_tdx(boottime_mr, &mr_key_provider)?,
            AttestationMode::GcpTdx => self.decode_mr_tpm(boottime_mr, &mr_key_provider)?,
            AttestationMode::DstackNitro => bail!("Nitro attestation is not supported"),
        };
        Ok(AppInfo {
            app_id: self.find_event_payload("app-id").unwrap_or_default(),
            compose_hash: self.find_event_payload("compose-hash").unwrap_or_default(),
            instance_id: self.find_event_payload("instance-id").unwrap_or_default(),
            os_image_hash: self.find_event_payload("os-image-hash").unwrap_or_default(),
            device_id: sha256(self.report.get_ppid()).to_vec(),
            mr_system: mrs.mr_system,
            mr_aggregated: mrs.mr_aggregated,
            key_provider_info,
        })
    }
}

impl<T> Attestation<T> {
    /// Decode the quote
    pub fn decode_tdx_quote(&self) -> Result<Quote> {
        let Some(tdx_quote) = &self.tdx_quote else {
            bail!("tdx_quote not found");
        };
        Quote::parse(&tdx_quote.quote)
    }

    fn find_event(&self, name: &str) -> Result<RuntimeEvent> {
        for event in &self.runtime_events {
            if event.event == "system-ready" {
                break;
            }
            if event.event == name {
                return Ok(event.clone());
            }
        }
        Err(anyhow!("event {name} not found"))
    }

    /// Replay event logs
    pub fn replay_runtime_events<H: Hasher>(&self, to_event: Option<&str>) -> H::Output {
        cc_eventlog::replay_events::<H>(&self.runtime_events, to_event)
    }

    fn find_event_payload(&self, event: &str) -> Result<Vec<u8>> {
        self.find_event(event).map(|event| event.payload)
    }

    fn find_event_hex_payload(&self, event: &str) -> Result<String> {
        self.find_event(event)
            .map(|event| hex::encode(&event.payload))
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event_hex_payload("app-id")
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event_hex_payload("instance-id")
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_compose_hash(&self) -> Result<String> {
        self.find_event_hex_payload("compose-hash")
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event_hex_payload("rootfs-hash")
    }
}

#[cfg(feature = "quote")]
impl Attestation {
    /// Create an attestation for local machine (auto-detect mode)
    pub fn local() -> Result<Self> {
        Self::quote(&[0u8; 64])
    }

    /// Reconstruct from tdx quote and event log, for backward compatibility
    pub fn from_tdx_quote(quote: Vec<u8>, event_log: &[u8]) -> Result<Self> {
        let tdx_eventlog: Vec<TdxEvent> =
            serde_json::from_slice(event_log).context("Failed to parse tdx_event_log")?;
        let runtime_events = tdx_eventlog
            .iter()
            .flat_map(|event| event.to_runtime_event())
            .collect();
        let report_data = {
            let quote = dcap_qvl::quote::Quote::parse(&quote).context("Invalid TDX quote")?;
            let report = quote.report.as_td10().context("Invalid TDX report")?;
            report.report_data
        };
        Ok(Attestation {
            mode: AttestationMode::DstackTdx,
            tpm_quote: None,
            tdx_quote: Some(TdxQuote {
                quote,
                event_log: tdx_eventlog,
            }),
            runtime_events,
            report_data,
            config: "".into(),
            report: (),
        })
    }

    /// Create an attestation from a report data
    pub fn quote(report_data: &[u8; 64]) -> Result<Self> {
        let mode = AttestationMode::detect()?;
        let runtime_events = RuntimeEvent::read_all().context("Failed to read runtime events")?;
        let tpm_qualifying_data;
        let tdx_quote;
        if mode.has_tdx() {
            let quote = tdx_attest::get_quote(report_data).context("Failed to get quote")?;
            let event_log =
                cc_eventlog::tdx::read_event_log().context("Failed to read event log")?;
            tpm_qualifying_data = sha256(&quote);
            tdx_quote = Some(TdxQuote { quote, event_log });
        } else {
            tpm_qualifying_data = sha256(report_data);
            tdx_quote = None;
        };
        let tpm_quote = if mode.has_tpm() {
            let tpm_ctx = tpm_attest::TpmContext::detect().context("Failed to open TPM context")?;
            let quote = tpm_ctx
                .create_quote(&tpm_qualifying_data, &tpm_attest::dstack_pcr_policy())
                .context("Failed to create TPM quote")?;
            Some(quote)
        } else {
            None
        };
        // TODO: Find a better way handling this hardcode path
        let config =
            fs_err::read_to_string("/dstack/.host-shared/.sys-config.json").unwrap_or_default();
        Ok(Self {
            mode,
            tdx_quote,
            tpm_quote,
            runtime_events,
            report_data: *report_data,
            config,
            report: (),
        })
    }
}

impl Attestation {
    /// Wrap into a versioned attestation for encoding
    pub fn into_versioned(self) -> VersionedAttestation {
        VersionedAttestation::V0 { attestation: self }
    }

    /// Verify the quote
    pub async fn verify_with_ra_pubkey(
        self,
        ra_pubkey_der: &[u8],
        pccs_url: Option<&str>,
    ) -> Result<VerifiedAttestation> {
        let expected_report_data = QuoteContentType::RaTlsCert.to_report_data(ra_pubkey_der);
        if self.report_data != expected_report_data {
            bail!("report data mismatch");
        }
        self.verify(pccs_url).await
    }

    /// Verify the quote
    pub async fn verify(self, pccs_url: Option<&str>) -> Result<VerifiedAttestation> {
        let tpm_report = if self.mode.has_tpm() {
            let report = self
                .verify_tpm()
                .await
                .context("Failed to verify TPM quote")?;
            let pcr_ind = self
                .mode
                .tpm_runtime_pcr()
                .context("Failed to get runtime PCR no")?;
            let replayed_rt_pcr = self.replay_runtime_events::<Sha256>(None);
            let quoted_rt_pcr = report
                .get_pcr(pcr_ind)
                .context("No runtime PCR in TPM report")?;
            if replayed_rt_pcr != quoted_rt_pcr[..] {
                bail!(
                    "PCR{pcr_ind} mismatch, quoted: {}, replayed: {}",
                    hex::encode(quoted_rt_pcr),
                    hex::encode(replayed_rt_pcr),
                );
            }
            Some(report)
        } else {
            None
        };
        let tdx_report = if self.mode.has_tdx() {
            let report = self.verify_tdx(pccs_url).await?;
            let td_report = report.report.as_td10().context("no td report")?;
            let replayed_rtmr = self.replay_runtime_events::<Sha384>(None);
            if replayed_rtmr != td_report.rt_mr3 {
                bail!(
                    "RTMR3 mismatch, quoted: {}, replayed: {}",
                    hex::encode(td_report.rt_mr3),
                    hex::encode(replayed_rtmr)
                );
            }
            Some(report)
        } else {
            None
        };

        match self.mode {
            AttestationMode::DstackTdx => {
                // For bare dstack TDX machine, we only make sure the report data is correct
                let Some(tdx_report) = &tdx_report else {
                    bail!("TDX report is missing in dstack-tdx mode");
                };
                let td_report_data = get_report_data(tdx_report);
                if td_report_data != self.report_data[..] {
                    bail!("tdx report_data mismatch");
                }
            }
            AttestationMode::GcpTdx => {
                let Some(tdx_report) = &tdx_report else {
                    bail!("TDX report is missing in gcp-tdx mode");
                };
                let Some(td10_report) = tdx_report.report.as_td10() else {
                    bail!("TD10 report is missing in gcp-tdx mode");
                };
                if td10_report.report_data != self.report_data[..] {
                    bail!("tdx report_data mismatch");
                }
                let tdx_quote = &self.tdx_quote.as_ref().context("TDX quote missing")?.quote;
                let Some(tpm_report) = &tpm_report else {
                    bail!("TPM report is missing in gcp-tdx mode");
                };
                // TPM quote the TDX quote
                let qualifying_data = sha256(tdx_quote);
                if qualifying_data != tpm_report.attest.qualified_data[..] {
                    bail!("tpm qualified_data mismatch");
                }
            }
            AttestationMode::DstackNitro => {
                bail!("Nitro not supported");
            }
        }
        let report = DstackVerifiedReport {
            mode: self.mode,
            tdx_report,
            tpm_report,
        };
        if report.is_empty() {
            bail!("nothing verified");
        }
        Ok(VerifiedAttestation {
            mode: self.mode,
            tdx_quote: self.tdx_quote,
            tpm_quote: self.tpm_quote,
            runtime_events: self.runtime_events,
            report_data: self.report_data,
            config: self.config,
            report,
        })
    }

    async fn verify_tpm(&self) -> Result<TpmVerifiedReport> {
        let tpm_quote = self.tpm_quote.as_ref().context("TPM quote missing")?;
        tpm_qvl::get_collateral_and_verify(tpm_quote).await
    }

    async fn verify_tdx(&self, pccs_url: Option<&str>) -> Result<TdxVerifiedReport> {
        let quote = &self.tdx_quote.as_ref().context("TDX quote missing")?.quote;
        let mut pccs_url = Cow::Borrowed(pccs_url.unwrap_or_default());
        if pccs_url.is_empty() {
            // try to read from PCCS_URL env var
            pccs_url = match std::env::var("PCCS_URL") {
                Ok(url) => Cow::Owned(url),
                Err(_) => Cow::Borrowed(""),
            };
        }
        let tdx_report =
            dcap_qvl::collateral::get_collateral_and_verify(quote, Some(pccs_url.as_ref()))
                .await
                .context("Failed to get collateral")?;
        validate_tcb(&tdx_report)?;
        Ok(tdx_report)
    }
}

/// Validate the TCB attributes
pub fn validate_tcb(report: &TdxVerifiedReport) -> Result<()> {
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
