// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Attestation functions

use std::{borrow::Cow, time::SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::{RuntimeEvent, TdxEvent};
use dcap_qvl::{
    quote::{EnclaveReport, Quote, Report, TDReport10, TDReport15},
    verify::VerifiedReport as TdxVerifiedReport,
};
use dstack_types::{Platform, VmConfig};
use ez_hash::{sha256, Hasher, Sha256, Sha384};
use or_panic::ResultOrPanic;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use sha2::Digest as _;
use tpm_qvl::verify::VerifiedReport as TpmVerifiedReport;

// Re-export TpmQuote from tpm-types
pub use tpm_types::TpmQuote;

const DSTACK_TDX: &str = "dstack-tdx";
const DSTACK_GCP_TDX: &str = "dstack-gcp-tdx";
const DSTACK_NITRO_ENCLAVE: &str = "dstack-nitro-enclave";

/// Attestation mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AttestationMode {
    /// Intel TDX with DCAP quote only
    #[default]
    #[serde(rename = "dstack-tdx")]
    DstackTdx,
    /// GCP TDX with DCAP quote only
    #[serde(rename = "dstack-gcp-tdx")]
    DstackGcpTdx,
    /// Dstack attestation SDK in AWS Nitro Enclave
    #[serde(rename = "dstack-nitro-enclave")]
    DstackNitroEnclave,
}

impl AttestationMode {
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
                    return Ok(Self::DstackGcpTdx);
                }
                bail!("Unsupported platform: GCP(-tdx)");
            }
            Platform::NitroEnclave => Ok(Self::DstackNitroEnclave),
        }
    }

    /// Check if TDX quote should be included
    pub fn has_tdx(&self) -> bool {
        match self {
            Self::DstackTdx => true,
            Self::DstackGcpTdx => true,
            Self::DstackNitroEnclave => false,
        }
    }

    /// Get TPM runtime event PCR index
    pub fn tpm_runtime_pcr(&self) -> Option<u32> {
        match self {
            Self::DstackGcpTdx => Some(14),
            Self::DstackTdx => None,
            Self::DstackNitroEnclave => None,
        }
    }

    /// As string for debug
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DstackTdx => DSTACK_TDX,
            Self::DstackGcpTdx => DSTACK_GCP_TDX,
            Self::DstackNitroEnclave => DSTACK_NITRO_ENCLAVE,
        }
    }

    /// Returns true if the attestation mode supports composability (OS image + runtime loadable application)
    pub fn is_composable(&self) -> bool {
        match self {
            Self::DstackTdx => true,
            Self::DstackGcpTdx => true,
            Self::DstackNitroEnclave => false,
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

/// Verified Nitro Enclave attestation report
#[derive(Clone, Debug, Serialize)]
pub struct NitroVerifiedReport {
    /// Module ID
    pub module_id: String,
    /// PCR0 - Enclave image hash
    pub pcrs: NitroPcrs,
    /// User data from attestation
    #[serde(with = "serde_human_bytes")]
    pub user_data: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Represents a verified attestation
#[derive(Clone)]
pub enum DstackVerifiedReport {
    DstackTdx(TdxVerifiedReport),
    DstackGcpTdx {
        tdx_report: TdxVerifiedReport,
        tpm_report: TpmVerifiedReport,
    },
    DstackNitroEnclave(NitroVerifiedReport),
}

impl DstackVerifiedReport {
    pub fn tdx_report(&self) -> Option<&TdxVerifiedReport> {
        match self {
            DstackVerifiedReport::DstackTdx(report) => Some(report),
            DstackVerifiedReport::DstackGcpTdx { tdx_report, .. } => Some(tdx_report),
            DstackVerifiedReport::DstackNitroEnclave(_) => None,
        }
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

/// Represents an NSM (Nitro Security Module) attestation document
#[derive(Clone, Encode, Decode)]
pub struct NsmQuote {
    /// The COSE Sign1 attestation document from NSM
    pub document: Vec<u8>,
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
        if let Some(tdx_quote) = attestation.tdx_quote_mut() {
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

#[derive(Clone, Encode, Decode)]
pub struct DstackGcpTdxQuote {
    pub tdx_quote: TdxQuote,
    pub tpm_quote: TpmQuote,
}

#[derive(Clone, Encode, Decode)]
pub struct DstackNitroQuote {
    pub nsm_quote: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NitroPcrs {
    #[serde(with = "serde_human_bytes")]
    pub pcr0: Vec<u8>,
    #[serde(with = "serde_human_bytes")]
    pub pcr1: Vec<u8>,
    #[serde(with = "serde_human_bytes")]
    pub pcr2: Vec<u8>,
}

impl NitroPcrs {
    fn is_zero(&self) -> bool {
        self.pcr0.iter().all(|&b| b == 0)
            && self.pcr1.iter().all(|&b| b == 0)
            && self.pcr2.iter().all(|&b| b == 0)
    }
}

impl DstackNitroQuote {
    pub fn decode_cose(&self) -> Result<nsm_attest::AttestationDocument> {
        nsm_attest::AttestationDocument::from_cose(&self.nsm_quote)
            .context("Failed to decode NSM attestation document")
    }

    pub fn decode_image_hash(&self) -> Result<Vec<u8>> {
        let pcrs = self.decode_pcrs()?;
        let hash = if pcrs.is_zero() {
            [0u8; 32]
        } else {
            sha256([&pcrs.pcr0, &pcrs.pcr1, &pcrs.pcr2])
        };
        Ok(hash.to_vec())
    }

    pub fn decode_pcrs(&self) -> Result<NitroPcrs> {
        let doc = self.decode_cose()?;
        let pcr0 = doc.pcrs.get(&0).cloned().context("PCR 0 not found")?;
        let pcr1 = doc.pcrs.get(&1).cloned().context("PCR 1 not found")?;
        let pcr2 = doc.pcrs.get(&2).cloned().context("PCR 2 not found")?;
        Ok(NitroPcrs { pcr0, pcr1, pcr2 })
    }
}

#[derive(Clone, Encode, Decode)]
pub enum AttestationQuote {
    DstackTdx(TdxQuote),
    DstackGcpTdx(DstackGcpTdxQuote),
    DstackNitroEnclave(DstackNitroQuote),
}

impl AttestationQuote {
    pub fn mode(&self) -> AttestationMode {
        match self {
            AttestationQuote::DstackTdx { .. } => AttestationMode::DstackTdx,
            AttestationQuote::DstackGcpTdx { .. } => AttestationMode::DstackGcpTdx,
            AttestationQuote::DstackNitroEnclave { .. } => AttestationMode::DstackNitroEnclave,
        }
    }
}

/// Attestation data
#[derive(Clone, Encode, Decode)]
pub struct Attestation<R = ()> {
    /// The quote
    pub quote: AttestationQuote,

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
    pub fn tdx_quote_mut(&mut self) -> Option<&mut TdxQuote> {
        match &mut self.quote {
            AttestationQuote::DstackTdx(quote) => Some(quote),
            AttestationQuote::DstackGcpTdx(q) => Some(&mut q.tdx_quote),
            AttestationQuote::DstackNitroEnclave(_) => None,
        }
    }

    pub fn tdx_quote(&self) -> Option<&TdxQuote> {
        match &self.quote {
            AttestationQuote::DstackTdx(quote) => Some(quote),
            AttestationQuote::DstackGcpTdx(q) => Some(&q.tdx_quote),
            AttestationQuote::DstackNitroEnclave(_) => None,
        }
    }

    pub fn tpm_quote(&self) -> Option<&TpmQuote> {
        match &self.quote {
            AttestationQuote::DstackTdx(_) => None,
            AttestationQuote::DstackGcpTdx(q) => Some(&q.tpm_quote),
            AttestationQuote::DstackNitroEnclave(_) => None,
        }
    }

    /// Get TDX quote bytes
    pub fn get_tdx_quote_bytes(&self) -> Option<Vec<u8>> {
        self.tdx_quote().map(|q| q.quote.clone())
    }

    /// Get TDX event log bytes
    pub fn get_tdx_event_log_bytes(&self) -> Option<Vec<u8>> {
        self.tdx_quote()
            .map(|q| serde_json::to_vec(&q.event_log).unwrap_or_default())
    }

    /// Get TDX event log string
    pub fn get_tdx_event_log_string(&self) -> Option<String> {
        self.tdx_quote()
            .map(|q| serde_json::to_string(&q.event_log).unwrap_or_default())
    }

    pub fn get_td10_report(&self) -> Option<TDReport10> {
        self.tdx_quote()
            .and_then(|q| Quote::parse(&q.quote).ok())
            .and_then(|quote| quote.report.as_td10().cloned())
    }
}

pub trait GetDeviceId {
    fn get_devide_id(&self) -> Vec<u8>;
}

impl GetDeviceId for () {
    fn get_devide_id(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl GetDeviceId for DstackVerifiedReport {
    fn get_devide_id(&self) -> Vec<u8> {
        match self {
            DstackVerifiedReport::DstackTdx(tdx_report) => tdx_report.ppid.to_vec(),
            DstackVerifiedReport::DstackGcpTdx { tdx_report, .. } => tdx_report.ppid.to_vec(),
            DstackVerifiedReport::DstackNitroEnclave(report) => {
                // i-1234567890abcdef0-enc9876543210abcde -> i-1234567890abcdef0
                report
                    .module_id
                    .split_once('-')
                    .map(|(id, _)| id.as_bytes().to_vec())
                    .unwrap_or_default()
            }
        }
    }
}

struct Mrs {
    mr_system: [u8; 32],
    mr_aggregated: [u8; 32],
}

impl<T: GetDeviceId> Attestation<T> {
    fn decode_mr_gcp_tpm(
        &self,
        boottime_mr: bool,
        mr_key_provider: &[u8],
        os_image_hash: &[u8],
        tpm_quote: &TpmQuote,
    ) -> Result<Mrs> {
        let mr_system = sha256([os_image_hash, mr_key_provider]);
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

    fn decode_mr_nitro_nsm(&self, nsm_quote: &DstackNitroQuote) -> Result<Mrs> {
        // Parse NSM attestation document to get PCR values
        let pcrs = nsm_quote.decode_pcrs()?;

        // Compute mr_system from PCR values and mr_key_provider
        let mr_system = sha256([&pcrs.pcr0, &pcrs.pcr1, &pcrs.pcr2]);
        let mr_aggregated = mr_system;

        Ok(Mrs {
            mr_system,
            mr_aggregated,
        })
    }

    fn decode_mr_tdx(
        &self,
        boottime_mr: bool,
        mr_key_provider: &[u8],
        tdx_quote: &TdxQuote,
    ) -> Result<Mrs> {
        let quote = Quote::parse(&tdx_quote.quote).context("Failed to parse quote")?;
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

    /// Decode the VM config from the external or embedded config
    pub fn decode_vm_config<'a>(&'a self, mut config: &'a str) -> Result<VmConfig> {
        if config.is_empty() {
            config = &self.config;
        }
        if config.is_empty() {
            // No vm config for nitro enclave
            config = "{}";
        }
        let vm_config: VmConfig =
            serde_json::from_str(config).context("Failed to parse vm config")?;
        Ok(vm_config)
    }

    /// Decode the app info from the event log
    pub fn decode_app_info(&self, boottime_mr: bool) -> Result<AppInfo> {
        self.decode_app_info_ex(boottime_mr, "")
    }

    pub fn decode_app_info_ex(&self, boottime_mr: bool, vm_config: &str) -> Result<AppInfo> {
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
        let os_image_hash = self
            .decode_vm_config(vm_config)
            .context("Failed to decode os image hash")?
            .os_image_hash;
        let mrs = match &self.quote {
            AttestationQuote::DstackTdx(q) => {
                self.decode_mr_tdx(boottime_mr, &mr_key_provider, q)?
            }
            AttestationQuote::DstackGcpTdx(q) => {
                self.decode_mr_gcp_tpm(boottime_mr, &mr_key_provider, &os_image_hash, &q.tpm_quote)?
            }
            AttestationQuote::DstackNitroEnclave(q) => self.decode_mr_nitro_nsm(q)?,
        };
        let compose_hash = if self.quote.mode().is_composable() {
            self.find_event_payload("compose-hash").unwrap_or_default()
        } else {
            os_image_hash.clone()
        };
        Ok(AppInfo {
            app_id: self.find_event_payload("app-id").unwrap_or_default(),
            instance_id: self.find_event_payload("instance-id").unwrap_or_default(),
            device_id: sha256(self.report.get_devide_id()).to_vec(),
            mr_system: mrs.mr_system,
            mr_aggregated: mrs.mr_aggregated,
            key_provider_info,
            os_image_hash,
            compose_hash,
        })
    }
}

impl<T> Attestation<T> {
    /// Decode the quote
    pub fn decode_tdx_quote(&self) -> Result<Quote> {
        let Some(tdx_quote) = self.tdx_quote() else {
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

impl Attestation {
    /// Reconstruct from tdx quote and event log, for backward compatibility
    pub fn from_tdx_quote(quote: Vec<u8>, event_log: &[u8]) -> Result<Self> {
        let tdx_eventlog: Vec<TdxEvent> =
            serde_json::from_slice(event_log).context("Failed to parse tdx_event_log")?;
        let runtime_events = tdx_eventlog
            .iter()
            .flat_map(|event| event.to_runtime_event())
            .collect();
        let report_data = {
            let quote = Quote::parse(&quote).context("Invalid TDX quote")?;
            let report = quote.report.as_td10().context("Invalid TDX report")?;
            report.report_data
        };
        Ok(Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote,
                event_log: tdx_eventlog,
            }),
            runtime_events,
            report_data,
            config: "".into(),
            report: (),
        })
    }
}

#[cfg(feature = "quote")]
impl Attestation {
    /// Create an attestation for local machine (auto-detect mode)
    pub fn local() -> Result<Self> {
        Self::quote(&[0u8; 64])
    }

    /// Create an attestation from a report data
    pub fn quote(report_data: &[u8; 64]) -> Result<Self> {
        Self::quote_with_app_id(report_data, None)
    }

    pub fn quote_with_app_id(report_data: &[u8; 64], app_id: Option<[u8; 20]>) -> Result<Self> {
        let mode = AttestationMode::detect()?;
        let runtime_events = if mode.is_composable() {
            RuntimeEvent::read_all().context("Failed to read runtime events")?
        } else if let Some(app_id) = app_id {
            vec![RuntimeEvent::new("app-id".to_string(), app_id.to_vec())]
        } else {
            vec![]
        };

        let quote = match mode {
            AttestationMode::DstackTdx => {
                let quote = tdx_attest::get_quote(report_data).context("Failed to get quote")?;
                let event_log =
                    cc_eventlog::tdx::read_event_log().context("Failed to read event log")?;
                AttestationQuote::DstackTdx(TdxQuote { quote, event_log })
            }
            AttestationMode::DstackGcpTdx => {
                let quote = tdx_attest::get_quote(report_data).context("Failed to get quote")?;
                let event_log =
                    cc_eventlog::tdx::read_event_log().context("Failed to read event log")?;
                let tpm_qualifying_data = sha256(&quote);
                let tdx_quote = TdxQuote { quote, event_log };
                let tpm_ctx =
                    tpm_attest::TpmContext::detect().context("Failed to open TPM context")?;
                let tpm_quote = tpm_ctx
                    .create_quote(&tpm_qualifying_data, &tpm_attest::dstack_pcr_policy())
                    .context("Failed to create TPM quote")?;
                AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
                    tdx_quote,
                    tpm_quote,
                })
            }
            AttestationMode::DstackNitroEnclave => {
                let nsm_quote = nsm_attest::get_attestation(report_data)
                    .context("Failed to get NSM attestation")?;
                AttestationQuote::DstackNitroEnclave(DstackNitroQuote { nsm_quote })
            }
        };
        let config = match &quote {
            AttestationQuote::DstackTdx(_) | AttestationQuote::DstackGcpTdx(_) => {
                // TODO: Find a better way handling this hardcode path
                fs_err::read_to_string("/dstack/.host-shared/.sys-config.json").unwrap_or_default()
            }
            AttestationQuote::DstackNitroEnclave(quote) => {
                let os_image_hash = quote
                    .decode_image_hash()
                    .context("Failed to decode image hash")?;
                serde_json::to_string(&serde_json::json!({
                    "os_image_hash": hex::encode(os_image_hash),
                }))
                .context("Failed to serialize config")?
            }
        };

        Ok(Self {
            quote,
            runtime_events,
            report_data: *report_data,
            config,
            report: (),
        })
    }
}

impl Attestation {
    /// Verify the quote with optional custom time (testing hook)
    pub async fn verify_with_time(
        self,
        pccs_url: Option<&str>,
        now: Option<SystemTime>,
    ) -> Result<VerifiedAttestation> {
        let report = match &self.quote {
            AttestationQuote::DstackTdx(q) => {
                let report = self.verify_tdx(pccs_url, &q.quote).await?;
                DstackVerifiedReport::DstackTdx(report)
            }
            AttestationQuote::DstackGcpTdx(q) => {
                let tdx_report = self.verify_tdx(pccs_url, &q.tdx_quote.quote).await?;
                let tpm_report = self
                    .verify_tpm(&q.tpm_quote, &sha256(&q.tdx_quote.quote))
                    .await
                    .context("Failed to verify TPM quote")?;
                DstackVerifiedReport::DstackGcpTdx {
                    tdx_report,
                    tpm_report,
                }
            }
            AttestationQuote::DstackNitroEnclave(quote) => {
                let report = self
                    .verify_nitro_enclave_with_time(quote, now)
                    .await
                    .context("Failed to verify Nitro Enclave")?;
                DstackVerifiedReport::DstackNitroEnclave(report)
            }
        };

        Ok(VerifiedAttestation {
            quote: self.quote,
            runtime_events: self.runtime_events,
            report_data: self.report_data,
            config: self.config,
            report,
        })
    }

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
        self.verify_with_time(pccs_url, None).await
    }

    /// Verify Nitro Enclave attestation with optional custom time (testing hook)
    ///
    /// This performs full cryptographic verification:
    /// 1. Verifies COSE Sign1 signature using ECDSA P-384 with SHA-384
    /// 2. Verifies certificate chain from attestation document to AWS Nitro root CA
    /// 3. Validates user_data matches expected report_data
    async fn verify_nitro_enclave_with_time(
        &self,
        nsm_quote: &DstackNitroQuote,
        now: Option<SystemTime>,
    ) -> Result<NitroVerifiedReport> {
        // Verify COSE signature and certificate chain using nsm-qvl
        // CRL fetch is unreliable (e.g. 403 from S3), so keep it disabled here by default.
        let verified_report = nsm_qvl::verify_attestation(
            &nsm_quote.nsm_quote,
            nsm_qvl::AWS_NITRO_ENCLAVES_ROOT_G1,
            None,
            now,
        )
        .context("NSM attestation verification failed")?;

        // Verify user_data matches report_data
        let Some(user_data) = verified_report.user_data.clone() else {
            bail!("NSM attestation document does not contain user_data");
        };
        if user_data != self.report_data {
            bail!("NSM user_data does not match report_data");
        }

        // Decode PCRs from quote
        let pcrs = nsm_quote
            .decode_pcrs()
            .context("Failed to decode nitro pcrs")?;

        Ok(NitroVerifiedReport {
            module_id: verified_report.module_id,
            pcrs,
            user_data,
            timestamp: verified_report.timestamp,
        })
    }

    async fn verify_tpm(
        &self,
        quote: &TpmQuote,
        qualifying_data: &[u8],
    ) -> Result<TpmVerifiedReport> {
        let report = tpm_qvl::get_collateral_and_verify(quote).await?;
        let pcr_ind = self
            .quote
            .mode()
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
        if report.attest.qualified_data != qualifying_data {
            bail!("tpm qualified_data mismatch");
        }
        Ok(report)
    }

    async fn verify_tdx(&self, pccs_url: Option<&str>, quote: &[u8]) -> Result<TdxVerifiedReport> {
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

        let td_report = tdx_report.report.as_td10().context("no td report")?;
        let replayed_rtmr = self.replay_runtime_events::<Sha384>(None);
        if replayed_rtmr != td_report.rt_mr3 {
            bail!(
                "RTMR3 mismatch, quoted: {}, replayed: {}",
                hex::encode(td_report.rt_mr3),
                hex::encode(replayed_rtmr)
            );
        }

        if td_report.report_data != self.report_data[..] {
            bail!("tdx report_data mismatch");
        }
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
