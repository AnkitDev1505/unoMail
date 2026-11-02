//! DMARC aggregate, ARF feedback and TLS-RPT reports: parsing and generation.
//!
//! Taken from mail-auth 0.13.3 (Stalwart Labs, Apache-2.0 OR MIT), which dropped this module in
//! 0.14, and adapted to mail-parser 1.0. The helpers that built records from mail-auth's
//! verification outputs were not needed and were left out.

#![allow(clippy::all)]

/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod arf;
pub mod dmarc;
pub mod tlsrpt;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, io::Read, net::IpAddr};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DateRange {
    pub begin: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range: DateRange,
    pub error: Vec<String>,
    #[serde(default)]
    pub generator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Alignment {
    Relaxed,
    Strict,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
    #[default]
    Unspecified,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ActionDisposition {
    None,
    Pass,
    Quarantine,
    Reject,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyPublished {
    pub domain: String,
    pub version_published: Option<f32>,
    pub adkim: Alignment,
    pub aspf: Alignment,
    pub p: Disposition,
    pub sp: Disposition,
    #[serde(default)]
    pub np: Disposition,
    pub testing: bool,
    #[serde(default)]
    pub discovery_method: Discovery,
    pub fo: Option<String>,
}

impl Eq for PolicyPublished {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Discovery {
    Psl,
    Treewalk,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DmarcResult {
    Pass,
    Fail,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyOverride {
    LocalPolicy,
    MailingList,
    PolicyTestMode,
    TrustedForwarder,
    #[default]
    Other,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyOverrideReason {
    pub type_: PolicyOverride,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    pub disposition: ActionDisposition,
    pub dkim: DmarcResult,
    pub spf: DmarcResult,
    pub reason: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Clone, Hash, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub source_ip: Option<IpAddr>,
    pub count: u32,
    pub policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Extension {
    pub name: String,
    pub definition: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identifier {
    pub envelope_to: Option<String>,
    pub envelope_from: String,
    pub header_from: String,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DkimResult {
    #[default]
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DKIMAuthResult {
    pub domain: String,
    pub selector: String,
    pub result: DkimResult,
    pub human_result: Option<String>,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SPFDomainScope {
    Helo,
    MailFrom,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SpfResult {
    #[default]
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SPFAuthResult {
    pub domain: String,
    pub scope: SPFDomainScope,
    pub result: SpfResult,
    pub human_result: Option<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthResult {
    pub dkim: Vec<DKIMAuthResult>,
    pub spf: Vec<SPFAuthResult>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifier,
    pub auth_results: AuthResult,
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Report {
    pub version: f32,
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub record: Vec<Record>,
    pub extensions: Vec<Extension>,
}

impl Eq for Report {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MailParseError,
    ReportParseError(String),
    UncompressError(String),
    ReportTooLarge,
    NoReportsFound,
}

const MAX_SIZE_RESERVATION: u64 = 64 * 1024;

pub(crate) fn read_capped(
    reader: impl Read,
    size_hint: u64,
    max_size: usize,
) -> Result<Vec<u8>, Error> {
    let max_size = max_size as u64;
    if size_hint > max_size {
        return Err(Error::ReportTooLarge);
    }

    let mut buf = Vec::with_capacity(size_hint.min(MAX_SIZE_RESERVATION) as usize);
    reader
        .take(max_size.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| Error::UncompressError(err.to_string()))?;

    if buf.len() as u64 > max_size {
        return Err(Error::ReportTooLarge);
    }

    Ok(buf)
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::ReportParseError(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Feedback<'x> {
    pub feedback_type: FeedbackType,
    pub arrival_date: Option<i64>,
    pub authentication_results: Vec<Cow<'x, str>>,
    pub incidents: u32,
    pub original_envelope_id: Option<Cow<'x, str>>,
    pub original_mail_from: Option<Cow<'x, str>>,
    pub original_rcpt_to: Option<Cow<'x, str>>,
    pub reported_domain: Vec<Cow<'x, str>>,
    pub reported_uri: Vec<Cow<'x, str>>,
    pub reporting_mta: Option<Cow<'x, str>>,
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<Cow<'x, str>>,
    pub version: u32,
    pub source_port: u32,

    // Auth-Failure keys
    pub auth_failure: AuthFailureType,
    pub delivery_result: DeliveryResult,
    pub dkim_adsp_dns: Option<Cow<'x, str>>,
    pub dkim_canonicalized_body: Option<Cow<'x, str>>,
    pub dkim_canonicalized_header: Option<Cow<'x, str>>,
    pub dkim_domain: Option<Cow<'x, str>>,
    pub dkim_identity: Option<Cow<'x, str>>,
    pub dkim_selector: Option<Cow<'x, str>>,
    pub dkim_selector_dns: Option<Cow<'x, str>>,
    pub spf_dns: Option<Cow<'x, str>>,
    pub identity_alignment: IdentityAlignment,

    pub message: Option<Cow<'x, str>>,
    pub headers: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum AuthFailureType {
    Adsp,
    BodyHash,
    Revoked,
    Signature,
    Spf,
    Dmarc,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum IdentityAlignment {
    None,
    Spf,
    Dkim,
    DkimSpf,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum DeliveryResult {
    Delivered,
    Spam,
    Policy,
    Reject,
    Other,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Default)]
pub enum FeedbackType {
    Abuse,
    AuthFailure,
    Fraud,
    NotSpam,
    #[default]
    Other,
    Virus,
}
