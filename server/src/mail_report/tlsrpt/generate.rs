/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::TlsReport;
use flate2::{Compression, write::GzEncoder};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, address::Address, content_type::ContentType},
    mime::{BodyPart, MimePart, make_boundary},
};
use std::io;

impl TlsReport {
    pub fn write_rfc5322<'x>(
        &self,
        report_domain: &'x str,
        submitter: &'x str,
        from: impl Into<Address<'x>>,
        to: impl Iterator<Item = &'x str>,
        writer: impl io::Write,
    ) -> io::Result<()> {
        // Compress JSON report
        let json = self.to_json();
        let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
        io::Write::write_all(&mut e, json.as_bytes())?;
        let bytes = e.finish()?;
        self.write_rfc5322_from_bytes(report_domain, submitter, from, to, &bytes, writer)
    }

    pub fn write_rfc5322_from_bytes<'x>(
        &self,
        report_domain: &str,
        submitter: &str,
        from: impl Into<Address<'x>>,
        to: impl Iterator<Item = &'x str>,
        bytes: &[u8],
        writer: impl io::Write,
    ) -> io::Result<()> {
        MessageBuilder::new()
            .from(from)
            .header(
                "To",
                HeaderType::Address(Address::List(to.map(|to| (*to).into()).collect())),
            )
            .message_id(format!("{}@{}", make_boundary("."), submitter))
            .header("TLS-Report-Domain", HeaderType::Text(report_domain.into()))
            .header("TLS-Report-Submitter", HeaderType::Text(submitter.into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .subject(format!(
                "Report Domain: {} Submitter: {} Report-ID: <{}>",
                report_domain, submitter, self.report_id
            ))
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "tlsrpt"),
                BodyPart::Multipart(vec![
                    MimePart::new(
                        ContentType::new("text/plain"),
                        BodyPart::Text(
                            format!(
                                concat!(
                                    "TLS report from {}\r\n\r\n",
                                    "Report Domain: {}\r\n",
                                    "Submitter: {}\r\n",
                                    "Report-ID: {}\r\n",
                                ),
                                submitter, report_domain, submitter, self.report_id
                            )
                            .into(),
                        ),
                    ),
                    MimePart::new(
                        ContentType::new("application/tlsrpt+gzip"),
                        BodyPart::Binary(bytes.into()),
                    )
                    .attachment(format!(
                        "{}!{}!{}!{}.json.gz",
                        submitter,
                        report_domain,
                        self.date_range.start_datetime.to_timestamp(),
                        self.date_range.end_datetime.to_timestamp()
                    )),
                ]),
            ))
            .write_to(writer)
    }

    pub fn to_rfc5322<'x>(
        &self,
        report_domain: &'x str,
        submitter: &'x str,
        from: impl Into<Address<'x>>,
        to: impl Iterator<Item = &'x str>,
    ) -> io::Result<String> {
        let mut buf = Vec::new();
        self.write_rfc5322(report_domain, submitter, from, to, &mut buf)?;
        String::from_utf8(buf).map_err(io::Error::other)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

