/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::TlsReport;
use crate::mail_report::{Error, read_capped};
use flate2::read::GzDecoder;
use mail_parser::{MessageParser, PartKind};
use std::io::Cursor;
use zip::ZipArchive;

impl TlsReport {
    pub fn parse_json(report: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(report).map_err(|err| Error::ReportParseError(err.to_string()))
    }

    pub fn parse_rfc5322(report: &[u8], max_size: usize) -> Result<Self, Error> {
        let message = MessageParser::new()
            .parse(report)
            .ok_or(Error::MailParseError)?;
        let mut error = Error::NoReportsFound;

        for part in message.root().parts() {
            match part.kind() {
                PartKind::Binary | PartKind::InlineBinary => {
                    let report = part.decoded();
                    enum ReportType {
                        Json,
                        Gzip,
                        Zip,
                    }

                    let (_, ext) = part
                        .attachment_name()
                        .unwrap_or("file.none")
                        .rsplit_once('.')
                        .unwrap_or(("file", "none"));
                    let subtype = part
                        .content_type()
                        .and_then(|ct| ct.subtype())
                        .unwrap_or("none");
                    let rt = if subtype.eq_ignore_ascii_case("tlsrpt+gzip") {
                        ReportType::Gzip
                    } else if subtype.eq_ignore_ascii_case("tlsrpt+zip") {
                        ReportType::Zip
                    } else if subtype.eq_ignore_ascii_case("tlsrpt+json") {
                        ReportType::Json
                    } else if ext.eq_ignore_ascii_case("gz") {
                        ReportType::Gzip
                    } else if ext.eq_ignore_ascii_case("zip") {
                        ReportType::Zip
                    } else if ext.eq_ignore_ascii_case("json") {
                        ReportType::Json
                    } else {
                        continue;
                    };

                    match rt {
                        ReportType::Gzip => {
                            let report: &[u8] = report.as_ref();
                            let buf = read_capped(GzDecoder::new(report), 0, max_size)?;

                            match Self::parse_json(&buf) {
                                Ok(report) => return Ok(report),
                                Err(err) => {
                                    error = err;
                                }
                            }
                        }
                        ReportType::Zip => {
                            let mut archive = ZipArchive::new(Cursor::new(report))
                                .map_err(|err| Error::UncompressError(err.to_string()))?;
                            for i in 0..archive.len() {
                                match archive.by_index(i) {
                                    Ok(mut file) => {
                                        let size_hint = file.size();
                                        let buf = read_capped(&mut file, size_hint, max_size)?;
                                        match Self::parse_json(&buf) {
                                            Ok(report) => return Ok(report),
                                            Err(err) => {
                                                error = err;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        error = Error::UncompressError(err.to_string());
                                    }
                                }
                            }
                        }
                        ReportType::Json => match Self::parse_json(&report) {
                            Ok(report) => return Ok(report),
                            Err(err) => {
                                error = err;
                            }
                        },
                    }
                }
                _ => (),
            }
        }

        Err(error)
    }
}

