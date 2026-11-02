//! FETCH data items: envelope, body structure and body sections.

use mail_parser::{AddressList, ContentType, MessagePart, MessageRef, PartKind};

use super::parse::{nstring, string};
use crate::security::authn::find_header_end;

fn unfold(value: &str) -> String {
    value.replace(['\r', '\n'], "").trim().to_owned()
}

fn address_list(out: &mut Vec<u8>, list: Option<AddressList<'_>>) {
    let entries: Vec<_> = list.map(|l| l.mailboxes().filter(|a| a.address().is_some()).collect()).unwrap_or_default();
    if entries.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for entry in entries {
        let address = entry.address().unwrap_or_default();
        let (mailbox, host) = address.rsplit_once('@').unwrap_or((address, ""));
        out.push(b'(');
        // As in a header: not every client takes UTF-8 here.
        nstring(out, entry.name().map(crate::util::encode_header_text).as_deref().map(str::as_bytes));
        out.extend_from_slice(b" NIL ");
        string(out, mailbox.as_bytes());
        out.push(b' ');
        string(out, host.as_bytes());
        out.push(b')');
    }
    out.push(b')');
}

/// ENVELOPE: (date subject from sender reply-to to cc bcc in-reply-to message-id)
pub fn envelope(out: &mut Vec<u8>, msg: MessageRef<'_>) {
    out.push(b'(');
    nstring(out, crate::mime::raw_header(msg.headers(), "Date").map(unfold).as_deref().map(str::as_bytes));
    out.push(b' ');
    nstring(out, crate::mime::raw_header(msg.headers(), "Subject").map(unfold).as_deref().map(str::as_bytes));
    out.push(b' ');
    address_list(out, msg.from());
    out.push(b' ');
    address_list(out, msg.sender().or(msg.from()));
    out.push(b' ');
    address_list(out, msg.reply_to().or(msg.from()));
    for list in [msg.to(), msg.cc(), msg.bcc()] {
        out.push(b' ');
        address_list(out, list);
    }
    out.push(b' ');
    nstring(out, msg.in_reply_to().and_then(|list| list.first()).map(|id| format!("<{id}>")).as_deref().map(str::as_bytes));
    out.push(b' ');
    nstring(out, msg.message_id().map(|id| format!("<{id}>")).as_deref().map(str::as_bytes));
    out.push(b')');
}

fn params(out: &mut Vec<u8>, content_type: Option<ContentType<'_>>) {
    let attributes: Vec<_> = content_type.map(|c| c.attributes().collect()).unwrap_or_default();
    if attributes.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for (i, (name, value)) in attributes.into_iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        string(out, name.as_bytes());
        out.push(b' ');
        string(out, value.as_bytes());
    }
    out.push(b')');
}

/// BODYSTRUCTURE of `part`, recursing into multiparts. `extended` adds the extension fields.
pub fn body_structure(out: &mut Vec<u8>, part: MessagePart<'_>, extended: bool, depth: usize) {
    let content_type = part.content_type();
    if part.is_multipart() && depth < 20 {
        out.push(b'(');
        for child in part.children() {
            body_structure(out, child, extended, depth + 1);
        }
        out.push(b' ');
        string(out, content_type.and_then(|c| c.subtype()).unwrap_or("mixed").to_ascii_uppercase().as_bytes());
        if extended {
            out.push(b' ');
            params(out, content_type);
            out.extend_from_slice(b" NIL NIL");
        }
        out.push(b')');
        return;
    }
    let (ctype, subtype) = match content_type {
        Some(c) => (c.ctype().to_ascii_uppercase(), c.subtype().unwrap_or("PLAIN").to_ascii_uppercase()),
        None => ("TEXT".to_owned(), "PLAIN".to_owned()),
    };
    let body = part.raw_body();
    out.push(b'(');
    string(out, ctype.as_bytes());
    out.push(b' ');
    string(out, subtype.as_bytes());
    out.push(b' ');
    params(out, content_type);
    out.push(b' ');
    nstring(out, part.content_id().map(|id| format!("<{id}>")).as_deref().map(str::as_bytes));
    out.push(b' ');
    nstring(out, part.content_description().map(str::as_bytes));
    out.push(b' ');
    string(out, part.content_transfer_encoding().unwrap_or("7BIT").to_ascii_uppercase().as_bytes());
    out.extend_from_slice(format!(" {}", body.len()).as_bytes());
    if ctype == "TEXT" {
        out.extend_from_slice(format!(" {}", body.iter().filter(|b| **b == b'\n').count()).as_bytes());
    }
    // An attached message also has its envelope, its structure and its size in lines.
    if let PartKind::Message(inner) = part.kind()
        && ctype == "MESSAGE"
        && subtype == "RFC822"
        && depth < 20
    {
        out.push(b' ');
        envelope(out, inner);
        out.push(b' ');
        body_structure(out, inner.root_part(), extended, depth + 1);
        out.extend_from_slice(format!(" {}", body.iter().filter(|b| **b == b'\n').count()).as_bytes());
    }
    if extended {
        out.extend_from_slice(b" NIL ");
        match part.content_disposition() {
            Some(disposition) => {
                out.push(b'(');
                string(out, disposition.ctype().to_ascii_uppercase().as_bytes());
                out.push(b' ');
                params(out, Some(disposition));
                out.push(b')');
            }
            None => out.extend_from_slice(b"NIL"),
        }
        out.extend_from_slice(b" NIL");
    }
    out.push(b')');
}

/// A parsed `BODY[...]` section specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub path: Vec<u32>,
    pub kind: SectionKind,
    /// `<start.length>` partial range.
    pub partial: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionKind {
    /// The whole message or part.
    All,
    Header,
    Text,
    Mime,
    HeaderFields { names: Vec<String>, not: bool },
}

impl Section {
    /// Parses the text between the brackets plus an optional `<a.b>` suffix.
    pub fn parse(spec: &str, partial: &str) -> Option<Section> {
        let mut path = Vec::new();
        let mut rest = spec;
        // Leading part numbers: "1.2.HEADER" -> [1, 2] + "HEADER".
        loop {
            let (head, tail) = rest.split_once('.').unwrap_or((rest, ""));
            match head.parse::<u32>() {
                Ok(n) if n > 0 && path.len() < 20 => {
                    path.push(n);
                    rest = tail;
                    if rest.is_empty() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let upper = rest.to_ascii_uppercase();
        let kind = if upper.is_empty() {
            SectionKind::All
        } else if upper == "HEADER" {
            SectionKind::Header
        } else if upper == "TEXT" {
            SectionKind::Text
        } else if upper == "MIME" && !path.is_empty() {
            SectionKind::Mime
        } else {
            let fields = upper.strip_prefix("HEADER.FIELDS")?;
            let (not, list) = match fields.strip_prefix(".NOT") {
                Some(list) => (true, list),
                None => (false, fields),
            };
            let list = list.trim().strip_prefix('(')?.strip_suffix(')')?;
            let names: Vec<String> = list.split_whitespace().map(|n| n.trim_matches('"').to_owned()).collect();
            if names.is_empty() || names.len() > 50 {
                return None;
            }
            SectionKind::HeaderFields { names, not }
        };
        let partial = if partial.is_empty() {
            None
        } else {
            let inner = partial.strip_prefix('<')?.strip_suffix('>')?;
            let (start, len) = inner.split_once('.')?;
            Some((start.parse().ok()?, len.parse().ok()?))
        };
        Some(Section { path, kind, partial })
    }

    /// The canonical name used in the response, e.g. `BODY[1.HEADER]<0>`.
    pub fn response_name(&self) -> String {
        let mut spec: Vec<String> = self.path.iter().map(u32::to_string).collect();
        match &self.kind {
            SectionKind::All => {}
            SectionKind::Header => spec.push("HEADER".into()),
            SectionKind::Text => spec.push("TEXT".into()),
            SectionKind::Mime => spec.push("MIME".into()),
            SectionKind::HeaderFields { names, not } => {
                spec.push(format!("HEADER.FIELDS{} ({})", if *not { ".NOT" } else { "" }, names.join(" ")));
            }
        }
        let partial = self.partial.map(|(start, _)| format!("<{start}>")).unwrap_or_default();
        format!("BODY[{}]{partial}", spec.join("."))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BinaryError {
    NoSuchPart,
    /// The part uses a Content-Transfer-Encoding we cannot undo (RFC 3516 UNKNOWN-CTE).
    UnknownEncoding,
}

/// The contents of a part with its transfer encoding undone (RFC 3516), or the whole message
/// for an empty path. `Ok(None)` is a part that does not exist (answered with NIL).
pub fn binary_bytes(raw: &[u8], msg: MessageRef<'_>, section: &Section) -> Result<Option<Vec<u8>>, BinaryError> {
    if section.path.is_empty() {
        return Ok(Some(raw.to_vec()));
    }
    let part = match resolve_part(msg, &section.path) {
        None => return Ok(None),
        Some(Found::Inside(inner, path)) => return binary_bytes(inner.raw(), inner, &Section { path, kind: section.kind.clone(), partial: None }),
        Some(Found::Part(part)) => part,
    };
    if part.is_multipart() {
        return Err(BinaryError::NoSuchPart);
    }
    let body = part.raw_body();
    let encoding = part.content_transfer_encoding().unwrap_or("7bit").trim().to_ascii_lowercase();
    match encoding.as_str() {
        "7bit" | "8bit" | "binary" | "" => Ok(Some(body.to_vec())),
        "base64" => {
            let clean: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
            let clean = clean.strip_suffix(b"==").or_else(|| clean.strip_suffix(b"=")).unwrap_or(&clean);
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, clean).map(Some).map_err(|_| BinaryError::UnknownEncoding)
        }
        "quoted-printable" => Ok(Some(quoted_printable(body))),
        _ => Err(BinaryError::UnknownEncoding),
    }
}

/// Undoes quoted-printable (RFC 2045 6.7); malformed escapes are kept as they are.
fn quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'=' if body.get(i + 1) == Some(&b'\r') && body.get(i + 2) == Some(&b'\n') => i += 3,
            b'=' if body.get(i + 1) == Some(&b'\n') => i += 2,
            b'=' => match (body.get(i + 1).copied().and_then(hex), body.get(i + 2).copied().and_then(hex)) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    i += 3;
                }
                _ => {
                    out.push(b'=');
                    i += 1;
                }
            },
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// Keeps (or drops, with `not`) the named header fields; always ends with the blank line.
fn filter_headers(headers: &[u8], names: &[String], not: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut keep = false;
    for line in headers.split_inclusive(|b| *b == b'\n') {
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            let name = line.split(|b| *b == b':').next().unwrap_or(&[]);
            let listed = names.iter().any(|n| n.as_bytes().eq_ignore_ascii_case(name));
            keep = listed != not;
        }
        if keep {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// The part a path leads to, or the attached message it goes into with the rest of the path.
enum Found<'m> {
    Part(MessagePart<'m>),
    Inside(MessageRef<'m>, Vec<u32>),
}

fn resolve_part<'m>(msg: MessageRef<'m>, path: &[u32]) -> Option<Found<'m>> {
    let mut part = msg.root_part();
    for (done, number) in path.iter().enumerate() {
        if done > 0
            && let PartKind::Message(inner) = part.kind()
        {
            return Some(Found::Inside(inner, path[done..].to_vec()));
        }
        part = if part.is_multipart() {
            part.children().nth(*number as usize - 1)?
        } else if *number == 1 {
            // A non-multipart message has exactly one part: itself.
            part
        } else {
            return None;
        };
    }
    Some(Found::Part(part))
}

/// Extracts the bytes selected by `section` from the raw message.
pub fn section_bytes(raw: &[u8], msg: MessageRef<'_>, section: &Section) -> Option<Vec<u8>> {
    // The header block includes the blank line that terminates it.
    let split = find_header_end(raw);
    let header_end = if raw[split..].starts_with(b"\r\n") {
        split + 2
    } else if raw[split..].starts_with(b"\n") {
        split + 1
    } else {
        split
    };
    let data: Vec<u8> = if section.path.is_empty() {
        match &section.kind {
            SectionKind::All => raw.to_vec(),
            SectionKind::Header => raw[..header_end].to_vec(),
            SectionKind::Text => raw[header_end..].to_vec(),
            SectionKind::HeaderFields { names, not } => filter_headers(&raw[..header_end], names, *not),
            SectionKind::Mime => return None,
        }
    } else {
        match resolve_part(msg, &section.path)? {
            Found::Inside(inner, path) => section_bytes(inner.raw(), inner, &Section { path, kind: section.kind.clone(), partial: None })?,
            Found::Part(part) => match (part.kind(), &section.kind) {
                // HEADER and TEXT of an attached message mean that message's own.
                (PartKind::Message(inner), SectionKind::Header | SectionKind::Text | SectionKind::HeaderFields { .. }) => {
                    section_bytes(inner.raw(), inner, &Section { path: Vec::new(), kind: section.kind.clone(), partial: None })?
                }
                (_, SectionKind::All | SectionKind::Text) => part.raw_body().to_vec(),
                (_, SectionKind::Mime | SectionKind::Header) => part.raw_headers().to_vec(),
                (_, SectionKind::HeaderFields { names, not }) => filter_headers(part.raw_headers(), names, *not),
            },
        }
    };
    Some(match section.partial {
        Some((start, len)) => data.get(start.min(data.len())..(start.saturating_add(len)).min(data.len())).unwrap_or(&[]).to_vec(),
        None => data,
    })
}

#[cfg(test)]
mod tests {
    use mail_parser::MessageParser;

    use super::*;

    const SIMPLE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Hi there\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\nMessage-ID: <id1@example.org>\r\n\r\nHello\r\nWorld\r\n";
    const MULTI: &[u8] = b"From: a@example.org\r\nSubject: Files\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n--B\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--B--\r\n";

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn envelope_of_simple_message() {
        let msg = MessageParser::default().parse(SIMPLE).unwrap();
        let mut out = Vec::new();
        envelope(&mut out, msg.root());
        assert_eq!(
            text(out),
            r#"("Mon, 05 Oct 2026 10:00:00 +0000" "Hi there" (("Alice" NIL "alice" "example.org")) (("Alice" NIL "alice" "example.org")) (("Alice" NIL "alice" "example.org")) ((NIL NIL "bob" "example.org")) NIL NIL NIL "<id1@example.org>")"#
        );
    }

    #[test]
    fn body_structures() {
        let msg = MessageParser::default().parse(SIMPLE).unwrap();
        let mut out = Vec::new();
        body_structure(&mut out, msg.root_part(), false, 0);
        assert_eq!(text(out), r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 14 2)"#);

        let msg = MessageParser::default().parse(MULTI).unwrap();
        let mut out = Vec::new();
        body_structure(&mut out, msg.root_part(), true, 0);
        let structure = text(out);
        assert!(structure.starts_with(r#"(("TEXT" "PLAIN" ("charset" "utf-8") NIL NIL "7BIT" "#), "{structure}");
        assert!(structure.contains(r#"("APPLICATION" "PDF" ("name" "a.pdf") NIL NIL "BASE64" "#), "{structure}");
        assert!(structure.contains(r#"("ATTACHMENT" ("filename" "a.pdf"))"#), "{structure}");
        assert!(structure.ends_with(r#" "MIXED" ("boundary" "B") NIL NIL)"#), "{structure}");
    }

    /// Sections and the structure of a message attached in the clear and of one attached in base64,
    /// whose parts' offsets refer to its decoded body rather than to the outer message.
    #[test]
    fn attached_messages() {
        use base64::Engine;
        let inner = "From: b@example.org\r\nSubject: Inner\r\nContent-Type: multipart/mixed; boundary=\"C\"\r\n\r\n--C\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--C\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--C--\r\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
        for (encoding, body) in [("7bit", inner), ("base64", encoded.as_str())] {
            let raw = format!("From: a@example.org\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nouter\r\n--B\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n--B--\r\n");
            let msg = MessageParser::default().parse(raw.as_bytes()).unwrap();
            let get = |spec: &str| text(section_bytes(raw.as_bytes(), msg.root(), &Section::parse(spec, "").unwrap()).unwrap());
            assert_eq!(get("2.1").trim_end(), "first", "{encoding}");
            assert_eq!(get("2.2").trim_end(), "second", "{encoding}");
            assert_eq!(get("2.HEADER.FIELDS (SUBJECT)"), "Subject: Inner\r\n\r\n", "{encoding}");
            assert!(get("2.TEXT").contains("second"), "{encoding}");
            assert!(get("2.MIME").contains("message/rfc822"), "{encoding}");
            assert_eq!(binary_bytes(raw.as_bytes(), msg.root(), &Section::parse("2.2", "").unwrap()).unwrap().unwrap().trim_ascii_end(), b"second", "{encoding}");
            let mut out = Vec::new();
            body_structure(&mut out, msg.root_part(), false, 0);
            assert!(text(out).contains(r#""Inner""#), "{encoding}");
        }
    }

    #[test]
    fn section_parsing() {
        assert_eq!(Section::parse("", ""), Some(Section { path: vec![], kind: SectionKind::All, partial: None }));
        assert_eq!(Section::parse("1.2.MIME", "<0.10>"), Some(Section { path: vec![1, 2], kind: SectionKind::Mime, partial: Some((0, 10)) }));
        let fields = Section::parse("HEADER.FIELDS (From \"To\")", "").unwrap();
        assert_eq!(fields.kind, SectionKind::HeaderFields { names: vec!["FROM".into(), "TO".into()], not: false });
        assert_eq!(fields.response_name(), "BODY[HEADER.FIELDS (FROM TO)]");
        assert_eq!(Section::parse("2.header", "<5.1>").unwrap().response_name(), "BODY[2.HEADER]<5>");
        for (spec, partial) in [("BOGUS", ""), ("MIME", ""), ("HEADER.FIELDS ()", ""), ("HEADER.FIELDS From", ""), ("", "<x.y>"), ("", "0.5")] {
            assert!(Section::parse(spec, partial).is_none(), "{spec:?} {partial:?}");
        }
    }

    #[test]
    fn section_extraction() {
        let msg = MessageParser::default().parse(SIMPLE).unwrap();
        let get = |spec: &str, partial: &str| text(section_bytes(SIMPLE, msg.root(), &Section::parse(spec, partial).unwrap()).unwrap());
        assert_eq!(get("", "").as_bytes(), SIMPLE);
        assert_eq!(get("TEXT", ""), "Hello\r\nWorld\r\n");
        assert!(get("HEADER", "").ends_with("Message-ID: <id1@example.org>\r\n\r\n"));
        assert_eq!(get("HEADER.FIELDS (subject TO)", ""), "To: bob@example.org\r\nSubject: Hi there\r\n\r\n");
        assert!(!get("HEADER.FIELDS.NOT (subject)", "").contains("Subject"));
        assert_eq!(get("TEXT", "<2.5>"), "llo\r\n");
        assert_eq!(get("TEXT", "<500.5>"), "");
        assert_eq!(get("1", ""), "Hello\r\nWorld\r\n");
        assert!(section_bytes(SIMPLE, msg.root(), &Section::parse("2", "").unwrap()).is_none());

        let msg = MessageParser::default().parse(MULTI).unwrap();
        let get = |spec: &str| text(section_bytes(MULTI, msg.root(), &Section::parse(spec, "").unwrap()).unwrap());
        assert_eq!(get("1").trim_end(), "Body text");
        assert_eq!(get("2").trim_end(), "QUJD");
        assert!(get("2.MIME").contains("Content-Disposition: attachment"));
        assert!(section_bytes(MULTI, msg.root(), &Section::parse("3", "").unwrap()).is_none());
    }
}
