//! Small helpers over the parsed form of a message.

use std::collections::HashMap;

use mail_parser::{Headers, Message, PartId};

/// The value of a header field as written (with its folding), when it is valid UTF-8.
pub fn raw_header<'m>(headers: Headers<'m>, name: &str) -> Option<&'m str> {
    std::str::from_utf8(headers.get(name)?.raw_value()).ok()
}

/// The number of each part of the top-level message, counted in document order and without the
/// parts of attached messages. These numbers are the part ids of JMAP and of blob ids
/// (`<hash>.<number>`), which clients and the search index keep, so they must stay stable.
pub fn part_numbers(message: &Message<'_>) -> HashMap<PartId, usize> {
    message.root().parts().enumerate().map(|(number, part)| (part.id(), number)).collect()
}

#[cfg(test)]
mod tests {
    use mail_parser::MessageParser;

    use super::*;

    /// A part after an attached message keeps the number it always had, although the parser's own
    /// ids also count the parts inside the attached message.
    #[test]
    fn part_numbers_leave_out_attached_messages() {
        let raw = b"From: a@example.org\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: message/rfc822\r\n\r\nFrom: b@example.org\r\nContent-Type: multipart/mixed; boundary=\"C\"\r\n\r\n--C\r\nContent-Type: text/plain\r\n\r\ninner\r\n--C--\r\n--B\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nPDF\r\n--B--\r\n";
        let message = MessageParser::default().parse(&raw[..]).unwrap();
        let numbers = part_numbers(&message);
        let pdf = message.attachments().find(|part| part.attachment_name() == Some("a.pdf")).unwrap();
        assert_eq!(numbers[&pdf.id()], 2);
        assert_eq!(message.root().parts().nth(2).unwrap().id(), pdf.id());
        assert_ne!(u64::from(pdf.id()), 2, "the attached message's parts are numbered too");
    }

    #[test]
    fn raw_header_keeps_the_value_as_written() {
        let message = MessageParser::default().parse_headers(&b"List-Id: Some list\r\n <l.example.org>\r\nSubject:\r\n\r\n"[..]).unwrap();
        assert_eq!(raw_header(message.headers(), "list-id").map(str::trim), Some("Some list\r\n <l.example.org>"));
        assert_eq!(raw_header(message.headers(), "Subject").map(str::trim), Some(""));
        assert_eq!(raw_header(message.headers(), "To"), None);
    }
}
