//! IMAP METADATA (RFC 5464), NOTIFY (RFC 5465) and REPLACE (RFC 8508).

mod common;

use common::{Client, PASSWORD, TestEnv, message};
use tokio::net::TcpListener;
use unomail::imap;

async fn setup() -> (TestEnv, std::net::SocketAddr) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(imap::serve(env.app.clone(), listener));
    (env, addr)
}

async fn deliver(env: &TestEnv, subject: &str) {
    let mut c = Client::smtp(env.mx).await;
    let from = "carol@remote.example";
    assert!(c.send_mail(from, &["bob@example.org"], &message(from, "bob@example.org", subject, "body")).await.starts_with("250"));
}

async fn cmd(c: &mut Client, tag: &str, command: &str) -> String {
    c.send_raw(format!("{tag} {command}\r\n").as_bytes()).await;
    read_until(c, &format!("{tag} ")).await
}

/// Reads lines until one starts with `prefix`, returning all of them.
async fn read_until(c: &mut Client, prefix: &str) -> String {
    let mut out = String::new();
    loop {
        let line = c.read_line().await.expect("connection closed");
        out.push_str(&line);
        out.push('\n');
        if line.starts_with(prefix) {
            return out;
        }
    }
}

async fn login(addr: std::net::SocketAddr) -> Client {
    let mut c = Client::connect_tls(addr).await;
    let greeting = c.read_line().await.unwrap();
    for capability in ["METADATA", "NOTIFY", "REPLACE"] {
        assert!(greeting.contains(capability), "{capability} missing: {greeting}");
    }
    assert!(cmd(&mut c, "l", &format!("LOGIN bob@example.org \"{PASSWORD}\"")).await.contains("l OK"));
    c
}

#[tokio::test]
async fn metadata_on_mailboxes_and_the_server() {
    let (_env, addr) = setup().await;
    let mut c = login(addr).await;

    assert!(cmd(&mut c, "s1", "SETMETADATA INBOX (/private/comment \"My inbox\" /shared/vendor/x/color \"red\")").await.contains("s1 OK"));
    let got = cmd(&mut c, "g1", "GETMETADATA INBOX /private/comment").await;
    assert!(got.contains("* METADATA \"INBOX\" (/private/comment \"My inbox\")"), "{got}");
    // Entry names are case-insensitive; missing entries come back as NIL.
    let got = cmd(&mut c, "g2", "GETMETADATA INBOX (/PRIVATE/COMMENT /private/missing)").await;
    assert!(got.contains("/private/comment \"My inbox\" /private/missing NIL"), "{got}");

    // DEPTH reaches below the entry asked for.
    let got = cmd(&mut c, "g3", "GETMETADATA (DEPTH infinity) INBOX /shared/vendor").await;
    assert!(got.contains("/shared/vendor/x/color \"red\""), "{got}");
    let got = cmd(&mut c, "g4", "GETMETADATA (DEPTH 1) INBOX /shared/vendor").await;
    assert!(!got.contains("color"), "two levels down: {got}");
    let got = cmd(&mut c, "g5", "GETMETADATA (MAXSIZE 3) INBOX /private/comment").await;
    assert!(got.contains("g5 OK [METADATA LONGENTRIES 8]") && !got.contains("My inbox"), "{got}");

    // Removing with NIL.
    assert!(cmd(&mut c, "s2", "SETMETADATA INBOX (/private/comment NIL)").await.contains("s2 OK"));
    assert!(cmd(&mut c, "g6", "GETMETADATA INBOX /private/comment").await.contains("/private/comment NIL"));

    // Server entries, and the derived special use.
    assert!(cmd(&mut c, "s3", "SETMETADATA \"\" (/private/vendor/client/theme \"dark\")").await.contains("s3 OK"));
    assert!(cmd(&mut c, "g7", "GETMETADATA \"\" /private/vendor/client/theme").await.contains("* METADATA \"\" (/private/vendor/client/theme \"dark\")"));
    assert!(cmd(&mut c, "s4", "SETMETADATA \"\" (/shared/comment \"hi\")").await.contains("s4 NO [NOPERM]"));
    // "\\Sent" has a backslash, so it comes back as a literal.
    assert!(cmd(&mut c, "g8", "GETMETADATA Sent /private/specialuse").await.contains("\\Sent"));
    assert!(cmd(&mut c, "s5", "SETMETADATA Sent (/private/specialuse \"\\\\Junk\")").await.contains("s5 NO"));

    // Invalid names, and nothing stored when one entry of several is refused.
    assert!(cmd(&mut c, "b1", "SETMETADATA INBOX (/comment \"x\")").await.contains("b1 BAD"));
    assert!(cmd(&mut c, "b2", "SETMETADATA INBOX (/private/a \"x\" /private/b*c \"y\")").await.contains("b2 BAD"));
    assert!(cmd(&mut c, "g9", "GETMETADATA INBOX /private/a").await.contains("/private/a NIL"));

    // Entries go with their mailbox.
    assert!(cmd(&mut c, "c", "CREATE Projects").await.contains("c OK"));
    assert!(cmd(&mut c, "s6", "SETMETADATA Projects (/private/comment \"work\")").await.contains("s6 OK"));
    assert!(cmd(&mut c, "r", "RENAME Projects Work").await.contains("r OK"));
    assert!(cmd(&mut c, "g10", "GETMETADATA Work /private/comment").await.contains("\"work\""));
    assert!(cmd(&mut c, "d", "DELETE Work").await.contains("d OK"));
    assert!(cmd(&mut c, "c2", "CREATE Work").await.contains("c2 OK"));
    assert!(cmd(&mut c, "g11", "GETMETADATA Work /private/comment").await.contains("/private/comment NIL"));
}

#[tokio::test]
async fn replace_swaps_one_message_for_another() {
    let (_env, addr) = setup().await;
    let mut c = login(addr).await;
    let draft = "Subject: Draft one\r\n\r\nfirst\r\n";
    c.send_raw(format!("a APPEND Drafts (\\Draft) {{{}+}}\r\n{draft}\r\n", draft.len()).as_bytes()).await;
    assert!(read_until(&mut c, "a ").await.contains("a OK [APPENDUID"));
    assert!(cmd(&mut c, "s", "SELECT Drafts").await.contains("* 1 EXISTS"));

    let draft = "Subject: Draft two\r\n\r\nsecond\r\n";
    c.send_raw(format!("r UID REPLACE 1 Drafts (\\Draft) {{{}+}}\r\n{draft}\r\n", draft.len()).as_bytes()).await;
    let replaced = read_until(&mut c, "r ").await;
    let appenduid = replaced.find("* OK [APPENDUID").expect(&replaced);
    let expunge = replaced.find("* 1 EXPUNGE").expect(&replaced);
    assert!(appenduid < expunge && replaced.contains("r OK"), "{replaced}");

    let fetched = cmd(&mut c, "f", "FETCH 1:* (BODY.PEEK[HEADER.FIELDS (SUBJECT)])").await;
    assert!(fetched.contains("Draft two") && !fetched.contains("Draft one"), "{fetched}");

    // One message only, and it must exist.
    assert!(cmd(&mut c, "x1", "REPLACE 1:2 Drafts {1+}\r\nx").await.contains("x1 BAD"));
    assert!(cmd(&mut c, "x2", "UID REPLACE 99 Drafts {1+}\r\nx").await.contains("x2 NO"));
}

#[tokio::test]
async fn notify_reports_changes_without_a_command() {
    let (env, addr) = setup().await;
    let mut c = login(addr).await;
    let mut other = login(addr).await;
    assert!(cmd(&mut c, "s", "SELECT INBOX").await.contains("s OK"));

    assert!(cmd(&mut c, "b", "NOTIFY SET (PERSONAL (AnnotationChange))").await.contains("b NO [BADEVENT"));
    assert!(cmd(&mut c, "b2", "NOTIFY SET (PERSONAL (MessageNew))").await.contains("b2 BAD"));
    let set = cmd(&mut c, "n", "NOTIFY SET STATUS (SELECTED (MessageNew (UID BODY.PEEK[HEADER.FIELDS (SUBJECT)]) MessageExpunge FlagChange)) (PERSONAL (MessageNew MessageExpunge MailboxName SubscriptionChange MailboxMetadataChange))").await;
    assert!(set.contains("n OK") && set.contains("* STATUS \"Sent\" (MESSAGES 0 "), "{set}");
    assert!(!set.contains("* STATUS \"INBOX\""), "the selected mailbox reports itself: {set}");

    // New mail in the selected mailbox arrives with the attributes asked for.
    deliver(&env, "Pushed").await;
    let pushed = read_until(&mut c, "* 1 FETCH").await;
    assert!(pushed.contains("* 1 EXISTS"), "{pushed}");
    let rest = read_until(&mut c, ")").await;
    assert!(pushed.contains("Subject: Pushed") || rest.contains("Subject: Pushed"), "{pushed}{rest}");

    // Another session's changes to other mailboxes.
    assert!(cmd(&mut other, "c", "CREATE Lists").await.contains("c OK"));
    assert!(read_until(&mut c, "* LIST").await.contains("\"Lists\""));
    let append = "Subject: x\r\n\r\ny\r\n";
    other.send_raw(format!("a APPEND Lists {{{}+}}\r\n{append}\r\n", append.len()).as_bytes()).await;
    read_until(&mut other, "a ").await;
    assert!(read_until(&mut c, "* STATUS").await.contains("* STATUS \"Lists\" (MESSAGES 1 UIDNEXT 2 "));
    assert!(cmd(&mut other, "u", "UNSUBSCRIBE Lists").await.contains("u OK"));
    let unsubscribed = read_until(&mut c, "* LIST").await;
    assert!(unsubscribed.contains("\"Lists\"") && !unsubscribed.contains("\\Subscribed"), "{unsubscribed}");
    assert!(cmd(&mut other, "r", "RENAME Lists Newsletters").await.contains("r OK"));
    assert!(read_until(&mut c, "* LIST").await.contains("\"Newsletters\" (\"OLDNAME\" (\"Lists\"))"));
    assert!(cmd(&mut other, "m", "SETMETADATA Newsletters (/private/comment \"x\")").await.contains("m OK"));
    assert!(read_until(&mut c, "* METADATA").await.contains("* METADATA \"Newsletters\" /private/comment"));
    assert!(cmd(&mut other, "d", "DELETE Newsletters").await.contains("d OK"));
    assert!(read_until(&mut c, "* LIST").await.contains("(\\NonExistent) \"/\" \"Newsletters\""));

    // Expunges in the selected mailbox are pushed too.
    assert!(cmd(&mut other, "s", "SELECT INBOX").await.contains("s OK"));
    assert!(cmd(&mut other, "x", "STORE 1 +FLAGS.SILENT (\\Deleted)").await.contains("x OK"));
    assert!(read_until(&mut c, "* 1 FETCH").await.contains("\\Deleted"));
    assert!(cmd(&mut other, "e", "EXPUNGE").await.contains("e OK"));
    read_until(&mut c, "* 1 EXPUNGE").await;

    assert!(cmd(&mut c, "none", "NOTIFY NONE").await.contains("none OK"));
}
