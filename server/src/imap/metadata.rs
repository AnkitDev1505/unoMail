//! METADATA (RFC 5464): entries on mailboxes and on the server ("" as the mailbox name).
//!
//! Private entries are kept per account; shared mailbox entries under the mailbox owner, so
//! everyone the mailbox is shared with sees the same ones. `/private/specialuse` (RFC 6154 5)
//! is derived from the mailbox role and cannot be set.

use std::sync::LazyLock;

use tokio::sync::broadcast;

use super::{CmdResult, Session, bad, internal, no, special_use};
use super::parse::{Arg, string};
use crate::store::Mailbox;

/// The largest value accepted, in octets.
pub const MAX_VALUE: usize = 64 * 1024;
/// Entries one account may have in all.
const MAX_ENTRIES: i64 = 1000;
const MAX_NAME: usize = 1024;

/// An entry set or removed, for NOTIFY (RFC 5465 MailboxMetadataChange / ServerMetadataChange).
#[derive(Debug, Clone)]
pub struct Change {
    /// The account whose view of the entry changed (the owner, for shared entries).
    pub account_id: i64,
    pub mailbox_id: Option<i64>,
    pub entry: String,
}

pub static CHANGES: LazyLock<broadcast::Sender<Change>> = LazyLock::new(|| broadcast::channel(256).0);

/// A valid entry name in its canonical (lowercase) form.
fn entry_name(text: &str) -> Option<String> {
    let name = text.to_ascii_lowercase();
    let valid = name.len() <= MAX_NAME
        && (name.starts_with("/private/") || name.starts_with("/shared/"))
        && !name.ends_with('/')
        && !name.contains("//")
        && name.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'*' && b != b'%');
    valid.then_some(name)
}

fn is_private(entry: &str) -> bool {
    entry.starts_with("/private/")
}

/// Where the entries of one mailbox (or the server) are read and written.
struct Target {
    mailbox: Option<Mailbox>,
    rights: String,
}

impl Target {
    /// The account an entry is stored under, and its mailbox column.
    fn key(&self, viewer: i64, entry: &str) -> (i64, Option<i64>) {
        match &self.mailbox {
            None => (viewer, None),
            Some(mailbox) if is_private(entry) => (viewer, Some(mailbox.id)),
            Some(mailbox) => (mailbox.account_id, Some(mailbox.id)),
        }
    }

    /// RFC 5464 3.4: lookup for private entries, read (to see) or write (to set) for shared ones.
    fn may(&self, entry: &str, write: bool) -> bool {
        if self.mailbox.is_none() {
            // Server entries: private ones are the account's own, shared ones are read-only.
            return is_private(entry) || !write;
        }
        let right = if is_private(entry) { 'l' } else if write { 'w' } else { 'r' };
        self.rights.contains(right)
    }
}

impl Session {
    async fn metadata_target(&self, name: Option<String>) -> Result<Target, String> {
        match name {
            None => Err("BAD mailbox name required".into()),
            Some(name) if name.is_empty() => Ok(Target { mailbox: None, rights: String::new() }),
            Some(name) => {
                let (mailbox, rights) = self.find_mailbox_rights(Some(name)).await?;
                Ok(Target { mailbox: Some(mailbox), rights })
            }
        }
    }

    /// The stored value of one entry, derived ones included.
    async fn metadata_value(&self, target: &Target, entry: &str) -> Result<Option<Vec<u8>>, String> {
        if entry == "/private/specialuse" {
            let role = target.mailbox.as_ref().and_then(|m| m.role.as_deref());
            let flag = special_use(role).trim();
            return Ok((!flag.is_empty()).then(|| flag.as_bytes().to_vec()));
        }
        let (account, mailbox) = target.key(self.account_id(), entry);
        sqlx::query_scalar("SELECT value FROM imap_metadata WHERE account_id = ? AND mailbox_id IS ? AND name = ?")
            .bind(account)
            .bind(mailbox)
            .bind(entry)
            .fetch_optional(&self.app.db)
            .await
            .map_err(internal)
    }

    /// Entries strictly below `entry`, `depth` levels deep (`None`: all of them).
    async fn metadata_children(&self, target: &Target, entry: &str, depth: Option<usize>) -> Result<Vec<(String, Vec<u8>)>, String> {
        let (account, mailbox) = target.key(self.account_id(), entry);
        let prefix = format!("{entry}/");
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT name, value FROM imap_metadata WHERE account_id = ? AND mailbox_id IS ? AND substr(name, 1, ?) = ? ORDER BY name")
            .bind(account)
            .bind(mailbox)
            .bind(prefix.len() as i64)
            .bind(&prefix)
            .fetch_all(&self.app.db)
            .await
            .map_err(internal)?;
        Ok(rows.into_iter().filter(|(name, _)| depth.is_none_or(|depth| name[prefix.len()..].matches('/').count() < depth)).collect())
    }

    /// GETMETADATA [(MAXSIZE n DEPTH 0|1|infinity)] mailbox entry | (entries)
    pub(super) async fn cmd_getmetadata(&mut self, args: &[Arg]) -> std::io::Result<CmdResult> {
        let mut args = args;
        let (mut max_size, mut depth) = (None, Some(0));
        if let Some(Arg::List(options)) = args.first() {
            let mut options = options.iter();
            while let Some(option) = options.next() {
                let value = options.next().and_then(Arg::text);
                match (option.atom_upper().as_deref(), value.as_deref().map(str::to_ascii_lowercase).as_deref()) {
                    (Some("MAXSIZE"), Some(n)) if n.parse::<usize>().is_ok() => max_size = n.parse().ok(),
                    (Some("DEPTH"), Some("0")) => depth = Some(0),
                    (Some("DEPTH"), Some("1")) => depth = Some(1),
                    (Some("DEPTH"), Some("infinity")) => depth = None,
                    _ => return Ok(bad("unknown GETMETADATA option")),
                }
            }
            args = &args[1..];
        }
        let target = match self.metadata_target(args.first().and_then(Arg::text)).await {
            Ok(target) => target,
            Err(err) => return Ok(Err(err)),
        };
        let requested: Vec<Arg> = match args.get(1) {
            Some(Arg::List(entries)) => entries.clone(),
            Some(entry) => vec![entry.clone()],
            None => return Ok(bad("usage: GETMETADATA mailbox entries")),
        };
        if requested.is_empty() {
            return Ok(bad("no entries requested"));
        }
        let mut found: Vec<(String, Option<Vec<u8>>)> = Vec::new();
        for entry in &requested {
            let Some(entry) = entry.text().as_deref().and_then(entry_name) else { return Ok(bad("invalid entry name")) };
            if !target.may(&entry, false) {
                return Ok(no("[NOPERM] you may not read this entry"));
            }
            let value = match self.metadata_value(&target, &entry).await {
                Ok(value) => value,
                Err(err) => return Ok(Err(err)),
            };
            let children = if depth == Some(0) { Vec::new() } else {
                match self.metadata_children(&target, &entry, depth).await {
                    Ok(children) => children,
                    Err(err) => return Ok(Err(err)),
                }
            };
            found.push((entry, value));
            found.extend(children.into_iter().map(|(name, value)| (name, Some(value))));
        }
        // MAXSIZE: larger values are left out and the largest of them is reported.
        let mut longest = 0;
        found.retain(|(_, value)| match (value, max_size) {
            (Some(value), Some(max)) if value.len() > max => {
                longest = longest.max(value.len());
                false
            }
            _ => true,
        });
        if !found.is_empty() {
            let mut out = b"* METADATA ".to_vec();
            let name = target.mailbox.as_ref().map(|m| self.encode_name(&m.name)).unwrap_or_default();
            string(&mut out, name.as_bytes());
            out.extend_from_slice(b" (");
            for (i, (entry, value)) in found.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                out.extend_from_slice(entry.as_bytes());
                out.push(b' ');
                match value {
                    Some(value) => string(&mut out, value),
                    None => out.extend_from_slice(b"NIL"),
                }
            }
            out.extend_from_slice(b")\r\n");
            self.send(&out).await?;
        }
        if longest > 0 {
            return Ok(Ok(format!("[METADATA LONGENTRIES {longest}] GETMETADATA completed")));
        }
        Ok(Ok("GETMETADATA completed".into()))
    }

    /// SETMETADATA mailbox (entry value|NIL ...): all entries or none.
    pub(super) async fn cmd_setmetadata(&mut self, args: &[Arg]) -> CmdResult {
        let target = self.metadata_target(args.first().and_then(Arg::text)).await?;
        let Some(Arg::List(pairs)) = args.get(1) else { return bad("usage: SETMETADATA mailbox (entry value ...)") };
        if pairs.is_empty() || pairs.len() % 2 != 0 {
            return bad("entries and values come in pairs");
        }
        let mut changes = Vec::new();
        for pair in pairs.chunks(2) {
            let Some(entry) = pair[0].text().as_deref().and_then(entry_name) else { return bad("invalid entry name") };
            let value = match &pair[1] {
                Arg::Atom(atom) if atom.eq_ignore_ascii_case("NIL") => None,
                Arg::Str(value) => Some(value.clone()),
                _ => return bad("values are strings or NIL"),
            };
            if entry == "/private/specialuse" {
                return no("[CANNOT] the special use follows the mailbox's role");
            }
            if !target.may(&entry, true) {
                return no("[NOPERM] you may not change this entry");
            }
            if value.as_ref().is_some_and(|v| v.len() > MAX_VALUE) {
                return Err(format!("NO [METADATA MAXSIZE {MAX_VALUE}] the value is too large"));
            }
            changes.push((entry, value));
        }
        let viewer = self.account_id();
        let mut tx = self.app.db.begin_with("BEGIN IMMEDIATE").await.map_err(internal)?;
        let mut touched = Vec::new();
        for (entry, value) in &changes {
            let (account, mailbox) = target.key(viewer, entry);
            sqlx::query("DELETE FROM imap_metadata WHERE account_id = ? AND mailbox_id IS ? AND name = ?")
                .bind(account)
                .bind(mailbox)
                .bind(entry)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            if let Some(value) = value {
                sqlx::query("INSERT INTO imap_metadata (account_id, mailbox_id, name, value) VALUES (?, ?, ?, ?)")
                    .bind(account)
                    .bind(mailbox)
                    .bind(entry)
                    .bind(value)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM imap_metadata WHERE account_id = ?").bind(account).fetch_one(&mut *tx).await.map_err(internal)?;
                if count > MAX_ENTRIES {
                    return no("[METADATA TOOMANY] too many entries");
                }
            }
            touched.push(Change { account_id: account, mailbox_id: mailbox, entry: entry.clone() });
        }
        tx.commit().await.map_err(internal)?;
        for change in touched {
            let _ = CHANGES.send(change);
        }
        Ok("SETMETADATA completed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::entry_name;

    #[test]
    fn entry_names() {
        assert_eq!(entry_name("/Private/Comment").as_deref(), Some("/private/comment"));
        assert_eq!(entry_name("/shared/vendor/x/y").as_deref(), Some("/shared/vendor/x/y"));
        for invalid in ["/private", "/private/", "/other/x", "/shared//x", "/shared/x/", "/shared/a*b", "/shared/a b", "comment"] {
            assert_eq!(entry_name(invalid), None, "{invalid}");
        }
    }
}
