//! NOTIFY (RFC 5465): changes reported as they happen, outside IDLE and for other mailboxes.
//!
//! Other mailboxes are reported with STATUS, LIST and METADATA responses. Only the account's
//! own mailboxes are watched; shared ones are not. The selected mailbox gets its usual
//! EXISTS/EXPUNGE/FETCH responses, sent as soon as the change happens instead of after the
//! next command (with SELECTED-DELAYED, expunges still wait for a command).

use std::collections::HashMap;

use tokio::sync::broadcast::{self, error::RecvError};

use super::parse::{Arg, list_match, string, uid_set};
use super::{CmdResult, Session, bad, internal, metadata, special_use};
use crate::store::{Change, Mailbox};

const SUPPORTED: &str = "(MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange MailboxMetadataChange ServerMetadataChange)";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Events {
    /// MessageNew and MessageExpunge (which must be asked for together).
    messages: bool,
    flags: bool,
    names: bool,
    subscriptions: bool,
    metadata: bool,
    server_metadata: bool,
}

#[derive(Debug, Clone)]
enum Filter {
    Inboxes,
    Personal,
    Subscribed,
    Subtree(Vec<String>),
    Mailboxes(Vec<String>),
}

impl Filter {
    fn matches(&self, mailbox: &Mailbox) -> bool {
        match self {
            Filter::Inboxes => mailbox.name == "INBOX",
            Filter::Personal => true,
            Filter::Subscribed => mailbox.subscribed,
            Filter::Subtree(roots) => roots.iter().any(|root| mailbox.name == *root || mailbox.name.starts_with(&format!("{root}/"))),
            Filter::Mailboxes(names) => names.iter().any(|name| list_match(name, &mailbox.name) || (name.eq_ignore_ascii_case("INBOX") && mailbox.name == "INBOX")),
        }
    }
}

/// What was last reported about one mailbox.
struct Known {
    name: String,
    subscribed: bool,
    highest_modseq: i64,
    status: Vec<u8>,
}

pub(super) struct Notify {
    /// Events for the selected mailbox; None leaves it to the usual command-bound updates.
    selected: Option<Events>,
    /// SELECTED-DELAYED: expunges wait for a command.
    delayed: bool,
    /// MessageNew fetch attributes for the selected mailbox.
    fetch: Vec<Arg>,
    filters: Vec<(Filter, Events)>,
    server_metadata: bool,
    known: HashMap<i64, Known>,
    pub(super) changes: broadcast::Receiver<Change>,
    pub(super) metadata: broadcast::Receiver<metadata::Change>,
}

impl Notify {
    /// The events asked for a mailbox other than the selected one (the first matching filter).
    fn events_for(&self, mailbox: &Mailbox) -> Option<Events> {
        self.filters.iter().find(|(filter, _)| filter.matches(mailbox)).map(|(_, events)| *events)
    }

    /// Someone watching subscriptions: a mailbox just unsubscribed no longer matches the filter.
    fn watches_subscriptions(&self) -> bool {
        self.filters.iter().any(|(filter, events)| matches!(filter, Filter::Subscribed) && events.subscriptions)
    }

    /// Whether the selected mailbox is updated as soon as it changes.
    pub(super) fn live_selected(&self) -> bool {
        self.selected.is_some_and(|e| e.messages || e.flags)
    }
}

fn parse_events(arg: &Arg, selected: bool) -> Result<(Events, Vec<Arg>), String> {
    let mut events = Events::default();
    let mut fetch = Vec::new();
    let list = match arg {
        Arg::Atom(atom) if atom.eq_ignore_ascii_case("NONE") => return Ok((events, fetch)),
        Arg::List(list) => list,
        _ => return Err("BAD events are a list or NONE".into()),
    };
    let (mut new, mut expunge) = (false, false);
    let mut items = list.iter().peekable();
    while let Some(item) = items.next() {
        match item.atom_upper().as_deref() {
            Some("MESSAGENEW") => {
                new = true;
                if let Some(Arg::List(attributes)) = items.peek() {
                    if !selected {
                        return Err("BAD fetch attributes are only for the selected mailbox".into());
                    }
                    fetch = attributes.clone();
                    items.next();
                }
            }
            Some("MESSAGEEXPUNGE") => expunge = true,
            Some("FLAGCHANGE") => events.flags = true,
            Some("MAILBOXNAME") => events.names = true,
            Some("SUBSCRIPTIONCHANGE") => events.subscriptions = true,
            Some("MAILBOXMETADATACHANGE") => events.metadata = true,
            Some("SERVERMETADATACHANGE") => events.server_metadata = true,
            _ => return Err(format!("NO [BADEVENT {SUPPORTED}] unsupported event")),
        }
    }
    // RFC 5465 5: MessageNew and MessageExpunge go together, and FlagChange needs them.
    if new != expunge || (events.flags && !new) {
        return Err("BAD MessageNew and MessageExpunge go together, and FlagChange needs them".into());
    }
    events.messages = new;
    Ok((events, fetch))
}

impl Session {
    /// NOTIFY NONE | NOTIFY SET [STATUS] (filter events) ...
    pub(super) async fn cmd_notify(&mut self, args: &[Arg]) -> std::io::Result<CmdResult> {
        match args.first().and_then(Arg::atom_upper).as_deref() {
            Some("NONE") if args.len() == 1 => {
                self.notify = None;
                return Ok(Ok("NOTIFY completed".into()));
            }
            Some("SET") => {}
            _ => return Ok(bad("usage: NOTIFY SET [STATUS] (filter events) ... | NOTIFY NONE")),
        }
        let mut rest = &args[1..];
        let status = rest.first().and_then(Arg::atom_upper).as_deref() == Some("STATUS");
        if status {
            rest = &rest[1..];
        }
        if rest.is_empty() {
            return Ok(bad("at least one event group is required"));
        }
        let (mut selected, mut delayed, mut fetch, mut filters) = (None, false, Vec::new(), Vec::new());
        let mut server_metadata = false;
        for group in rest {
            let Arg::List(group) = group else { return Ok(bad("event groups are lists")) };
            let Some(kind) = group.first().and_then(Arg::atom_upper) else { return Ok(bad("filter required")) };
            let names = |arg: Option<&Arg>| -> Option<Vec<String>> {
                match arg? {
                    Arg::List(names) => names.iter().map(|n| n.text().map(|n| self.decode_name(&n))).collect(),
                    one => Some(vec![self.decode_name(&one.text()?)]),
                }
            };
            let (filter, events_arg) = match kind.as_str() {
                "SELECTED" | "SELECTED-DELAYED" => (None, group.get(1)),
                "INBOXES" => (Some(Filter::Inboxes), group.get(1)),
                "PERSONAL" => (Some(Filter::Personal), group.get(1)),
                "SUBSCRIBED" => (Some(Filter::Subscribed), group.get(1)),
                "SUBTREE" => match names(group.get(1)) {
                    Some(roots) => (Some(Filter::Subtree(roots)), group.get(2)),
                    None => return Ok(bad("SUBTREE needs mailbox names")),
                },
                "MAILBOXES" => match names(group.get(1)) {
                    Some(list) => (Some(Filter::Mailboxes(list)), group.get(2)),
                    None => return Ok(bad("MAILBOXES needs mailbox names")),
                },
                _ => return Ok(Err("NO [BADEVENT] unsupported filter".into())),
            };
            let Some(events_arg) = events_arg else { return Ok(bad("events required")) };
            let (events, attributes) = match parse_events(events_arg, filter.is_none()) {
                Ok(parsed) => parsed,
                Err(err) => return Ok(Err(err)),
            };
            server_metadata |= events.server_metadata;
            match filter {
                None => {
                    selected = Some(events);
                    delayed = kind == "SELECTED-DELAYED";
                    fetch = attributes;
                }
                Some(filter) => filters.push((filter, events)),
            }
        }
        let mut notify = Notify {
            selected,
            delayed,
            fetch,
            filters,
            server_metadata,
            known: HashMap::new(),
            changes: self.app.store.subscribe(),
            metadata: metadata::CHANGES.subscribe(),
        };
        let mailboxes = match self.app.store.list_mailboxes(self.account_id()).await {
            Ok(mailboxes) => mailboxes,
            Err(err) => return Ok(Err(internal(err))),
        };
        let mut out = Vec::new();
        for mailbox in &mailboxes {
            let Some(events) = notify.events_for(mailbox) else { continue };
            let line = if events.messages { self.notify_status(mailbox, events).await } else { Ok(Vec::new()) };
            let line = match line {
                Ok(line) => line,
                Err(err) => return Ok(Err(err)),
            };
            // NOTIFY SET STATUS: where each watched mailbox stands now.
            if status && !self.is_selected(mailbox.id) {
                out.extend_from_slice(&line);
            }
            notify.known.insert(mailbox.id, Known { name: mailbox.name.clone(), subscribed: mailbox.subscribed, highest_modseq: mailbox.highest_modseq, status: line });
        }
        self.send(&out).await?;
        self.notify = Some(notify);
        Ok(Ok("NOTIFY completed".into()))
    }

    fn is_selected(&self, mailbox_id: i64) -> bool {
        self.selected.as_ref().is_some_and(|s| s.mailbox.id == mailbox_id)
    }

    async fn notify_status(&mut self, mailbox: &Mailbox, events: Events) -> Result<Vec<u8>, String> {
        let mut items = vec!["MESSAGES", "UIDNEXT", "UIDVALIDITY"];
        if events.flags {
            items.push("UNSEEN");
            if self.condstore {
                items.push("HIGHESTMODSEQ");
            }
        }
        let items: Vec<Arg> = items.into_iter().map(|i| Arg::Atom(i.into())).collect();
        // Reporting HIGHESTMODSEQ must not switch CONDSTORE on by itself.
        let condstore = self.condstore;
        let line = self.status_line(mailbox, &items).await;
        self.condstore = condstore;
        line
    }

    /// Reports what changed, after a store change (None: possibly anything).
    pub(super) async fn notify_change(&mut self, change: Option<Change>) -> std::io::Result<()> {
        let Some(notify) = &self.notify else { return Ok(()) };
        let selected = self.selected.as_ref().map(|s| (s.mailbox.id, s.mailbox.account_id));
        let (live, delayed, fetch) = (notify.live_selected(), notify.delayed, notify.fetch.clone());
        let account = self.account_id();
        let touches_selected = selected.is_some_and(|(id, owner)| change.as_ref().is_none_or(|c| c.mailbox_id == id && c.account_id == owner));
        if live && touches_selected {
            let added = self.sync_with(!delayed).await?;
            if !fetch.is_empty() && !added.is_empty() {
                let set = uid_set(&added.iter().map(|&u| i64::from(u)).collect::<Vec<_>>());
                let args = [Arg::Atom(set), Arg::List(fetch)];
                // FETCH replies are the client's own business; only the data matters here.
                let _ = self.cmd_fetch(&args, true).await?;
            }
        }
        if change.as_ref().is_some_and(|c| c.account_id != account) {
            return Ok(());
        }
        let mailboxes = match self.app.store.list_mailboxes(account).await {
            Ok(mailboxes) => mailboxes,
            Err(err) => {
                tracing::debug!(err = %internal(err), "NOTIFY could not list mailboxes");
                return Ok(());
            }
        };
        let mut out = Vec::new();
        let mut known = self.notify.as_mut().map(|n| std::mem::take(&mut n.known)).unwrap_or_default();
        for mailbox in &mailboxes {
            let Some(events) = self.notify.as_ref().and_then(|n| n.events_for(mailbox)) else {
                if known.remove(&mailbox.id).is_some_and(|old| old.subscribed && !mailbox.subscribed) && self.notify.as_ref().is_some_and(Notify::watches_subscriptions) {
                    self.list_line(&mut out, special_use(mailbox.role.as_deref()).trim_start(), &mailbox.name, None);
                }
                continue;
            };
            let previous = known.remove(&mailbox.id);
            let flags = format!("{}{}", special_use(mailbox.role.as_deref()), if mailbox.subscribed { " \\Subscribed" } else { "" });
            match &previous {
                None if events.names || (events.subscriptions && mailbox.subscribed) => self.list_line(&mut out, flags.trim_start(), &mailbox.name, None),
                Some(old) if old.name != mailbox.name && events.names => self.list_line(&mut out, flags.trim_start(), &mailbox.name, Some(&old.name)),
                Some(old) if old.subscribed != mailbox.subscribed && events.subscriptions => self.list_line(&mut out, flags.trim_start(), &mailbox.name, None),
                _ => {}
            }
            let mut status = previous.as_ref().map(|p| p.status.clone()).unwrap_or_default();
            let moved = previous.as_ref().is_none_or(|p| p.highest_modseq != mailbox.highest_modseq);
            if events.messages
                && moved
                && let Ok(line) = self.notify_status(mailbox, events).await
            {
                // Unchanged counters are not repeated; the selected mailbox reports itself.
                if line != status && previous.is_some() && !self.is_selected(mailbox.id) {
                    out.extend_from_slice(&line);
                }
                status = line;
            }
            known.insert(mailbox.id, Known { name: mailbox.name.clone(), subscribed: mailbox.subscribed, highest_modseq: mailbox.highest_modseq, status });
        }
        // What is left was deleted (or no longer matches a filter: then it was renamed away).
        let removed: Vec<i64> = known.keys().copied().filter(|id| !mailboxes.iter().any(|m| m.id == *id)).collect();
        let names = self.notify.as_ref().is_some_and(|n| n.filters.iter().any(|(_, e)| e.names));
        for id in removed {
            if let Some(gone) = known.remove(&id)
                && names
            {
                self.list_line(&mut out, "\\NonExistent", &gone.name, None);
            }
        }
        if let Some(notify) = &mut self.notify {
            notify.known = known;
        }
        if out.is_empty() { Ok(()) } else { self.send(&out).await }
    }

    fn list_line(&self, out: &mut Vec<u8>, flags: &str, name: &str, old_name: Option<&str>) {
        out.extend_from_slice(format!("* LIST ({flags}) \"/\" ").as_bytes());
        string(out, self.encode_name(name).as_bytes());
        if let Some(old) = old_name {
            out.extend_from_slice(b" (\"OLDNAME\" (");
            string(out, self.encode_name(old).as_bytes());
            out.extend_from_slice(b"))");
        }
        out.extend_from_slice(b"\r\n");
    }

    /// Reports an entry another session set or removed (by name only, RFC 5465 5.7 / 5.8).
    pub(super) async fn notify_metadata(&mut self, change: metadata::Change) -> std::io::Result<()> {
        let Some(notify) = &self.notify else { return Ok(()) };
        if change.account_id != self.account_id() {
            return Ok(());
        }
        let name = match change.mailbox_id {
            None if notify.server_metadata => String::new(),
            None => return Ok(()),
            Some(id) => {
                let Ok(mailbox) = self.app.store.mailbox(change.account_id, id).await else { return Ok(()) };
                let watched = if self.is_selected(id) { notify.selected.is_some_and(|e| e.metadata) } else { notify.events_for(&mailbox).is_some_and(|e| e.metadata) };
                if !watched {
                    return Ok(());
                }
                self.encode_name(&mailbox.name)
            }
        };
        let mut out = b"* METADATA ".to_vec();
        string(&mut out, name.as_bytes());
        out.extend_from_slice(format!(" {}\r\n", change.entry).as_bytes());
        self.send(&out).await
    }

    /// Waits for the next command, reporting changes while there is none.
    pub(super) async fn await_command(&mut self) -> Result<(), crate::net::ReadError> {
        // Unlike a client that sends commands, this one may only ever listen.
        let mut recheck = tokio::time::interval(crate::auth::RECHECK_INTERVAL);
        recheck.tick().await;
        loop {
            let Some(notify) = &mut self.notify else { return Ok(()) };
            enum Event {
                Ready(Result<(), crate::net::ReadError>),
                Store(Option<Change>),
                Metadata(Option<metadata::Change>),
                Recheck,
            }
            let event = tokio::select! {
                ready = self.conn.wait_readable() => Event::Ready(ready),
                _ = recheck.tick() => Event::Recheck,
                change = notify.changes.recv() => match change {
                    Ok(change) => Event::Store(Some(change)),
                    Err(RecvError::Lagged(_)) => Event::Store(None),
                    Err(RecvError::Closed) => return Err(crate::net::ReadError::Closed),
                },
                change = notify.metadata.recv() => match change {
                    Ok(change) => Event::Metadata(Some(change)),
                    Err(_) => Event::Metadata(None),
                },
            };
            let sent = match event {
                Event::Ready(ready) => return ready,
                Event::Recheck => {
                    if !self.still_signed_in().await {
                        self.line("* BYE the sign-in is no longer valid").await.map_err(crate::net::ReadError::from)?;
                        return Err(crate::net::ReadError::Closed);
                    }
                    Ok(())
                }
                Event::Store(change) => self.notify_change(change).await,
                Event::Metadata(Some(change)) => self.notify_metadata(change).await,
                Event::Metadata(None) => Ok(()),
            };
            sent.map_err(crate::net::ReadError::from)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Arg, parse_events};

    fn atoms(items: &[&str]) -> Arg {
        Arg::List(items.iter().map(|i| Arg::Atom((*i).into())).collect())
    }

    #[test]
    fn event_rules() {
        let (events, _) = parse_events(&atoms(&["MessageNew", "MessageExpunge", "FlagChange"]), false).unwrap();
        assert!(events.messages && events.flags);
        assert!(parse_events(&atoms(&["MessageNew"]), false).is_err());
        assert!(parse_events(&atoms(&["FlagChange"]), false).is_err());
        assert!(parse_events(&atoms(&["AnnotationChange"]), false).unwrap_err().contains("BADEVENT"));
        let with_fetch = Arg::List(vec![Arg::Atom("MessageNew".into()), atoms(&["UID", "FLAGS"]), Arg::Atom("MessageExpunge".into())]);
        assert_eq!(parse_events(&with_fetch, true).unwrap().1.len(), 2);
        assert!(parse_events(&with_fetch, false).is_err());
        assert_eq!(parse_events(&Arg::Atom("NONE".into()), false).unwrap().0, Default::default());
    }
}
