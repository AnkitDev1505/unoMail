//! A list of domains known to host phishing pages, downloaded from a public feed (by default
//! Phishing Army, <https://phishing.army/>) and refreshed in the background.
//!
//! The list serves two purposes: the built-in filter scores incoming mail that links to a
//! listed domain, and the web client marks such links and warns before they are opened. The
//! client sends the hosts of the links it shows to this server, never to the feed.
//!
//! The last good download is kept in the data directory, so a restart does not need the feed,
//! and a failed or empty download never replaces it.

use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use serde::Serialize;

use crate::{app::App, util::now};

/// The feed used unless the administrator chooses another.
pub const DEFAULT_URL: &str = "https://phishing.army/download/phishing-army-domains.txt";
/// Largest download accepted (the feed is about 3 MB).
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Most domains kept (the feed has about 150 000).
const MAX_ENTRIES: usize = 3_000_000;
/// How often the loop looks at whether a download is due (and at changed settings).
const TICK: Duration = Duration::from_secs(5 * 60);
/// Wait after a failed download before the next attempt.
const RETRY_SECS: i64 = 3600;
const CACHE_FILE: &str = "phishing-list.txt";

/// What the administrator sees about the list.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    /// Domains in the list in use.
    pub entries: usize,
    /// When the list in use was downloaded (Unix time), 0 when none is loaded.
    pub updated_at: i64,
    /// Address the list in use came from.
    pub source: String,
    /// Last attempt to download, successful or not.
    pub checked_at: i64,
    /// Why the last attempt failed, if it did.
    pub error: Option<String>,
}

#[derive(Default)]
pub struct PhishingList {
    domains: ArcSwap<HashSet<Box<str>>>,
    status: parking_lot::Mutex<Status>,
    /// Wakes the loop for a download now (the administrator asked, or the address changed).
    wake: tokio::sync::Notify,
}

impl PhishingList {
    pub fn status(&self) -> Status {
        self.status.lock().clone()
    }

    /// Asks the background loop to download the list now.
    pub fn refresh_now(&self) {
        self.wake.notify_one();
    }

    /// Puts a list in use as if it had been downloaded from `source` (for tests).
    pub fn replace(&self, text: &str, source: &str) -> Result<(), String> {
        self.install(parse(text)?, source, now());
        Ok(())
    }

    fn install(&self, domains: HashSet<Box<str>>, source: &str, updated_at: i64) {
        let mut status = self.status.lock();
        status.entries = domains.len();
        status.updated_at = updated_at;
        status.source = source.to_owned();
        status.error = None;
        self.domains.store(Arc::new(domains));
    }

    /// The listed domain that `host` is or belongs to, unless the administrator exempted it.
    /// Matches the host and each parent domain with at least two labels, so a listed
    /// `evil.example` also catches `login.evil.example`.
    pub fn matching(&self, host: &str, allowed: &[String]) -> Option<String> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let host = host.strip_prefix("www.").unwrap_or(&host);
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let domains = self.domains.load();
        if domains.is_empty() {
            return None;
        }
        let candidates = || std::iter::successors(Some(host), |h| h.split_once('.').map(|(_, rest)| rest)).filter(|h| h.contains('.'));
        if candidates().any(|candidate| allowed.iter().any(|a| a == candidate)) {
            return None;
        }
        candidates().find(|candidate| domains.contains(*candidate)).map(str::to_owned)
    }
}

/// Reads one line of a list in any of the usual formats: a bare domain, a hosts file line
/// (`0.0.0.0 domain`), an Adblock rule (`||domain^`) or a wildcard (`*.domain`).
fn parse_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['#', '!', '[', ';']) {
        return None;
    }
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    let token = if first.parse::<std::net::IpAddr>().is_ok() { tokens.next()? } else { first };
    let token = token.trim_start_matches("||").trim_start_matches("*.").trim_end_matches('^').trim_end_matches('.').to_lowercase();
    let token = token.strip_prefix("www.").unwrap_or(&token);
    if token.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') {
        // The fast path for the usual case: already in normal form.
        return crate::util::is_valid_domain(token).then(|| token.to_owned());
    }
    crate::util::normalize_domain(token).map(|d| d.to_ascii_lowercase())
}

/// The domains of a downloaded list; an error when it holds none (a broken download).
pub fn parse(text: &str) -> Result<HashSet<Box<str>>, String> {
    let domains: HashSet<Box<str>> = text.lines().filter_map(parse_line).take(MAX_ENTRIES).map(String::into_boxed_str).collect();
    if domains.is_empty() {
        return Err("the downloaded list contains no domains".into());
    }
    Ok(domains)
}

fn cache_path(app: &App) -> PathBuf {
    app.cfg.data_dir.join(CACHE_FILE)
}

/// The cached list: (source address, download time, domains).
fn read_cache(app: &App) -> Option<(String, i64, HashSet<Box<str>>)> {
    let text = std::fs::read_to_string(cache_path(app)).ok()?;
    let mut lines = text.lines();
    let source = lines.next()?.strip_prefix("# source: ")?.to_owned();
    let updated_at = lines.next()?.strip_prefix("# updated: ")?.parse().ok()?;
    let domains = parse(&text).ok()?;
    Some((source, updated_at, domains))
}

fn write_cache(app: &App, source: &str, updated_at: i64, domains: &HashSet<Box<str>>) -> std::io::Result<()> {
    let mut text = format!("# source: {source}\n# updated: {updated_at}\n");
    for domain in domains {
        text.push_str(domain);
        text.push('\n');
    }
    let path = cache_path(app);
    let partial = path.with_extension("txt.partial");
    std::fs::write(&partial, text)?;
    std::fs::rename(partial, path)
}

async fn download(url: &str) -> anyhow::Result<HashSet<Box<str>>> {
    // Feeds are often served through a redirect to a mirror or CDN.
    let client = crate::outbound::builder().timeout(Duration::from_secs(120)).redirect(reqwest::redirect::Policy::limited(5)).build()?;
    let mut response = client.get(url).header("Accept", "text/plain").send().await?.error_for_status()?;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(body.len() + chunk.len() <= MAX_BYTES, "the list is larger than {} MB", MAX_BYTES / 1024 / 1024);
        body.extend_from_slice(&chunk);
    }
    parse(&String::from_utf8_lossy(&body)).map_err(anyhow::Error::msg)
}

/// Keeps the list loaded and fresh while it is switched on; empties it when switched off.
pub async fn run(app: Arc<App>) {
    let list = &app.phishing;
    let mut cached = read_cache(&app);
    loop {
        let rt = app.rt();
        if !rt.phishing_list_enabled {
            let loaded = list.status.lock().entries > 0;
            if loaded {
                list.domains.store(Arc::default());
                *list.status.lock() = Status::default();
            }
        } else {
            let url = rt.phishing_list_url.clone();
            // The list kept on disk, at start or after the list was switched on again.
            let empty = list.status.lock().entries == 0;
            if let Some((source, updated_at, domains)) = cached.take()
                && source == url
                && empty
            {
                list.install(domains, &source, updated_at);
            }
            let status = list.status();
            let stale = status.source != url || now() - status.updated_at >= rt.phishing_list_refresh_hours * 3600;
            let may_try = status.error.is_none() || now() - status.checked_at >= RETRY_SECS.min(rt.phishing_list_refresh_hours * 3600);
            if stale && may_try {
                fetch(&app, &url).await;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(TICK) => {}
            () = list.wake.notified() => {
                // Asked for: download even if the list is fresh.
                let rt = app.rt();
                if rt.phishing_list_enabled {
                    fetch(&app, &rt.phishing_list_url).await;
                }
            }
        }
    }
}

/// Downloads the list from `url` and puts it in use; a failure keeps the previous one.
pub async fn fetch(app: &App, url: &str) {
    let list = &app.phishing;
    let started = now();
    {
        // While it runs: checked, neither updated nor failed (the panel waits for either).
        let mut status = list.status.lock();
        status.checked_at = started;
        status.error = None;
    }
    match download(url).await {
        Ok(domains) => {
            tracing::info!(entries = domains.len(), url, "phishing domain list updated");
            if let Err(err) = write_cache(app, url, started, &domains) {
                tracing::warn!(error = %err, "the phishing domain list could not be saved");
            }
            list.install(domains, url, started);
        }
        Err(err) => {
            tracing::warn!(error = %err, url, "the phishing domain list could not be downloaded; the previous one stays in use");
            list.status.lock().error = Some(crate::util::sanitize_line(&err.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(domains: &[&str]) -> PhishingList {
        let list = PhishingList::default();
        list.install(domains.iter().map(|d| Box::<str>::from(*d)).collect(), DEFAULT_URL, 1);
        list
    }

    #[test]
    fn every_usual_format_is_read() {
        let text = "# Phishing Army\n\nevil.example\n0.0.0.0 hosts.example\n||adblock.example^\n*.wild.example\nWWW.Upper.Example\n! comment\nnot a domain\n127.0.0.1 localhost\nb\u{fc}cher.example\n";
        let mut domains: Vec<String> = parse(text).unwrap().into_iter().map(String::from).collect();
        domains.sort();
        assert_eq!(domains, ["adblock.example", "evil.example", "hosts.example", "upper.example", "wild.example", "xn--bcher-kva.example"]);
        assert!(parse("# only comments\n\n").is_err(), "an empty download never replaces a list");
    }

    #[test]
    fn hosts_match_their_listed_domain() {
        let list = list(&["evil.example", "login.shared.example"]);
        assert_eq!(list.matching("evil.example", &[]).as_deref(), Some("evil.example"));
        assert_eq!(list.matching("Secure.Login.EVIL.example.", &[]).as_deref(), Some("evil.example"));
        assert_eq!(list.matching("www.evil.example", &[]).as_deref(), Some("evil.example"));
        assert_eq!(list.matching("a.login.shared.example", &[]).as_deref(), Some("login.shared.example"));
        assert_eq!(list.matching("shared.example", &[]), None, "a listed subdomain does not condemn its parent");
        assert_eq!(list.matching("notevil.example", &[]), None);
        assert_eq!(list.matching("example", &[]), None);
        assert_eq!(list.matching("192.0.2.1", &[]), None);
        // The administrator's exceptions win, for the domain and everything below it.
        let allowed = vec!["evil.example".to_owned()];
        assert_eq!(list.matching("login.evil.example", &allowed), None);
        assert_eq!(PhishingList::default().matching("evil.example", &[]), None, "no list loaded");
    }
}
