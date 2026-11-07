# Threat model

What unoMail protects, who can reach it and how, the risks it accepts, and what an operator
should check and do. The controls themselves are summarised in the
[security model](security-model.md); configuration is in `server/src/config.rs`. To report a
vulnerability, see the [security policy](../SECURITY.md).

## 1. Assets

| Asset | Where it lives |
| --- | --- |
| Message contents and attachments | blob store (`<data>/blobs` or S3), optionally sealed (`blob.key`) |
| Message metadata, search index, contacts, calendars | SQLite database `<data>/unomail.db` (plaintext) |
| Account credentials | Argon2id hashes, app-password hashes, TOTP secrets (sealed), passkey public keys |
| Browser sessions | random tokens; only SHA-256 hashes stored; `HttpOnly` `SameSite=Strict` cookies |
| Server secrets | `secret.key` (seals third-party credentials, TOTP and S/MIME keys), `blob.key`, `vapid.key`, DKIM and TLS private keys (database) |
| Outbound reputation | DKIM keys, the server's IP addresses, the delivery queue |
| Backups | directory or bucket set by `UNOMAIL_BACKUP_*` |

## 2. Entry points and trust boundaries

| Entry point | Who reaches it | Boundary enforced by |
| --- | --- | --- |
| SMTP port 25 (MX) | anyone | no authentication offered; recipients must be local (`Relay access denied` otherwise); SPF/DKIM/DMARC/ARC verdicts added by us (skipped only for loopback and `UNOMAIL_TRUSTED_NETWORKS`), forged `Authentication-Results` removed; DNSBL, reputation, greylisting, size and recipient limits; strict CRLF (no SMTP smuggling) |
| SMTP 587/465 (submission) | users | TLS before AUTH; envelope sender and `From` must be the user's own address, alias or identity; per-account hourly limits with automatic blocking; outbound spam/virus scan |
| LMTP (off by default) | front mail server | only private networks or the allow list; relaying refused |
| IMAP 993/143, POP3 995 | users | TLS before credentials (`LOGINDISABLED` in plaintext); per-mailbox rights (ACL); literal size limits before reading |
| ManageSieve 4190 | users | STARTTLS before `AUTHENTICATE`; 1 KiB literals before sign-in, 64 KiB after |
| HTTPS web API and JMAP | users, admins | session cookie + per-session CSRF token on every state change; JMAP objects scoped to the account or shared folders; role checks (super admin, domain admin confined to delegated domains) |
| JMAP WebSocket | users | same authentication; cross-origin upgrades refused (Origin check) |
| Public pages `/lists/...`, `/.well-known/mta-sts.txt` | anyone | unguessable tokens (256-bit random, or 128-bit HMAC for unsubscribe); GET never changes anything |
| Outbound connections (SMTP delivery, image proxy, push services, MTA-STS, BIMI, report POSTs, identity provider) | the server | destinations resolved and refused when private/loopback/link-local (IPv4 and IPv6), connection pinned to the checked address, redirects re-checked, size and time limits |
| Milters, rspamd, clamd | trusted local services | configured by the operator only |
| CLI (`backup`, `restore`, `migrate-blobs`) | operator with shell access | filesystem permissions |

Attacker classes considered: unauthenticated internet clients (SMTP, HTTP, IMAP), malicious
remote mail servers and DNS zones, senders of hostile messages (HTML, MIME, attachments,
S/MIME/OpenPGP structures), authenticated malicious users, compromised accounts, and other tabs
or sites in the user's browser. A compromised server process or operator is **out of scope**:
it can read everything except OpenPGP mail encrypted to keys the server never holds.

## 3. Residual risks and limits

- **Database in plaintext.** Encryption at rest covers message blobs and backups, not the live
  database (subjects, addresses, previews, search index). Use disk encryption for that.
- **Plaintext seen by the server.** Before storage the server (and rspamd, clamd, milters) reads
  every message, including those then encrypted to a user's OpenPGP key. S/MIME private keys
  are held by the server (sealed with `secret.key`).
- **Backscatter by design.** Mailbox-full bounces go to the claimed sender (headers only now).
  TLS-RPT reports go to whatever `rua` the receiving domain publishes, without external
  verification (RFC 8460 defines none); mailing-list confirmation mails go to the address in
  `From`. Volumes are small (one per request or per domain and day).
- **List amplification.** A list open to posts from anyone (`posting = anyone`) with many remote
  members multiplies one message; posts from non-members are held by default.
- **Spoofed list posts.** "Members only" trusts `From`/envelope; forged member addresses pass
  unless DMARC of the member's domain rejects them.
- **TLS-RPT/DMARC report and push verification** requests go to addresses chosen by remote
  domains or users (public addresses only, bounded in number).
- **No coverage-guided fuzzing** yet (cargo-fuzz needs a nightly toolchain); the robustness tests
  are random, not coverage-driven. `cargo deny` is not installed here; licences and duplicate
  crates were not checked.
- **Administrators** can reset a user's password and second factors (audited) and thereby
  reach their mail; there is no separation from the operator.
- **Multi-node** deployments are not supported; one compromised host holds everything.
- **Unsafe content is recognised by rules, not by a scanner.** Link, sender-name and attachment
  warnings in the web client and the server's refusal of executable attachments work on names
  and addresses. Archives other than ZIP (7z, RAR, ...), password-protected or nested archives,
  and documents carrying exploits or macros are only caught by a virus scanner: keep ClamAV
  (or Rspamd's antivirus module) enabled. The warnings appear in this web client only; IMAP
  and POP3 clients get the messages as they are. A look-alike domain written in plain ASCII
  (`paypa1.com`) is not detected unless the link text names a different domain, or the domain
  is on the downloaded phishing list (which, like any blocklist, lags behind new sites).

## 4. Production checklist

- Set `UNOMAIL_HOSTNAME`, a real certificate (ACME or uploaded) and keep `UNOMAIL_COOKIE_SECURE`
  and `UNOMAIL_HTTP_REDIRECT` at their defaults (true).
- Never set `UNOMAIL_ALLOW_PRIVATE_DESTINATIONS` outside tests.
- Make sure port 25 sees the real client addresses (no NAT or userland proxy in front, or a
  warning appears in the log); list real relays only in `UNOMAIL_TRUSTED_NETWORKS`.
- Keep *Refuse executable attachments* on, and the bundled rspamd and clamd (or milters) running; *Accept mail when the filter is down* (Server settings) and
  `UNOMAIL_MILTER_FAIL_OPEN` stay off.
- Expose only the mail and web ports; LMTP stays off unless a front server needs it, and then
  only on a private network.
- Back up `secret.key`, `blob.key` and `vapid.key` separately from the data backups.
- Run `./audit.sh` before releases (and weekly in CI), and `cargo test`, `pnpm test` and the
  Playwright suite.
- Encrypt the disk holding `/data`.

## 5. Incident response

- **Compromised account:** disable it or reset its password (signs out every session, ends
  open IMAP/POP3/SMTP connections within a minute, revokes its app passwords and cancels
  scheduled messages), reset its second factors (also revokes app passwords, ends sessions and
  cancels scheduled messages), review the audit log, the passkeys, sender identities, Sieve
  redirects and sent mail.
- **Spam outbreak:** the account is blocked automatically on exceeding its hourly limit; check
  the queue page, hold or delete queued messages, review the outbound log.
- **Exposed secret:** rotate DKIM keys (new selector), replace the TLS certificate, and for
  `secret.key` re-enter the third-party credentials it sealed (identity SMTP passwords, LDAP,
  OIDC secret, webhook secrets) and ask users to set up TOTP and S/MIME again.
- **Data breach:** sessions can be revoked globally by deleting rows of the `sessions` table;
  notify affected users as the law requires.
