-- IMAP METADATA (RFC 5464): annotations on mailboxes and on the server. Private entries belong
-- to the account that set them; shared ones are stored under the mailbox owner (or, for server
-- entries, under the account itself). A NULL mailbox is the server.
CREATE TABLE imap_metadata (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox_id  INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,                   -- lowercase, starting with /private/ or /shared/
    value       BLOB NOT NULL
) STRICT;

CREATE UNIQUE INDEX imap_metadata_entry ON imap_metadata (account_id, COALESCE(mailbox_id, 0), name);
CREATE INDEX imap_metadata_mailbox ON imap_metadata (mailbox_id);
