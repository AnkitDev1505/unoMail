// The first draft of a reply or forward: recipients, subject and the quoted message.

import { t, uiLocale } from '../i18n';
import { type Draft, type EmailFull, formatAddress } from './jmapClient';
import { emailHtml, isDecrypted, type ReaderAction } from './Reader';
import { escapeHtml, textToHtml } from './sanitize';

export const EMPTY_DRAFT: Draft = { to: '', cc: '', bcc: '', subject: '', html: '', attachments: [] };



function prefixed(subject: string, prefix: string): string {
  return subject.toLowerCase().startsWith(prefix.toLowerCase()) ? subject : `${prefix} ${subject}`;
}

/** A stored draft, as the composer continues it. */
export function draftFromStored(email: EmailFull, accountId: string): Draft {
  const clean = (cid: string) => cid.replace(/^<|>$/g, '');
  const cids = email.attachments.filter((a) => a.cid).map((a) => clean(a.cid!));
  return {
    ...EMPTY_DRAFT,
    to: (email.to ?? []).map(formatAddress).join(', '),
    cc: (email.cc ?? []).map(formatAddress).join(', '),
    bcc: (email.bcc ?? []).map(formatAddress).join(', '),
    subject: email.subject ?? '',
    html: emailHtml(email, accountId, Object.fromEntries(cids.map((cid) => [cid, `cid:${cid}`]))),
    attachments: email.attachments.map((a) => ({ blobId: a.blobId, name: a.name ?? 'file', type: a.type, size: a.size ?? 0, cid: a.cid ? clean(a.cid) : undefined })),
    from: email.from?.[0],
    inReplyTo: email.inReplyTo ?? undefined,
    references: email.references ?? undefined,
    answer: Boolean(email.inReplyTo?.length),
  };
}

/** Builds the initial draft for a reply or forward of `email`. */
export function draftFor(action: ReaderAction, email: EmailFull, ownAddress: string, accountId: string, suggestedText?: string): Draft {
  const sender = email.replyTo?.length ? email.replyTo : (email.from ?? []);
  // The translation is plain text from our own files; the values are escaped before they go in.
  const attribution = escapeHtml(t('On {{date}}, {{sender}} wrote:', { date: new Date(email.receivedAt).toLocaleString(uiLocale()), sender: (email.from ?? []).map(formatAddress).join(', ') }));
  const quoted = `<p><br></p><p>${attribution}</p><blockquote>${emailHtml(email, accountId)}</blockquote>`;
  const references = [...(email.references ?? []), ...(email.messageId ?? [])];
  // Quoting a decrypted message: the answer stays encrypted unless the user decides otherwise.
  const encrypted = isDecrypted(email) || undefined;
  if (action === 'forward') {
    // Files and embedded pictures go along. Parts of a message encrypted end to end cannot.
    const clean = (cid: string) => cid.replace(/^<|>$/g, '');
    const parts = encrypted ? [] : email.attachments;
    const cids = parts.filter((a) => a.cid).map((a) => clean(a.cid!));
    const html = `<p><br></p><p>${attribution}</p><blockquote>${emailHtml(email, accountId, Object.fromEntries(cids.map((cid) => [cid, `cid:${cid}`])))}</blockquote>`;
    return {
      ...EMPTY_DRAFT,
      subject: prefixed(email.subject, 'Fwd:'),
      html,
      answer: true,
      encrypted,
      attachments: parts.map((a) => ({ blobId: a.blobId, name: a.name ?? 'file', type: a.type, size: a.size ?? 0, cid: a.cid ? clean(a.cid) : undefined })),
    };
  }
  const owned = new Set([ownAddress, ...(email.ownedAddresses ?? []), ...(email.maskedAddresses ?? [])].map((a) => a.toLowerCase()));
  const others = action === 'replyAll' ? [...(email.to ?? []), ...(email.cc ?? [])].filter((a) => !owned.has(a.email.toLowerCase())) : [];
  const mask = email.maskedAddresses?.[0];
  return {
    ...EMPTY_DRAFT,
    // Answer from the identity the message was addressed to, if the user has one for it.
    fromHint: mask ? [mask] : [...(email.to ?? []), ...(email.cc ?? [])].map((a) => a.email),
    from: mask ? { name: null, email: mask } : undefined,
    // Answering one's own message continues with the people it went to.
    to: (sender.every((a) => owned.has(a.email.toLowerCase())) && email.to?.length ? email.to : sender).map(formatAddress).join(', '),
    cc: others.map(formatAddress).join(', '),
    subject: prefixed(email.subject, 'Re:'),
    html: suggestedText ? `<div class="unomail-reply-text">${textToHtml(suggestedText)}</div>${quoted}` : quoted,
    saveOnOpen: Boolean(suggestedText),
    answer: true,
    encrypted,
    inReplyTo: email.messageId ?? undefined,
    references: references.length ? references : undefined,
  };
}
