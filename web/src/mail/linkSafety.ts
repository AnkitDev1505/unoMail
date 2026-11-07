// What the server tells the client about links in messages: which tracking parameters to
// remove (the administrator's choice), and which hosts belong to known phishing domains. The
// hosts are checked against the list the server downloaded; they never leave this server.

import { useEffect, useState } from 'react';
import { get, post } from '../lib/api';
import type { CleanRules } from './cleanUrl';

export interface LinkSafety {
  phishing_warnings: boolean;
  clean_urls: CleanRules | null;
}

let loaded: LinkSafety | null = null;
let loading: Promise<LinkSafety> | null = null;

/** The rules once they are known (for code that cannot wait, like quoting a reply). */
export function currentLinkSafety(): LinkSafety | null {
  return loaded;
}

export function loadLinkSafety(): Promise<LinkSafety> {
  loading ??= get<LinkSafety>('/api/me/link-safety')
    .then((value) => (loaded = value))
    .catch(() => {
      // Without an answer links are shown as they are; a later message asks again.
      loading = null;
      return { phishing_warnings: false, clean_urls: null };
    });
  return loading;
}

export function useLinkSafety(): LinkSafety | null {
  const [value, setValue] = useState(loaded);
  useEffect(() => {
    if (value) return;
    let cancelled = false;
    void loadLinkSafety().then((result) => !cancelled && setValue(result));
    return () => {
      cancelled = true;
    };
  }, [value]);
  return value;
}

/** Answers already received: host to the listed domain, or null when it is not listed. */
const answers = new Map<string, string | null>();

/** The hosts among `hosts` that belong to a known phishing domain, mapped to that domain. */
export async function listedHosts(hosts: string[]): Promise<Record<string, string>> {
  const unknown = [...new Set(hosts.map((host) => host.toLowerCase()))].filter((host) => !answers.has(host)).slice(0, 1000);
  if (unknown.length) {
    const { listed } = await post<{ listed: Record<string, string> }>('/api/me/link-check', { hosts: unknown });
    // Answers are kept for this page's lifetime; the list changes only every few hours.
    if (answers.size > 20_000) answers.clear();
    for (const host of unknown) answers.set(host, listed[host] ?? null);
  }
  return Object.fromEntries(hosts.flatMap((host) => {
    const domain = answers.get(host.toLowerCase());
    return domain ? [[host.toLowerCase(), domain]] : [];
  }));
}
