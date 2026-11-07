// Removing tracking parameters from links, after clean-url (https://github.com/laststance/clean-url):
// query parameters such as utm_source, fbclid or gclid say nothing about the page and only tell
// the sender who clicked. The administrator decides which parameters go (Server settings).
//
// Only the parameters themselves are cut out: everything else in the address is kept exactly
// as written, encoding included, so a cleaned link still opens the same page.

export interface CleanRules {
  /** Parameter names removed, lower case. */
  params: string[];
  /** Parameters starting with one of these are removed too (e.g. `utm_`). */
  prefixes: string[];
  /** Links to these domains, or below them, are left alone. */
  exempt_domains: string[];
}

function decodeOr(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

/** Whether a parameter named `key` (as written in the address) is a tracking one. */
function tracking(key: string, rules: CleanRules): boolean {
  const name = decodeOr(key).trim().toLowerCase();
  return rules.params.includes(name) || rules.prefixes.some((prefix) => prefix && name.startsWith(prefix));
}

/** `query` (without its `?` or `#`) without tracking parameters, and how many went. */
function cleanQuery(query: string, rules: CleanRules): { kept: string; removed: number } {
  const parts = query.split('&');
  const kept = parts.filter((part) => !part || !tracking(part.split('=', 1)[0], rules));
  return { kept: kept.filter(Boolean).join('&'), removed: parts.length - kept.length };
}

/**
 * Fragments that carry parameters (`#utm_source=x&id=1`) are cleaned like a query. Anchors
 * (`#section`), routes of web applications (`#/inbox`, `#view?id=1`) and anything else stay.
 */
function cleanFragment(fragment: string, rules: CleanRules): { kept: string; removed: number } {
  const decoded = decodeOr(fragment);
  if (!fragment || decoded.startsWith('/') || !decoded.includes('=') || /^[\w-]+\?/.test(decoded)) return { kept: fragment, removed: 0 };
  return cleanQuery(fragment, rules);
}

function exempt(host: string, rules: CleanRules): boolean {
  const name = host.toLowerCase().replace(/\.$/, '');
  return rules.exempt_domains.some((domain) => name === domain || name.endsWith(`.${domain}`));
}

export interface Cleaned {
  url: string;
  /** Number of tracking parameters removed. */
  removed: number;
}

/** `href` without its tracking parameters; unchanged when it has none or is not a web address. */
export function cleanUrl(href: string, rules: CleanRules): Cleaned {
  const unchanged = { url: href, removed: 0 };
  let parsed: URL;
  try {
    parsed = new URL(href.trim());
  } catch {
    return unchanged;
  }
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || exempt(parsed.hostname, rules)) return unchanged;
  const text = href.trim();
  const hashAt = text.indexOf('#');
  const beforeHash = hashAt < 0 ? text : text.slice(0, hashAt);
  const queryAt = beforeHash.indexOf('?');
  const base = queryAt < 0 ? beforeHash : beforeHash.slice(0, queryAt);
  const query = queryAt < 0 ? null : cleanQuery(beforeHash.slice(queryAt + 1), rules);
  const fragment = hashAt < 0 ? null : cleanFragment(text.slice(hashAt + 1), rules);
  const removed = (query?.removed ?? 0) + (fragment?.removed ?? 0);
  if (!removed) return unchanged;
  const url = base + (query?.kept ? `?${query.kept}` : '') + (fragment?.kept ? `#${fragment.kept}` : '');
  return { url, removed };
}
