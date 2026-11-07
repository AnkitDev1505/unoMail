import { describe, expect, it } from 'vitest';
import { type CleanRules, cleanUrl } from './cleanUrl';

const rules: CleanRules = { params: ['fbclid', 'gclid', 'mc_eid', 'ref', 'linkcode'], prefixes: ['utm_'], exempt_domains: ['keep.example'] };
const clean = (href: string) => cleanUrl(href, rules).url;

describe('cleanUrl', () => {
  it('removes tracking parameters and keeps the rest exactly as written', () => {
    expect(clean('https://shop.example/item?id=42&utm_source=news&utm_medium=email&fbclid=abc')).toBe('https://shop.example/item?id=42');
    expect(clean('https://shop.example/?UTM_Campaign=x&q=a+b%20c&GCLID=1')).toBe('https://shop.example/?q=a+b%20c');
    expect(clean('https://shop.example/dp/1?linkCode=ll1&tag=x')).toBe('https://shop.example/dp/1?tag=x');
    expect(cleanUrl('https://shop.example/?utm_source=a&fbclid=b', rules)).toEqual({ url: 'https://shop.example/', removed: 2 });
  });

  it('leaves addresses without tracking alone', () => {
    for (const href of ['https://shop.example/a?id=1#top', 'https://shop.example/', 'mailto:a@b.example?subject=utm_source', 'not a url', 'https://user:pw@shop.example/?x=1']) {
      expect(cleanUrl(href, rules)).toEqual({ url: href, removed: 0 });
    }
  });

  it('keeps the rest of the address, credentials and port included', () => {
    expect(clean('https://user@shop.example:8443/p?utm_term=x#frag')).toBe('https://user@shop.example:8443/p#frag');
  });

  it('cleans parameter fragments but not anchors or app routes', () => {
    expect(clean('https://news.example/a#utm_source=feed&utm_medium=rss')).toBe('https://news.example/a');
    expect(clean('https://news.example/a?x=1#ref=home&page=2')).toBe('https://news.example/a?x=1#page=2');
    expect(clean('https://app.example/#/inbox?ref=mail')).toBe('https://app.example/#/inbox?ref=mail');
    expect(clean('https://app.example/#view?ref=mail')).toBe('https://app.example/#view?ref=mail');
  });

  it('honours exempt domains and their subdomains', () => {
    expect(clean('https://keep.example/?utm_source=x')).toBe('https://keep.example/?utm_source=x');
    expect(clean('https://www.keep.example/?ref=x')).toBe('https://www.keep.example/?ref=x');
    expect(clean('https://notkeep.example/?ref=x')).toBe('https://notkeep.example/');
  });

  it('removes nothing when switched to an empty list', () => {
    expect(cleanUrl('https://shop.example/?utm_source=x', { params: [], prefixes: [], exempt_domains: [] }).removed).toBe(0);
  });
});
