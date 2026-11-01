import { describe, expect, it } from 'vitest';
import { formatAddress, parseRecipients } from './jmapClient';

describe('recipient fields', () => {
  it('keep a name with a comma in one piece', () => {
    const smith = { name: 'Smith, John', email: 'j@x.org' };
    const field = [smith, { name: null, email: 'a@b.org' }, { name: 'Ann "A" Lee', email: 'ann@b.org' }].map(formatAddress).join(', ');
    expect(field).toBe('"Smith, John" <j@x.org>, a@b.org, "Ann \\"A\\" Lee" <ann@b.org>');
    expect(parseRecipients(field)).toEqual([smith, { name: null, email: 'a@b.org' }, { name: 'Ann "A" Lee', email: 'ann@b.org' }]);
  });

  it('split on both separators', () => {
    expect(parseRecipients('a@b.org; Bob <c@d.org>,').map((a) => a.email)).toEqual(['a@b.org', 'c@d.org']);
  });
});