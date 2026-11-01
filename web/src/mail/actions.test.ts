import { describe, expect, it } from 'vitest';
import { destinationOf, inFolderOf, placeOf } from './actions';

const roles = { inbox: 'in', sent: 'out', trash: 'bin', archive: 'old', junk: 'spam' };
const message = (id: string, folder: string) => ({ id, mailboxIds: { [folder]: true } });

describe('folder actions on a conversation', () => {
  const conversation = [message('a', 'in'), message('b', 'out'), message('c', 'bin'), message('d', 'bin')];

  it('deleting forever from Trash touches only what is in Trash', () => {
    const target = conversation[2];
    expect(destinationOf('trash', placeOf(roles, [target]), roles)).toBe('destroy');
    expect(inFolderOf(conversation, target).map((m) => m.id)).toEqual(['c', 'd']);
  });

  it('archiving from the inbox leaves sent mail where it is', () => {
    expect(inFolderOf(conversation, conversation[0]).map((m) => m.id)).toEqual(['a']);
  });
});
