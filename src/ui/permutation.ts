import { clear, el } from './dom';

export function drawPermutation(permWrap: HTMLElement, s: Uint8Array, marks: { i?: number; j?: number; out?: number }): void {
  clear(permWrap);
  const grid = el('div', { class: 'perm' });
  for (let idx = 0; idx < 256; idx++) {
    const cls =
      idx === marks.i ? 'perm-cell at-i stepped'
      : idx === marks.j ? 'perm-cell at-j stepped'
      : idx === marks.out ? 'perm-cell at-out stepped'
      : 'perm-cell';
    grid.append(el('span', {
      class: cls,
      title: `S[${idx}] = ${s[idx]}`,
      text: s[idx].toString(16).padStart(2, '0'),
    }));
  }
  permWrap.append(grid);
}

