/** Small DOM helpers. No crypto and no claims live here. */

type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (k === 'text') node.textContent = String(v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(c);
  return node;
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A labelled byte block. `spans` lets a panel colour named ranges. */
export interface ByteSpan {
  readonly from: number;
  readonly to: number;
  readonly cls: string;
}

export function byteBlock(
  label: string,
  bytes: Uint8Array,
  spans: readonly ByteSpan[] = []
): HTMLElement {
  const wrap = el('div');
  wrap.append(el('span', { class: 'bytes-label', text: label }));
  const box = el('div', { class: 'bytes' });
  for (let i = 0; i < bytes.length; i++) {
    const span = spans.find((s) => i >= s.from && i < s.to);
    const hex = bytes[i].toString(16).padStart(2, '0');
    if (span) box.append(el('span', { class: span.cls, text: hex }));
    else box.append(document.createTextNode(hex));
    box.append(document.createTextNode(i % 4 === 3 ? '  ' : ' '));
  }
  if (bytes.length === 0) box.append(document.createTextNode('(empty)'));
  wrap.append(box);
  return wrap;
}

/** A verdict chip: icon AND text AND colour, never colour alone. */
export type VerdictTone = 'pass' | 'fail' | 'alarm' | 'neutral';

const TONE_ICON: Record<VerdictTone, string> = {
  pass: '✓',
  fail: '✗',
  alarm: '⚠',
  neutral: '○',
};

export function verdict(tone: VerdictTone, text: string, attrs: Attrs = {}): HTMLElement {
  return el('span', { class: `verdict verdict-${tone}`, 'data-verdict': tone, ...attrs }, [
    el('i', { class: 'verdict-icon', 'aria-hidden': 'true', text: TONE_ICON[tone] }),
    el('span', { text }),
  ]);
}

export function note(tone: 'ok' | 'alarm' | 'bad' | 'neutral' | 'accent', children: (Node | string)[]): HTMLElement {
  return el('div', { class: `note note-${tone}` }, children);
}

export function card(children: (Node | string)[], attrs: Attrs = {}): HTMLElement {
  return el('div', { class: 'card', ...attrs }, children);
}

export function field(labelText: string, control: HTMLElement): HTMLElement {
  const id = control.id || `f-${Math.random().toString(36).slice(2, 9)}`;
  control.id = id;
  return el('div', { class: 'field' }, [el('label', { for: id, text: labelText }), control]);
}

/** A live region for async output (WCAG 4.1.3). */
export function statusRegion(id: string): HTMLElement {
  return el('div', { id, role: 'status', 'aria-live': 'polite' });
}

/** A scrollable region with a keyboard route and a name (WCAG 2.1.1). */
export function scroller(label: string, children: (Node | string)[], cls = 'table-wrap'): HTMLElement {
  return el('div', { class: cls, role: 'region', tabindex: '0', 'aria-label': label }, children);
}

export function details(summaryText: string, children: (Node | string)[]): HTMLElement {
  return el('details', {}, [el('summary', { text: summaryText }), ...children]);
}

export function dlRow(term: string, value: string, attrs: Attrs = {}): HTMLElement {
  return el('div', { class: 'count-row', ...attrs }, [
    el('dt', { text: term }),
    el('dd', { text: value }),
  ]);
}
