/**
 * WEP Crack — mount point.
 *
 * Five panels, rendered lazily on first activation: a tab that has never been
 * clicked is a panel that is not in the DOM at all. That is asserted in the a11y
 * gate's `boot()`, because an EMPTY region is exactly what a scan reports as
 * perfectly accessible — so "hidden and empty" is this lab's tell that a
 * renderer threw.
 *
 * No theme logic here. Dark is pinned by a literal in index.html before first
 * paint and there is no toggle.
 */

import './style.css';
import { NEGATIVE_CLAIM, renderPanel4 } from './ui/panel4Forge';
import { renderPanel1 } from './ui/panel1Rc4';
import { renderPanel2 } from './ui/panel2Wep';
import { renderPanel3 } from './ui/panel3Collision';
import { renderPanel5 } from './ui/panel5Ptw';
import { el } from './ui/dom';

interface PanelSpec {
  readonly id: string;
  readonly num: string;
  readonly tab: string;
  readonly lesson: string;
  readonly render: (host: HTMLElement) => void;
}

const PANELS: readonly PanelSpec[] = [
  { id: 'rc4', num: '1', tab: 'RC4 itself', lesson: 'Inspect the cipher', render: renderPanel1 },
  { id: 'wep', num: '2', tab: 'Wrap it in WEP', lesson: 'Build a protected body', render: renderPanel2 },
  { id: 'collision', num: '3', tab: 'Keystream reuse', lesson: 'Find a repeated IV', render: renderPanel3 },
  { id: 'forge', num: '4', tab: 'Forge a packet', lesson: 'Break authentication', render: renderPanel4 },
  { id: 'ptw', num: '5', tab: 'Recover the key', lesson: 'Run a real PTW attack', render: renderPanel5 },
];

function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('p', { class: 'eyebrow', text: 'INTERACTIVE CRYPTOGRAPHY LAB' }),
      el('h1', { class: 'cl-hero-title' }, ['WEP ', el('span', { text: 'Crack' })]),
      el('p', { class: 'cl-hero-sub', text: 'RC4 · WEP integrity failures · PTW key recovery' }),
      el('p', { class: 'hero-statement', text: 'A working cipher.\nA broken system.' }),
      el('p', {
        class: 'cl-hero-desc',
        text:
          'See WEP come apart, one experiment at a time. Inspect real cipher state, ' +
          'alter a message without the key, and try to recover a secret from public traffic.',
      }),
      el('div', { class: 'hero-actions' }, [
        el('a', { class: 'btn btn-primary', href: '#rc4', 'data-exhibit': 'rc4', text: 'Start the walkthrough →' }),
        el('a', { class: 'btn', href: '#forge', 'data-exhibit': 'forge', text: 'See the forgery ↗' }),
      ]),
      el('p', { class: 'hero-meta', text: 'Five hands-on exhibits · No setup · Runs locally in your browser' }),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('div', { class: 'packet-heading' }, [
        el('span', { class: 'cl-hero-why-label', text: 'INSIDE A WEP PROTECTED BODY' }),
        el('span', { class: 'packet-tag', text: '24-bit IV' }),
      ]),
      el('div', { class: 'packet-diagram' }, [
        el('div', { class: 'packet-part packet-public' }, [el('span', { text: 'PUBLIC' }), el('strong', { text: 'IV' }), el('small', { text: '3 bytes' })]),
        el('div', { class: 'packet-part packet-id' }, [el('span', { text: 'PUBLIC' }), el('strong', { text: 'Key ID' }), el('small', { text: '1 byte' })]),
        el('div', { class: 'packet-part packet-encrypted' }, [el('span', { text: 'ENCRYPTED WITH RC4' }), el('strong', { text: 'Payload + ICV' }), el('small', { text: 'message + 4-byte checksum' })]),
      ]),
      el('div', { class: 'failure-list' }, [
        ...[
          ['01', 'Repeat an IV', 'Repeat the keystream'],
          ['02', 'Repair a checksum', 'Change an accepted message'],
          ['03', 'Collect public IVs', 'Search for the shared key'],
        ].map(([num, title, consequence]) => el('div', { class: 'failure-row' }, [
          el('span', { class: 'failure-num', text: num }),
          el('strong', { text: title }),
          el('span', { class: 'failure-effect', text: consequence }),
        ])),
      ]),
      el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      el('p', {
        class: 'cl-hero-why-text',
        text:
          'A cipher can match every test vector and still sit inside a broken protocol. ' +
          'WEP’s failures live in the system around the cipher: its IVs, its checksum, ' +
          'and its per-packet keys.',
      }),
    ]),
  ]);
}

function scopeNote(): HTMLElement {
  return el('details', { class: 'scope-note' }, [
    el('summary', { id: 'scope-heading', text: 'About this lab: scope, assumptions, and what it proves' }),
    el('p', {
      text:
        'A teaching exhibit, not production crypto. The cryptography is real: RC4 and ' +
        'CRC-32 are hand-rolled here and checked against published vectors, the WEP ' +
        'construction follows the standard’s serialisation, the forgery is accepted by ' +
        'the same receiver that verifies ordinary packets, and the key recovery is an ' +
        'actual PTW implementation.',
    }),
    el('p', { text: 'What is modelled, and what is not:' }),
    el('ul', {}, [
      el('li', {
        text:
          'Modelled: the WEP protected body — the clear IV and Key ID field, and the ' +
          'encrypted payload and ICV.',
      }),
      el('li', {
        text:
          'Not modelled: the 802.11 MAC header, the outer frame check sequence, radio ' +
          'metadata, retransmissions and physical capture. This is not a complete on-air ' +
          'frame and not a capture-file format.',
      }),
      el('li', {
        text:
          'All traffic is generated locally by this page. There is no radio capture, no ' +
          'monitor mode, no injection and no capture-file import — deliberately, and not ' +
          'as an unfinished feature.',
      }),
      el('li', {
        text:
          'Synthetic traffic reproduces the cryptographic construction and the attack’s ' +
          'assumptions. Its packet mix, IV policy and known-plaintext availability are ' +
          'chosen by this lab, so its statistics are not those of arbitrary real traffic.',
      }),
    ]),
    el('p', { text: 'What it does NOT prove:' }),
    el('ul', {}, [
      el('li', {
        text:
          'Not that RC4 is sound. Passing test vectors shows agreement with a ' +
          'specification; RC4 has weaknesses beyond anything WEP does with it, and RFC ' +
          '7465 prohibits it in TLS.',
      }),
      el('li', {
        text:
          'Not that a patched WEP would be safe. There is no "secure WEP" setting — the ' +
          'separate obligations are sound key and nonce handling, cryptographic ' +
          'authentication, and a sound primitive and construction.',
      }),
      el('li', { text: `Not that a passing integrity check means anything about authenticity. ${NEGATIVE_CLAIM}` }),
      el('li', {
        text:
          'WPA2 and WPA3 are outside this experiment entirely, as are TKIP, chopchop and ' +
          'fragmentation attacks. FMS and KoreK are named here as possible future ' +
          'extensions and are NOT implemented.',
      }),
    ]),
  ]);
}

function footer(): HTMLElement {
  return el('footer', { class: 'scripture-footer' }, [
    el('p', {
      text:
        'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    }),
  ]);
}

function mount(): void {
  const app = document.getElementById('app');
  if (!app) throw new Error('#app is missing');
  app.tabIndex = -1;

  const rendered = new Set<string>();
  const tablist = el('div', { class: 'tablist', role: 'tablist', 'aria-label': 'Exhibits' });
  const panelNodes = new Map<string, HTMLElement>();
  const tabNodes = new Map<string, HTMLButtonElement>();
  const position = el('span', { class: 'exhibit-position', id: 'exhibit-position', role: 'status' });
  const previous = el('button', { class: 'btn', type: 'button', text: '← Previous exhibit' });
  const next = el('button', { class: 'btn btn-primary', type: 'button' });
  let activeId = PANELS[0].id;

  const experiment = el('section', { class: 'experiment', id: 'experiment', 'aria-labelledby': 'experiment-heading' });

  function navigate(id: string, scroll = false, focus = false): void {
    if (!PANELS.some((spec) => spec.id === id)) return;
    if (location.hash !== `#${id}`) history.pushState(null, '', `#${id}`);
    activate(id);
    if (scroll) experiment.scrollIntoView({ block: 'start' });
    if (focus) tabNodes.get(id)!.focus({ preventScroll: true });
  }

  function activate(id: string): void {
    activeId = id;
    for (const spec of PANELS) {
      const isActive = spec.id === id;
      const tab = tabNodes.get(spec.id)!;
      const panel = panelNodes.get(spec.id)!;
      tab.setAttribute('aria-selected', String(isActive));
      tab.tabIndex = isActive ? 0 : -1;
      panel.hidden = !isActive;
      if (isActive && !rendered.has(spec.id)) {
        spec.render(panel);
        rendered.add(spec.id);
      }
    }
    const index = PANELS.findIndex((spec) => spec.id === id);
    position.textContent = `Exhibit ${index + 1} of ${PANELS.length}`;
    previous.disabled = index === 0;
    next.textContent = index === PANELS.length - 1 ? 'Back to the beginning ↺' : `Next: ${PANELS[index + 1].tab} →`;
  }

  for (const spec of PANELS) {
    const tab = el('button', {
      class: 'tab-btn',
      type: 'button',
      role: 'tab',
      id: `tab-${spec.id}`,
      'aria-controls': `panel-${spec.id}`,
      'aria-selected': 'false',
      tabindex: '-1',
    }, [
      el('span', { class: 'tab-num', 'aria-hidden': 'true', text: spec.num.padStart(2, '0') }),
      el('span', { class: 'tab-copy' }, [el('span', { text: spec.tab }), el('small', { 'aria-hidden': 'true', text: spec.lesson })]),
    ]) as HTMLButtonElement;
    tab.addEventListener('click', () => navigate(spec.id));
    // Arrow-key navigation between tabs, which a tablist is expected to have.
    tab.addEventListener('keydown', (event) => {
      const keys = ['ArrowRight', 'ArrowLeft', 'Home', 'End'];
      if (!keys.includes(event.key)) return;
      event.preventDefault();
      const i = PANELS.findIndex((p) => p.id === spec.id);
      const next =
        event.key === 'ArrowRight' ? (i + 1) % PANELS.length
        : event.key === 'ArrowLeft' ? (i - 1 + PANELS.length) % PANELS.length
        : event.key === 'Home' ? 0
        : PANELS.length - 1;
      navigate(PANELS[next].id, false, true);
    });
    tabNodes.set(spec.id, tab);
    tablist.append(tab);

    const panel = el('div', {
      class: 'panel',
      id: `panel-${spec.id}`,
      role: 'tabpanel',
      'aria-labelledby': `tab-${spec.id}`,
      tabindex: '0',
      hidden: true,
    });
    panelNodes.set(spec.id, panel);
  }

  experiment.append(
    el('div', { class: 'experiment-heading' }, [
      el('div', {}, [el('p', { class: 'eyebrow', text: 'THE EXPERIMENT' }), el('h2', { id: 'experiment-heading', text: 'Follow the failure.' })]),
      position,
    ]),
    el('nav', { class: 'tabs', 'aria-label': 'Exhibits' }, [tablist]),
  );
  for (const spec of PANELS) experiment.append(panelNodes.get(spec.id)!);
  experiment.append(el('nav', { class: 'exhibit-navigation', 'aria-label': 'Continue the walkthrough' }, [previous, next]));

  previous.addEventListener('click', () => navigate(PANELS[Math.max(0, PANELS.findIndex((spec) => spec.id === activeId) - 1)].id, true, true));
  next.addEventListener('click', () => navigate(PANELS[(PANELS.findIndex((spec) => spec.id === activeId) + 1) % PANELS.length].id, true, true));

  const main = el('main', {}, [
    hero(),
    el('p', { class: 'lab-context' }, [
      el('span', { class: 'context-marker', 'aria-hidden': 'true', text: '◇' }),
      el('span', {}, [el('strong', { text: 'Real cryptography. Local, synthetic traffic.' }), ' A teaching exhibit, not production crypto.']),
    ]),
    experiment,
    scopeNote(),
  ]);

  app.append(main, footer());
  for (const link of app.querySelectorAll<HTMLAnchorElement>('[data-exhibit]')) {
    link.addEventListener('click', (event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      navigate(link.dataset.exhibit!, true, true);
    });
  }
  window.addEventListener('hashchange', () => {
    const id = location.hash.slice(1);
    if (PANELS.some((spec) => spec.id === id)) {
      activate(id);
      experiment.scrollIntoView({ block: 'start' });
    } else if (!location.hash) {
      activate(PANELS[0].id);
    }
  });
  const initial = PANELS.find((spec) => `#${spec.id}` === location.hash);
  activate(initial?.id ?? PANELS[0].id);
  if (initial) experiment.scrollIntoView({ block: 'start' });
}

mount();
