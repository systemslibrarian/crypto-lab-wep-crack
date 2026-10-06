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
  readonly render: (host: HTMLElement) => void;
}

const PANELS: readonly PanelSpec[] = [
  { id: 'rc4', num: '1', tab: 'RC4 itself', render: renderPanel1 },
  { id: 'wep', num: '2', tab: 'Wrap it in WEP', render: renderPanel2 },
  { id: 'collision', num: '3', tab: 'Keystream reuse', render: renderPanel3 },
  { id: 'forge', num: '4', tab: 'Forge a packet', render: renderPanel4 },
  { id: 'ptw', num: '5', tab: 'Recover the key', render: renderPanel5 },
];

function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title', text: 'WEP Crack' }),
      el('p', { class: 'cl-hero-sub', text: 'RC4 · WEP integrity failures · PTW key recovery' }),
      el('p', {
        class: 'cl-hero-desc',
        text:
          'Step the real RC4 key schedule, wrap a message in a WEP protected body, watch ' +
          'a repeated IV cancel the keystream, forge a packet the genuine integrity check ' +
          'accepts, and run PTW until the shared key falls out.',
      }),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      el('p', {
        class: 'cl-hero-why-text',
        text:
          'WEP protected most of the world’s wireless traffic for a decade, and its ' +
          'cipher was implemented correctly the whole time. It still fell in under a ' +
          'minute, because the system around the cipher reused keystream, checked ' +
          'integrity with a checksum, and handed the attacker three bytes of every key.',
      }),
    ]),
  ]);
}

function scopeNote(): HTMLElement {
  return el('section', { class: 'scope-note', 'aria-labelledby': 'scope-heading' }, [
    el('h2', { id: 'scope-heading', text: 'WHAT THIS IS, AND WHAT IT IS NOT' }),
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

  const rendered = new Set<string>();
  const tablist = el('div', { class: 'tablist', role: 'tablist', 'aria-label': 'Exhibits' });
  const panelNodes = new Map<string, HTMLElement>();
  const tabNodes = new Map<string, HTMLButtonElement>();

  function activate(id: string): void {
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
    }, [el('span', { class: 'tab-num', 'aria-hidden': 'true', text: spec.num }), el('span', { text: spec.tab })]) as HTMLButtonElement;
    tab.addEventListener('click', () => activate(spec.id));
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
      activate(PANELS[next].id);
      tabNodes.get(PANELS[next].id)!.focus();
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

  const main = el('main', {}, [el('nav', { class: 'tabs', 'aria-label': 'Exhibits' }, [tablist])]);
  for (const spec of PANELS) main.append(panelNodes.get(spec.id)!);

  app.append(hero(), scopeNote(), main, footer());
  activate(PANELS[0].id);
}

mount();
