import { Certificate } from 'pkijs';
import derEditorIconUrl from '@pkistudio/dereditor/dereditor.ico';
import pkistudioIconUrl from '@pkistudio/dereditor/pkistudio.ico';
import {
  CERTIFICATE_KEY_USAGES,
  KeyGadgetsCore,
  createCsr,
  createSelfSignedCertificate,
  createSubjectDn,
  derToPem,
  extractCertificatePublicKey,
  generateKeyPair,
  getSupportedKeyAlgorithms,
  pemToDer,
  recognizeKeyMaterial,
  subjectDnToString,
  type KeyGadgetsKeyMaterial,
  type SubjectDnMaterial
} from './core';
import { mountReadOnlyDerEditor } from './dereditor-adapter';
import { createId, toArrayBuffer } from './internal';
import { readPkcs12, writePkcs12 } from './pkcs12';
import { KEY_GADGETS_VERSION } from './version';

export type KeyGadgetsHost = {
  confirm?: (message: string) => boolean | Promise<boolean>;
  prompt?: (message: string, defaultValue?: string) => string | null | Promise<string | null>;
  saveFile?: (file: { bytes: Uint8Array; suggestedName: string; mimeType: string }) => void | Promise<void>;
};

export type InitKeyGadgetsOptions = {
  mount?: string | Element;
  theme?: 'light' | 'dark';
  host?: KeyGadgetsHost;
  materials?: KeyGadgetsKeyMaterial[];
};

export type KeyGadgetsAppInstance = {
  readonly materials: readonly KeyGadgetsKeyMaterial[];
  readonly selectedMaterial: KeyGadgetsKeyMaterial | null;
  loadBytes: (bytes: Uint8Array, sourceName?: string, password?: string) => Promise<readonly KeyGadgetsKeyMaterial[]>;
  generate: (algorithmId: string, label?: string) => Promise<KeyGadgetsKeyMaterial>;
  close: () => void;
};

type Selection = {
  keyId: string;
  kind: 'private-key' | 'public-key' | 'certificate' | 'subject-dn' | 'csr';
  itemId?: string;
};

export function initKeyGadgets(options: InitKeyGadgetsOptions = {}): KeyGadgetsAppInstance {
  const mount = resolveMount(options.mount ?? '#app');
  setDocumentIcon(hasDerEditorTransferPayload() ? derEditorIconUrl : pkistudioIconUrl);
  mount.innerHTML = template();
  mount.setAttribute('data-theme', options.theme ?? 'light');

  const tree = query<HTMLElement>(mount, '#keyTree');
  const details = query<HTMLElement>(mount, '#keyDetails');
  const viewerMount = query<HTMLElement>(mount, '#derEditorMount');
  const status = query<HTMLElement>(mount, '#status');
  const log = query<HTMLElement>(mount, '#operationLog');
  const fileInput = query<HTMLInputElement>(mount, '#fileInput');
  const algorithmSelect = query<HTMLSelectElement>(mount, '#algorithmSelect');
  const subjectForm = query<HTMLFormElement>(mount, '#subjectForm');
  const subjectInput = query<HTMLInputElement>(mount, '#subjectDn');
  const viewer = mountReadOnlyDerEditor(viewerMount);

  let materials = [...(options.materials ?? [])];
  let selection: Selection | null = firstSelection(materials[0]);

  const instance: KeyGadgetsAppInstance = {
    get materials() { return materials; },
    get selectedMaterial() { return selection ? findMaterial(selection.keyId) ?? null : null; },
    loadBytes,
    generate,
    close
  };

  void populateAlgorithms();
  render();

  query<HTMLButtonElement>(mount, '#generateButton').addEventListener('click', () => void run(async () => {
    if (!algorithmSelect.value) throw new Error('No supported key algorithm is selected.');
    await generate(algorithmSelect.value);
  }));
  query<HTMLButtonElement>(mount, '#openButton').addEventListener('click', () => fileInput.click());
  query<HTMLButtonElement>(mount, '#saveButton').addEventListener('click', () => void run(saveSelection));
  query<HTMLButtonElement>(mount, '#exportP12Button').addEventListener('click', () => void run(exportPkcs12));
  query<HTMLButtonElement>(mount, '#deleteButton').addEventListener('click', () => void run(deleteSelection));
  query<HTMLButtonElement>(mount, '#createCsrButton').addEventListener('click', () => void run(createSelectedCsr));
  query<HTMLButtonElement>(mount, '#createCertificateButton').addEventListener('click', () => void run(createSelectedCertificate));
  query<HTMLButtonElement>(mount, '#themeButton').addEventListener('click', () => {
    const theme = mount.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    mount.setAttribute('data-theme', theme);
  });

  fileInput.addEventListener('change', () => void run(async () => {
    const file = fileInput.files?.[0];
    fileInput.value = '';
    if (!file) return;
    await loadBytes(new Uint8Array(await file.arrayBuffer()), file.name);
  }));

  tree.addEventListener('click', (event) => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>('button[data-key-id][data-kind]');
    if (!button?.dataset.keyId || !button.dataset.kind) return;
    selection = {
      keyId: button.dataset.keyId,
      kind: button.dataset.kind as Selection['kind'],
      itemId: button.dataset.itemId
    };
    render();
  });

  subjectForm.addEventListener('submit', (event) => {
    event.preventDefault();
    void run(saveSubjectDn);
  });

  async function populateAlgorithms(): Promise<void> {
    const algorithms = await getSupportedKeyAlgorithms();
    algorithmSelect.replaceChildren(...algorithms.map((algorithm) => {
      const option = document.createElement('option');
      option.value = algorithm.id;
      option.textContent = algorithm.canonicalLabel;
      return option;
    }));
    if (algorithms.length === 0) {
      algorithmSelect.append(new Option('No supported algorithms', ''));
      algorithmSelect.disabled = true;
    }
    setStatus(`${algorithms.length} key algorithms available.`);
  }

  async function generate(algorithmId: string, label?: string): Promise<KeyGadgetsKeyMaterial> {
    setStatus('Generating key pair…');
    const material = await generateKeyPair(algorithmId, { label });
    material.subjectDns = [];
    material.csrs = [];
    materials.push(material);
    selection = firstSelection(material);
    logOperation('generateKeyPair', `${material.label} generated.`);
    render();
    return material;
  }

  async function loadBytes(
    bytes: Uint8Array,
    sourceName = 'imported.der',
    suppliedPassword?: string
  ): Promise<readonly KeyGadgetsKeyMaterial[]> {
    if (/\.(p12|pfx)$/i.test(sourceName)) {
      const password = suppliedPassword ?? await promptHost('PKCS#12 password', '');
      if (password === null) return [];
      const imported: KeyGadgetsKeyMaterial[] = (await readPkcs12(bytes, password, { sourceName }))
        .map((item) => ({ ...item, subjectDns: [], csrs: [] }));
      materials.push(...imported);
      selection = firstSelection(imported[0]);
      logOperation('readPkcs12', `${imported.length} key pair(s) imported from ${sourceName}.`);
      render();
      return imported;
    }

    const decoded = decodeImportedBytes(bytes);
    const material = await materialFromImportedBytes(decoded.bytes, decoded.label, sourceName);
    materials.push(material);
    selection = firstSelection(material);
    logOperation('loadBytes', `${sourceName} imported as ${selection?.kind ?? 'key material'}.`);
    render();
    return [material];
  }

  async function materialFromImportedBytes(
    bytes: Uint8Array,
    pemLabel: string | null,
    sourceName: string
  ): Promise<KeyGadgetsKeyMaterial> {
    const base: KeyGadgetsKeyMaterial = { id: createId(), label: sourceName, sourceName, subjectDns: [], csrs: [] };
    if (pemLabel?.includes('PRIVATE KEY')) base.privateKeyDer = bytes;
    else if (pemLabel?.includes('PUBLIC KEY')) base.publicKeyDer = bytes;
    else if (pemLabel?.includes('CERTIFICATE') || isCertificate(bytes)) {
      base.certificateDer = bytes;
      base.publicKeyDer = extractCertificatePublicKey(bytes);
    } else {
      const info = recognizeKeyMaterial({ privateKeyDer: bytes });
      if (info.family !== 'Unknown') base.privateKeyDer = bytes;
      else {
        const publicInfo = recognizeKeyMaterial({ publicKeyDer: bytes });
        if (publicInfo.family === 'Unknown') throw new Error('The file is not a recognized PKCS#8, SPKI, certificate, or PKCS#12 object.');
        base.publicKeyDer = bytes;
      }
    }
    const info = recognizeKeyMaterial(base);
    base.label = info.family === 'Unknown' ? sourceName : `${info.label} (${sourceName})`;
    return base;
  }

  function saveSubjectDn(): void {
    const material = selectedMaterialRequired();
    const value = subjectInput.value.trim();
    const bytes = createSubjectDn(value);
    const existing = selection?.kind === 'subject-dn'
      ? material.subjectDns?.find((item) => item.id === selection?.itemId)
      : undefined;
    if (existing) {
      existing.subjectDn = value;
      existing.bytes = bytes;
      existing.label = value;
      logOperation('createSubjectDn', 'SubjectDN updated.');
    } else {
      const subject: SubjectDnMaterial = { id: createId(), label: value, subjectDn: value, bytes };
      (material.subjectDns ??= []).push(subject);
      selection = { keyId: material.id, kind: 'subject-dn', itemId: subject.id };
      logOperation('createSubjectDn', 'SubjectDN created.');
    }
    render();
  }

  async function createSelectedCsr(): Promise<void> {
    const material = selectedMaterialRequired();
    const subject = selectedSubject(material);
    requireKeyPair(material);
    const result = await createCsr({
      privateKeyDer: material.privateKeyDer,
      publicKeyDer: material.publicKeyDer,
      subjectDn: subject.subjectDn,
      subjectBytes: subject.bytes,
      hashAlgorithm: selectedHash()
    });
    const csr = { id: createId(), label: `CSR: ${subject.subjectDn}`, ...result };
    (material.csrs ??= []).push(csr);
    selection = { keyId: material.id, kind: 'csr', itemId: csr.id };
    logOperation('createCsr', 'Certificate signing request created.');
    render();
  }

  async function createSelectedCertificate(): Promise<void> {
    const material = selectedMaterialRequired();
    const subject = selectedSubject(material);
    requireKeyPair(material);
    const validityDays = Number(query<HTMLInputElement>(mount, '#validityDays').value);
    const keyUsages = [...mount.querySelectorAll<HTMLInputElement>('input[name="keyUsage"]:checked')].map((input) => input.value);
    const result = await createSelfSignedCertificate({
      privateKeyDer: material.privateKeyDer,
      publicKeyDer: material.publicKeyDer,
      subjectDn: subject.subjectDn,
      subjectBytes: subject.bytes,
      hashAlgorithm: selectedHash(),
      validityDays,
      keyUsages
    });
    material.certificateDer = result.bytes;
    selection = { keyId: material.id, kind: 'certificate' };
    logOperation('createSelfSignedCertificate', `Self-signed certificate created for ${subject.subjectDn}.`);
    render();
  }

  async function saveSelection(): Promise<void> {
    const selected = selectionBytes();
    if (!selected) throw new Error('Select an item to save.');
    const output = exportFormat(selected);
    await saveHost({ bytes: output.bytes, suggestedName: output.name, mimeType: output.mimeType });
    logOperation('saveFile', `${output.name} saved.`);
  }

  async function exportPkcs12(): Promise<void> {
    const material = selectedMaterialRequired();
    if (!material.privateKeyDer) throw new Error('The selected key does not include a private key.');
    const password = await promptHost('Password for the new PKCS#12 file', '');
    if (password === null) return;
    const bytes = await writePkcs12([material], password);
    await saveHost({ bytes, suggestedName: safeName(material.label || 'key') + '.p12', mimeType: 'application/x-pkcs12' });
    logOperation('writePkcs12', 'PKCS#12 file created.');
  }

  async function deleteSelection(): Promise<void> {
    if (!selection) return;
    const material = findMaterial(selection.keyId);
    if (!material) return;
    const confirmed = await confirmHost(`Delete ${selection.kind}?`);
    if (!confirmed) return;
    if (selection.kind === 'subject-dn') material.subjectDns = material.subjectDns?.filter((item) => item.id !== selection?.itemId);
    else if (selection.kind === 'csr') material.csrs = material.csrs?.filter((item) => item.id !== selection?.itemId);
    else if (selection.kind === 'private-key') delete material.privateKeyDer;
    else if (selection.kind === 'public-key') delete material.publicKeyDer;
    else if (selection.kind === 'certificate') delete material.certificateDer;
    if (!material.privateKeyDer && !material.publicKeyDer && !material.certificateDer) {
      materials = materials.filter((item) => item.id !== material.id);
    }
    selection = firstSelection(materials[0]);
    logOperation('delete', 'Selected item deleted.');
    render();
  }

  function render(): void {
    tree.innerHTML = materials.length ? materials.map(renderMaterialTree).join('') : '<p class="empty">No keys loaded.</p>';
    const selected = selectionBytes();
    const material = selection ? findMaterial(selection.keyId) : undefined;
    if (!selected || !material) {
      details.innerHTML = '<p class="empty">Generate or import a key to begin.</p>';
      viewer.close();
      subjectForm.hidden = true;
      updateActions(false);
      return;
    }
    const info = recognizeKeyMaterial(material);
    details.innerHTML = `
      <h2>${escapeHtml(selected.label)}</h2>
      <dl>
        <dt>Key family</dt><dd>${escapeHtml(info.family)}</dd>
        <dt>Object</dt><dd>${escapeHtml(selection?.kind ?? '')}</dd>
        <dt>Length</dt><dd>${selected.bytes.byteLength.toLocaleString()} bytes</dd>
        <dt>Source</dt><dd>${escapeHtml(material.sourceName ?? 'Created in browser')}</dd>
      </dl>`;
    viewer.loadBytes(selected.bytes, `${selected.label} (${selected.bytes.byteLength} bytes)`);
    viewer.setEditable(false);
    subjectForm.hidden = false;
    const selectedItemId = selection?.itemId;
    const subject = selection?.kind === 'subject-dn'
      ? material.subjectDns?.find((item) => item.id === selectedItemId)
      : undefined;
    subjectInput.value = subject?.subjectDn ?? material.subjectDns?.[0]?.subjectDn ?? 'CN=example.test, O=Example, C=US';
    query<HTMLButtonElement>(mount, '#subjectSubmit').textContent = subject ? 'Update SubjectDN' : 'Add SubjectDN';
    updateActions(true);
  }

  function renderMaterialTree(material: KeyGadgetsKeyMaterial): string {
    const children = [
      material.privateKeyDer ? treeButton(material, 'private-key', 'Private Key') : '',
      material.publicKeyDer ? treeButton(material, 'public-key', 'Public Key') : '',
      material.certificateDer ? treeButton(material, 'certificate', 'Certificate') : '',
      ...(material.subjectDns ?? []).map((item) => treeButton(material, 'subject-dn', item.label, item.id)),
      ...(material.csrs ?? []).map((item) => treeButton(material, 'csr', item.label, item.id))
    ].join('');
    return `<section class="key-node"><h3>${escapeHtml(material.label || 'Key')}</h3><div class="tree-children">${children}</div></section>`;
  }

  function treeButton(material: KeyGadgetsKeyMaterial, kind: Selection['kind'], label: string, itemId?: string): string {
    const active = selection?.keyId === material.id && selection.kind === kind && selection.itemId === itemId;
    return `<button class="tree-item${active ? ' active' : ''}" data-key-id="${escapeHtml(material.id)}" data-kind="${kind}"${itemId ? ` data-item-id="${escapeHtml(itemId)}"` : ''}>${escapeHtml(label)}</button>`;
  }

  function selectionBytes(): { bytes: Uint8Array; kind: Selection['kind']; label: string } | null {
    if (!selection) return null;
    const material = findMaterial(selection.keyId);
    if (!material) return null;
    if (selection.kind === 'private-key' && material.privateKeyDer) return { bytes: material.privateKeyDer, kind: selection.kind, label: 'Private Key' };
    if (selection.kind === 'public-key' && material.publicKeyDer) return { bytes: material.publicKeyDer, kind: selection.kind, label: 'Public Key' };
    if (selection.kind === 'certificate' && material.certificateDer) return { bytes: material.certificateDer, kind: selection.kind, label: 'Certificate' };
    const item = selection.kind === 'subject-dn'
      ? material.subjectDns?.find((value) => value.id === selection?.itemId)
      : material.csrs?.find((value) => value.id === selection?.itemId);
    return item ? { bytes: item.bytes, kind: selection.kind, label: item.label } : null;
  }

  function selectedSubject(material: KeyGadgetsKeyMaterial): SubjectDnMaterial {
    const selectedItemId = selection?.itemId;
    const selected = selection?.kind === 'subject-dn'
      ? material.subjectDns?.find((item) => item.id === selectedItemId)
      : material.subjectDns?.[0];
    if (!selected) throw new Error('Create a SubjectDN first.');
    return selected;
  }

  function selectedMaterialRequired(): KeyGadgetsKeyMaterial {
    const material = selection ? findMaterial(selection.keyId) : undefined;
    if (!material) throw new Error('Select a key first.');
    return material;
  }

  function findMaterial(id: string): KeyGadgetsKeyMaterial | undefined {
    return materials.find((material) => material.id === id);
  }

  function updateActions(enabled: boolean): void {
    for (const id of ['saveButton', 'exportP12Button', 'deleteButton', 'createCsrButton', 'createCertificateButton']) {
      query<HTMLButtonElement>(mount, `#${id}`).disabled = !enabled;
    }
  }

  function selectedHash(): string {
    return query<HTMLSelectElement>(mount, '#hashAlgorithm').value;
  }

  async function run(action: () => void | Promise<void>): Promise<void> {
    try {
      await action();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setStatus(message, true);
      logOperation('error', message, true);
    }
  }

  function setStatus(message: string, error = false): void {
    status.textContent = message;
    status.classList.toggle('error', error);
  }

  function logOperation(operation: string, message: string, error = false): void {
    const item = document.createElement('li');
    item.classList.toggle('error', error);
    item.textContent = `${new Date().toLocaleTimeString()} ${operation}: ${message}`;
    log.prepend(item);
    setStatus(message, error);
  }

  async function confirmHost(message: string): Promise<boolean> {
    return options.host?.confirm ? options.host.confirm(message) : window.confirm(message);
  }

  async function promptHost(message: string, defaultValue = ''): Promise<string | null> {
    return options.host?.prompt ? options.host.prompt(message, defaultValue) : window.prompt(message, defaultValue);
  }

  async function saveHost(file: { bytes: Uint8Array; suggestedName: string; mimeType: string }): Promise<void> {
    if (options.host?.saveFile) return options.host.saveFile(file);
    const blob = new Blob([toArrayBuffer(file.bytes)], { type: file.mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = file.suggestedName;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url));
  }

  function close(): void {
    materials = [];
    selection = null;
    viewer.close();
    mount.replaceChildren();
  }

  return instance;
}

function template(): string {
  return `
    <main class="keygadgets-shell">
      <header class="app-header">
        <div><h1>Key Gadgets</h1><p>Local PKI key workspace</p></div>
        <div class="toolbar">
          <select id="algorithmSelect" aria-label="Key algorithm"><option>Detecting algorithms…</option></select>
          <button id="generateButton">Generate</button>
          <button id="openButton">Import</button>
          <button id="saveButton" disabled>Save item</button>
          <button id="exportP12Button" disabled>Export PKCS#12</button>
          <button id="deleteButton" class="danger" disabled>Delete</button>
          <button id="themeButton" aria-label="Toggle theme">Theme</button>
          <input id="fileInput" type="file" accept=".der,.pem,.key,.cer,.crt,.p12,.pfx" hidden />
        </div>
      </header>
      <section class="workspace">
        <aside class="tree-pane" aria-label="Key material"><div id="keyTree"></div></aside>
        <section class="content-pane">
          <div id="keyDetails" class="details"></div>
          <section class="viewer-pane" aria-label="ASN.1 viewer"><div id="derEditorMount"></div></section>
        </section>
        <aside class="action-pane">
          <form id="subjectForm" hidden>
            <h2>SubjectDN</h2>
            <label>Distinguished name<input id="subjectDn" required /></label>
            <button id="subjectSubmit" type="submit">Add SubjectDN</button>
          </form>
          <section class="certificate-form">
            <h2>CSR and certificate</h2>
            <label>Hash<select id="hashAlgorithm"><option>SHA-256</option><option>SHA-384</option><option>SHA-512</option></select></label>
            <label>Validity days<input id="validityDays" type="number" min="1" max="36500" value="365" /></label>
            <fieldset><legend>Key usage</legend>${CERTIFICATE_KEY_USAGES.map((usage) => `<label><input type="checkbox" name="keyUsage" value="${usage.id}"${usage.defaultChecked ? ' checked' : ''} /> ${usage.label}</label>`).join('')}</fieldset>
            <div class="stack"><button id="createCsrButton" disabled>Create CSR</button><button id="createCertificateButton" disabled>Create self-signed certificate</button></div>
          </section>
          <section class="about"><strong>Key Gadgets ${KEY_GADGETS_VERSION}</strong><span>DerEditor is embedded read-only.</span></section>
        </aside>
      </section>
      <footer><p id="status" role="status">Ready.</p><ol id="operationLog" aria-label="Operation log"></ol></footer>
    </main>`;
}

function decodeImportedBytes(bytes: Uint8Array): { bytes: Uint8Array; label: string | null } {
  const text = new TextDecoder().decode(bytes);
  const match = /-----BEGIN ([^-]+)-----/.exec(text);
  if (!match?.[1]) return { bytes, label: null };
  return { bytes: pemToDer(text, match[1]), label: match[1].toUpperCase() };
}

function isCertificate(bytes: Uint8Array): boolean {
  try {
    const certificate = Certificate.fromBER(toArrayBuffer(bytes));
    return Boolean(certificate.subjectPublicKeyInfo?.algorithm?.algorithmId && certificate.signatureAlgorithm.algorithmId);
  } catch {
    return false;
  }
}

function exportFormat(selected: { bytes: Uint8Array; kind: Selection['kind']; label: string }): {
  bytes: Uint8Array;
  name: string;
  mimeType: string;
} {
  const pemLabels: Partial<Record<Selection['kind'], string>> = {
    'private-key': 'PRIVATE KEY',
    'public-key': 'PUBLIC KEY',
    certificate: 'CERTIFICATE',
    csr: 'CERTIFICATE REQUEST'
  };
  const pemLabel = pemLabels[selected.kind];
  if (!pemLabel) return { bytes: selected.bytes, name: 'subject-dn.der', mimeType: 'application/pkix-attr-cert' };
  return {
    bytes: new TextEncoder().encode(derToPem(pemLabel, selected.bytes)),
    name: `${safeName(selected.label)}.pem`,
    mimeType: 'application/x-pem-file'
  };
}

function firstSelection(material?: KeyGadgetsKeyMaterial): Selection | null {
  if (!material) return null;
  if (material.privateKeyDer) return { keyId: material.id, kind: 'private-key' };
  if (material.publicKeyDer) return { keyId: material.id, kind: 'public-key' };
  if (material.certificateDer) return { keyId: material.id, kind: 'certificate' };
  return null;
}

function requireKeyPair(material: KeyGadgetsKeyMaterial): asserts material is KeyGadgetsKeyMaterial & {
  privateKeyDer: Uint8Array;
  publicKeyDer: Uint8Array;
} {
  if (!material.privateKeyDer || !material.publicKeyDer) throw new Error('Both private and public keys are required.');
}

function resolveMount(value: string | Element): Element {
  const mount = typeof value === 'string' ? document.querySelector(value) : value;
  if (!mount) throw new Error(`Key Gadgets mount was not found: ${String(value)}`);
  return mount;
}

function query<T extends Element>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);
  if (!element) throw new Error(`Required element was not found: ${selector}`);
  return element;
}

function setDocumentIcon(url: string): void {
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (!link) {
    link = document.createElement('link');
    link.rel = 'icon';
    document.head.append(link);
  }
  link.href = url;
}

function hasDerEditorTransferPayload(): boolean {
  const url = new URL(window.location.href);
  return url.searchParams.has('subtree') || url.searchParams.has('expand');
}

function safeName(value: string): string {
  return value.replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'key';
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character] ?? character);
}
