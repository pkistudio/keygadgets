import { Certificate } from 'pkijs';
import derEditorIconUrl from '@pkistudio/dereditor/dereditor.ico';
import pkistudioIconUrl from '@pkistudio/dereditor/pkistudio.ico';
import {
  CERTIFICATE_KEY_USAGES,
  KeyGadgetsCore,
  certificateMatchesKey,
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
  const certificateInput = query<HTMLInputElement>(mount, '#certificateInput');
  const algorithmSelect = query<HTMLSelectElement>(mount, '#algorithmSelect');
  const subjectForm = query<HTMLFormElement>(mount, '#subjectForm');
  const subjectInput = query<HTMLInputElement>(mount, '#subjectDn');
  const algorithmMenu = query<HTMLElement>(mount, '#algorithmMenu');
  const actionsMenu = query<HTMLElement>(mount, '#actionsMenu');
  const subjectDialog = query<HTMLDialogElement>(mount, '#subjectDialog');
  const csrDialog = query<HTMLDialogElement>(mount, '#csrDialog');
  const certificateDialog = query<HTMLDialogElement>(mount, '#certificateDialog');
  const aboutDialog = query<HTMLDialogElement>(mount, '#aboutDialog');
  const parentContextMenu = query<HTMLElement>(mount, '#parentContextMenu');
  const privateKeyContextMenu = query<HTMLElement>(mount, '#privateKeyContextMenu');
  const publicKeyContextMenu = query<HTMLElement>(mount, '#publicKeyContextMenu');
  const viewer = mountReadOnlyDerEditor(viewerMount);

  let materials = [...(options.materials ?? [])];
  let selection: Selection | null = firstSelection(materials[0]);
  let contextKeyId: string | null = null;
  let certificateTargetKeyId: string | null = null;

  const instance: KeyGadgetsAppInstance = {
    get materials() { return materials; },
    get selectedMaterial() { return selection ? findMaterial(selection.keyId) ?? null : null; },
    loadBytes,
    generate,
    close
  };

  void populateAlgorithms();
  render();

  query<HTMLButtonElement>(mount, '#generateButton').addEventListener('click', () => {
    setMenuOpen(algorithmMenu, algorithmMenu.hidden);
    setMenuOpen(actionsMenu, false);
  });
  algorithmMenu.addEventListener('click', (event) => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>('button[data-algorithm]');
    if (!button?.dataset.algorithm) return;
    algorithmSelect.value = button.dataset.algorithm;
    setMenuOpen(algorithmMenu, false);
    void run(async () => { await generate(button.dataset.algorithm!); });
  });
  query<HTMLButtonElement>(mount, '#openButton').addEventListener('click', () => fileInput.click());
  query<HTMLButtonElement>(mount, '#saveButton').addEventListener('click', () => {
    setMenuOpen(actionsMenu, false);
    void run(saveSelection);
  });
  query<HTMLButtonElement>(mount, '#exportP12Button').addEventListener('click', () => void run(exportPkcs12));
  query<HTMLButtonElement>(mount, '#deleteButton').addEventListener('click', () => {
    setMenuOpen(actionsMenu, false);
    void run(deleteSelection);
  });
  query<HTMLButtonElement>(mount, '#createCsrButton').addEventListener('click', () => void run(createSelectedCsr));
  query<HTMLButtonElement>(mount, '#createCertificateButton').addEventListener('click', () => void run(createSelectedCertificate));
  query<HTMLButtonElement>(mount, '#actionsButton').addEventListener('click', () => {
    setMenuOpen(actionsMenu, actionsMenu.hidden);
    setMenuOpen(algorithmMenu, false);
  });
  query<HTMLButtonElement>(mount, '#newSubjectButton').addEventListener('click', openSubjectDialog);
  query<HTMLButtonElement>(mount, '#openCsrDialogButton').addEventListener('click', openCsrDialog);
  query<HTMLButtonElement>(mount, '#openCertificateDialogButton').addEventListener('click', openCertificateDialog);

  query<HTMLButtonElement>(mount, '#parentNewSubjectButton').addEventListener('click', () => {
    selectContextKey();
    closeTreeContextMenus();
    openSubjectDialog();
  });
  query<HTMLButtonElement>(mount, '#parentDeleteButton').addEventListener('click', () => void run(async () => {
    const keyId = contextKeyRequired();
    closeTreeContextMenus();
    await deleteMaterial(keyId);
  }));
  query<HTMLButtonElement>(mount, '#privateNewCsrButton').addEventListener('click', () => {
    selectContextNode('private-key');
    closeTreeContextMenus();
    openCsrDialog();
  });
  query<HTMLButtonElement>(mount, '#privateNewCertificateButton').addEventListener('click', () => {
    selectContextNode('private-key');
    closeTreeContextMenus();
    openCertificateDialog();
  });
  query<HTMLButtonElement>(mount, '#privateDeleteButton').addEventListener('click', () => void run(async () => {
    selectContextNode('private-key');
    closeTreeContextMenus();
    await deleteSelection();
  }));
  query<HTMLButtonElement>(mount, '#publicDeleteButton').addEventListener('click', () => void run(async () => {
    selectContextNode('public-key');
    closeTreeContextMenus();
    await deleteSelection();
  }));
  query<HTMLButtonElement>(mount, '#loadCertificateFileButton').addEventListener('click', () => {
    certificateTargetKeyId = contextKeyRequired();
    closeTreeContextMenus();
    certificateInput.click();
  });
  query<HTMLButtonElement>(mount, '#loadCertificatePemButton').addEventListener('click', () => void run(async () => {
    const keyId = contextKeyRequired();
    closeTreeContextMenus();
    const text = await readClipboardText();
    await loadCertificateIntoMaterial(keyId, pemToDer(text, 'CERTIFICATE'), 'clipboard PEM');
  }));
  query<HTMLButtonElement>(mount, '#loadCertificateHexButton').addEventListener('click', () => void run(async () => {
    const keyId = contextKeyRequired();
    closeTreeContextMenus();
    const text = await readClipboardText();
    await loadCertificateIntoMaterial(keyId, hexToBytes(text), 'clipboard HEX');
  }));
  query<HTMLButtonElement>(mount, '#aboutButton').addEventListener('click', () => aboutDialog.showModal());
  query<HTMLButtonElement>(mount, '#closeAboutButton').addEventListener('click', () => aboutDialog.close());
  query<HTMLButtonElement>(mount, '#clearLogButton').addEventListener('click', () => {
    log.replaceChildren();
    logOperation('clear', 'API log cleared.');
  });
  query<HTMLButtonElement>(mount, '#themeButton').addEventListener('click', () => {
    const theme = mount.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    mount.setAttribute('data-theme', theme);
  });

  for (const button of mount.querySelectorAll<HTMLButtonElement>('[data-close-dialog]')) {
    button.addEventListener('click', () => button.closest<HTMLDialogElement>('dialog')?.close());
  }
  document.addEventListener('click', closePopupMenus);
  setupPaneResizer();
  setupLogResizer();

  fileInput.addEventListener('change', () => void run(async () => {
    const file = fileInput.files?.[0];
    fileInput.value = '';
    if (!file) return;
    await loadBytes(new Uint8Array(await file.arrayBuffer()), file.name);
  }));

  certificateInput.addEventListener('change', () => void run(async () => {
    const file = certificateInput.files?.[0];
    const keyId = certificateTargetKeyId;
    certificateInput.value = '';
    certificateTargetKeyId = null;
    if (!file || !keyId) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    const text = new TextDecoder().decode(bytes);
    await loadCertificateIntoMaterial(
      keyId,
      /-----BEGIN CERTIFICATE-----/i.test(text) ? pemToDer(text, 'CERTIFICATE') : bytes,
      file.name
    );
  }));

  tree.addEventListener('click', (event) => {
    const menuButton = (event.target as Element | null)?.closest<HTMLButtonElement>('button[data-tree-menu]');
    if (menuButton?.dataset.keyId && menuButton.dataset.treeMenu) {
      event.preventDefault();
      event.stopPropagation();
      openTreeContextMenu(menuButton.dataset.treeMenu, menuButton.dataset.keyId, menuButton);
      return;
    }
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
    algorithmMenu.replaceChildren(...algorithms.map((algorithm) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.algorithm = algorithm.id;
      button.textContent = algorithm.canonicalLabel;
      button.setAttribute('role', 'menuitem');
      return button;
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
    subjectDialog.close();
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
      hashAlgorithm: selectedHash('#csrHashAlgorithm')
    });
    const csr = { id: createId(), label: `CSR: ${subject.subjectDn}`, ...result };
    (material.csrs ??= []).push(csr);
    selection = { keyId: material.id, kind: 'csr', itemId: csr.id };
    logOperation('createCsr', 'Certificate signing request created.');
    csrDialog.close();
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
      hashAlgorithm: selectedHash('#certificateHashAlgorithm'),
      validityDays,
      keyUsages
    });
    material.certificateDer = result.bytes;
    selection = { keyId: material.id, kind: 'certificate' };
    logOperation('createSelfSignedCertificate', `Self-signed certificate created for ${subject.subjectDn}.`);
    certificateDialog.close();
    render();
  }

  async function loadCertificateIntoMaterial(keyId: string, certificateDer: Uint8Array, sourceName: string): Promise<void> {
    const material = findMaterial(keyId);
    if (!material) throw new Error('The target key pair was not found.');
    if (!isCertificate(certificateDer)) throw new Error('The selected data is not an X.509 certificate.');
    const matches = await certificateMatchesKey(material, certificateDer);
    if (!matches) {
      const apply = await confirmHost('The certificate public key does not match this key pair. Apply it anyway?');
      if (!apply) return;
    }
    material.certificateDer = certificateDer;
    if (matches) material.publicKeyDer = extractCertificatePublicKey(certificateDer);
    selection = { keyId, kind: 'certificate' };
    logOperation('Certificate.load', `${matches ? 'Loaded' : 'Applied'} certificate from ${sourceName}.`);
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

  async function deleteMaterial(keyId: string): Promise<void> {
    const material = findMaterial(keyId);
    if (!material) return;
    const confirmed = await confirmHost(`Delete ${material.label || 'key pair'}?`);
    if (!confirmed) return;
    materials = materials.filter((item) => item.id !== keyId);
    selection = firstSelection(materials[0]);
    logOperation('delete', 'Key pair deleted.');
    render();
  }

  function render(): void {
    tree.className = materials.length ? 'tree' : 'tree empty';
    tree.innerHTML = materials.length ? materials.map(renderMaterialTree).join('') : 'No key generated yet.';
    const selected = selectionBytes();
    const material = selection ? findMaterial(selection.keyId) : undefined;
    if (!selected || !material) {
      details.innerHTML = '<span>Generate or import a key to begin.</span>';
      viewer.close();
      subjectForm.hidden = true;
      updateActions(false);
      return;
    }
    const info = recognizeKeyMaterial(material);
    details.innerHTML = `
      <strong>${escapeHtml(selected.label)}</strong>
      <span>${escapeHtml(info.family)}</span>
      <span>${escapeHtml(selection?.kind ?? '')}</span>
      <span>${selected.bytes.byteLength.toLocaleString()} bytes</span>`;
    viewer.loadBytes(selected.bytes, `${selected.label} (${selected.bytes.byteLength} bytes)`);
    viewer.setEditable(false);
    subjectForm.hidden = false;
    const selectedItemId = selection?.itemId;
    const subject = selection?.kind === 'subject-dn'
      ? material.subjectDns?.find((item) => item.id === selectedItemId)
      : undefined;
    subjectInput.value = subject?.subjectDn ?? material.subjectDns?.[0]?.subjectDn ?? 'CN=example.test, O=Example, C=US';
    query<HTMLButtonElement>(mount, '#subjectSubmit').textContent = subject ? 'Update' : 'Create';
    updateActions(true);
  }

  function renderMaterialTree(material: KeyGadgetsKeyMaterial): string {
    const info = recognizeKeyMaterial(material);
    const children = [
      ...(material.subjectDns ?? []).map((item) => treeButton(material, 'subject-dn', item.label, item.id)),
      material.privateKeyDer ? treeButton(material, 'private-key', 'Private Key', undefined, info.label) : '',
      material.publicKeyDer ? treeButton(material, 'public-key', 'Public Key', undefined, info.label) : '',
      material.certificateDer ? treeButton(material, 'certificate', 'Certificate') : '',
      ...(material.csrs ?? []).map((item) => treeButton(material, 'csr', item.label, item.id))
    ].join('');
    return `<details class="tree-node" open>
      <summary><span class="tree-toggle" aria-hidden="true">−</span><button class="tree-icon-button" type="button" data-tree-menu="parent" data-key-id="${escapeHtml(material.id)}" aria-label="${escapeHtml(material.label || info.label)} actions"><span class="tree-icon folder" aria-hidden="true"></span></button><span class="tree-tag key-label">${escapeHtml(material.label || info.label)}</span></summary>
      <div class="tree-children">${children}</div>
    </details>`;
  }

  function treeButton(material: KeyGadgetsKeyMaterial, kind: Selection['kind'], label: string, itemId?: string, comment?: string): string {
    const active = selection?.keyId === material.id && selection.kind === kind && selection.itemId === itemId;
    const bytes = kind === 'private-key' ? material.privateKeyDer
      : kind === 'public-key' ? material.publicKeyDer
        : kind === 'certificate' ? material.certificateDer
          : kind === 'subject-dn' ? material.subjectDns?.find((item) => item.id === itemId)?.bytes
            : material.csrs?.find((item) => item.id === itemId)?.bytes;
    const suffix = comment ? ` // ${comment}` : '';
    const menuKind = kind === 'private-key' ? 'private' : kind === 'public-key' ? 'public' : '';
    const icon = menuKind
      ? `<button class="tree-icon-button" type="button" data-tree-menu="${menuKind}" data-key-id="${escapeHtml(material.id)}" aria-label="${escapeHtml(label)} actions"><span class="tree-icon leaf" aria-hidden="true"></span></button>`
      : '<span class="tree-icon leaf" aria-hidden="true"></span>';
    return `<details class="tree-node tree-leaf"><summary class="tree-row${active ? ' selected' : ''}">
      <span class="tree-toggle" aria-hidden="true"></span>${icon}
      <button class="tree-item" aria-label="${escapeHtml(label)}" data-key-id="${escapeHtml(material.id)}" data-kind="${kind}"${itemId ? ` data-item-id="${escapeHtml(itemId)}"` : ''}>${escapeHtml(label)} (${bytes?.byteLength ?? 0})${escapeHtml(suffix)}</button>
    </summary></details>`;
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
    const material = enabled && selection ? findMaterial(selection.keyId) : undefined;
    const hasKeyPair = Boolean(material?.privateKeyDer && material.publicKeyDer);
    const canIssue = hasKeyPair && Boolean(material?.subjectDns?.length);
    query<HTMLButtonElement>(mount, '#actionsButton').disabled = !enabled;
    query<HTMLButtonElement>(mount, '#saveButton').disabled = !enabled;
    query<HTMLButtonElement>(mount, '#deleteButton').disabled = !enabled;
    query<HTMLButtonElement>(mount, '#newSubjectButton').disabled = !enabled;
    query<HTMLButtonElement>(mount, '#exportP12Button').disabled = !material?.privateKeyDer;
    for (const id of ['openCsrDialogButton', 'openCertificateDialogButton', 'createCsrButton', 'createCertificateButton']) {
      query<HTMLButtonElement>(mount, `#${id}`).disabled = !canIssue;
    }
  }

  function selectedHash(selector: string): string {
    return query<HTMLSelectElement>(mount, selector).value;
  }

  function openSubjectDialog(): void {
    setMenuOpen(actionsMenu, false);
    subjectDialog.showModal();
    subjectInput.focus();
  }

  function openCsrDialog(): void {
    setMenuOpen(actionsMenu, false);
    syncSubjectPreview('#csrSubjectPreview');
    csrDialog.showModal();
  }

  function openCertificateDialog(): void {
    setMenuOpen(actionsMenu, false);
    syncSubjectPreview('#certificateSubjectPreview');
    certificateDialog.showModal();
  }

  function contextKeyRequired(): string {
    if (!contextKeyId || !findMaterial(contextKeyId)) throw new Error('The context-menu key pair was not found.');
    return contextKeyId;
  }

  function selectContextKey(): void {
    const keyId = contextKeyRequired();
    selection = firstSelection(findMaterial(keyId));
  }

  function selectContextNode(kind: 'private-key' | 'public-key'): void {
    selection = { keyId: contextKeyRequired(), kind };
  }

  function openTreeContextMenu(kind: string, keyId: string, anchor: HTMLElement): void {
    const menu = kind === 'parent' ? parentContextMenu
      : kind === 'private' ? privateKeyContextMenu
        : kind === 'public' ? publicKeyContextMenu
          : null;
    if (!menu) return;
    const shouldOpen = menu.hidden || contextKeyId !== keyId;
    closeTreeContextMenus();
    if (!shouldOpen) return;
    contextKeyId = keyId;
    if (menu === privateKeyContextMenu) {
      const material = findMaterial(keyId);
      const canIssue = Boolean(material?.privateKeyDer && material.publicKeyDer && material.subjectDns?.length);
      query<HTMLButtonElement>(mount, '#privateNewCsrButton').disabled = !canIssue;
      query<HTMLButtonElement>(mount, '#privateNewCertificateButton').disabled = !canIssue;
    }
    const rect = anchor.getBoundingClientRect();
    menu.style.left = `${Math.min(rect.left, window.innerWidth - 230)}px`;
    menu.style.top = `${Math.min(rect.bottom + 2, window.innerHeight - 160)}px`;
    menu.hidden = false;
  }

  function closeTreeContextMenus(): void {
    parentContextMenu.hidden = true;
    privateKeyContextMenu.hidden = true;
    publicKeyContextMenu.hidden = true;
  }

  function syncSubjectPreview(selector: string): void {
    const material = selectedMaterialRequired();
    const selectedItemId = selection?.itemId;
    const subject = selection?.kind === 'subject-dn'
      ? material.subjectDns?.find((item) => item.id === selectedItemId)
      : material.subjectDns?.[0];
    query<HTMLInputElement>(mount, selector).value = subject?.subjectDn ?? '';
  }

  function setMenuOpen(menu: HTMLElement, open: boolean): void {
    menu.hidden = !open;
    const trigger = menu.previousElementSibling;
    if (trigger instanceof HTMLButtonElement) trigger.setAttribute('aria-expanded', String(open));
  }

  function closePopupMenus(event: MouseEvent): void {
    const target = event.target instanceof Element ? event.target : null;
    if (!target?.closest('.menu-group')) {
      setMenuOpen(algorithmMenu, false);
      setMenuOpen(actionsMenu, false);
    }
    if (!target?.closest('.node-context-menu') && !target?.closest('[data-tree-menu]')) closeTreeContextMenus();
  }

  function setupPaneResizer(): void {
    const workspace = query<HTMLElement>(mount, '.workspace');
    const resizer = query<HTMLElement>(mount, '#paneResizer');
    let startX = 0;
    let startWidth = 0;
    resizer.addEventListener('pointerdown', (event) => {
      startX = event.clientX;
      const panel = query<HTMLElement>(mount, '.key-panel');
      startWidth = panel.getBoundingClientRect().width;
      workspace.classList.add('resizing');
      resizer.setPointerCapture(event.pointerId);
    });
    resizer.addEventListener('pointermove', (event) => {
      if (!resizer.hasPointerCapture(event.pointerId)) return;
      const maximum = Math.max(280, workspace.getBoundingClientRect().width - 340);
      const width = Math.min(maximum, Math.max(280, startWidth + event.clientX - startX));
      workspace.style.setProperty('--key-panel-width', `${width}px`);
    });
    resizer.addEventListener('pointerup', (event) => {
      workspace.classList.remove('resizing');
      if (resizer.hasPointerCapture(event.pointerId)) resizer.releasePointerCapture(event.pointerId);
    });
  }

  function setupLogResizer(): void {
    const shell = query<HTMLElement>(mount, '.shell');
    const resizer = query<HTMLElement>(mount, '#logResizer');
    const logPanel = query<HTMLElement>(mount, '.api-log-panel');
    let startY = 0;
    let startHeight = 0;
    resizer.addEventListener('pointerdown', (event) => {
      startY = event.clientY;
      startHeight = logPanel.getBoundingClientRect().height;
      shell.classList.add('resizing-rows');
      resizer.setPointerCapture(event.pointerId);
    });
    resizer.addEventListener('pointermove', (event) => {
      if (!resizer.hasPointerCapture(event.pointerId)) return;
      const height = Math.min(window.innerHeight * 0.45, Math.max(70, startHeight + startY - event.clientY));
      shell.style.setProperty('--api-log-height', `${height}px`);
    });
    resizer.addEventListener('pointerup', (event) => {
      shell.classList.remove('resizing-rows');
      if (resizer.hasPointerCapture(event.pointerId)) resizer.releasePointerCapture(event.pointerId);
    });
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
    const item = document.createElement('div');
    item.className = `api-log-entry${error ? ' error' : ''}`;
    const time = document.createElement('time');
    time.textContent = new Date().toISOString();
    const operationName = document.createElement('span');
    operationName.className = 'api-log-operation';
    operationName.textContent = operation;
    const detail = document.createElement('span');
    detail.className = 'api-log-detail';
    detail.textContent = message;
    item.append(time, operationName, detail);
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
    document.removeEventListener('click', closePopupMenus);
    mount.replaceChildren();
  }

  return instance;
}

function template(): string {
  return `
    <main class="keygadgets-shell shell">
      <nav class="toolbar" aria-label="Application">
        <strong>Key Gadgets</strong>
        <button id="aboutButton" type="button">About</button>
        <button id="themeButton" type="button">Theme</button>
      </nav>
      <section class="workspace">
        <section class="key-panel" aria-label="Key material">
          <nav class="key-menu" aria-label="Key actions">
            <div class="menu-group">
              <button id="generateButton" type="button" aria-haspopup="menu" aria-expanded="false">New</button>
              <div id="algorithmMenu" class="submenu" role="menu" hidden></div>
              <select id="algorithmSelect" class="visually-hidden" aria-label="Key algorithm"><option>Detecting algorithms…</option></select>
            </div>
            <button id="openButton" type="button">Open</button>
            <button id="exportP12Button" type="button" disabled>Save</button>
            <div class="menu-group">
              <button id="actionsButton" type="button" aria-haspopup="menu" aria-expanded="false" disabled>Actions</button>
              <div id="actionsMenu" class="submenu" role="menu" hidden>
                <button id="saveButton" type="button" role="menuitem" disabled>Save selected item</button>
                <button id="newSubjectButton" type="button" role="menuitem" disabled>New SubjectDN</button>
                <button id="openCsrDialogButton" type="button" role="menuitem" disabled>New CSR</button>
                <button id="openCertificateDialogButton" type="button" role="menuitem" disabled>New self-signed Cert</button>
                <button id="deleteButton" class="danger" type="button" role="menuitem" disabled>Delete</button>
              </div>
            </div>
            <input id="fileInput" class="visually-hidden" type="file" accept=".der,.pem,.key,.cer,.crt,.p12,.pfx" />
            <input id="certificateInput" class="visually-hidden" type="file" accept=".cer,.crt,.der,.pem,application/pkix-cert,application/x-x509-ca-cert" />
          </nav>
          <div id="parentContextMenu" class="node-context-menu" role="menu" hidden>
            <div class="node-context-menu-group" role="none">
              <button class="node-context-submenu-trigger" type="button" role="menuitem" aria-haspopup="menu">Load Certificate</button>
              <div class="node-context-submenu" role="menu" aria-label="Load Certificate">
                <button id="loadCertificateFileButton" type="button" role="menuitem">from File</button>
                <button id="loadCertificatePemButton" type="button" role="menuitem">from Clipboard as PEM</button>
                <button id="loadCertificateHexButton" type="button" role="menuitem">from Clipboard as HEX</button>
              </div>
            </div>
            <button id="parentNewSubjectButton" type="button" role="menuitem">New SubjectDN</button>
            <button id="parentDeleteButton" type="button" role="menuitem">Delete</button>
          </div>
          <div id="privateKeyContextMenu" class="node-context-menu" role="menu" hidden>
            <button id="privateNewCsrButton" type="button" role="menuitem">New CSR</button>
            <button id="privateNewCertificateButton" type="button" role="menuitem">New self-signed Cert</button>
            <button id="privateDeleteButton" type="button" role="menuitem">Delete</button>
          </div>
          <div id="publicKeyContextMenu" class="node-context-menu" role="menu" hidden>
            <button id="publicDeleteButton" type="button" role="menuitem">Delete</button>
          </div>
          <section class="key-card">
            <div id="keyTree" class="tree empty">No key generated yet.</div>
            <div id="keyDetails" class="selection-details"><span>Generate or import a key to begin.</span></div>
            <p id="status" class="notice" role="status">Ready.</p>
          </section>
        </section>
        <div id="paneResizer" class="pane-resizer" role="separator" aria-label="Resize panes" aria-orientation="vertical" tabindex="0"></div>
        <section class="viewer-panel" aria-label="ASN.1 viewer"><div id="derEditorMount"></div></section>
      </section>
      <div id="logResizer" class="api-log-resizer" role="separator" aria-label="Resize API log" aria-orientation="horizontal" tabindex="0"></div>
      <section class="api-log-panel" aria-label="API log">
        <header class="api-log-header"><button id="clearLogButton" type="button">Clear</button></header>
        <div id="operationLog" class="api-log-list" role="log" aria-live="polite"></div>
      </section>

      <dialog id="subjectDialog" class="app-dialog">
        <form id="subjectForm" class="dialog-panel">
          <h2>New SubjectDN</h2>
          <label class="dialog-field"><span>subjectDN</span><input id="subjectDn" required autocomplete="off" placeholder="CN=example.com, O=Example, C=JP" /></label>
          <div class="dialog-actions"><button type="button" data-close-dialog>Cancel</button><button id="subjectSubmit" type="submit">Create</button></div>
        </form>
      </dialog>

      <dialog id="csrDialog" class="app-dialog">
        <section class="dialog-panel">
          <h2>New CSR</h2>
          <label class="dialog-field"><span>subjectDN</span><input id="csrSubjectPreview" readonly /></label>
          <label class="dialog-field"><span>Hash algorithm</span><select id="csrHashAlgorithm"><option>SHA-256</option><option>SHA-384</option><option>SHA-512</option></select></label>
          <div class="dialog-actions"><button type="button" data-close-dialog>Cancel</button><button id="createCsrButton" type="button" disabled>Create</button></div>
        </section>
      </dialog>

      <dialog id="certificateDialog" class="app-dialog certificate-dialog">
        <section class="dialog-panel">
          <h2>New self-signed Cert</h2>
          <label class="dialog-field"><span>subjectDN</span><input id="certificateSubjectPreview" readonly /></label>
          <label class="dialog-field"><span>Hash algorithm</span><select id="certificateHashAlgorithm"><option>SHA-256</option><option>SHA-384</option><option>SHA-512</option></select></label>
          <label class="dialog-field"><span>Validity span days</span><input id="validityDays" type="number" min="1" max="36500" value="365" /></label>
          <fieldset class="checkbox-list"><legend>Key usage</legend>${CERTIFICATE_KEY_USAGES.map((usage) => `<label class="checkbox-list-item"><input type="checkbox" name="keyUsage" value="${usage.id}"${usage.defaultChecked ? ' checked' : ''} /><span>${usage.label}</span></label>`).join('')}</fieldset>
          <div class="dialog-actions"><button type="button" data-close-dialog>Cancel</button><button id="createCertificateButton" type="button" disabled>Create</button></div>
        </section>
      </dialog>

      <dialog id="aboutDialog" class="app-dialog about-dialog">
        <section class="about-panel">
          <p class="about-name">Key Gadgets</p>
          <p>Version ${KEY_GADGETS_VERSION}</p>
          <p>DerEditor is embedded read-only.</p>
          <div class="dialog-actions"><button id="closeAboutButton" type="button">Close</button></div>
        </section>
      </dialog>
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

async function readClipboardText(): Promise<string> {
  if (!navigator.clipboard?.readText) throw new Error('Clipboard read access is not available in this browser context.');
  const text = await navigator.clipboard.readText();
  if (!text.trim()) throw new Error('The clipboard is empty.');
  return text;
}

function hexToBytes(text: string): Uint8Array {
  const normalized = text.replace(/0x/gi, '').replace(/[\s:.-]/g, '');
  if (!normalized || normalized.length % 2 !== 0 || /[^0-9a-f]/i.test(normalized)) {
    throw new Error('Clipboard HEX must contain an even number of hexadecimal digits.');
  }
  return Uint8Array.from(normalized.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
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
