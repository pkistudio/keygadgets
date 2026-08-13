import DerEditorCore from '@pkistudio/dereditor/core';
import DerEditorOidResolver from '@pkistudio/dereditor/oid-resolver';
import DerEditorViewer, { type DerEditorViewerInstance } from '@pkistudio/dereditor/viewer';
import type { DerEditorInput, DerEditorParsedDocument } from '@pkistudio/dereditor/core';

export const derEditorVersion = DerEditorViewer.version;

export function parseDerEditorInput(input: DerEditorInput, format = 'auto'): DerEditorParsedDocument {
  return DerEditorCore.parseInput(input, { format, validateRoundTrip: true });
}

export function bytesToBase64(bytes: Uint8Array): string {
  return DerEditorCore.bytesToBase64(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
  return DerEditorCore.toLowerHexString(bytes);
}

export type MountDerEditorOptions = {
  editable?: boolean;
  fullscreen?: boolean;
  newWindowUrl?: string;
};

export function mountDerEditor(
  mount: Element | ShadowRoot,
  options: MountDerEditorOptions = {}
): DerEditorViewerInstance {
  const editable = options.editable ?? false;
  const viewer = DerEditorViewer.init({
    mount,
    editable,
    fullscreen: options.fullscreen ?? false,
    oidResolver: DerEditorOidResolver,
    newWindowUrl: options.newWindowUrl ?? new URL('viewer.html', window.location.href).href
  });
  viewer.setEditable(editable);
  return viewer;
}

export function mountReadOnlyDerEditor(mount: Element | ShadowRoot): DerEditorViewerInstance {
  return mountDerEditor(mount, { editable: false });
}

export { DerEditorCore, DerEditorOidResolver, DerEditorViewer };
