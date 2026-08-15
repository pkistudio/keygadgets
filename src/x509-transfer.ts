import { createId, toArrayBuffer } from './internal';

const READY = 'keygadgets:x509-ready';
const LOAD = 'keygadgets:x509-load';
const LOADED = 'keygadgets:x509-loaded';
const FAILED = 'keygadgets:x509-failed';
const TRANSFER_TIMEOUT_MS = 15_000;

type TransferEnvelope = {
  type: string;
  token: string;
  bytes?: ArrayBuffer;
  sourceName?: string;
  message?: string;
};

export type X509ViewerTransferOptions = {
  bytes: Uint8Array;
  sourceName: string;
  onLoaded?: () => void;
  onError?: (error: Error) => void;
};

export function openX509GadgetsViewer(options: X509ViewerTransferOptions): void {
  const token = createId();
  const viewerUrl = new URL('./x509-viewer.html', window.location.href);
  viewerUrl.hash = new URLSearchParams({ transfer: token }).toString();
  const openedViewerWindow = window.open(viewerUrl, '_blank');
  if (!openedViewerWindow) throw new Error('The X.509 Gadgets viewer window was blocked by the browser.');
  const viewerWindow = openedViewerWindow;

  const targetOrigin = window.location.origin;
  const certificateBuffer = toArrayBuffer(options.bytes);
  let sent = false;
  const timeout = window.setTimeout(() => {
    cleanup();
    options.onError?.(new Error('The X.509 Gadgets viewer did not accept the certificate in time.'));
  }, TRANSFER_TIMEOUT_MS);

  function cleanup(): void {
    window.clearTimeout(timeout);
    window.removeEventListener('message', receiveMessage);
  }

  function receiveMessage(event: MessageEvent): void {
    if (event.origin !== targetOrigin || event.source !== viewerWindow || !isEnvelope(event.data, token)) return;
    if (event.data.type === READY && !sent) {
      sent = true;
      viewerWindow.postMessage({
        type: LOAD,
        token,
        bytes: certificateBuffer,
        sourceName: options.sourceName
      } satisfies TransferEnvelope, targetOrigin, [certificateBuffer]);
      return;
    }
    if (event.data.type === LOADED) {
      cleanup();
      options.onLoaded?.();
      return;
    }
    if (event.data.type === FAILED) {
      cleanup();
      options.onError?.(new Error(event.data.message || 'X.509 Gadgets could not load the certificate.'));
    }
  }

  window.addEventListener('message', receiveMessage);
}

export function receiveX509GadgetsTransfer(loadObject: (bytes: Uint8Array, sourceName: string) => void): void {
  const sourceWindow = window.opener;
  const transferToken = new URLSearchParams(window.location.hash.slice(1)).get('transfer');
  if (!sourceWindow || !transferToken) return;
  const opener = sourceWindow;
  const token = transferToken;

  const sourceOrigin = window.location.origin;
  window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);

  function finish(message: TransferEnvelope): void {
    opener.postMessage(message, sourceOrigin);
    window.removeEventListener('message', receiveMessage);
    window.opener = null;
  }

  function receiveMessage(event: MessageEvent): void {
    if (event.origin !== sourceOrigin || event.source !== opener || !isEnvelope(event.data, token) || event.data.type !== LOAD) return;
    try {
      if (!(event.data.bytes instanceof ArrayBuffer)) throw new Error('The certificate transfer did not contain DER bytes.');
      loadObject(new Uint8Array(event.data.bytes), event.data.sourceName || 'certificate.der');
      finish({ type: LOADED, token });
    } catch (error) {
      finish({
        type: FAILED,
        token,
        message: error instanceof Error ? error.message : String(error)
      });
    }
  }

  window.addEventListener('message', receiveMessage);
  opener.postMessage({ type: READY, token } satisfies TransferEnvelope, sourceOrigin);
}

function isEnvelope(value: unknown, token: string): value is TransferEnvelope {
  if (!value || typeof value !== 'object') return false;
  const envelope = value as Partial<TransferEnvelope>;
  return typeof envelope.type === 'string' && envelope.token === token;
}
