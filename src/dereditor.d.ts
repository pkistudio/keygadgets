declare module '@pkistudio/dereditor/core' {
  export type DerEditorInput = string | Uint8Array | ArrayBuffer | ArrayBufferView;

  export type DerEditorParsedNode = {
    id?: string;
    tagClass: 0 | 1 | 2 | 3;
    tagNumber: number;
    constructed: boolean;
    offset: number;
    start: number;
    headerLength: number;
    length: number;
    valueStart: number;
    valueEnd: number;
    end: number;
    depth: number;
    indefinite: boolean;
    encapsulated: boolean;
    children: DerEditorParsedNode[];
    valueBytes: Uint8Array;
    dirty: boolean;
    validationError: string;
  };

  export type DerEditorParsedDocument = {
    format: string;
    bytes: Uint8Array;
    encodedBytes: Uint8Array;
    nodes: DerEditorParsedNode[];
  };

  export type DerEditorCoreApi = {
    VERSION: string;
    decodeInput: (input: DerEditorInput, options?: { format?: string }) => { bytes: Uint8Array; format: string };
    parseInput: (input: DerEditorInput, options?: { format?: string; validateRoundTrip?: boolean }) => DerEditorParsedDocument;
    getNodeBytes: (nodes: DerEditorParsedNode[], nodeId: string) => Uint8Array;
    base64ToBytes: (text: string) => Uint8Array;
    bytesToBase64: (bytes: Uint8Array) => string;
    hexToBytes: (text: string, options?: { allowEmpty?: boolean }) => Uint8Array;
    toLowerHexString: (bytes: Uint8Array) => string;
    toHex: (bytes: Uint8Array, maxLength?: number) => string;
    decodePem: (text: string) => Uint8Array;
    decodeOid: (bytes: Uint8Array) => string;
  };

  const core: DerEditorCoreApi;
  export default core;
}

declare module '@pkistudio/dereditor/oid-resolver' {
  export type DerEditorOidResolverInstance = {
    readonly names: Readonly<Record<string, string>>;
    resolve: (oid: string) => string;
    create: (names?: Record<string, string>) => DerEditorOidResolverInstance;
  };

  const resolver: DerEditorOidResolverInstance;
  export default resolver;
}

declare module '@pkistudio/dereditor/viewer' {
  import type { DerEditorCoreApi, DerEditorInput } from '@pkistudio/dereditor/core';
  import type { DerEditorOidResolverInstance } from '@pkistudio/dereditor/oid-resolver';

  export type DerEditorViewerInstance = {
    close: () => void;
    getNodeBytes: (nodeId: string) => Uint8Array;
    loadBytes: (input: DerEditorInput, notice?: string) => void;
    mount: Element | ShadowRoot;
    root: Element | ShadowRoot;
    setEditable: (editable: boolean) => void;
  };

  export type DerEditorViewerApi = {
    core: DerEditorCoreApi;
    version: string;
    init: (options: {
      mount: string | Element | ShadowRoot;
      shadowRoot?: boolean;
      fullscreen?: boolean;
      editable?: boolean;
      oidResolver?: DerEditorOidResolverInstance | ((oid: string) => string) | Record<string, string>;
      newWindowUrl?: string;
    }) => DerEditorViewerInstance;
  };

  const viewer: DerEditorViewerApi;
  export default viewer;
}

declare module '@pkistudio/dereditor/pkistudio.ico' {
  const iconUrl: string;
  export default iconUrl;
}

declare module '@pkistudio/dereditor/dereditor.ico' {
  const iconUrl: string;
  export default iconUrl;
}
