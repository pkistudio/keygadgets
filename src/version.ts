declare const __KEYGADGETS_VERSION__: string | undefined;

export const KEY_GADGETS_VERSION = typeof __KEYGADGETS_VERSION__ === 'string'
  ? __KEYGADGETS_VERSION__
  : '0.1.1';
