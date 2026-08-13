import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DerEditorCore,
  bytesToBase64,
  bytesToHex,
  derEditorVersion,
  parseDerEditorInput
} from '../src/dereditor-adapter';

test('imports DerEditor viewer without requiring a DOM', () => {
  assert.equal(derEditorVersion, '0.1.4');
  assert.equal(DerEditorCore.VERSION, '0.1.4');
});

test('uses the published DerEditor Core for ASN.1 representations', () => {
  const bytes = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]);
  const parsed = parseDerEditorInput(bytes);
  assert.equal(parsed.nodes.length, 1);
  assert.equal(bytesToHex(bytes), '3003020101');
  assert.equal(bytesToBase64(bytes), 'MAMCAQE=');
});
