import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { CertificationRequest, Certificate } from 'pkijs';
import {
  KeyGadgetsCore,
  createCsr,
  createSelfSignedCertificate,
  createSubjectDn,
  derToPem,
  generateKeyPair,
  pemToDer,
  recognizeKeyMaterial,
  subjectDnToString,
  verifyPrivateKeyMatchesPublicKey
} from '../src/core';
import { readPkcs12, writePkcs12 } from '../src/pkcs12';
import { toArrayBuffer } from '../src/internal';

test('exposes stable versioned Core API', () => {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  assert.equal(KeyGadgetsCore.version, packageJson.version);
  assert.equal(typeof KeyGadgetsCore.generateKeyPair, 'function');
  assert.equal(typeof KeyGadgetsCore.readPkcs12, 'function');
});

test('encodes and decodes SubjectDN values', () => {
  const value = 'CN=example.test, O=Example Org, C=US';
  const bytes = createSubjectDn(value);
  assert.ok(bytes.byteLength > 20);
  assert.equal(subjectDnToString(bytes), value);
});

test('converts DER to PEM and back', () => {
  const input = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01]);
  const pem = derToPem('TEST OBJECT', input);
  assert.match(pem, /BEGIN TEST OBJECT/);
  assert.deepEqual(pemToDer(pem, 'TEST OBJECT'), input);
});

test('generates and recognizes RSA and EC key pairs', async () => {
  const rsa = await generateKeyPair('rsassa-pkcs1-v1_5-2048');
  assert.equal(recognizeKeyMaterial(rsa).family, 'RSA');
  assert.match(recognizeKeyMaterial(rsa).label, /^RSA 2048$/);
  assert.ok(rsa.privateKeyDer);
  assert.ok(rsa.publicKeyDer);
  assert.equal(await verifyPrivateKeyMatchesPublicKey(rsa.privateKeyDer, rsa.publicKeyDer), true);

  const ec = await generateKeyPair('ecdsa-p-256');
  assert.deepEqual(recognizeKeyMaterial(ec), {
    family: 'EC',
    label: 'EC P-256',
    canSign: true,
    canDerive: true,
    namedCurve: 'P-256'
  });
  assert.ok(ec.privateKeyDer && ec.publicKeyDer);
  assert.equal(await verifyPrivateKeyMatchesPublicKey(ec.privateKeyDer, ec.publicKeyDer), true);
});

test('creates a verifiable CSR and self-signed certificate', async () => {
  const key = await generateKeyPair('ecdsa-p-256');
  assert.ok(key.privateKeyDer && key.publicKeyDer);
  const subjectDn = 'CN=keygadgets.test, O=PKI Studio, C=US';
  const subjectBytes = createSubjectDn(subjectDn);
  const csr = await createCsr({
    privateKeyDer: key.privateKeyDer,
    publicKeyDer: key.publicKeyDer,
    subjectDn,
    subjectBytes,
    hashAlgorithm: 'SHA-256'
  });
  const request = CertificationRequest.fromBER(toArrayBuffer(csr.bytes));
  assert.equal(await request.verify(), true);

  const result = await createSelfSignedCertificate({
    privateKeyDer: key.privateKeyDer,
    publicKeyDer: key.publicKeyDer,
    subjectDn,
    subjectBytes,
    hashAlgorithm: 'SHA-256',
    validityDays: 30,
    keyUsages: ['digitalSignature']
  });
  const certificate = Certificate.fromBER(toArrayBuffer(result.bytes));
  assert.equal(certificate.subject.typesAndValues.length, 3);
  assert.equal(await certificate.verify(certificate), true);
});

test('creates verifiable RSA PKCS#10 and certificate signatures', async () => {
  const key = await generateKeyPair('rsassa-pkcs1-v1_5-2048');
  assert.ok(key.privateKeyDer && key.publicKeyDer);
  const subjectDn = 'CN=rsa.test, O=PKI Studio, C=US';
  const subjectBytes = createSubjectDn(subjectDn);
  const csr = await createCsr({
    privateKeyDer: key.privateKeyDer,
    publicKeyDer: key.publicKeyDer,
    subjectDn,
    subjectBytes,
    hashAlgorithm: 'SHA-384'
  });
  assert.equal(await CertificationRequest.fromBER(toArrayBuffer(csr.bytes)).verify(), true);

  const result = await createSelfSignedCertificate({
    privateKeyDer: key.privateKeyDer,
    publicKeyDer: key.publicKeyDer,
    subjectDn,
    subjectBytes,
    hashAlgorithm: 'SHA-384',
    validityDays: 30,
    keyUsages: ['digitalSignature', 'keyCertSign']
  });
  const certificate = Certificate.fromBER(toArrayBuffer(result.bytes));
  assert.equal(await certificate.verify(certificate), true);
});

test('round-trips multiple password-protected PKCS#12 key pairs', async () => {
  const key = await generateKeyPair('ecdsa-p-256', { label: 'PKCS12 certified key' });
  const keyWithoutCertificate = await generateKeyPair('ecdsa-p-256', { label: 'PKCS12 bare key' });
  assert.ok(key.privateKeyDer && key.publicKeyDer);
  assert.ok(keyWithoutCertificate.privateKeyDer && keyWithoutCertificate.publicKeyDer);
  const subjectDn = 'CN=pkcs12.test, O=PKI Studio, C=US';
  const certificate = await createSelfSignedCertificate({
    privateKeyDer: key.privateKeyDer,
    publicKeyDer: key.publicKeyDer,
    subjectDn,
    subjectBytes: createSubjectDn(subjectDn),
    hashAlgorithm: 'SHA-256',
    validityDays: 30,
    keyUsages: ['digitalSignature']
  });
  const encoded = await writePkcs12([
    { label: key.label, privateKeyDer: key.privateKeyDer, certificateDer: certificate.bytes },
    { label: keyWithoutCertificate.label, privateKeyDer: keyWithoutCertificate.privateKeyDer }
  ], 'secret');
  const decoded = await readPkcs12(encoded, 'secret');
  assert.equal(decoded.length, 2);
  assert.equal(decoded[0]?.label, 'PKCS12 certified key');
  assert.deepEqual(decoded[0]?.privateKeyDer, key.privateKeyDer);
  assert.deepEqual(decoded[0]?.publicKeyDer, key.publicKeyDer);
  assert.deepEqual(decoded[0]?.certificateDer, certificate.bytes);
  assert.equal(decoded[1]?.label, 'PKCS12 bare key');
  assert.deepEqual(decoded[1]?.privateKeyDer, keyWithoutCertificate.privateKeyDer);
  assert.deepEqual(decoded[1]?.publicKeyDer, keyWithoutCertificate.publicKeyDer);
  assert.equal(decoded[1]?.certificateDer, undefined);
  await assert.rejects(
    () => writePkcs12([{
      label: keyWithoutCertificate.label,
      privateKeyDer: keyWithoutCertificate.privateKeyDer,
      certificateDer: certificate.bytes
    }], 'secret'),
    /certificate.*does not match/i
  );
  await assert.rejects(() => readPkcs12(encoded, 'wrong'), /integrity|password|signature/i);
});
