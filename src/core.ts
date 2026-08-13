import * as asn1js from 'asn1js';
import {
  AlgorithmIdentifier as PkijsAlgorithmIdentifier,
  AttributeTypeAndValue,
  BasicConstraints,
  Certificate,
  CertificationRequest,
  Extension,
  RelativeDistinguishedNames,
  Time
} from 'pkijs';
import { bytesEqual, createId, toArrayBuffer } from './internal';
import { readPkcs12, writePkcs12, type Pkcs12KeyMaterial } from './pkcs12';
import { KEY_GADGETS_VERSION } from './version';

export type CsrMaterial = {
  id: string;
  label: string;
  subjectDn: string;
  hashAlgorithm: string;
  bytes: Uint8Array;
};

export type SubjectDnMaterial = {
  id: string;
  label: string;
  subjectDn: string;
  bytes: Uint8Array;
};

export type KeyGadgetsKeyMaterial = Omit<Pkcs12KeyMaterial, 'privateKeyDer' | 'publicKeyDer'> & {
  privateKeyDer?: Uint8Array;
  publicKeyDer?: Uint8Array;
  csrs?: CsrMaterial[];
  subjectDns?: SubjectDnMaterial[];
};

export type RecognizedKeyInfo = {
  family: 'RSA' | 'EC' | 'Ed25519' | 'Ed448' | 'X25519' | 'X448' | 'Unknown';
  label: string;
  canSign: boolean;
  canDerive: boolean;
  namedCurve?: string;
};

export type KeyAlgorithmCandidate = {
  id: string;
  canonicalId: string;
  canonicalLabel: string;
  algorithm: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  usages: KeyUsage[];
};

export type CertificateKeyUsage = {
  id: string;
  label: string;
  bit: number;
  defaultChecked?: boolean;
};

export type GenerateKeyPairOptions = { createId?: () => string; label?: string };

export type CreateCsrOptions = {
  privateKeyDer: Uint8Array;
  publicKeyDer: Uint8Array;
  subjectDn: string;
  subjectBytes: Uint8Array;
  hashAlgorithm: string;
};

export type CsrResult = { subjectDn: string; hashAlgorithm: string; bytes: Uint8Array };

export type CreateSelfSignedCertificateOptions = {
  privateKeyDer: Uint8Array;
  publicKeyDer: Uint8Array;
  subjectDn: string;
  subjectBytes: Uint8Array;
  hashAlgorithm: string;
  validityDays: number;
  keyUsages: string[];
};

export type CertificateResult = {
  subjectDn: string;
  hashAlgorithm: string;
  validityDays: number;
  bytes: Uint8Array;
};

type Asn1Node = ReturnType<typeof asn1js.fromBER>['result'];

const RSA_SIGNATURE_OIDS: Record<string, string> = {
  'SHA-1': '1.2.840.113549.1.1.5',
  'SHA-256': '1.2.840.113549.1.1.11',
  'SHA-384': '1.2.840.113549.1.1.12',
  'SHA-512': '1.2.840.113549.1.1.13'
};

export const KEY_ALGORITHM_CANDIDATES: KeyAlgorithmCandidate[] = [
  ...createRsaCandidates('RSASSA-PKCS1-v1_5', 'SHA-256', ['sign', 'verify']),
  ...createRsaCandidates('RSA-PSS', 'SHA-256', ['sign', 'verify']),
  ...createRsaCandidates('RSA-OAEP', 'SHA-256', ['encrypt', 'decrypt']),
  ...createNamedCurveCandidates('ECDSA', ['P-256', 'P-384', 'P-521'], ['sign', 'verify']),
  ...createNamedCurveCandidates('ECDH', ['P-256', 'P-384', 'P-521'], ['deriveBits']),
  ...createNamedCurveCandidates('Ed25519', ['Ed25519'], ['sign', 'verify']),
  ...createNamedCurveCandidates('Ed448', ['Ed448'], ['sign', 'verify']),
  ...createNamedCurveCandidates('X25519', ['X25519'], ['deriveBits']),
  ...createNamedCurveCandidates('X448', ['X448'], ['deriveBits'])
];

export const CERTIFICATE_KEY_USAGES: CertificateKeyUsage[] = [
  { id: 'digitalSignature', label: 'digitalSignature', bit: 0 },
  { id: 'nonRepudiation', label: 'nonRepudiation', bit: 1 },
  { id: 'keyEncipherment', label: 'keyEncipherment', bit: 2 },
  { id: 'dataEncipherment', label: 'dataEncipherment', bit: 3 },
  { id: 'keyAgreement', label: 'keyAgreement', bit: 4 },
  { id: 'keyCertSign', label: 'certSign', bit: 5, defaultChecked: true },
  { id: 'cRLSign', label: 'crlSign', bit: 6, defaultChecked: true },
  { id: 'encipherOnly', label: 'encipherOnly', bit: 7 },
  { id: 'decipherOnly', label: 'decipherOnly', bit: 8 }
];

export async function getSupportedKeyAlgorithms(): Promise<KeyAlgorithmCandidate[]> {
  const support = await Promise.all(KEY_ALGORITHM_CANDIDATES.map(async (candidate) => ({
    candidate,
    supported: await isKeyAlgorithmSupported(candidate)
  })));
  const unique = new Map<string, KeyAlgorithmCandidate>();
  for (const item of support) {
    if (item.supported && !unique.has(item.candidate.canonicalId)) unique.set(item.candidate.canonicalId, item.candidate);
  }
  return [...unique.values()];
}

export async function generateKeyPair(
  selection: string,
  options: GenerateKeyPairOptions = {}
): Promise<KeyGadgetsKeyMaterial> {
  const candidate = KEY_ALGORITHM_CANDIDATES.find((item) => item.id === selection);
  if (!candidate) throw new Error(`Unsupported algorithm: ${selection || '(none selected)'}`);
  const generated = await crypto.subtle.generateKey(candidate.algorithm, true, candidate.usages);
  if (!isCryptoKeyPair(generated)) throw new Error('The browser did not return a key pair.');
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.exportKey('pkcs8', generated.privateKey),
    crypto.subtle.exportKey('spki', generated.publicKey)
  ]);
  const material: KeyGadgetsKeyMaterial = {
    id: options.createId?.() ?? createId(),
    privateKeyDer: new Uint8Array(privateKey),
    publicKeyDer: new Uint8Array(publicKey)
  };
  material.label = options.label || recognizeKeyMaterial(material).label;
  return material;
}

export function recognizeKeyMaterial(
  material: Pick<KeyGadgetsKeyMaterial, 'privateKeyDer' | 'publicKeyDer'>
): RecognizedKeyInfo {
  return (material.publicKeyDer ? recognizePublicKey(material.publicKeyDer) : null)
    ?? (material.privateKeyDer ? recognizePrivateKey(material.privateKeyDer) : recognized('Unknown', 'Unknown'));
}

export function extractCertificatePublicKey(certificateDer: Uint8Array): Uint8Array {
  const certificate = Certificate.fromBER(toArrayBuffer(certificateDer));
  return new Uint8Array(certificate.subjectPublicKeyInfo.toSchema().toBER(false));
}

export async function certificateMatchesKey(
  material: Pick<KeyGadgetsKeyMaterial, 'privateKeyDer' | 'publicKeyDer'>,
  certificateDerOrPublicKey: Uint8Array,
  inputKind: 'certificate' | 'public-key' = 'certificate'
): Promise<boolean> {
  const publicKey = inputKind === 'certificate'
    ? extractCertificatePublicKey(certificateDerOrPublicKey)
    : certificateDerOrPublicKey;
  if (material.publicKeyDer) return bytesEqual(material.publicKeyDer, publicKey);
  if (!material.privateKeyDer) throw new Error('A private or public key is required.');
  return verifyPrivateKeyMatchesPublicKey(material.privateKeyDer, publicKey);
}

export async function verifyPrivateKeyMatchesPublicKey(
  privateKeyDer: Uint8Array,
  publicKeyDer: Uint8Array,
  info = recognizeKeyMaterial({ privateKeyDer, publicKeyDer })
): Promise<boolean> {
  try {
    const data = new TextEncoder().encode('Key Gadgets key pair check');
    const algorithms = keyPairCheckAlgorithms(info);
    const [privateKey, publicKey] = await Promise.all([
      crypto.subtle.importKey('pkcs8', toArrayBuffer(privateKeyDer), algorithms.importAlgorithm, false, ['sign']),
      crypto.subtle.importKey('spki', toArrayBuffer(publicKeyDer), algorithms.importAlgorithm, false, ['verify'])
    ]);
    const signature = await crypto.subtle.sign(algorithms.signAlgorithm, privateKey, data);
    return crypto.subtle.verify(algorithms.signAlgorithm, publicKey, signature, data);
  } catch {
    return false;
  }
}

export function createSubjectDn(subjectDn: string): Uint8Array {
  const subject = new RelativeDistinguishedNames({ typesAndValues: parseSubjectDnText(subjectDn) });
  return new Uint8Array(subject.toSchema().toBER(false));
}

export function parseSubjectDn(bytes: Uint8Array): RelativeDistinguishedNames {
  const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
  if (asn1.offset === -1) throw new Error('Invalid SubjectDN DER.');
  if (asn1.offset !== bytes.byteLength) throw new Error('SubjectDN DER has trailing data.');
  return new RelativeDistinguishedNames({ schema: asn1.result });
}

export function subjectDnToString(bytes: Uint8Array): string {
  const subject = parseSubjectDn(bytes);
  if (subject.typesAndValues.length === 0) throw new Error('SubjectDN has no attributes.');
  return [...subject.typesAndValues].reverse().map(formatSubjectAttribute).join(', ');
}

export function getCertificateSubjectDn(certificateDer: Uint8Array): Uint8Array {
  const certificate = Certificate.fromBER(toArrayBuffer(certificateDer));
  return new Uint8Array(certificate.subject.toSchema().toBER(false));
}

export async function createCsr(options: CreateCsrOptions): Promise<CsrResult> {
  const info = recognizeKeyMaterial(options);
  ensureCertificateSigningFamily(info);
  const [privateKey, publicKey] = await Promise.all([
    importSigningPrivateKey(options.privateKeyDer, info, options.hashAlgorithm),
    importSigningPublicKey(options.publicKeyDer, info, options.hashAlgorithm)
  ]);
  const request = new CertificationRequest();
  request.subject = parseSubjectDn(options.subjectBytes);
  await request.subjectPublicKeyInfo.importKey(publicKey);
  request.attributes = [];
  if (info.family === 'RSA') await signCertificationRequestWithRsa(request, privateKey, options.hashAlgorithm);
  else await request.sign(privateKey, options.hashAlgorithm);
  return {
    subjectDn: options.subjectDn,
    hashAlgorithm: options.hashAlgorithm,
    bytes: new Uint8Array(request.toSchema(true).toBER(false))
  };
}

export async function createSelfSignedCertificate(
  options: CreateSelfSignedCertificateOptions
): Promise<CertificateResult> {
  const info = recognizeKeyMaterial(options);
  ensureCertificateSigningFamily(info);
  if (!Number.isInteger(options.validityDays) || options.validityDays < 1 || options.validityDays > 36500) {
    throw new Error('Validity days must be an integer between 1 and 36500.');
  }
  const subject = parseSubjectDn(options.subjectBytes);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + options.validityDays * 86400000);
  const [privateKey, publicKey] = await Promise.all([
    importSigningPrivateKey(options.privateKeyDer, info, options.hashAlgorithm),
    importSigningPublicKey(options.publicKeyDer, info, options.hashAlgorithm)
  ]);
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({ valueHex: toArrayBuffer(randomSerialNumber()) });
  certificate.issuer = subject;
  certificate.subject = subject;
  certificate.notBefore = new Time({ type: 0, value: notBefore });
  certificate.notAfter = new Time({ type: 0, value: notAfter });
  await certificate.subjectPublicKeyInfo.importKey(publicKey);
  certificate.extensions = createCertificateExtensions(options.keyUsages);
  if (info.family === 'RSA') await signCertificateWithRsa(certificate, privateKey, options.hashAlgorithm);
  else await certificate.sign(privateKey, options.hashAlgorithm);
  return {
    subjectDn: options.subjectDn,
    hashAlgorithm: options.hashAlgorithm,
    validityDays: options.validityDays,
    bytes: new Uint8Array(certificate.toSchema(true).toBER(false))
  };
}

export function derToPem(label: string, bytes: Uint8Array): string {
  const base64 = bytesToBase64(bytes);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export function pemToDer(text: string, expectedLabel?: string): Uint8Array {
  const pattern = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/g;
  const blocks: Uint8Array[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const label = match[1];
    const body = match[2];
    if (!label || body === undefined) continue;
    if (expectedLabel && label.toUpperCase() !== expectedLabel.toUpperCase()) continue;
    const base64 = body.replace(/\s+/g, '');
    if (!base64) throw new Error(`PEM block ${label} has no base64 data.`);
    blocks.push(base64ToBytes(base64));
  }
  if (blocks.length === 0) throw new Error(expectedLabel ? `${expectedLabel} PEM was not found.` : 'PEM block was not found.');
  return concatBytes(blocks);
}

export { bytesEqual, toArrayBuffer, readPkcs12, writePkcs12 };

export const KeyGadgetsCore = {
  version: KEY_GADGETS_VERSION,
  keyAlgorithms: KEY_ALGORITHM_CANDIDATES,
  certificateKeyUsages: CERTIFICATE_KEY_USAGES,
  getSupportedKeyAlgorithms,
  generateKeyPair,
  recognizeKeyMaterial,
  extractCertificatePublicKey,
  certificateMatchesKey,
  verifyPrivateKeyMatchesPublicKey,
  createSubjectDn,
  parseSubjectDn,
  subjectDnToString,
  getCertificateSubjectDn,
  createCsr,
  createSelfSignedCertificate,
  readPkcs12,
  writePkcs12,
  derToPem,
  pemToDer,
  bytesEqual,
  toArrayBuffer
};

function createRsaCandidates(name: string, hash: string, usages: KeyUsage[]): KeyAlgorithmCandidate[] {
  return [2048, 3072, 4096].map((modulusLength) => ({
    id: `${name.toLowerCase()}-${modulusLength}`,
    canonicalId: `rsa-${modulusLength}`,
    canonicalLabel: `RSA ${modulusLength}`,
    algorithm: { name, modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash },
    usages
  }));
}

function createNamedCurveCandidates(name: string, curves: string[], usages: KeyUsage[]): KeyAlgorithmCandidate[] {
  return curves.map((namedCurve) => ({
    id: name === namedCurve ? name.toLowerCase() : `${name.toLowerCase()}-${namedCurve.toLowerCase()}`,
    canonicalId: name === 'ECDSA' || name === 'ECDH' ? `ec-${namedCurve.toLowerCase()}` : name.toLowerCase(),
    canonicalLabel: name === 'ECDSA' || name === 'ECDH' ? `EC ${namedCurve}` : name,
    algorithm: name === namedCurve ? { name } : { name, namedCurve },
    usages
  }));
}

async function isKeyAlgorithmSupported(candidate: KeyAlgorithmCandidate): Promise<boolean> {
  try {
    return isCryptoKeyPair(await crypto.subtle.generateKey(candidate.algorithm, true, candidate.usages));
  } catch {
    return false;
  }
}

function isCryptoKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return 'privateKey' in value && 'publicKey' in value;
}

function recognizePublicKey(bytes: Uint8Array): RecognizedKeyInfo | null {
  try {
    const root = parseAsn1(bytes);
    const algorithm = parseAlgorithmIdentifier(readSequenceChild(root, 0));
    if (algorithm.oid === '1.2.840.113549.1.1.1') {
      const modulusBits = readRsaPublicKeyBits(readSequenceChild(root, 1));
      return recognized('RSA', modulusBits ? `RSA ${modulusBits}` : 'RSA');
    }
    return infoFromAlgorithmIdentifier(algorithm.oid, algorithm.parameters);
  } catch {
    return null;
  }
}

function recognizePrivateKey(bytes: Uint8Array): RecognizedKeyInfo {
  try {
    const algorithm = parseAlgorithmIdentifier(readSequenceChild(parseAsn1(bytes), 1));
    if (algorithm.oid === '1.2.840.113549.1.1.1') return recognized('RSA', 'RSA');
    return infoFromAlgorithmIdentifier(algorithm.oid, algorithm.parameters);
  } catch {
    return recognized('Unknown', 'Unknown');
  }
}

function infoFromAlgorithmIdentifier(oid: string, parameters: string | null): RecognizedKeyInfo {
  if (oid === '1.2.840.10045.2.1') {
    const namedCurve = parameters ? curveNameFromOid(parameters) : undefined;
    return recognized('EC', namedCurve ? `EC ${namedCurve}` : 'EC', namedCurve);
  }
  if (oid === '1.3.101.112') return recognized('Ed25519', 'Ed25519');
  if (oid === '1.3.101.113') return recognized('Ed448', 'Ed448');
  if (oid === '1.3.101.110') return recognized('X25519', 'X25519');
  if (oid === '1.3.101.111') return recognized('X448', 'X448');
  return recognized('Unknown', `Unknown (${oid})`);
}

function recognized(family: RecognizedKeyInfo['family'], label: string, namedCurve?: string): RecognizedKeyInfo {
  return {
    family,
    label,
    canSign: ['RSA', 'EC', 'Ed25519', 'Ed448'].includes(family),
    canDerive: ['EC', 'X25519', 'X448'].includes(family),
    namedCurve
  };
}

function keyPairCheckAlgorithms(info: RecognizedKeyInfo): {
  importAlgorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  signAlgorithm: AlgorithmIdentifier | EcdsaParams;
} {
  if (info.family === 'RSA') {
    const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    return { importAlgorithm: algorithm, signAlgorithm: algorithm };
  }
  if (info.family === 'EC' && info.namedCurve) {
    return {
      importAlgorithm: { name: 'ECDSA', namedCurve: info.namedCurve },
      signAlgorithm: { name: 'ECDSA', hash: 'SHA-256' }
    };
  }
  if (info.family === 'Ed25519' || info.family === 'Ed448') {
    const algorithm = { name: info.family };
    return { importAlgorithm: algorithm, signAlgorithm: algorithm };
  }
  throw new Error(`${info.label} cannot be checked with a signature.`);
}

function ensureCertificateSigningFamily(info: RecognizedKeyInfo): void {
  if (info.family !== 'RSA' && info.family !== 'EC') {
    throw new Error(`${info.label} is not supported for certificate or CSR signing.`);
  }
}

async function importSigningPrivateKey(bytes: Uint8Array, info: RecognizedKeyInfo, hash: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', toArrayBuffer(bytes), signingKeyAlgorithm(info, hash), false, ['sign']);
}

async function importSigningPublicKey(bytes: Uint8Array, info: RecognizedKeyInfo, hash: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', toArrayBuffer(bytes), signingKeyAlgorithm(info, hash), true, ['verify']);
}

function signingKeyAlgorithm(info: RecognizedKeyInfo, hash: string): RsaHashedImportParams | EcKeyImportParams {
  if (info.family === 'RSA') return { name: 'RSASSA-PKCS1-v1_5', hash };
  if (info.family === 'EC' && info.namedCurve) return { name: 'ECDSA', namedCurve: info.namedCurve };
  throw new Error(`${info.label} is not supported for signing.`);
}

async function signCertificationRequestWithRsa(
  request: CertificationRequest,
  privateKey: CryptoKey,
  hash: string
): Promise<void> {
  request.signatureAlgorithm = rsaSignatureAlgorithm(hash);
  await signRsaDer(request as unknown as RsaSignable, privateKey);
}

async function signCertificateWithRsa(certificate: Certificate, privateKey: CryptoKey, hash: string): Promise<void> {
  certificate.signature = rsaSignatureAlgorithm(hash);
  certificate.signatureAlgorithm = rsaSignatureAlgorithm(hash);
  await signRsaDer(certificate, privateKey);
}

type RsaSignable = {
  tbsView: Uint8Array;
  signatureValue: asn1js.BitString;
  encodeTBS: () => asn1js.Sequence;
};

async function signRsaDer(target: RsaSignable, privateKey: CryptoKey): Promise<void> {
  target.tbsView = new Uint8Array(target.encodeTBS().toBER(false));
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, toArrayBuffer(target.tbsView));
  target.signatureValue = new asn1js.BitString({ valueHex: signature });
}

function rsaSignatureAlgorithm(hash: string): PkijsAlgorithmIdentifier {
  const algorithmId = RSA_SIGNATURE_OIDS[hash.toUpperCase()];
  if (!algorithmId) throw new Error(`${hash} is not supported for RSA signing.`);
  return new PkijsAlgorithmIdentifier({ algorithmId, algorithmParams: new asn1js.Null() });
}

function createCertificateExtensions(keyUsages: string[]): Extension[] {
  const selected = new Set(keyUsages);
  const basicConstraints = new BasicConstraints({ cA: selected.has('keyCertSign') });
  const keyUsage = createKeyUsageBitString(selected);
  return [
    new Extension({
      extnID: '2.5.29.19',
      critical: selected.has('keyCertSign'),
      extnValue: basicConstraints.toSchema().toBER(false),
      parsedValue: basicConstraints
    }),
    new Extension({
      extnID: '2.5.29.15',
      critical: true,
      extnValue: keyUsage.toBER(false),
      parsedValue: keyUsage
    })
  ];
}

function createKeyUsageBitString(selected: Set<string>): asn1js.BitString {
  const highest = CERTIFICATE_KEY_USAGES.reduce(
    (value, usage) => selected.has(usage.id) ? Math.max(value, usage.bit) : value,
    0
  );
  const bytes = new Uint8Array(Math.floor(highest / 8) + 1);
  for (const usage of CERTIFICATE_KEY_USAGES) {
    if (selected.has(usage.id)) bytes[Math.floor(usage.bit / 8)]! |= 0x80 >> (usage.bit % 8);
  }
  return new asn1js.BitString({ valueHex: toArrayBuffer(bytes) });
}

function randomSerialNumber(): Uint8Array {
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] = (serial[0] ?? 0) & 0x7f;
  if (serial.every((byte) => byte === 0)) serial[15] = 1;
  return serial;
}

function parseSubjectDnText(subjectDn: string): AttributeTypeAndValue[] {
  const parts = splitSubjectDn(subjectDn);
  if (parts.length === 0) throw new Error('SubjectDN is required.');
  return [...parts].reverse().map((part) => {
    const separator = findUnescaped(part, '=');
    if (separator <= 0) throw new Error(`Invalid SubjectDN part: ${part}`);
    const name = unescapeDnValue(part.slice(0, separator).trim());
    const value = unescapeDnValue(part.slice(separator + 1).trim());
    if (!name || !value) throw new Error(`Invalid SubjectDN part: ${part}`);
    return new AttributeTypeAndValue({ type: subjectOid(name), value: subjectValue(name, value) });
  });
}

function splitSubjectDn(value: string): string[] {
  const trimmed = value.trim();
  if (!trimmed) return [];
  return splitEscaped(trimmed.startsWith('/') ? trimmed.slice(1) : trimmed, trimmed.startsWith('/') ? '/' : ',');
}

function splitEscaped(value: string, separator: string): string[] {
  const parts: string[] = [];
  let current = '';
  let escaped = false;
  for (const character of value) {
    if (escaped) {
      current += `\\${character}`;
      escaped = false;
    } else if (character === '\\') {
      escaped = true;
    } else if (character === separator) {
      if (current.trim()) parts.push(current.trim());
      current = '';
    } else {
      current += character;
    }
  }
  if (escaped) current += '\\';
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function findUnescaped(value: string, needle: string): number {
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) escaped = false;
    else if (character === '\\') escaped = true;
    else if (character === needle) return index;
  }
  return -1;
}

function unescapeDnValue(value: string): string {
  return value.replace(/\\([,=\\/])/g, '$1');
}

function subjectOid(name: string): string {
  const names: Record<string, string> = {
    C: '2.5.4.6', ST: '2.5.4.8', S: '2.5.4.8', L: '2.5.4.7', O: '2.5.4.10',
    OU: '2.5.4.11', CN: '2.5.4.3', DC: '0.9.2342.19200300.100.1.25',
    SN: '2.5.4.5', SERIALNUMBER: '2.5.4.5', EMAILADDRESS: '1.2.840.113549.1.9.1'
  };
  const oid = names[name.toUpperCase()] ?? (/^\d+(\.\d+)+$/.test(name) ? name : undefined);
  if (!oid) throw new Error(`Unsupported SubjectDN attribute: ${name}`);
  return oid;
}

function subjectValue(name: string, value: string): asn1js.Utf8String | asn1js.PrintableString | asn1js.IA5String {
  const normalized = name.toUpperCase();
  if (normalized === 'C') return new asn1js.PrintableString({ value });
  if (normalized === 'EMAILADDRESS' || normalized === 'DC') return new asn1js.IA5String({ value });
  return new asn1js.Utf8String({ value });
}

function formatSubjectAttribute(attribute: AttributeTypeAndValue): string {
  const valueBlock = attribute.value.valueBlock as { value?: unknown };
  const value = typeof valueBlock.value === 'string' ? valueBlock.value : attribute.value.toString();
  return `${subjectName(attribute.type)}=${value.replace(/[\\,=\/]/g, (character) => `\\${character}`)}`;
}

function subjectName(oid: string): string {
  const names: Record<string, string> = {
    '2.5.4.6': 'C', '2.5.4.8': 'ST', '2.5.4.7': 'L', '2.5.4.10': 'O',
    '2.5.4.11': 'OU', '2.5.4.3': 'CN', '0.9.2342.19200300.100.1.25': 'DC',
    '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress'
  };
  return names[oid] ?? oid;
}

function parseAsn1(bytes: Uint8Array): Asn1Node {
  const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
  if (asn1.offset === -1 || asn1.offset !== bytes.byteLength) throw new Error('Invalid DER.');
  return asn1.result;
}

function readChildren(node: Asn1Node): Asn1Node[] {
  const block = node.valueBlock as { value?: Asn1Node[] };
  return Array.isArray(block.value) ? block.value : [];
}

function readSequenceChild(node: Asn1Node, index: number): Asn1Node {
  const child = readChildren(node)[index];
  if (!child) throw new Error('Missing ASN.1 sequence child.');
  return child;
}

function parseAlgorithmIdentifier(node: Asn1Node): { oid: string; parameters: string | null } {
  const children = readChildren(node);
  const oid = children[0];
  if (!(oid instanceof asn1js.ObjectIdentifier)) throw new Error('Missing algorithm OID.');
  return {
    oid: oid.valueBlock.toString(),
    parameters: children[1] instanceof asn1js.ObjectIdentifier ? children[1].valueBlock.toString() : null
  };
}

function readRsaPublicKeyBits(node: Asn1Node): number | null {
  if (!(node instanceof asn1js.BitString)) return null;
  const bytes = (node.valueBlock as { valueHexView?: Uint8Array }).valueHexView;
  if (!bytes?.length) return null;
  const modulus = readSequenceChild(parseAsn1(bytes), 0);
  const modulusBytes = (modulus.valueBlock as { valueHexView?: Uint8Array }).valueHexView;
  if (!(modulus instanceof asn1js.Integer) || !modulusBytes?.length) return null;
  let offset = 0;
  while (offset < modulusBytes.length - 1 && modulusBytes[offset] === 0) offset += 1;
  const first = modulusBytes[offset] ?? 0;
  return (modulusBytes.length - offset - 1) * 8 + (first === 0 ? 0 : 32 - Math.clz32(first));
}

function curveNameFromOid(oid: string): string | undefined {
  return {
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34': 'P-384',
    '1.3.132.0.35': 'P-521'
  }[oid];
}

function base64ToBytes(base64: string): Uint8Array {
  if (typeof atob === 'function') return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let binary = '';
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
  }
  return Buffer.from(bytes).toString('base64');
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
