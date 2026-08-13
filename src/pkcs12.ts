import * as asn1js from 'asn1js';
import {
  Attribute,
  AuthenticatedSafe,
  CertBag,
  Certificate,
  PFX,
  PKCS8ShroudedKeyBag,
  PrivateKeyInfo,
  SafeBag,
  SafeContents,
  id_CertBag_X509Certificate
} from 'pkijs';
import { createId, toArrayBuffer } from './internal';

export type Pkcs12KeyMaterial = {
  id: string;
  label?: string;
  privateKeyDer: Uint8Array;
  publicKeyDer?: Uint8Array;
  certificateDer?: Uint8Array;
  sourceName?: string;
};

export type Pkcs12ExportKeyMaterial = {
  label?: string;
  privateKeyDer?: Uint8Array;
  certificateDer?: Uint8Array;
};

export type ReadPkcs12Options = {
  sourceName?: string;
  createId?: () => string;
};

const OID_PKCS12_KEY_BAG = '1.2.840.113549.1.12.10.1.1';
const OID_PKCS12_SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
const OID_PKCS12_CERT_BAG = '1.2.840.113549.1.12.10.1.3';
const OID_FRIENDLY_NAME = '1.2.840.113549.1.9.20';
const OID_LOCAL_KEY_ID = '1.2.840.113549.1.9.21';

export async function readPkcs12(
  bytes: Uint8Array,
  password: string,
  options: ReadPkcs12Options = {}
): Promise<Pkcs12KeyMaterial[]> {
  const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
  if (asn1.offset === -1 || asn1.offset !== bytes.byteLength) throw new Error('Invalid PKCS#12 ASN.1.');

  const passwordBuffer = toArrayBuffer(new TextEncoder().encode(password));
  const pfx = new PFX({ schema: asn1.result });
  await pfx.parseInternalValues({ password: passwordBuffer, checkIntegrity: Boolean(pfx.macData) });

  const authenticatedSafe = pfx.parsedValue?.authenticatedSafe;
  if (!authenticatedSafe) throw new Error('PKCS#12 authenticatedSafe was not found.');
  await authenticatedSafe.parseInternalValues({
    safeContents: authenticatedSafe.safeContents.map(() => ({ password: passwordBuffer }))
  });

  const privateKeys: IndexedPrivateKey[] = [];
  const certificates: IndexedCertificate[] = [];
  for (const parsedSafeContent of readParsedSafeContents(authenticatedSafe.parsedValue)) {
    for (const bag of parsedSafeContent.value.safeBags) {
      if (bag.bagId === OID_PKCS12_KEY_BAG && bag.bagValue instanceof PrivateKeyInfo) {
        privateKeys.push(indexPrivateKey(bag, bag.bagValue));
        continue;
      }
      if (bag.bagId === OID_PKCS12_SHROUDED_KEY_BAG && bag.bagValue instanceof PKCS8ShroudedKeyBag) {
        await parseShroudedKeyBag(bag.bagValue, passwordBuffer);
        if (!bag.bagValue.parsedValue) throw new Error('Could not decrypt a PKCS#12 private key bag.');
        privateKeys.push(indexPrivateKey(bag, bag.bagValue.parsedValue));
        continue;
      }
      if (bag.bagId === OID_PKCS12_CERT_BAG && bag.bagValue instanceof CertBag) {
        const certificate = readX509Certificate(bag.bagValue);
        if (certificate) certificates.push({ localKeyId: getLocalKeyId(bag), certificate });
      }
    }
  }

  if (privateKeys.length === 0) throw new Error('No private key was found in the PKCS#12 file.');
  return privateKeys.map((privateKey, index) => {
    const certificate = findMatchingCertificate(privateKey, certificates, index);
    return {
      id: options.createId?.() ?? createId(),
      label: privateKey.friendlyName || privateKey.localKeyId || undefined,
      privateKeyDer: toDer(privateKey.privateKeyInfo),
      publicKeyDer: certificate ? toDer(certificate.subjectPublicKeyInfo) : undefined,
      certificateDer: certificate ? toDer(certificate) : undefined,
      sourceName: options.sourceName
    };
  });
}

export async function writePkcs12(keys: Pkcs12ExportKeyMaterial[], password: string): Promise<Uint8Array> {
  if (keys.length === 0) throw new Error('No key pair was selected.');

  const passwordBuffer = toArrayBuffer(new TextEncoder().encode(password));
  const safeBags: SafeBag[] = [];
  for (const key of keys) {
    if (!key.privateKeyDer) throw new Error(`${key.label || 'Selected key pair'} does not have a private key.`);

    const localKeyId = randomBytes(20);
    const bagAttributes = createBagAttributes(key.label, localKeyId);
    const shroudedKeyBag = new PKCS8ShroudedKeyBag({
      parsedValue: PrivateKeyInfo.fromBER(toArrayBuffer(key.privateKeyDer))
    });
    await shroudedKeyBag.makeInternalValues({
      password: passwordBuffer,
      contentEncryptionAlgorithm: { name: 'AES-CBC', length: 256, iv: toArrayBuffer(randomBytes(16)) },
      hmacHashAlgorithm: 'SHA-256',
      iterationCount: 100000
    });

    safeBags.push(new SafeBag({
      bagId: OID_PKCS12_SHROUDED_KEY_BAG,
      bagValue: shroudedKeyBag,
      bagAttributes
    }));
    if (key.certificateDer) {
      safeBags.push(new SafeBag({
        bagId: OID_PKCS12_CERT_BAG,
        bagValue: new CertBag({ parsedValue: Certificate.fromBER(toArrayBuffer(key.certificateDer)) }),
        bagAttributes
      }));
    }
  }

  const authenticatedSafe = new AuthenticatedSafe({
    parsedValue: { safeContents: [{ privacyMode: 0, value: new SafeContents({ safeBags }) }] }
  });
  await authenticatedSafe.makeInternalValues({ safeContents: [{}] });

  const pfx = new PFX({ parsedValue: { integrityMode: 0, authenticatedSafe } });
  await pfx.makeInternalValues({
    password: passwordBuffer,
    iterations: 100000,
    pbkdf2HashAlgorithm: { name: 'SHA-256' },
    hmacHashAlgorithm: 'SHA-256'
  });
  return new Uint8Array(pfx.toSchema().toBER(false));
}

export const readPkcs12Keys = readPkcs12;
export const writePkcs12Keys = writePkcs12;

type IndexedPrivateKey = {
  friendlyName: string | null;
  localKeyId: string | null;
  privateKeyInfo: PrivateKeyInfo;
};

type IndexedCertificate = {
  localKeyId: string | null;
  certificate: Certificate;
};

type ParsedSafeContent = { value: SafeContents };
type ShroudedKeyParser = { parseInternalValues: (parameters: { password: ArrayBuffer }) => Promise<void> };

function indexPrivateKey(bag: SafeBag, privateKeyInfo: PrivateKeyInfo): IndexedPrivateKey {
  return { friendlyName: getFriendlyName(bag), localKeyId: getLocalKeyId(bag), privateKeyInfo };
}

function readParsedSafeContents(parsedValue: unknown): ParsedSafeContent[] {
  if (!isRecord(parsedValue) || !Array.isArray(parsedValue.safeContents)) {
    throw new Error('PKCS#12 safe contents were not parsed.');
  }
  return parsedValue.safeContents.filter((content): content is ParsedSafeContent => {
    return isRecord(content) && content.value instanceof SafeContents;
  });
}

async function parseShroudedKeyBag(bag: PKCS8ShroudedKeyBag, password: ArrayBuffer): Promise<void> {
  await (bag as unknown as ShroudedKeyParser).parseInternalValues({ password });
}

function readX509Certificate(certBag: CertBag): Certificate | null {
  if (certBag.certId !== id_CertBag_X509Certificate) return null;
  if (certBag.parsedValue instanceof Certificate) return certBag.parsedValue;
  throw new Error('PKCS#12 certificate bag did not contain an X.509 certificate.');
}

function findMatchingCertificate(
  privateKey: IndexedPrivateKey,
  certificates: IndexedCertificate[],
  fallbackIndex: number
): Certificate | undefined {
  if (certificates.length === 0) return undefined;
  if (privateKey.localKeyId) {
    const match = certificates.find((certificate) => certificate.localKeyId === privateKey.localKeyId);
    if (match) return match.certificate;
  }
  return certificates[Math.min(fallbackIndex, certificates.length - 1)]?.certificate;
}

function getLocalKeyId(bag: SafeBag): string | null {
  const attribute = bag.bagAttributes?.find((item) => item.type === OID_LOCAL_KEY_ID);
  const value = attribute?.values[0];
  return value instanceof asn1js.OctetString ? toHex(value.valueBlock.valueHexView) : null;
}

function getFriendlyName(bag: SafeBag): string | null {
  const attribute = bag.bagAttributes?.find((item) => item.type === OID_FRIENDLY_NAME);
  const value = attribute?.values[0];
  return value instanceof asn1js.BmpString || value instanceof asn1js.Utf8String
    ? value.valueBlock.value
    : null;
}

function createBagAttributes(label: string | undefined, localKeyId: Uint8Array): Attribute[] {
  const attributes = [new Attribute({
    type: OID_LOCAL_KEY_ID,
    values: [new asn1js.OctetString({ valueHex: toArrayBuffer(localKeyId) })]
  })];
  if (label) attributes.unshift(new Attribute({
    type: OID_FRIENDLY_NAME,
    values: [new asn1js.BmpString({ value: label })]
  }));
  return attributes;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toDer(value: { toSchema: () => { toBER: (sizeOnly?: boolean) => ArrayBuffer } }): Uint8Array {
  return new Uint8Array(value.toSchema().toBER(false));
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
