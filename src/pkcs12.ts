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
import { bytesEqual, createId, toArrayBuffer } from './internal';

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
        if (certificate) certificates.push({
          localKeyId: getLocalKeyId(bag),
          certificate,
          publicKeyDer: toDer(certificate.subjectPublicKeyInfo)
        });
      }
    }
  }

  if (privateKeys.length === 0) throw new Error('No private key was found in the PKCS#12 file.');
  const unmatchedCertificates = [...certificates];
  const materials: Pkcs12KeyMaterial[] = [];
  for (const privateKey of privateKeys) {
    const privateKeyDer = toDer(privateKey.privateKeyInfo);
    const derivedPublicKeyDer = await derivePublicKey(privateKey.privateKeyInfo);
    const certificate = takeMatchingCertificate(privateKey, unmatchedCertificates, derivedPublicKeyDer);
    materials.push({
      id: options.createId?.() ?? createId(),
      label: privateKey.friendlyName || privateKey.localKeyId || undefined,
      privateKeyDer,
      publicKeyDer: certificate ? certificate.publicKeyDer : derivedPublicKeyDer,
      certificateDer: certificate ? toDer(certificate.certificate) : undefined,
      sourceName: options.sourceName
    });
  }
  return materials;
}

export async function writePkcs12(keys: Pkcs12ExportKeyMaterial[], password: string): Promise<Uint8Array> {
  if (keys.length === 0) throw new Error('No key pair was selected.');

  const passwordBuffer = toArrayBuffer(new TextEncoder().encode(password));
  const safeBags: SafeBag[] = [];
  for (const key of keys) {
    if (!key.privateKeyDer) throw new Error(`${key.label || 'Selected key pair'} does not have a private key.`);

    const privateKeyInfo = PrivateKeyInfo.fromBER(toArrayBuffer(key.privateKeyDer));
    const localKeyId = randomBytes(20);
    const bagAttributes = createBagAttributes(key.label, localKeyId);
    const shroudedKeyBag = new PKCS8ShroudedKeyBag({
      parsedValue: privateKeyInfo
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
      const certificate = Certificate.fromBER(toArrayBuffer(key.certificateDer));
      const publicKeyDer = await derivePublicKey(privateKeyInfo);
      if (publicKeyDer && !bytesEqual(publicKeyDer, toDer(certificate.subjectPublicKeyInfo))) {
        throw new Error(`${key.label || 'Selected key pair'} has a certificate that does not match its private key.`);
      }
      safeBags.push(new SafeBag({
        bagId: OID_PKCS12_CERT_BAG,
        bagValue: new CertBag({ parsedValue: certificate }),
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
  publicKeyDer: Uint8Array;
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

function takeMatchingCertificate(
  privateKey: IndexedPrivateKey,
  certificates: IndexedCertificate[],
  publicKeyDer: Uint8Array | undefined
): IndexedCertificate | undefined {
  if (certificates.length === 0) return undefined;
  if (privateKey.localKeyId) {
    const matchIndex = certificates.findIndex((certificate) => {
      return certificate.localKeyId === privateKey.localKeyId
        && (!publicKeyDer || bytesEqual(certificate.publicKeyDer, publicKeyDer));
    });
    if (matchIndex !== -1) return certificates.splice(matchIndex, 1)[0];
  }
  if (publicKeyDer) {
    const matchIndex = certificates.findIndex((certificate) => bytesEqual(certificate.publicKeyDer, publicKeyDer));
    return matchIndex === -1 ? undefined : certificates.splice(matchIndex, 1)[0];
  }
  return certificates.shift();
}

async function derivePublicKey(privateKeyInfo: PrivateKeyInfo): Promise<Uint8Array | undefined> {
  try {
    const parameters = publicKeyDerivationParameters(privateKeyInfo);
    if (!parameters) return undefined;
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      toArrayBuffer(toDer(privateKeyInfo)),
      parameters.algorithm,
      true,
      parameters.privateUsages
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', privateKey);
    delete publicJwk.d;
    delete publicJwk.p;
    delete publicJwk.q;
    delete publicJwk.dp;
    delete publicJwk.dq;
    delete publicJwk.qi;
    delete publicJwk.oth;
    publicJwk.key_ops = [...parameters.publicUsages];
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicJwk,
      parameters.algorithm,
      true,
      parameters.publicUsages
    );
    return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  } catch {
    return undefined;
  }
}

function publicKeyDerivationParameters(privateKeyInfo: PrivateKeyInfo): {
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  privateUsages: KeyUsage[];
  publicUsages: KeyUsage[];
} | undefined {
  const oid = privateKeyInfo.privateKeyAlgorithm.algorithmId;
  if (oid === '1.2.840.113549.1.1.1') {
    return {
      algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      privateUsages: ['sign'],
      publicUsages: ['verify']
    };
  }
  if (oid === '1.2.840.10045.2.1') {
    const curveOid = privateKeyInfo.privateKeyAlgorithm.algorithmParams;
    const namedCurve = curveOid instanceof asn1js.ObjectIdentifier ? curveNameFromOid(curveOid.valueBlock.toString()) : undefined;
    return namedCurve ? {
      algorithm: { name: 'ECDSA', namedCurve },
      privateUsages: ['sign'],
      publicUsages: ['verify']
    } : undefined;
  }
  const name = {
    '1.3.101.112': 'Ed25519',
    '1.3.101.113': 'Ed448',
    '1.3.101.110': 'X25519',
    '1.3.101.111': 'X448'
  }[oid];
  if (!name) return undefined;
  const signing = name === 'Ed25519' || name === 'Ed448';
  return {
    algorithm: { name },
    privateUsages: signing ? ['sign'] : ['deriveBits'],
    publicUsages: signing ? ['verify'] : []
  };
}

function curveNameFromOid(oid: string): string | undefined {
  return {
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34': 'P-384',
    '1.3.132.0.35': 'P-521'
  }[oid];
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
