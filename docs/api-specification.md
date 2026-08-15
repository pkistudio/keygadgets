# Key Gadgets API Specification

## Package entry points

| Entry point | Contract |
| --- | --- |
| `@pkistudio/keygadgets` | Core API |
| `@pkistudio/keygadgets/core` | Core API alias |
| `@pkistudio/keygadgets/pkcs12` | PKCS#12 API |
| `@pkistudio/keygadgets/app` | Browser application API |
| `@pkistudio/keygadgets/styles.css` | Browser application stylesheet |

## Core

The Core entry point exports individual functions and the `KeyGadgetsCore`
namespace object.

### Key generation

- `getSupportedKeyAlgorithms()` probes the active WebCrypto implementation and
  returns one candidate for each supported canonical key type.
- `generateKeyPair(selection, options?)` returns extractable PKCS#8 private-key
  and SPKI public-key DER bytes.
- `recognizeKeyMaterial(material)` identifies RSA, EC, Ed25519, Ed448, X25519,
  X448, or unknown material.
- `verifyPrivateKeyMatchesPublicKey(privateKeyDer, publicKeyDer)` performs a
  sign/verify check for signing key families.
- `certificateMatchesKey(material, input, inputKind?)` compares or verifies a
  certificate or SPKI public key against a key material object.

### SubjectDN, CSR, and certificate

- `createSubjectDn(text)` encodes comma-form or slash-form SubjectDN text.
- `parseSubjectDn(bytes)` parses an encoded RDNSequence.
- `subjectDnToString(bytes)` returns escaped comma-form text.
- `createCsr(options)` creates a PKCS#10 CSR for RSA or EC keys.
- `createSelfSignedCertificate(options)` creates a v3 RSA or EC certificate.
- `extractCertificatePublicKey(certificateDer)` returns SPKI DER.
- `getCertificateSubjectDn(certificateDer)` returns subject RDNSequence DER.

Supported SubjectDN names are C, ST/S, L, O, OU, CN, DC, SN/serialNumber,
emailAddress, and dotted-decimal OIDs. C uses PrintableString; DC and
emailAddress use IA5String; other values use UTF8String.

### Representations

- `derToPem(label, bytes)`
- `pemToDer(text, expectedLabel?)`
- `bytesEqual(left, right)`
- `toArrayBuffer(bytes)`

## PKCS#12

`readPkcs12(bytes, password, options?)` reads key bags, shrouded key bags, and
X.509 certificate bags. It matches keys and certificates by localKeyId where
available.

`writePkcs12(keys, password)` writes one or more private keys and optional
certificates. A missing private key is rejected.

The aliases `readPkcs12Keys` and `writePkcs12Keys` are also exported.

## Browser application

`initKeyGadgets(options?)` returns:

```ts
type KeyGadgetsAppInstance = {
  readonly materials: readonly KeyGadgetsKeyMaterial[];
  readonly selectedMaterial: KeyGadgetsKeyMaterial | null;
  loadBytes(bytes, sourceName?, password?): Promise<readonly KeyGadgetsKeyMaterial[]>;
  generate(algorithmId, label?): Promise<KeyGadgetsKeyMaterial>;
  close(): void;
};
```

The `host` option can provide `confirm`, `prompt`, and `saveFile` callbacks.
Browser defaults are used when a callback is omitted.

The embedded DerEditor is initialized with the packaged OID Resolver and
`editable: false`. Key Gadgets does not depend on its DOM structure.
DerEditor transfers open in a separate editable `viewer.html`; the transferred
subtree is independent and does not update the Key Gadgets application state.

The browser UI can open a selected certificate in the published X.509 Gadgets
App through **Send to > X509 Gadgets**. A local `x509-viewer.html` entry imports
only the package's public `./app` and `./styles.css` exports. The two same-origin
windows exchange a copied DER `ArrayBuffer` through an authenticated,
one-time `postMessage` handshake; the transfer is not part of the public Key
Gadgets App API and does not modify the source material.

## Errors and compatibility

Parsing, conversion, unsupported algorithms, password failures, and missing
required objects throw `Error`. Error text is diagnostic and is not a stable
machine-readable code.

Only exported declarations and package entry points are stable. PKIjs objects,
application DOM structure, and implementation helpers are not public API.
