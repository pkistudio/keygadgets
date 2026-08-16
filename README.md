# Key Gadgets

Key Gadgets is a local-only browser application and reusable TypeScript API for
generating, importing, exporting, and inspecting PKI key material.

Current version: 0.1.3

Private keys, certificates, CSRs, SubjectDN values, and PKCS#12 files stay in
browser memory unless the user explicitly exports them. The application does
not retrieve remote resources or send telemetry, and its production page sets
`connect-src 'none'`.

## Features

- Generate browser-supported RSA, EC, Ed25519, Ed448, X25519, and X448 key
  pairs through WebCrypto.
- Import and export PKCS#8 private keys, SPKI public keys, certificates, and
  password-protected PKCS#12 files.
- Recognize key families and common RSA sizes and named EC curves.
- Create and edit SubjectDN values in Key Gadgets-owned forms.
- Create PKCS#10 CSRs and self-signed certificates for RSA and EC keys.
- Match certificates and public keys to private keys.
- Inspect every DER object in an embedded read-only DerEditor.
- Send a certificate directly to an independent X.509 Gadgets viewer window.
- Use the Core, PKCS#12, and browser App APIs independently.

## Independence

The only runtime dependencies on other PkiStudio packages are the published,
version-pinned `@pkistudio/dereditor` and `@pkistudio/x509gadgets` packages. Key
Gadgets does not consume source, internal paths, workflows, Git branches, or
unpublished APIs from any PkiStudio repository.

DerEditor integration is isolated in `src/dereditor-adapter.ts`. The embedded
viewer receives DER bytes and is always read-only. SubjectDN editing does not
use or observe DerEditor DOM internals. A subtree sent to the standalone
DerEditor window may be edited independently and is not synchronized back.
X.509 Gadgets integration uses only its published App and stylesheet exports;
certificate DER is copied directly to its standalone window without network or
persistent-storage transfer.

See [the dependency policy](docs/dependency-policy.md) for the enforced rules.

## Install

```sh
npm install @pkistudio/keygadgets
```

Package exports:

- `@pkistudio/keygadgets`: Core API
- `@pkistudio/keygadgets/core`: Core API alias
- `@pkistudio/keygadgets/pkcs12`: PKCS#12 helpers
- `@pkistudio/keygadgets/app`: browser application initializer
- `@pkistudio/keygadgets/styles.css`: application stylesheet

## Core API

```ts
import {
  createSubjectDn,
  generateKeyPair,
  createCsr
} from '@pkistudio/keygadgets';

const key = await generateKeyPair('ecdsa-p-256');
const subjectDn = 'CN=example.test, O=Example, C=US';
const subjectBytes = createSubjectDn(subjectDn);

const csr = await createCsr({
  privateKeyDer: key.privateKeyDer!,
  publicKeyDer: key.publicKeyDer!,
  subjectDn,
  subjectBytes,
  hashAlgorithm: 'SHA-256'
});

console.log(csr.bytes.byteLength);
```

## PKCS#12 API

```ts
import { readPkcs12, writePkcs12 } from '@pkistudio/keygadgets/pkcs12';

const pfx = await writePkcs12([key], 'password');
const imported = await readPkcs12(pfx, 'password');
```

PKCS#12 exports use a shrouded PKCS#8 key bag with AES-256-CBC, SHA-256-based
integrity protection, and 100,000 iterations. The browser app saves every
workspace item containing a private key into one PKCS#12 file and reloads all
of them. For supported algorithms, a public key is recovered from the private
key when no certificate is present.

## Browser app

```ts
import { initKeyGadgets } from '@pkistudio/keygadgets/app';
import '@pkistudio/keygadgets/styles.css';

const app = initKeyGadgets({
  mount: '#app',
  theme: 'dark',
  host: {
    saveFile: async ({ bytes, suggestedName }) => {
      console.log('save', suggestedName, bytes.byteLength);
    }
  }
});

await app.generate('ecdsa-p-256', 'Signing key');
```

Host callbacks keep file storage, prompts, and confirmation behavior outside
the reusable package.

## Development

```sh
npm install
npm test
npm run check
npm run build
npm run test:e2e:install
npm run test:e2e
npm run pack:dry-run
```

Use `npm run dev` during development. See the
[feature specification](docs/feature-specification.md),
[API specification](docs/api-specification.md), and
[deployment guide](docs/deployment.md) for stable behavior and distribution
details.

## License

MIT
