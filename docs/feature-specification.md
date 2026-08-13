# Key Gadgets Feature Specification

## Scope

Key Gadgets creates and manages PKI key material supplied by or generated for
the user. All operations are local. Private key material is not persisted
unless a host or user explicitly saves it.

## Key material

The application supports WebCrypto key-pair generation for browser-supported
RSA, EC, Ed25519, Ed448, X25519, and X448 algorithms. Duplicate WebCrypto
generation modes that produce the same canonical key encoding are shown once.

A key workspace item can contain a PKCS#8 private key, SPKI public key,
certificate, multiple SubjectDN values, and multiple CSRs.

## Import and export

The browser application accepts PEM or DER PKCS#8 private keys, SPKI public
keys, X.509 certificates, and `.p12`/`.pfx` PKCS#12 files. PKCS#12 import and
export require an explicit password prompt or host-supplied password.

Individual private keys, public keys, certificates, and CSRs are exported as
PEM. SubjectDN values are exported as DER. PKCS#12 export includes the selected
private key and its certificate when available.

## SubjectDN and issuance

SubjectDN values are created and edited in a Key Gadgets-owned form. The
embedded ASN.1 viewer never acts as the source of editable SubjectDN state.

RSA and EC key pairs can create SHA-256, SHA-384, or SHA-512 PKCS#10 CSRs and
self-signed certificates. Certificate validity is bounded to 1 through 36,500
days. Users select X.509 KeyUsage bits; BasicConstraints reflects whether
keyCertSign is selected.

## DerEditor

Every selected DER object is displayed using the published
`@pkistudio/dereditor` Viewer and packaged OID Resolver. The embedded viewer is
always read-only. Integration uses only documented package exports and public
Viewer methods.

DerEditor's public **Send to > New Window** action opens an independent,
editable standalone viewer at `viewer.html`. Changes in that standalone viewer
are deliberately not synchronized back into Key Gadgets state.

## Browser layout

The desktop layout follows Private Key Gadgets: a compact application toolbar,
a resizable key-material tree on the left, the read-only ASN.1 viewer on the
right, and a resizable API log along the bottom. Key generation and selected
item actions use toolbar menus. SubjectDN, CSR, and self-signed certificate
options use focused dialogs rather than a permanent side panel. Narrow screens
stack the key and viewer panels without changing operations.

Tree folder and key icons open contextual command menus without expanding or
collapsing their nodes. The parent menu loads certificates from files or PEM
and hexadecimal clipboard text, creates SubjectDN values, and deletes the key
pair. Private-key and public-key menus expose the applicable creation and
deletion commands. These commands share the same handlers as the Actions menu.

## Network and dependency boundary

The application performs no network requests. The production Content Security
Policy sets `connect-src 'none'`. Runtime code and OID data are bundled from
installed npm packages; no CDN or repository URL is used.

Only the exact published DerEditor npm package is allowed from the PkiStudio
scope. Automated tests enforce source, lockfile, workflow, and package policy.

## Initial compatibility limits

- CSR and certificate creation initially supports RSA and named-curve EC keys.
- Key matching through signatures applies only to signing key families.
- PKCS#12 import supports PKIjs-compatible key, shrouded-key, and X.509
  certificate bags; uncommon proprietary bag types are ignored.
- Browser algorithm availability follows the active WebCrypto implementation.
