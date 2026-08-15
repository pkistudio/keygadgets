# Dependency Policy

## PkiStudio boundary

`@pkistudio/dereditor` and `@pkistudio/x509gadgets` are the only allowed runtime
dependencies whose package names begin with `@pkistudio/`. They must be
installed from npm at exact versions and used only through exports declared by
their `package.json` files.

X.509 Gadgets integration uses only its published `./app` and `./styles.css`
exports. Key Gadgets does not copy its implementation, import internal paths,
or retrieve code from its repository at build or runtime.

The project must not:

- depend on `@pkistudio/pvkgadgets`, `@pkistudio/certgadgets`, or
  `@pkistudio/pkistudiojs`;
- copy DerEditor or X.509 Gadgets implementation files into this repository;
- use Git URLs, submodules, workspace links, or unpublished DerEditor paths;
- checkout another PkiStudio repository in CI; or
- retrieve runtime code or OID data from a CDN or repository URL.

## General dependencies

PKIjs and ASN1js provide standards-oriented PKI and ASN.1 models. Exact direct
dependency versions and the npm lockfile make updates reviewable.

## Enforcement

Tests inspect `package.json`, the lockfile, source imports, CI workflows, and
browser source. Dependency updates must be isolated and validated through the
normal review process.
