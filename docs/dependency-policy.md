# Dependency Policy

## PkiStudio boundary

`@pkistudio/dereditor` is the only allowed runtime dependency whose package
name begins with `@pkistudio/`. It must be installed from npm at an exact
version and used only through exports declared by its `package.json`.

The project must not:

- depend on `@pkistudio/pvkgadgets`, `@pkistudio/certgadgets`, or
  `@pkistudio/pkistudiojs`;
- copy DerEditor implementation files into this repository;
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
