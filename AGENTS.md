# Project Guidelines

## Project overview

Key Gadgets is a local-only browser application and reusable TypeScript API for
generating, importing, exporting, and inspecting PKI key material.

## Architecture

- Keep all key and certificate processing client-side.
- Do not implement remote retrieval or telemetry.
- The only allowed dependencies on other PkiStudio packages are the published,
  version-pinned `@pkistudio/dereditor` and `@pkistudio/x509gadgets` npm packages.
- Consume only DerEditor package exports. Do not copy its source, import its
  internal paths, use a Git dependency, or checkout its repository in CI.
- Keep DerEditor interoperability in `src/dereditor-adapter.ts`.
- Keep X.509 Gadgets window transfer interoperability in `src/x509-transfer.ts`.
- Keep reusable key and certificate operations in `src/core.ts`, PKCS#12
  operations in `src/pkcs12.ts`, and DOM behavior in `src/app.ts`.
- Keep the embedded DerEditor read-only. SubjectDN editing belongs to Key
  Gadgets and must not depend on DerEditor DOM internals.

## Development commands

Run before handing off code changes:

```sh
npm test
npm run check
npm run build
npm run test:e2e
npm run pack:dry-run
```

Run `npm run test:e2e:install` once on a new development machine before the
browser suite. Build the production output before running E2E tests.

## Conventions

- Preserve strict TypeScript checks.
- Keep private keys in memory unless a user explicitly exports them.
- Add focused fixtures and tests for cryptographic behavior changes.
- Update specifications when public behavior or dependency boundaries change.
