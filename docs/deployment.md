# Deployment

## Static application

`npm run build` produces the complete static application under `dist/`. The
Vite base is relative, so the same artifact can be served from GitHub Pages or
another static subpath without modification.

The checked-in Pages workflow validates tests and the production build before
uploading `dist/`. Configure the repository Pages source as **GitHub Actions**
before the first deployment.

## Security boundary

The production HTML contains a Content Security Policy with `connect-src
'none'`. No runtime asset is loaded from a CDN. DerEditor code, OID data, and
icons are resolved from the pinned npm package during the build.

## Package verification

Before npm publication, run:

```sh
npm ci
npm test
npm run check
npm run build
npm run test:e2e
npm run pack:dry-run
```

Publication is a separate explicit operation and is not triggered by the Pages
workflow.
