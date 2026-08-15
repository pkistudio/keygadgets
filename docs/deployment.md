# Deployment and Release

## GitHub Pages

`.github/workflows/pages.yml` deploys after every push to `main` and can also
be started manually. The build job installs from the lockfile, audits
dependencies, runs unit and policy tests, performs strict TypeScript checking,
builds the production application, runs the Chromium acceptance suite, checks
the npm package contents, and verifies the local-only Content Security Policy.

Only the validated `dist` directory is uploaded as the Pages artifact. The
deploy job publishes that artifact to the `github-pages` environment, downloads
every public file, and compares it byte-for-byte with the retained build output.
The expected site is:

```text
https://pkistudio.github.io/keygadgets/
```

The Release workflow refuses to release a `main` commit until that exact commit
has a successful `github-pages` deployment.

Pages uses GitHub's short-lived workflow token and OIDC, as required by
`actions/deploy-pages`; it does not use a long-lived personal access token.
Repository administrators must keep **Settings → Pages → Build and deployment →
Source** set to **GitHub Actions**. The `github-pages` environment must allow
`main` without reviewers, wait timers, or custom protection rules.

## GitHub authentication

`KEYGADGETS_GH_TOKEN` may be added as a repository Actions secret when a
dedicated GitHub token is desired. It must be able to read deployments and
create tags and Releases in `pkistudio/keygadgets`. The Release and npm
workflows prefer it for GitHub API access and authenticated checkout/tag
operations, then fall back to the short-lived `github.token` with the explicit
workflow permissions declared in each file.

A GitHub token cannot authenticate to the npm registry. npm publication uses
Trusted Publishing through OIDC. Because `@pkistudio/keygadgets` has not been
published yet, the first publication can instead use a temporary npm publishing
token stored as `NPM_TOKEN` in the `npm` environment.

## Version preparation

Version metadata must reach `main` through a normal pull request before a
Release is created. For example:

```sh
npm run release:prepare -- 0.1.1
npm test
npm run check
npm run build
npm run test:e2e
npm run pack:dry-run
```

The preparation command updates `package.json`, `package-lock.json`,
`src/version.ts`, and the README version marker together. Commit and merge those
changes, then wait for the Pages deployment of that exact commit to succeed.
The initial `0.1.0` metadata is already synchronized and does not need a
preparation commit.

## Create a GitHub Release

Run **Actions → Release → Run workflow** from `main`:

- optionally enter an exact `X.Y.Z` version, without a `v` prefix;
- otherwise select `patch`, `minor`, or `major`;
- enter `RELEASE` as confirmation.

The workflow checks the Pages deployment, resolves the version, verifies that
all version markers were pre-merged, runs package validation, pushes an
annotated version tag, and creates a stable GitHub Release.

## Publish to npm

Create an environment named `npm`. For the first publication, add a temporary
npm publishing token to that environment as `NPM_TOKEN`, then run **Actions →
Publish to npm → Run workflow** with:

- the published GitHub Release version, or leave it blank for the latest;
- authentication `token-bootstrap`;
- confirmation `NPM_RELEASE`.

After the package exists on npm, configure npm Trusted Publishing for:

- GitHub organization: `pkistudio`
- repository: `keygadgets`
- workflow: `npm-publish.yml`
- environment: `npm`

Remove `NPM_TOKEN` after bootstrap. Subsequent publications use authentication
`trusted`; GitHub exchanges the workflow's OIDC identity for short-lived npm
credentials. The workflow accepts only a published, stable GitHub Release,
checks package and lockfile versions, rejects an existing npm version, reruns
the complete validation suite, publishes, and verifies registry availability.

## Local verification

```sh
npm ci
npm run test:e2e:install
npm test
npm run check
npm run build
npm run test:e2e
npm run pack:dry-run
```

Relative Vite asset paths allow the same `dist` directory to run under the
repository subpath and in local preview.
