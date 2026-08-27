# Publishing

## First release

1. Commit the publishing workflow to the default branch.
2. Publish the package once from a clean checkout:

   ```sh
   npm login
   npm ci --ignore-scripts
   npm publish
   ```

   The publish command runs the package checks automatically.

3. In the package settings on npmjs.com, add a **GitHub Actions trusted
   publisher**:
   - Organization or user: `clammet`
   - Repository: `convex-googly-auth`
   - Workflow filename: `release.yml`
   - Environment: leave blank
   - Allowed action: `npm publish`

4. In the GitHub repository's Actions variables, set `NPM_RELEASE_ENABLED=true`.

No `NPM_TOKEN` GitHub secret is required.

## Later releases

### Dependency updates

Renovate adds a patch Changeset containing its dependency update summaries.
After the dependency pull request passes CI and merges, the release workflow
creates a **Version Packages** pull request, enables auto-merge, and publishes
the resulting version to npm after CI passes again. GitHub Action-only and
lockfile-maintenance updates do not publish a package version. The same short
update summaries are written to `CHANGELOG.md` and the GitHub release.

A major peer-dependency update produces a major package release and still waits
for a human to merge the original Renovate pull request.

### Other changes

1. For each user-visible change, run:

   ```sh
   npm run changeset
   ```

   Choose the version bump, write a short description, and commit the generated
   file.

2. Merge the change into `main`. The release workflow will open or update a
   **Version Packages** pull request.
3. Merge the Version Packages pull request to publish the new npm version and
   create the GitHub release.
