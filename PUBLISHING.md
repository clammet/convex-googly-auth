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
