# GitHub Actions

## Example SDK updates

`notify-examples.yml` sends `sdk-changed` to `helius-labs/zolana-examples`
after SDK changes land on `main`, or when started manually. It uses a GitHub App
installation token restricted to that repository with Contents write permission.
The token expires after one hour and is revoked at job completion.

Configure the App before merging the authentication change:

1. [Register an organization-owned GitHub App](https://github.com/organizations/helius-labs/settings/apps/new)
   (for example, `zolana-examples-dispatch`). Set the homepage to this repository,
   disable webhooks, allow installation only on this account, and grant repository
   **Contents: Read and write**. No organization permissions are needed.
2. Install the App on `helius-labs`, selecting only `zolana-examples`.
3. Copy its **Client ID** into the `zolana` Actions variable
   `EXAMPLES_DISPATCH_APP_CLIENT_ID`. Generate a private key and store the PEM as
   the `zolana` Actions secret `EXAMPLES_DISPATCH_APP_PRIVATE_KEY`:

   ```sh
   gh variable set EXAMPLES_DISPATCH_APP_CLIENT_ID --repo helius-labs/zolana --body '<client-id>'
   gh secret set EXAMPLES_DISPATCH_APP_PRIVATE_KEY --repo helius-labs/zolana < /path/to/app.private-key.pem
   ```

4. After merging, run `notify-examples.yml` with the desired SDK commit SHA.
   Confirm that dispatch succeeds and `sync-sdk` starts in `zolana-examples`, then
   remove the unused `CROSS_REPO_TOKEN` secret from `zolana`. Check other consumers
   before revoking the underlying PAT; `zolana-examples/notify-docs.yml` also uses
   a secret with that name.

See [GitHub App authentication in Actions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow)
and the [dispatch API permissions](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event).
