# commit-audit

Mistral Workflow that audits new commits on a watched branch of a GitHub repository
(default: `croffasia/itsaplan@main`) for security and logic issues, one commit at a
time, and returns a Markdown report.

## How it works

1. Reads the last reviewed SHA from `commit-audit/state.json` in this repository
   (or from the input `since_sha`).
2. Lists new commits on the watched branch via the GitHub API.
3. For each commit: fetches the diff and the linked PR's check runs, then asks a
   Mistral model to review it against a security/correctness checklist
   (auth bypass, share-link access control, XSS, SQL injection, SSRF, secrets,
   race conditions, contradictions, migration safety, CI status).
4. Writes the report as the execution result and advances the state to the new head.

## Configuration

- Input: `{owner, repo, branch, since_sha?, max_commits?}`
- `GITHUB_TOKEN` (workspace secret bound to the deployment): raises the GitHub API
  rate limit and allows writing the state file. Public repos also work without it.
- `AUDIT_MODEL`: model used for the review (default `mistral-large-latest`).

## Deploy

Managed deployment built from this directory (`build_directory=commit-audit`,
`Dockerfile` at its root). The schedule is managed from Mistral Studio
(cron `0 * * * *`, hourly).

## Tests

```bash
uv run pytest tests/
```
