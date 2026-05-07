# Repo guidance for AI assistants

## What this is

`awsup` is a CLI for submitting and tracking AWS TEAM (the open-source AWS IAM Identity Center JIT access app) elevated-access requests from the terminal. It reads the user's TEAM session from browser localStorage and talks to the deployment's AppSync GraphQL API and Cognito.

## CRITICAL: this repo is public

This repository is public on GitHub. **Never** include identifiable or deployment-specific data in committed code, commit messages, issues, PRs, comments, tests, or fixtures. That includes, but is not limited to:

- Personal names, email addresses, usernames (including `idc_*` Cognito usernames)
- AWS account IDs, account names, OU names
- AWS SSO instance IDs (`ssoins-*`), permission set IDs (`ps-*`), permission set ARNs
- AppSync API IDs, AppSync/Cognito endpoint hostnames, Cognito user/identity pool IDs, Cognito client IDs
- Tenant-specific group names, role names, ticket numbers, Slack channel names, internal email domains
- Any tokens, JWTs, session IDs, request IDs, trace IDs, CloudFront IDs, IPs

When you need to illustrate a problem with a real example (e.g., from a HAR capture or a user's session):

- Redact to generic placeholders before writing it anywhere committed: `ACCOUNT_NAME`, `123456789012`, `arn:aws:sso:::permissionSet/ssoins-XXXX/ps-YYYY`, `user@example.com`, etc.
- Describe the *shape* of the data, not the data itself. "All three entitlements returned `duration: \"2\"`" is fine; pasting the JSON with real account names is not.
- HAR files (`*.har`) and other captures in the working tree are local-only debugging artifacts. Treat their contents as sensitive. Do not quote them verbatim into issues or PRs.

If you're unsure whether something is sensitive, leave it out and ask.

## Code conventions

- Go module is `github.com/drogers0/awsup`. Binary is `awsup`.
- `internal/` packages: `appsync` (GraphQL client + auth), `policy` (entitlements, realtime subscription), `settings` (tenant settings), plus others as the tree grows.
- Prefer editing existing files over adding new ones; don't add speculative abstractions.
- No comments unless the *why* is non-obvious. No attribution lines on commits or PRs.
