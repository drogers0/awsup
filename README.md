# awsup

CLI for submitting and tracking AWS TEAM elevated-access requests from the terminal.

## Install

### Homebrew (coming soon)

A Homebrew formula will be available once the tap is set up:

```sh
# brew install drogers0/tap/awsup  # coming soon
```

### Manual

Download the binary for your platform from the [releases page](https://github.com/drogers0/awsup/releases) and put it in your PATH:

```sh
# macOS arm64 example
curl -L https://github.com/drogers0/awsup/releases/latest/download/darwin-arm64 -o awsup
chmod +x awsup
mv awsup /usr/local/bin/
```

Verify the download against `checksums.txt` on the releases page.

## Setup

1. **Sign into TEAM in your browser.** There is no `awsup login` command — the CLI reads your session from browser localStorage automatically. Supported browsers: Chrome, Edge, Brave, Chromium, Arc.

2. **Run `awsup init`** to auto-discover your deployment's config from your browser session:

   ```sh
   awsup init
   ```

   This scans browser localStorage for an active TEAM session and fetches the remaining config values from the frontend. It then offers to write `~/.config/awsup/default.env` for you. For non-default profiles, use `awsup --profile <name> init`.

   Flags:

   | Flag | Description |
   |------|-------------|
   | `--yes` | Skip confirmation and write immediately |
   | `--print` | Print discovered config only; do not write |

   <details>
   <summary>Manual alternative</summary>

   Create `~/.config/awsup/default.env` with your deployment's values:

   ```env
   TEAM_COGNITO_APP_CLIENT_ID=<your-app-client-id>
   TEAM_APPSYNC_ENDPOINT=https://<your-appsync-id>.appsync-api.<region>.amazonaws.com/graphql
   TEAM_FRONTEND_URL=https://<your-team-frontend-url>
   TEAM_COGNITO_USER_POOL_ID=<region>_<poolid>
   TEAM_COGNITO_HOSTED_UI_DOMAIN=https://<your-domain>.auth.<region>.amazoncognito.com
   ```

   Optional:

   | Variable | Description |
   |----------|-------------|
   | `TEAM_AMPLIFY_USER_AGENT` | Override the Amplify user-agent string sent with AppSync requests. Defaults to `aws-amplify/5.3.26 api/1 framework/1`. |
   </details>

3. **Verify setup:**

   ```sh
   awsup settings
   ```

## Commands

### `awsup request`

Submit an elevated-access request. All flags are optional — you'll be prompted for any that are omitted.

```sh
awsup request \
  --account 123456789012 \
  --role ReadOnlyAccess \
  --duration 4 \
  --justification "Investigating prod incident INC-1234" \
  --ticket INC-1234 \
  --yes
```

Flags:

| Flag | Description |
|------|-------------|
| `--account <id\|name>` | AWS account ID or display name |
| `--role <name\|arn>` | Permission set name or ARN |
| `--duration <hours>` | Duration in hours |
| `--justification <text>` | Business reason |
| `--ticket <ref>` | Ticket reference |
| `--start <iso8601>` | Start time (default: now) |
| `--yes` | Skip confirmation prompt |
| `--json` | Output created request as JSON |

### `awsup list`

List your requests with optional filtering.

```sh
awsup list
awsup list --status pending
awsup list --status approved --json
awsup list --limit 10
```

Flags:

| Flag | Description |
|------|-------------|
| `--status <value>` | Filter by status (pending, approved, active, expired, …) |
| `--limit N` | Max records (default: all) |
| `--json` | Output JSON array |

### `awsup settings`

Show deployment policy constraints (max duration, ticket requirement, approval flow).

```sh
awsup settings
awsup settings --json
```

### `awsup profile ls`

List configured profiles.

```sh
awsup profile ls
```

### Multiple profiles

Use `--profile` (or `-p`) to switch between configurations. Each profile has its own `.env` file and token cache.

```sh
# Use a non-default profile
awsup --profile staging list
awsup -p prod request --account 111222333444 --role AdminAccess --duration 2 --justification "deploy"
```

Profile config files live at `~/.config/awsup/<profile>.env`. For example:

```
~/.config/awsup/default.env   # used without --profile
~/.config/awsup/staging.env   # used with --profile staging
~/.config/awsup/prod.env      # used with --profile prod
```

The `AWSUP_PROFILE` environment variable is also respected as a default profile name.

## Troubleshooting

- **Browser localStorage locked**: The browser is running and its storage is locked. Close the browser and retry.

- **Session expired**: Re-sign into TEAM in your browser, then retry. The CLI will re-read the fresh token automatically.

- **No eligible accounts shown (null policy)**: You have direct account grants rather than group-based entitlements. Enter your account ID and role ARN manually when prompted, or use `--account` and `--role` flags.

- **Requests list is empty or wrong case**: The list query is case-sensitive on the email address. Ensure the email in your TEAM account matches exactly.

## Protocol reference

See [aws-elevated-access-request-flow.md](docs/aws-elevated-access-request-flow.md) for the AppSync protocol details.
