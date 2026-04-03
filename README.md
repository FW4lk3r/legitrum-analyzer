# Legitrum Analyzer

Docker-based compliance analyzer that runs on your infrastructure. Your source code never leaves your servers.

## How it works

1. The container mounts your project directory as read-only
2. It indexes all source files and extracts relevant code snippets
3. Only snippets (max 40KB per criterion) are sent to the Legitrum server for AI evaluation
4. The full source code never leaves your environment

## Usage

### Option 1: Environment variables (quick)

```bash
LEGITRUM_TOKEN=your-token ASSESSMENT_ID=your-assessment-id docker compose up
```

Or with `docker run` directly:

```bash
docker run \
  -e LEGITRUM_TOKEN=your-token \
  -e ASSESSMENT_ID=your-assessment-id \
  -v /path/to/your/project:/repo:ro \
  legitrum/analyzer:latest
```

### Option 2: Secrets file (recommended)

Create a `.env.secrets` file from the example:

```bash
cp .env.example .env.secrets
```

Fill in your token and assessment ID, then run:

```bash
docker compose up
```

The `.env.secrets` file is gitignored and will never be committed.

Both methods work simultaneously — if `.env.secrets` exists it's loaded automatically, and any environment variables you pass will override it.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LEGITRUM_TOKEN` | Yes | — | API token from legitrum.com/settings/tokens |
| `ASSESSMENT_ID` | Yes | — | Assessment ID from Legitrum |
| `LEGITRUM_SERVER` | No | `https://legitrum.com` | Legitrum server URL |
| `LOG_LEVEL` | No | `info` | `info` or `debug` |
| `PROJECT_PATH` | No | `.` | Path to project (docker compose only) |
| `ENABLE_STRICT_VALIDATION` | No | `true` | File validation (magic bytes, entropy) |
| `LOG_DESTINATION` | No | `stderr` | Log output: `stderr` or a file path |
| `APP_ENV` | No | `development` | `development`, `staging`, or `production` (blocked) |

### Persistent Logging

To write logs to a file instead of stderr:

```bash
docker run \
  -e LOG_DESTINATION=/var/log/legitrum/analyzer.log \
  -v /var/log/legitrum:/var/log/legitrum \
  ...
```

Log files are created with `0640` permissions (owner read/write, group read). The directory is created automatically with `0750` permissions if it doesn't exist.

For log aggregation, use Docker's native log drivers instead:

```bash
docker run --log-driver=fluentd ...
docker run --log-driver=awslogs ...
```

## Build

```bash
docker compose build
```

Or without Compose:

```bash
docker build -t legitrum/analyzer .
```

## Security

- [SECURITY.md](SECURITY.md) — Security policy, vulnerability reporting, and input validation
- [DEPENDENCY_SECURITY.md](DEPENDENCY_SECURITY.md) — Dependency audit process and SLAs
- [PATCH_MANAGEMENT_POLICY.md](PATCH_MANAGEMENT_POLICY.md) — Vulnerability response SLAs and patch workflow
- [docs/VULNERABILITY_MANAGEMENT_PROCESS.md](docs/VULNERABILITY_MANAGEMENT_PROCESS.md) — Detailed workflow, triage matrix, and metrics
- [docs/ENCRYPTION_POLICY.md](docs/ENCRYPTION_POLICY.md) — TLS requirements
- [docs/SERVER_VALIDATION_CONTRACT.md](docs/SERVER_VALIDATION_CONTRACT.md) — API contract

## Architecture

```
Your Server                    Legitrum Server
┌─────────────────┐           ┌─────────────────┐
│ Docker Container │    →     │ AI Evaluation    │
│                  │  snippets │                  │
│ Index files      │    ←     │                  │
│ Extract snippets │  results  │ Store findings   │
│ Send to Legitrum │          │ Generate reports │
└─────────────────┘           └─────────────────┘
     /repo (ro)
     Your code stays here
```
