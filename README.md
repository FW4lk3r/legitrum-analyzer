# Legitrum Analyzer

Docker-based compliance analyzer that runs on your infrastructure. Your source code never leaves your servers.

## How it works

1. The container mounts your project directory as read-only
2. It indexes all source files and extracts relevant code snippets
3. Only snippets (max 40KB per criterion) are sent to the Legitrum server for AI evaluation
4. The full source code never leaves your environment

## Usage

```bash
docker run \
  -e LEGITRUM_TOKEN=your-token \
  -e ASSESSMENT_ID=your-assessment-id \
  -v /path/to/your/project:/repo:ro \
  legitrum/analyzer:latest
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LEGITRUM_TOKEN` | Yes | — | API token from legitrum.com/settings/tokens |
| `ASSESSMENT_ID` | Yes | — | Assessment ID from Legitrum |
| `LEGITRUM_SERVER` | No | `https://legitrum.com` | Legitrum server URL |
| `LOG_LEVEL` | No | `info` | `info` or `debug` |

## Build

```bash
docker build -t legitrum/analyzer .
```

## Architecture

```
Your Server                    Legitrum Server
┌─────────────────┐           ┌─────────────────┐
│ Docker Container │    →     │ AI Evaluation    │
│                  │  snippets │ (Anthropic API)  │
│ Index files      │    ←     │                  │
│ Extract snippets │  results  │ Store findings   │
│ Send to Legitrum │          │ Generate reports │
└─────────────────┘           └─────────────────┘
     /repo (ro)
     Your code stays here
```
