# mcp-email-server

[![Release](https://img.shields.io/github/v/release/ai-zerolab/mcp-email-server)](https://img.shields.io/github/v/release/ai-zerolab/mcp-email-server)
[![Build status](https://img.shields.io/github/actions/workflow/status/ai-zerolab/mcp-email-server/main.yml?branch=main)](https://github.com/ai-zerolab/mcp-email-server/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/ai-zerolab/mcp-email-server/branch/main/graph/badge.svg)](https://codecov.io/gh/ai-zerolab/mcp-email-server)
[![Commit activity](https://img.shields.io/github/commit-activity/m/ai-zerolab/mcp-email-server)](https://img.shields.io/github/commit-activity/m/ai-zerolab/mcp-email-server)
[![License](https://img.shields.io/github/license/ai-zerolab/mcp-email-server)](https://img.shields.io/github/license/ai-zerolab/mcp-email-server)
[![smithery badge](https://smithery.ai/badge/@ai-zerolab/mcp-email-server)](https://smithery.ai/server/@ai-zerolab/mcp-email-server)

IMAP and SMTP via MCP Server

- **Github repository**: <https://github.com/ai-zerolab/mcp-email-server/>
- **Documentation** <https://ai-zerolab.github.io/mcp-email-server/>

## Installation

### Manual Installation

We recommend using [uv](https://github.com/astral-sh/uv) to manage your environment.

Try `uvx mcp-email-server@latest ui` to config, and use following configuration for mcp client:

```json
{
  "mcpServers": {
    "zerolib-email": {
      "command": "uvx",
      "args": ["mcp-email-server@latest", "stdio"]
    }
  }
}
```

This package is available on PyPI, so you can install it using `pip install mcp-email-server`

After that, configure your email server using the ui: `mcp-email-server ui`

Then you can try it in [Claude Desktop](https://claude.ai/download). If you want to intergrate it with other mcp client, run `$which mcp-email-server` for the path and configure it in your client like:

```json
{
  "mcpServers": {
    "zerolib-email": {
      "command": "{{ ENTRYPOINT }}",
      "args": ["stdio"]
    }
  }
}
```

If `docker` is avaliable, you can try use docker image, but you may need to config it in your client using `tools` via `MCP`. The default config path is `~/.config/zerolib/mcp_email_server/config.toml`

```json
{
  "mcpServers": {
    "zerolib-email": {
      "command": "docker",
      "args": ["run", "-it", "ghcr.io/ai-zerolab/mcp-email-server:latest"]
    }
  }
}
```

### Installing via Smithery

To install Email Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@ai-zerolab/mcp-email-server):

```bash
npx -y @smithery/cli install @ai-zerolab/mcp-email-server --client claude
```

## Configuration

### Logging

The MCP email server supports flexible logging configuration through environment variables:

- `MCP_EMAIL_SERVER_LOG_LEVEL`: Set the log level (default: "INFO"). Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
- `MCP_EMAIL_SERVER_LOG_FILE`: Path to log file (default: disabled). When set, logs will be written to both console and file
- `MCP_EMAIL_SERVER_LOG_ROTATION`: Log rotation size (default: "10 MB"). Examples: "500 KB", "10 MB", "1 GB"
- `MCP_EMAIL_SERVER_LOG_RETENTION`: How long to keep rotated logs (default: "7 days"). Examples: "7 days", "4 weeks", "6 months"

Example usage with file logging:

```bash
export MCP_EMAIL_SERVER_LOG_LEVEL=DEBUG
export MCP_EMAIL_SERVER_LOG_FILE=/home/user/mcp-email-server/logs/server.log
export MCP_EMAIL_SERVER_LOG_ROTATION="5 MB"
export MCP_EMAIL_SERVER_LOG_RETENTION="14 days"
uv run mcp-email-server stdio
```

When file logging is enabled:
- Log files are automatically rotated when they reach the specified size
- Old log files are compressed as .zip files
- Logs older than the retention period are automatically deleted
- The log directory is created automatically if it doesn't exist

## Development

This project is managed using [uv](https://github.com/ai-zerolab/uv).

Try `make install` to install the virtual environment and install the pre-commit hooks.

Use `uv run mcp-email-server` for local development.

## Releasing a new version

- Create an API Token on [PyPI](https://pypi.org/).
- Add the API Token to your projects secrets with the name `PYPI_TOKEN` by visiting [this page](https://github.com/ai-zerolab/mcp-email-server/settings/secrets/actions/new).
- Create a [new release](https://github.com/ai-zerolab/mcp-email-server/releases/new) on Github.
- Create a new tag in the form `*.*.*`.

For more details, see [here](https://fpgmaas.github.io/cookiecutter-uv/features/cicd/#how-to-trigger-a-release).
