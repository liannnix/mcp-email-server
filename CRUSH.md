# MCP Email Server - Development Guide

## Build/Test/Lint Commands

- `make install` - Install dependencies and pre-commit hooks
- `make check` - Run linting and code quality checks
- `make test` - Run all tests with coverage
- `uv run python -m pytest tests/test_file.py::test_function` - Run specific test
- `uv run ruff check . --fix` - Auto-fix linting issues
- `uv run ruff format .` - Format code

## Code Style Guidelines

### Naming Conventions

- **snake_case** for variables, functions, methods
- **PascalCase** for classes and types
- **UPPER_SNAKE_CASE** for constants

### Imports Order

1. Standard library imports
2. Third-party imports
3. Local imports
4. Type checking imports in `TYPE_CHECKING` blocks

### Type Annotations

- Use comprehensive type hints throughout
- Prefer Union types over Optional where appropriate
- Use Literal types for string enums
- Annotate async functions with proper return types

### Error Handling

- Use specific exception types in try/except blocks
- Log errors with descriptive context using loguru
- Include proper cleanup in finally blocks
- Use Pydantic for data validation

### Formatting

- Line length: 120 characters
- Use ruff for linting and formatting
- Follow pre-commit hooks configuration

### Async Patterns

- Use async/await for all I/O operations
- Properly type async generators and coroutines
- Handle connection cleanup in context managers

### Testing

- Use pytest with asyncio support
- Follow existing test patterns in tests/ directory
- Include proper fixtures and mocks

### Configuration

- Store config in TOML format
- Use environment variables with sensible defaults
- Follow Pydantic settings patterns
