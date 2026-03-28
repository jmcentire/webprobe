# webprobe SOPs

## Tech Stack
- Language: Python 3.12+
- Testing: pytest + pytest-asyncio
- Build: hatchling
- Linting: ruff (if configured)
- Type checking: pyright/mypy optional

## Standards
- Type annotations on all public functions
- Pydantic v2 BaseModel for all data structures
- Async throughout for I/O-bound operations
- Click for CLI commands
- YAML for user-facing config, JSON for machine artifacts

## Verification
- All modules must be importable without side effects
- pytest for unit tests
- End-to-end test against a live URL (talentsync.pro)
- Run twice, diff results for stability

## Preferences
- Prefer stdlib over third-party where practical
- Keep files under 400 lines
- No premature abstraction: one file per concern
- Integrate transmogrifier for LLM prompt quality
- All deps must be MIT/Apache/BSD compatible
