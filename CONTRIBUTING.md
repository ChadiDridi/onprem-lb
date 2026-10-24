# Contributing

1. `uv venv && uv pip install -e '.[dev,fast]'`
2. Make the change with tests. Integration tests use real sockets on localhost; see `tests/conftest.py` for backends.
3. Run `pytest` and `ruff check src tests && ruff format --check src tests`.
4. Open a PR describing the behaviour change.

Behaviour that touches HTTP parsing or framing needs a test for the malicious variant as well.
