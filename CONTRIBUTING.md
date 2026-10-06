# Contributing to ELK-Checker

Contributions are welcome for monitoring logic, persistence, UI, notification integrations, security controls and test coverage.

## Local validation

```bash
python -m pip install -r requirements-dev.txt
pytest -q
python -m compileall -q app.py elkcheck KaveNegar.py tests
```

## Rules

- Never commit Elasticsearch credentials, API keys, notification tokens, phone numbers, private hostnames, internal IP ranges or runtime data.
- Use `.env.example` for documented configuration.
- Add tests for query-building, rule-engine, authentication or security-store changes.
- Keep defaults safe for local development.
- Document cross-platform behavior when a change is OS-specific.

For undisclosed vulnerabilities, follow `SECURITY.md` instead of opening a public issue.
