# Security Policy

ELK-Checker can store Elasticsearch endpoints, credentials, notification tokens and recipient information. Treat its `data/` directory as sensitive runtime state.

## Public repository rules

Never commit:

- Elasticsearch usernames/passwords or API keys
- Kavenegar API keys or real recipient phone numbers
- Bale tokens
- Flask `SECRET_KEY` values
- generated runtime JSON files under `data/`
- internal infrastructure addresses that should remain private

The public build defaults to `127.0.0.1` and generates a random bootstrap admin password when `ELK_ADMIN_PASSWORD` is not supplied. For production, explicitly configure both a strong `SECRET_KEY` and `ELK_ADMIN_PASSWORD`.
