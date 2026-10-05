import asyncio


def send_bale_script_message(*, bot_url, script_name, token, content, metadata=None):
    try:
        from balebot import ScriptClient
    except ImportError as exc:
        raise RuntimeError(
            "The 'balebot' package is not installed. Install your library (e.g. pip install -e path/to/balebot)."
        ) from exc

    async def _run():
        client = ScriptClient(
            bot_url=bot_url,
            script_name=script_name,
            token=token,
        )
        return await client.send_message(content=content, metadata=metadata or {})

    return asyncio.run(_run())
