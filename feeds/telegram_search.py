#!/usr/bin/env python3
"""Search public Telegram channels for a query (Telethon, runs under ml/.venv).

Needs TELEGRAM_API_ID / TELEGRAM_API_HASH in config/.env (my.telegram.org). Searches the
channels listed in TELEGRAM_CHANNELS and, when that is empty, Telegram's global search.
Use a throwaway account: the session file grants full account access and is never committed.

    python feeds/telegram_search.py --login          # one-time interactive login
    python feeds/telegram_search.py "<query>" [--limit 25]
"""
import argparse
import asyncio
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SESSION = ROOT / "config" / "telegram.session"


def _env():
    env = {}
    p = ROOT / "config" / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                env[k.strip().upper()] = v.strip().strip('"').strip("'")
    env.update({k: v for k, v in os.environ.items() if k.startswith("TELEGRAM_")})
    return env


def _row(msg, chat):
    username = getattr(chat, "username", None)
    title = getattr(chat, "title", None) or username or str(getattr(msg, "chat_id", ""))
    link = f"https://t.me/{username}/{msg.id}" if username else ""
    return {"chat": title, "link": link, "text": (msg.raw_text or "")[:500],
            "date": msg.date.isoformat(timespec="seconds") if msg.date else ""}


async def search(query, limit=25):
    env = _env()
    api_id, api_hash = env.get("TELEGRAM_API_ID"), env.get("TELEGRAM_API_HASH")
    if not (api_id and api_hash):
        return {"error": "Telegram is not configured: add TELEGRAM_API_ID / TELEGRAM_API_HASH to config/.env"}
    from telethon import TelegramClient, functions, types
    client = TelegramClient(str(SESSION), int(api_id), api_hash)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            return {"error": "Telegram session missing: run  ml/.venv/bin/python feeds/telegram_search.py --login"}
        channels = [c.strip().lstrip("@") for c in (env.get("TELEGRAM_CHANNELS") or "").split(",") if c.strip()]
        rows, errors = [], []
        if channels:
            per = max(3, limit // len(channels))
            for ch in channels:
                try:
                    ent = await client.get_entity(ch)
                    async for m in client.iter_messages(ent, search=query, limit=per):
                        rows.append(_row(m, ent))
                except Exception as e:
                    errors.append(f"{ch}: {type(e).__name__}")
        else:
            r = await client(functions.messages.SearchGlobalRequest(
                q=query, filter=types.InputMessagesFilterEmpty(), min_date=None, max_date=None,
                offset_rate=0, offset_peer=types.InputPeerEmpty(), offset_id=0, limit=limit))
            chats = {c.id: c for c in r.chats}
            for m in r.messages:
                peer = getattr(m, "peer_id", None)
                cid = getattr(peer, "channel_id", None) or getattr(peer, "chat_id", None)
                rows.append(_row(m, chats.get(cid)))
        rows.sort(key=lambda x: x["date"], reverse=True)
        out = {"query": query, "messages": rows[:limit], "scope": channels or ["global search"]}
        if errors:
            out["errors"] = errors
        return out
    finally:
        await client.disconnect()


async def login():
    env = _env()
    api_id, api_hash = env.get("TELEGRAM_API_ID"), env.get("TELEGRAM_API_HASH")
    if not (api_id and api_hash):
        print("add TELEGRAM_API_ID / TELEGRAM_API_HASH to config/.env first", file=sys.stderr)
        return 2
    from telethon import TelegramClient
    client = TelegramClient(str(SESSION), int(api_id), api_hash)
    await client.start()
    SESSION.chmod(0o600)
    me = await client.get_me()
    print(f"logged in as {getattr(me, 'username', None) or me.id}; session: {SESSION}")
    await client.disconnect()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?", default="")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--login", action="store_true")
    a = ap.parse_args()
    if a.login:
        sys.exit(asyncio.run(login()))
    if not a.query.strip():
        ap.error("query is required")
    try:
        out = asyncio.run(search(a.query.strip(), a.limit))
    except Exception as e:
        out = {"error": f"{type(e).__name__}: {str(e)[:160]}"}
    json.dump(out, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()
