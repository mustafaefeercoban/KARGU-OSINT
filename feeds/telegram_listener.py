#!/usr/bin/env python3
"""Background listener for public Telegram channels. Appends every message to
<case>/telegram.jsonl and flags the ones that mention a case seed.

Needs TELEGRAM_API_ID / TELEGRAM_API_HASH (my.telegram.org) and TELEGRAM_CHANNELS in
config/.env. Runs under ml/.venv (Telethon). Use a throwaway account: automated clients
get banned, and the session file grants full account access — keep it under .tor-like
permissions and never commit it.

    ml/.venv/bin/python feeds/telegram_listener.py <case-folder>
"""
import asyncio
import datetime
import json
import os
import pathlib
import re
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


def _seeds(case_dir):
    js = next(case_dir.glob("*.json"), None)
    if not js:
        return []
    try:
        s = json.loads(js.read_text(encoding="utf-8")).get("seeds") or {}
    except Exception:
        return []
    out = []
    for k in ("names", "usernames", "emails", "phones", "domains"):
        out += [str(v).lower() for v in s.get(k) or [] if len(str(v)) >= 4]
    return sorted(set(out))


async def run(case_dir):
    env = _env()
    api_id, api_hash = env.get("TELEGRAM_API_ID"), env.get("TELEGRAM_API_HASH")
    channels = [c.strip().lstrip("@") for c in (env.get("TELEGRAM_CHANNELS") or "").split(",") if c.strip()]
    if not (api_id and api_hash):
        print("skipped — TELEGRAM_API_ID / TELEGRAM_API_HASH not set in config/.env", file=sys.stderr)
        return 2
    if not channels:
        print("skipped — TELEGRAM_CHANNELS is empty (comma-separated public channel names)", file=sys.stderr)
        return 2
    from telethon import TelegramClient, events
    seeds = _seeds(case_dir)
    out = case_dir / "telegram.jsonl"
    client = TelegramClient(str(SESSION), int(api_id), api_hash)
    await client.start()
    SESSION.chmod(0o600)
    print(f"listening on {len(channels)} channel(s), {len(seeds)} seed(s) -> {out}", flush=True)

    @client.on(events.NewMessage(chats=channels))
    async def handler(ev):
        text = ev.raw_text or ""
        low = text.lower()
        hit = [s for s in seeds if s in low]
        rec = {"when": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "channel": getattr(ev.chat, "username", None) or str(ev.chat_id),
               "id": ev.id, "text": text[:2000], "hit": hit}
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if hit:
            print(f"[HIT] {rec['channel']} · {', '.join(hit)} · {text[:80]!r}", flush=True)

    await client.run_until_disconnected()
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    case_dir = pathlib.Path(sys.argv[1])
    if not case_dir.is_dir():
        case_dir = ROOT / "cases" / sys.argv[1]
    if not case_dir.is_dir():
        print(f"no such case folder: {case_dir}", file=sys.stderr); sys.exit(2)
    try:
        sys.exit(asyncio.run(run(case_dir)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
