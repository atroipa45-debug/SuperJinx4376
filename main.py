"""Entry point: starts the admin panel (port 8080 by default) and the Telegram bot in one process."""
import asyncio
import logging
import os

import aiohttp
from aiohttp import web

from bot import BotManager
from db import DB
from web import build_app


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.getenv("DB_PATH"), "/data/bot.db" if os.path.isdir("/data") else None,
                  os.path.join(base, "data", "bot.db"), "/tmp/bot.db"]
    db = None
    for path in [c for c in candidates if c]:
        try:
            db = DB(path)
            logging.info("database: %s", path)
            break
        except Exception as e:  # noqa
            logging.warning("cannot open database at %s: %s", path, e)
    if db is None:
        raise SystemExit("no writable location for the database")
    session = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=300, ttl_dns_cache=300, keepalive_timeout=60),
        cookie_jar=aiohttp.DummyCookieJar())
    bm = BotManager(db, session)
    app = build_app(db, bm, session)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    ports = [8080]
    env_port = os.getenv("PORT", "").strip()
    if env_port.isdigit() and int(env_port) not in ports:
        ports.append(int(env_port))
    for port in ports:
        await web.TCPSite(runner, "0.0.0.0", port).start()
        logging.info("admin panel listening on port %s", port)
    if db.get("token") and db.get("bot_enabled"):
        await bm.start()
    bm.start_background()
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda l, ctx: logging.error("unhandled: %s", ctx.get("message"), exc_info=ctx.get("exception")))
    stop = asyncio.Event()
    import signal
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await stop.wait()
    finally:
        logging.info("shutting down")
        await bm.stop()
        await runner.cleanup()
        await session.close()
        try:
            db.c.close()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
