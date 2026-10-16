"""SQLite storage (WAL mode). Queries are sub-millisecond, so they run inline on the event loop."""
import copy
import json
import os
import sqlite3
import time

from defaults import DEFAULTS, DEFAULT_TEXTS

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, phone TEXT,
  balance INTEGER DEFAULT 0, banned INTEGER DEFAULT 0, ref_by INTEGER, ref_earned INTEGER DEFAULT 0,
  is_reseller INTEGER DEFAULT 0, reseller_discount INTEGER DEFAULT 0, test_used INTEGER DEFAULT 0,
  state TEXT DEFAULT '', created INTEGER, last_seen INTEGER);
CREATE INDEX IF NOT EXISTS ix_users_ref ON users(ref_by);
CREATE TABLE IF NOT EXISTS servers(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, type TEXT, url TEXT, username TEXT, password TEXT,
  extra TEXT DEFAULT '{}', capacity INTEGER DEFAULT 0, active INTEGER DEFAULT 1, created INTEGER);
CREATE TABLE IF NOT EXISTS plans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, category TEXT DEFAULT '', volume_gb REAL DEFAULT 0,
  days INTEGER DEFAULT 30, users_limit INTEGER DEFAULT 1, price INTEGER DEFAULT 0, server_id INTEGER,
  active INTEGER DEFAULT 1, sort INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan_id INTEGER, plan_name TEXT, server_id INTEGER,
  name TEXT, remote TEXT DEFAULT '{}', link TEXT, volume_gb REAL, expire_at INTEGER, price INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active', notified INTEGER DEFAULT 0, created INTEGER);
CREATE INDEX IF NOT EXISTS ix_svc_user ON services(user_id);
CREATE INDEX IF NOT EXISTS ix_svc_status ON services(status, expire_at);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, plan_id INTEGER, plan_name TEXT,
  service_id INTEGER, base_amount INTEGER DEFAULT 0, amount INTEGER DEFAULT 0, discount_code TEXT,
  method TEXT, status TEXT DEFAULT 'draft', receipt TEXT, receipt_type TEXT, card TEXT, admin_msgs TEXT DEFAULT '[]',
  note TEXT, created INTEGER, handled_by TEXT, handled_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS ix_orders_user ON orders(user_id);
CREATE TABLE IF NOT EXISTS discounts(
  code TEXT PRIMARY KEY, percent INTEGER, max_uses INTEGER DEFAULT 0, used INTEGER DEFAULT 0,
  active INTEGER DEFAULT 1, expire_at INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS cards(
  id INTEGER PRIMARY KEY AUTOINCREMENT, number TEXT, owner TEXT, bank TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS tickets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, subject TEXT, status TEXT DEFAULT 'open',
  created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS ticket_msgs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, sender TEXT, text TEXT, created INTEGER);
CREATE INDEX IF NOT EXISTS ix_tmsg ON ticket_msgs(ticket_id);
CREATE TABLE IF NOT EXISTS stock(
  id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, config TEXT, used_by INTEGER, used_at INTEGER);
CREATE INDEX IF NOT EXISTS ix_stock ON stock(server_id, used_by);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, created INTEGER);
"""


class DB:
    def __init__(self, path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self.path = path
        self.c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.c.row_factory = sqlite3.Row
        for p in ("journal_mode=WAL", "synchronous=NORMAL", "busy_timeout=5000", "cache_size=-32000", "temp_store=MEMORY"):
            self.c.execute("PRAGMA " + p)
        self.prepare()

    def prepare(self):
        """Creates / upgrades tables and loads the settings cache (also used after restoring a backup)."""
        self.c.executescript(SCHEMA)
        for t, col in (("orders", "retries INTEGER DEFAULT 0"), ("orders", "retry_at INTEGER DEFAULT 0"),
                       ("orders", "disc_claimed INTEGER DEFAULT 0"), ("services", "vol_alert INTEGER DEFAULT 0")):
            try:
                self.c.execute(f"ALTER TABLE {t} ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass
        self.c.execute("CREATE INDEX IF NOT EXISTS ix_orders_retry ON orders(retry_at, status)")
        self._s = {}
        for r in self.c.execute("SELECT k, v FROM settings"):
            try:
                self._s[r["k"]] = json.loads(r["v"])
            except ValueError:
                pass

    def restore(self, src_path):
        """Replaces all data with a backup file after checking that it really is a bot database."""
        src = sqlite3.connect(src_path)
        try:
            ok = src.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            names = {r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not ok or not {"settings", "users", "orders", "services", "servers"} <= names:
                raise ValueError("این فایل، بکاپ معتبر این ربات نیست")
            need = {"users": {"id", "balance"}, "orders": {"id", "user_id", "status", "amount"},
                    "services": {"id", "user_id", "server_id", "remote"}, "servers": {"id", "type", "url"}}
            for tb, cols in need.items():
                have = {r[1] for r in src.execute(f"PRAGMA table_info({tb})")}
                if not cols <= have:
                    raise ValueError("این فایل، بکاپ معتبر این ربات نیست")
            src.backup(self.c)
        except sqlite3.DatabaseError:
            raise ValueError("فایل بکاپ خراب است یا دیتابیس نیست")
        finally:
            src.close()
        self.prepare()

    # ---- queries
    def one(self, q, *p):
        r = self.c.execute(q, p).fetchone()
        return dict(r) if r else None

    def all(self, q, *p):
        return [dict(r) for r in self.c.execute(q, p).fetchall()]

    def val(self, q, *p):
        r = self.c.execute(q, p).fetchone()
        return r[0] if r else None

    def run(self, q, *p):
        return self.c.execute(q, p).lastrowid

    def exec(self, q, *p):
        return self.c.execute(q, p).rowcount

    def tx(self, steps):
        """Runs several statements as one atomic transaction; steps is a function that receives a cursor."""
        self.c.execute("BEGIN IMMEDIATE")
        try:
            r = steps(self.c)
        except BaseException:
            self.c.execute("ROLLBACK")
            raise
        self.c.execute("COMMIT" if r else "ROLLBACK")
        return r

    # ---- settings (cached in memory)
    def get(self, k, default=None):
        if k in self._s:
            v = self._s[k]
            if k == "texts":
                merged = dict(DEFAULT_TEXTS)
                merged.update(v or {})
                return merged
            if isinstance(v, dict) and isinstance(DEFAULTS.get(k), dict):
                merged = copy.deepcopy(DEFAULTS[k])
                merged.update(v)
                return merged
            return v
        if k in DEFAULTS:
            return copy.deepcopy(DEFAULTS[k])
        return default

    def set(self, k, v):
        self._s[k] = v
        self.c.execute(
            "INSERT INTO settings(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (k, json.dumps(v, ensure_ascii=False)),
        )

    def log(self, text):
        self.c.execute("INSERT INTO logs(text, created) VALUES(?, ?)", (text, int(time.time())))

    def backup(self, dest):
        bk = sqlite3.connect(dest)
        with bk:
            self.c.backup(bk)
        bk.close()
