"""Admin panel web server (aiohttp): REST API + single-page panel."""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import time
import urllib.parse

from aiohttp import web

from bot import TZ
from panels import TYPES, PanelError, get_adapter, normalize_url, smart_detect
from tg import TG, TGError

log = logging.getLogger("web")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OPEN = {"/api/state", "/api/setup", "/api/login", "/api/tg-login"}
SETTING_KEYS = {"toggles", "texts", "buttons", "channel", "support", "test_cfg", "ref", "min_charge", "max_charge",
                "pay_methods", "panel_url", "reseller_discount", "cleanup_days"}
TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")


class Err(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def J(data, status=200):
    return web.json_response(data, status=status, dumps=lambda o: json.dumps(o, ensure_ascii=False, default=str))


_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")


def norm_pw(pw):
    """Persian / Arabic keyboards type different digits; the same password must work on every keyboard."""
    return str(pw or "").strip().translate(_DIGITS).replace("\u200c", "")


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", norm_pw(pw).encode(), salt.encode(), 120000).hex()


def check_pw(pw, stored):
    try:
        salt = stored.split("$")[0]
    except (AttributeError, IndexError):
        return False
    if hmac.compare_digest(hash_pw(pw, salt), stored):
        return True
    # passwords saved by older versions were hashed without normalisation
    raw = salt + "$" + hashlib.pbkdf2_hmac("sha256", str(pw or "").encode(), salt.encode(), 120000).hex()
    return hmac.compare_digest(raw, stored)


def day_start(t):
    return (t + TZ) // 86400 * 86400 - TZ


def num(v, default=0, lo=None, hi=None):
    try:
        n = float(v)
    except (TypeError, ValueError):
        n = default
    if lo is not None:
        n = max(lo, n)
    if hi is not None:
        n = min(hi, n)
    return n


def check_row(table, d):
    """Rejects values that would break the bot: negative prices, zero users, endless names."""
    if table == "plans":
        if "price" in d and d["price"] < 0:
            raise Err("قیمت پلن نمی‌تواند منفی باشد")
        if "days" in d and not 0 <= d["days"] <= 3650:
            raise Err("مدت پلن باید بین ۰ تا ۳۶۵۰ روز باشد")
        if "volume_gb" in d and d["volume_gb"] < 0:
            raise Err("حجم پلن نمی‌تواند منفی باشد")
        if "users_limit" in d and not 1 <= d["users_limit"] <= 100:
            raise Err("تعداد کاربر باید بین ۱ تا ۱۰۰ باشد")
        for k in ("name", "category"):
            if k in d and len(d[k] or "") > 60:
                raise Err("نام پلن یا دسته‌بندی حداکثر ۶۰ کاراکتر است")
    if table == "servers" and "capacity" in d and d["capacity"] < 0:
        raise Err("ظرفیت سرور نمی‌تواند منفی باشد")
    if table == "cards":
        for k in ("owner", "bank"):
            if k in d and len(d[k] or "") > 60:
                raise Err("نام صاحب کارت یا بانک حداکثر ۶۰ کاراکتر است")


class Api:
    def __init__(self, db, bm, session):
        self.db, self.bm, self.s = db, bm, session
        self.login_hits = {}
        self.receipt_cache = {}

    # ------------------------------------------------------------ auth
    def sessions(self):
        return self.db.get("sessions") or {}

    def new_session(self, data):
        ss = {k: v for k, v in self.sessions().items() if v > time.time()}
        tok = secrets.token_urlsafe(32)
        ss[tok] = int(time.time()) + 86400 * 14
        self.db.set("sessions", ss)
        resp = J({**data, "token": tok})
        resp.set_cookie("jx", tok, max_age=86400 * 14, httponly=True, samesite="None", secure=True)
        return resp

    def authed(self, r):
        # header token (Telegram Mini App, blocked cookies) or cookie: either valid one is enough,
        # so an old token left in the browser can never lock out a valid session
        ss, t = self.sessions(), time.time()
        return any(tok and ss.get(tok, 0) > t for tok in (r.headers.get("X-Auth"), r.cookies.get("jx")))

    def _ip(self, r):
        # Railway's proxy appends the real client address last; earlier entries can be faked by the client
        return (r.headers.get("X-Forwarded-For") or r.remote or "").split(",")[-1].strip()

    def rate_limited(self, r):
        """Only wrong passwords count; 10 mistakes in 5 minutes pause logins from that address."""
        t = time.time()
        hits = [h for h in self.login_hits.get(self._ip(r), []) if t - h < 300]
        self.login_hits[self._ip(r)] = hits
        return len(hits) >= 10

    def login_failed(self, r):
        t = time.time()
        if len(self.login_hits) > 2000:
            self.login_hits = {k: v for k, v in self.login_hits.items() if v and t - v[-1] < 300}
        self.login_hits.setdefault(self._ip(r), []).append(t)

    async def body(self, r):
        try:
            d = await r.json()
            return d if isinstance(d, dict) else {}
        except Exception:
            raise Err("درخواست نامعتبر است")

    async def state(self, r):
        return J({"setup": bool(self.db.get("password")), "authed": self.authed(r),
                  "brand_channel": os.getenv("BRAND_CHANNEL", ""), "bot": self.db.get("bot_info")})

    async def setup(self, r):
        if self.db.get("password"):
            raise Err("پنل قبلاً راه‌اندازی شده است", 403)
        d = await self.body(r)
        token = (d.get("token") or "").strip()
        admin = str(d.get("admin_id") or "").strip()
        pw = norm_pw(d.get("password"))
        url = (d.get("panel_url") or "").strip().rstrip("/")
        if not TOKEN_RE.match(token):
            raise Err("فرمت توکن ربات صحیح نیست")
        if not admin.isdigit():
            raise Err("آیدی عددی ادمین معتبر نیست")
        if len(pw) < 6:
            raise Err("رمز عبور باید حداقل ۶ کاراکتر باشد")
        try:
            me = await TG(token, self.s).call("getMe")
        except TGError as e:
            raise Err("توکن توسط تلگرام تأیید نشد" if e.code == 401 else "ارتباط با تلگرام برقرار نشد، دوباره تلاش کنید")
        self.db.set("token", token)
        self.db.set("admins", [{"id": int(admin), "name": d.get("admin_name") or "مالک", "role": "owner"}])
        self.db.set("panel_url", url)
        self.db.set("password", hash_pw(pw))
        self.db.set("bot_enabled", True)
        self.db.log("راه‌اندازی اولیه پنل انجام شد")
        await self.bm.start(token)
        return self.new_session({"ok": True, "bot": {"username": me.get("username"), "name": me.get("first_name")}})

    async def login(self, r):
        if self.rate_limited(r):
            raise Err("تعداد تلاش‌ها زیاد است؛ چند دقیقه دیگر تلاش کنید", 429)
        d = await self.body(r)
        if not await asyncio.to_thread(check_pw, d.get("password") or "", self.db.get("password") or ""):
            self.login_failed(r)
            raise Err("رمز عبور اشتباه است", 401)
        self.login_hits.pop(self._ip(r), None)
        return self.new_session({"ok": True})

    async def tg_login(self, r):
        """Auto-login when the panel is opened as a Telegram Mini App by an admin."""
        d = await self.body(r)
        init = d.get("init") or ""
        token = self.db.get("token")
        if not init or not token:
            raise Err("unauthorized", 401)
        pairs = dict(urllib.parse.parse_qsl(init, keep_blank_values=True))
        h = pairs.pop("hash", "")
        dcs = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        calc = hmac.new(secret, dcs.encode(), hashlib.sha256).hexdigest()
        try:
            auth_date = int(pairs.get("auth_date", 0))
        except (TypeError, ValueError):
            auth_date = 0
        if not hmac.compare_digest(calc, h) or abs(time.time() - auth_date) > 86400:
            raise Err("unauthorized", 401)
        try:
            uid = json.loads(pairs.get("user", "{}")).get("id")
        except ValueError:
            uid = None
        # the full panel is for the owner and full admins; payment/support admins work from inside the bot
        if not self.bm.is_admin(uid, ("full",)):
            raise Err("unauthorized", 401)
        return self.new_session({"ok": True})

    async def logout(self, r):
        ss = self.sessions()
        for tok in (r.headers.get("X-Auth"), r.cookies.get("jx")):
            ss.pop(tok or "", None)
        self.db.set("sessions", ss)
        resp = J({"ok": True})
        resp.del_cookie("jx")
        return resp

    async def password(self, r):
        d = await self.body(r)
        if not check_pw(d.get("old") or "", self.db.get("password")):
            raise Err("رمز فعلی اشتباه است")
        if len(norm_pw(d.get("new"))) < 6:
            raise Err("رمز جدید باید حداقل ۶ کاراکتر باشد")
        self.db.set("password", hash_pw(d["new"]))
        self.db.set("sessions", {})
        self.db.log("رمز پنل تغییر کرد")
        return self.new_session({"ok": True})

    # ------------------------------------------------------------ dashboard
    async def dashboard(self, r):
        db, t = self.db, int(time.time())
        ds = day_start(t)
        done = "status IN ('approved','paid') AND kind!='charge'"
        series = {row["d"]: row for row in db.all(
            f"SELECT (handled_at+{TZ})/86400 AS d, SUM(amount) AS s, COUNT(*) AS c FROM orders WHERE {done} AND handled_at>=? GROUP BY d",
            ds - 29 * 86400)}
        first = (ds + TZ) // 86400 - 29
        sales = [{"d": (first + i) * 86400 - TZ, "s": (series.get(first + i) or {}).get("s") or 0,
                  "c": (series.get(first + i) or {}).get("c") or 0} for i in range(30)]
        users_series = {row["d"]: row["c"] for row in db.all(
            f"SELECT (created+{TZ})/86400 AS d, COUNT(*) AS c FROM users WHERE created>=? GROUP BY d", ds - 29 * 86400)}
        return J({
            "users": db.val("SELECT COUNT(*) FROM users"),
            "users_today": db.val("SELECT COUNT(*) FROM users WHERE created>=?", ds),
            "active": db.val("SELECT COUNT(*) FROM services WHERE status='active'"),
            "services_today": db.val("SELECT COUNT(*) FROM services WHERE created>=?", ds),
            "sales_today": db.val(f"SELECT COALESCE(SUM(amount),0) FROM orders WHERE {done} AND handled_at>=?", ds),
            "sales_yesterday": db.val(f"SELECT COALESCE(SUM(amount),0) FROM orders WHERE {done} AND handled_at>=? AND handled_at<?", ds - 86400, ds),
            "sales_month": sum(x["s"] for x in sales),
            "pending": db.val("SELECT COUNT(*) FROM orders WHERE status='pending'"),
            "tickets": db.val("SELECT COUNT(*) FROM tickets WHERE status='open'"),
            "wallets": db.val("SELECT COALESCE(SUM(balance),0) FROM users"),
            "series": sales,
            "users_series": [users_series.get(first + i, 0) for i in range(30)],
            "top": db.all(f"SELECT plan_name AS name, COUNT(*) AS c, SUM(amount) AS s FROM orders WHERE {done} GROUP BY plan_name ORDER BY c DESC LIMIT 5"),
            "status": db.all("SELECT status, COUNT(*) AS c FROM orders WHERE status!='draft' GROUP BY status"),
            "volume_ok": db.path.startswith("/data") or bool(os.getenv("DB_PATH")) or not any(k.startswith("RAILWAY_") for k in os.environ),
            "servers": db.all("SELECT s.id, s.name, s.type, s.capacity, s.active, (SELECT COUNT(*) FROM services v WHERE v.server_id=s.id AND v.status='active') AS used FROM servers s"),
            "recent": self._orders("1=1", (), 6),
            "bot": self.bm.status(),
        })

    # ------------------------------------------------------------ orders
    def _orders(self, where, params, limit=50, offset=0):
        return self.db.all(f"""SELECT o.id, o.user_id, o.kind, o.plan_name, o.amount, o.base_amount, o.discount_code, o.method,
            o.status, o.card, o.note, o.created, o.handled_by, o.handled_at, (o.receipt IS NOT NULL) AS has_receipt,
            u.username, u.first_name FROM orders o LEFT JOIN users u ON u.id=o.user_id
            WHERE o.status NOT IN ('draft','await_receipt') AND {where} ORDER BY o.id DESC LIMIT ? OFFSET ?""", *params, limit, offset)

    async def orders(self, r):
        st = r.query.get("status", "")
        q = r.query.get("q", "").strip()
        page = int(num(r.query.get("page"), 0, 0))
        where, params = ["1=1"], []
        if st:
            where.append("o.status=?")
            params.append(st)
        if q:
            where.append("(CAST(o.id AS TEXT)=? OR CAST(o.user_id AS TEXT)=? OR u.username LIKE ?)")
            params += [q, q, f"%{q.lstrip('@')}%"]
        rows = self._orders(" AND ".join(where), params, 50, page * 50)
        return J({"items": rows, "more": len(rows) == 50})

    async def order_action(self, r):
        oid = int(r.match_info["id"])
        act = r.match_info["act"]
        try:
            d = await r.json()
        except Exception:
            d = {}
        if act == "approve":
            ok, msg = await self.bm.approve(oid, "پنل مدیریت")
        else:
            ok, msg = await self.bm.reject(oid, "پنل مدیریت", (d.get("reason") or "")[:300])
        if not ok:
            raise Err(msg)
        return J({"ok": True, "msg": msg})

    async def receipt(self, r):
        oid = int(r.match_info["id"])
        o = self.db.one("SELECT receipt FROM orders WHERE id=?", oid)
        if not o or not o["receipt"] or not self.bm.tg:
            raise web.HTTPNotFound()
        if oid in self.receipt_cache:
            data, ct = self.receipt_cache[oid]
        else:
            try:
                data, ct = await self.bm.tg.download(o["receipt"])
            except TGError:
                raise web.HTTPNotFound()
            # small memory budget (about 40 MB) so the server never runs out of RAM
            while self.receipt_cache and (len(self.receipt_cache) >= 40 or sum(len(x[0]) for x in self.receipt_cache.values()) + len(data) > 40 * 1024 ** 2):
                self.receipt_cache.pop(next(iter(self.receipt_cache)))
            if len(data) < 8 * 1024 ** 2:
                self.receipt_cache[oid] = (data, ct)
        return web.Response(body=data, content_type=ct.split(";")[0], headers={"Cache-Control": "private, max-age=3600"})

    # ------------------------------------------------------------ users
    async def users(self, r):
        q = r.query.get("q", "").strip().lstrip("@")
        flt = r.query.get("f", "")
        page = int(num(r.query.get("page"), 0, 0))
        where, params = ["1=1"], []
        if q:
            where.append("(CAST(u.id AS TEXT) LIKE ? OR u.username LIKE ? OR u.first_name LIKE ? OR u.phone LIKE ?)")
            params += [f"{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
        if flt == "banned":
            where.append("u.banned=1")
        elif flt == "resellers":
            where.append("u.is_reseller=1")
        elif flt == "buyers":
            where.append("EXISTS(SELECT 1 FROM services s WHERE s.user_id=u.id)")
        rows = self.db.all(f"""SELECT u.id, u.username, u.first_name, u.phone, u.balance, u.banned, u.is_reseller, u.reseller_discount,
            u.created, u.last_seen, u.ref_earned, (SELECT COUNT(*) FROM services s WHERE s.user_id=u.id AND s.status='active') AS services,
            (SELECT COUNT(*) FROM users x WHERE x.ref_by=u.id) AS refs
            FROM users u WHERE {' AND '.join(where)} ORDER BY u.created DESC LIMIT 50 OFFSET ?""", *params, page * 50)
        total = self.db.val(f"SELECT COUNT(*) FROM users u WHERE {' AND '.join(where)}", *params)
        return J({"items": rows, "total": total, "more": len(rows) == 50})

    async def user_detail(self, r):
        uid = int(r.match_info["id"])
        u = self.db.one("SELECT * FROM users WHERE id=?", uid)
        if not u:
            raise Err("کاربر یافت نشد", 404)
        u["services"] = self.db.all("SELECT * FROM services WHERE user_id=? ORDER BY id DESC LIMIT 50", uid)
        u["orders"] = self._orders("o.user_id=?", (uid,), 30)
        u["refs"] = self.db.val("SELECT COUNT(*) FROM users WHERE ref_by=?", uid)
        return J(u)

    async def user_action(self, r):
        uid = int(r.match_info["id"])
        act = r.match_info["act"]
        d = await self.body(r)
        u = self.db.one("SELECT * FROM users WHERE id=?", uid)
        if not u:
            raise Err("کاربر یافت نشد", 404)
        if act == "balance":
            amount = int(num(d.get("amount"), 0, 0))
            op = d.get("op", "add")
            if op == "add":
                self.db.run("UPDATE users SET balance=balance+? WHERE id=?", amount, uid)
            elif op == "sub":
                self.db.run("UPDATE users SET balance=MAX(0, balance-?) WHERE id=?", amount, uid)
            else:
                self.db.run("UPDATE users SET balance=? WHERE id=?", amount, uid)
            nb = self.db.val("SELECT balance FROM users WHERE id=?", uid)
            if d.get("notify") and op == "add" and amount:
                from bot import money
                await self.bm.safe_send(uid, f"کیف پول شما توسط مدیریت به مبلغ <b>{money(amount)}</b> شارژ شد.\nموجودی فعلی: <b>{money(nb)}</b>")
            self.db.log(f"تغییر موجودی کاربر {uid} به {nb}")
            return J({"ok": True, "balance": nb})
        if act == "ban":
            v = 1 if d.get("ban") else 0
            self.db.run("UPDATE users SET banned=? WHERE id=?", v, uid)
            self.db.log(("مسدود کردن" if v else "رفع مسدودی") + f" کاربر {uid}")
            return J({"ok": True})
        if act == "message":
            text = (d.get("text") or "").strip()
            if not text:
                raise Err("متن پیام خالی است")
            if not await self.bm.safe_send(uid, text):
                raise Err("ارسال پیام ناموفق بود (ربات خاموش است یا کاربر ربات را مسدود کرده)")
            return J({"ok": True})
        if act == "reseller":
            self.db.run("UPDATE users SET is_reseller=?, reseller_discount=? WHERE id=?", 1 if d.get("on") else 0,
                        int(num(d.get("discount"), 0, 0, 95)), uid)
            self.db.log(f"تغییر وضعیت نمایندگی کاربر {uid}")
            return J({"ok": True})
        if act == "reset-test":
            self.db.run("UPDATE users SET test_used=0 WHERE id=?", uid)
            return J({"ok": True})
        raise Err("عملیات نامعتبر")

    async def reseller_add(self, r):
        d = await self.body(r)
        uid = int(num(d.get("id"), 0))
        if not self.db.one("SELECT id FROM users WHERE id=?", uid):
            raise Err("این کاربر هنوز ربات را استارت نکرده است")
        self.db.run("UPDATE users SET is_reseller=1, reseller_discount=? WHERE id=?", int(num(d.get("discount"), 20, 0, 95)), uid)
        self.db.log(f"افزودن نماینده {uid}")
        return J({"ok": True})

    # ------------------------------------------------------------ services
    async def services(self, r):
        q = r.query.get("q", "").strip().lstrip("@")
        st = r.query.get("status", "")
        page = int(num(r.query.get("page"), 0, 0))
        where, params = ["s.status!='deleted'"], []
        if st:
            where.append("s.status=?")
            params.append(st)
        if q:
            where.append("(s.name LIKE ? OR CAST(s.user_id AS TEXT)=? OR u.username LIKE ?)")
            params += [f"%{q}%", q, f"%{q}%"]
        rows = self.db.all(f"""SELECT s.*, u.username, u.first_name, v.name AS server_name, v.type AS server_type FROM services s
            LEFT JOIN users u ON u.id=s.user_id LEFT JOIN servers v ON v.id=s.server_id
            WHERE {' AND '.join(where)} ORDER BY s.id DESC LIMIT 50 OFFSET ?""", *params, page * 50)
        return J({"items": rows, "more": len(rows) == 50})

    def _svc_srv(self, sid):
        s = self.db.one("SELECT * FROM services WHERE id=?", sid)
        if not s:
            raise Err("سرویس یافت نشد", 404)
        return s, self.db.one("SELECT * FROM servers WHERE id=?", s["server_id"])

    async def service_usage(self, r):
        s, srv = self._svc_srv(int(r.match_info["id"]))
        if not srv:
            raise Err("سرور این سرویس حذف شده است")
        return J(await get_adapter(srv, self.s).usage(json.loads(s["remote"] or "{}")))

    async def service_extend(self, r):
        s, srv = self._svc_srv(int(r.match_info["id"]))
        if not srv:
            raise Err("سرور این سرویس حذف شده است")
        d = await self.body(r)
        days = int(num(d.get("days"), 0, 0, 3650))
        gb = num(d.get("gb"), s["volume_gb"] or 0, 0)
        exp = (max(int(time.time()), s["expire_at"] or 0) + days * 86400) if days else (s["expire_at"] or 0)
        if srv and srv["type"] != "stock":
            await get_adapter(srv, self.s).renew(json.loads(s["remote"] or "{}"), gb, exp)
        self.db.run("UPDATE services SET expire_at=?, volume_gb=?, status='active', notified=0 WHERE id=?", exp, gb, s["id"])
        self.db.log(f"تمدید دستی سرویس {s['name']}")
        return J({"ok": True})

    async def service_delete(self, r):
        s, srv = self._svc_srv(int(r.match_info["id"]))
        if srv and srv["type"] != "stock":
            try:
                await get_adapter(srv, self.s).delete(json.loads(s["remote"] or "{}"))
            except PanelError:
                pass
        self.db.run("UPDATE services SET status='deleted' WHERE id=?", s["id"])
        self.db.log(f"حذف سرویس {s['name']}")
        return J({"ok": True})

    # ------------------------------------------------------------ generic CRUD
    def crud(self, table, fields, pk="id"):
        async def list_(r):
            order = "sort, price" if table == "plans" else pk
            rows = self.db.all(f"SELECT * FROM {table} ORDER BY {order}")
            if table == "servers":
                for x in rows:
                    x["password"] = ""
                    x["extra"] = json.loads(x.get("extra") or "{}")
                    if x["extra"].get("api_key"):
                        x["extra"]["api_key"] = ""
                    x["used"] = self.db.val("SELECT COUNT(*) FROM services WHERE server_id=? AND status='active'", x["id"])
                    x["stock_free"] = self.db.val("SELECT COUNT(*) FROM stock WHERE server_id=? AND used_by IS NULL", x["id"])
                    x["health"] = self.bm.health.get(x["id"])
                    x["queued"] = self.db.val("SELECT COUNT(*) FROM orders WHERE retry_at>0 AND status IN ('approved','paid')")
            return J(rows)

        def clean(d):
            out = {}
            for f, typ in fields.items():
                if f not in d:
                    continue
                v = d[f]
                if typ == "int":
                    v = int(num(v, 0))
                elif typ == "float":
                    v = num(v, 0, 0)
                elif typ == "bool":
                    v = 1 if v else 0
                elif typ == "json":
                    v = json.dumps(v if isinstance(v, dict) else {}, ensure_ascii=False)
                elif typ == "nint":
                    v = int(v) if str(v or "").strip().lstrip("-").isdigit() else None
                else:
                    v = str(v if v is not None else "").strip()
                out[f] = v
            return out

        async def create(r):
            d = clean(await self.body(r))
            det = None
            if table == "discounts":
                d["percent"] = max(0, min(100, int(d.get("percent") or 0)))
                d["code"] = d.get("code", "").strip().upper()
                if not re.fullmatch(r"[A-Z0-9_-]{2,32}", d["code"]):
                    raise Err("کد تخفیف فقط با حروف انگلیسی، عدد، خط تیره و زیرخط (۲ تا ۳۲ کاراکتر) ساخته می‌شود")
                if not d["code"]:
                    raise Err("کد را وارد کنید")
                if self.db.one("SELECT code FROM discounts WHERE code=?", d["code"]):
                    raise Err("این کد قبلاً ساخته شده است")
            if table == "cards" and len(re.sub(r"\D", "", d.get("number", ""))) not in (16, 24, 26):
                raise Err("شماره کارت یا شبا معتبر نیست")
            if table == "servers":
                d["created"] = int(time.time())
                if d.get("type") not in TYPES:
                    raise Err("نوع پنل نامعتبر است")
                if d.get("type") == "auto":
                    det = await self.detect_safe({**d, "extra": json.loads(d.get("extra") or "{}")})
                    d.update(type=det["type"], url=det["url"], username=det["username"], password=det["password"],
                             extra=json.dumps(det["extra"], ensure_ascii=False))
                    d["name"] = d.get("name") or det["name"]
                elif d.get("type") != "stock":
                    d["url"] = normalize_url(d.get("url"), d.get("type"))
                    if not d["url"]:
                        raise Err("آدرس پنل را وارد کنید")
                if not d.get("name"):
                    raise Err("نام سرور را وارد کنید")
            if table == "plans" and not d.get("name"):
                raise Err("نام پلن را وارد کنید")
            check_row(table, d)
            cols = ",".join(d)
            rid = self.db.run(f"INSERT INTO {table}({cols}) VALUES({','.join('?' * len(d))})", *d.values())
            self.db.log(f"افزودن مورد جدید در {table}")
            out = {"ok": True, "id": d.get("code") or rid}
            if table == "servers" and det:
                out.update(type=det["type"], label=det["label"], name=d["name"], msg=det["msg"])
            return J(out)

        async def update(r):
            key = r.match_info["id"]
            raw = await self.body(r)
            d = clean(raw)
            check_row(table, d)
            if table == "discounts" and "percent" in d:
                d["percent"] = max(0, min(100, int(d["percent"] or 0)))
            if table == "servers":
                if "url" in d:
                    d["url"] = normalize_url(d["url"], d.get("type") or self.db.val("SELECT type FROM servers WHERE id=?", key) or "")
                if d.get("type") == "auto":
                    d.pop("type")
                if not raw.get("password"):
                    d.pop("password", None)
                if "extra" in d:
                    old = json.loads(self.db.val("SELECT extra FROM servers WHERE id=?", key) or "{}")
                    new = json.loads(d["extra"])
                    if not new.get("api_key") and old.get("api_key"):
                        new["api_key"] = old["api_key"]
                    d["extra"] = json.dumps(new, ensure_ascii=False)
            d.pop(pk, None)
            if not d:
                return J({"ok": True})
            self.db.run(f"UPDATE {table} SET {','.join(f'{k}=?' for k in d)} WHERE {pk}=?", *d.values(), key)
            return J({"ok": True})

        async def delete(r):
            self.db.run(f"DELETE FROM {table} WHERE {pk}=?", r.match_info["id"])
            self.db.log(f"حذف مورد از {table}")
            return J({"ok": True})

        return list_, create, update, delete

    async def detect_safe(self, srv):
        try:
            return await asyncio.wait_for(smart_detect(srv, self.s), 45)
        except asyncio.TimeoutError:
            raise Err("پنل در زمان مقرر جواب نداد؛ لینک و پورت را بررسی کنید")

    async def server_test(self, r):
        if "id" in r.match_info:
            srv = self.db.one("SELECT * FROM servers WHERE id=?", int(r.match_info["id"]))
            if not srv:
                raise Err("سرور یافت نشد", 404)
        else:
            d = await self.body(r)
            srv = {"type": d.get("type"), "url": d.get("url"), "username": d.get("username"),
                   "password": d.get("password"), "extra": d.get("extra") or {}}
        if srv.get("type") == "auto":
            det = await self.detect_safe(srv)
            return J({"ok": True, "msg": det["msg"], "type": det["type"], "label": det["label"], "name": det["name"],
                      "url": det["url"], "details": det["details"]})
        t0 = time.monotonic()
        try:
            msg = await get_adapter(srv, self.s).test()
        except PanelError as e:
            if srv.get("id"):
                self.bm._mark(srv["id"], False, err=str(e))
            raise
        if srv.get("id"):
            self.bm._mark(srv["id"], True, int((time.monotonic() - t0) * 1000))
        return J({"ok": True, "msg": msg})

    async def stock_get(self, r):
        sid = int(r.match_info["id"])
        return J({"free": self.db.val("SELECT COUNT(*) FROM stock WHERE server_id=? AND used_by IS NULL", sid),
                  "used": self.db.val("SELECT COUNT(*) FROM stock WHERE server_id=? AND used_by IS NOT NULL", sid)})

    async def stock_add(self, r):
        sid = int(r.match_info["id"])
        d = await self.body(r)
        lines = [x.strip() for x in (d.get("configs") or "").splitlines() if x.strip()]
        for x in lines:
            self.db.run("INSERT INTO stock(server_id, config) VALUES(?,?)", sid, x)
        self.db.log(f"افزودن {len(lines)} کانفیگ به انبار")
        return J({"ok": True, "added": len(lines)})

    async def stock_clear(self, r):
        n = self.db.exec("DELETE FROM stock WHERE server_id=? AND used_by IS NULL", int(r.match_info["id"]))
        return J({"ok": True, "deleted": n})

    # ------------------------------------------------------------ tickets
    async def tickets(self, r):
        st = r.query.get("status", "")
        rows = self.db.all(f"""SELECT t.*, u.username, u.first_name, (SELECT text FROM ticket_msgs m WHERE m.ticket_id=t.id ORDER BY m.id DESC LIMIT 1) AS last
            FROM tickets t LEFT JOIN users u ON u.id=t.user_id {"WHERE t.status=?" if st else ""} ORDER BY t.updated DESC LIMIT 100""",
                           *([st] if st else []))
        return J(rows)

    async def ticket_get(self, r):
        tid = int(r.match_info["id"])
        t = self.db.one("SELECT t.*, u.username, u.first_name FROM tickets t LEFT JOIN users u ON u.id=t.user_id WHERE t.id=?", tid)
        if not t:
            raise Err("تیکت یافت نشد", 404)
        t["msgs"] = self.db.all("SELECT * FROM ticket_msgs WHERE ticket_id=? ORDER BY id", tid)
        return J(t)

    async def ticket_reply(self, r):
        d = await self.body(r)
        text = (d.get("text") or "").strip()
        if not text:
            raise Err("متن پاسخ خالی است")
        if len(text) > 3500:
            raise Err("متن پاسخ بیش از حد طولانی است (حداکثر ۳۵۰۰ کاراکتر)")
        ok = await self.bm.ticket_reply(int(r.match_info["id"]), text)
        return J({"ok": True, "delivered": ok})

    async def ticket_status(self, r):
        d = await self.body(r)
        self.db.run("UPDATE tickets SET status=?, updated=? WHERE id=?", "closed" if d.get("status") == "closed" else "open",
                    int(time.time()), int(r.match_info["id"]))
        return J({"ok": True})

    # ------------------------------------------------------------ admins
    async def admins(self, r):
        return J(self.db.get("admins"))

    async def admin_add(self, r):
        d = await self.body(r)
        aid = str(d.get("id") or "").strip()
        if not aid.isdigit():
            raise Err("آیدی عددی معتبر نیست")
        role = d.get("role") if d.get("role") in ("full", "pay", "support") else "full"
        ad = [a for a in self.db.get("admins") if str(a["id"]) != aid or a["role"] == "owner"]
        if any(str(a["id"]) == aid for a in ad):
            raise Err("این کاربر مالک ربات است")
        ad.append({"id": int(aid), "name": (d.get("name") or "ادمین").strip()[:40], "role": role})
        self.db.set("admins", ad)
        self.db.log(f"افزودن ادمین {aid}")
        return J({"ok": True})

    async def admin_del(self, r):
        aid = r.match_info["id"]
        self.db.set("admins", [a for a in self.db.get("admins") if str(a["id"]) != aid or a["role"] == "owner"])
        self.db.log(f"حذف ادمین {aid}")
        return J({"ok": True})

    # ------------------------------------------------------------ settings / bot
    async def settings_get(self, r):
        out = {k: self.db.get(k) for k in SETTING_KEYS}
        out["bot"] = self.db.get("bot_info")
        out["types"] = TYPES
        return J(out)

    async def settings_put(self, r):
        d = await self.body(r)
        for k, v in d.items():
            if k not in SETTING_KEYS:
                continue
            if k == "panel_url":
                v = str(v).strip().rstrip("/")
            if k in ("min_charge", "max_charge"):
                v = int(num(v, 0, 0))
            if k == "reseller_discount":
                v = int(num(v, 0, 0, 95))
            if k == "cleanup_days":
                v = int(num(v, 0, 0, 365))
            if k == "buttons":
                if not isinstance(v, list):
                    continue
                v = [{"id": str(b.get("id") or secrets.token_hex(3))[:16], "text": str(b.get("text") or "-")[:60],
                      "style": b.get("style") if b.get("style") in ("primary", "success", "danger") else "",
                      "wide": bool(b.get("wide")), "enabled": bool(b.get("enabled")),
                      "type": b.get("type") if b.get("type") in ("sys", "link", "text") else "text",
                      "value": str(b.get("value") or "")[:3000]} for b in v[:40]]
            if k == "texts":
                cur = self.db.get("texts")
                cur.update({kk: str(vv)[:3500] for kk, vv in (v or {}).items()})
                v = cur
            if k in ("toggles", "pay_methods", "ref", "test_cfg"):
                cur = self.db.get(k)
                cur.update(v or {})
                v = cur
            if k == "ref":
                for f, hi in (("percent", 100), ("gift", 10 ** 9)):
                    try:
                        v[f] = min(hi, max(0, int(str(v.get(f) or 0).translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")))))
                    except ValueError:
                        raise Err("مقدار زیرمجموعه‌گیری باید عدد مثبت باشد")
            self.db.set(k, v)
        self.db.log("به‌روزرسانی تنظیمات: " + "، ".join(k for k in d if k in SETTING_KEYS))
        return J({"ok": True})

    async def bot_get(self, r):
        return J({**self.bm.status(), "panel_url": self.db.get("panel_url"), "enabled": self.db.get("bot_enabled"),
                  "token_hint": (self.db.get("token") or "")[:10], "token": self.db.get("token") or "",
                  "admins": [{"id": a.get("id"), "role": a.get("role")} for a in (self.db.get("admins") or [])]})

    async def bot_token(self, r):
        d = await self.body(r)
        token = (d.get("token") or "").strip()
        if not TOKEN_RE.match(token):
            raise Err("فرمت توکن صحیح نیست")
        if not await self.bm.start(token):
            await self.bm.start()
            raise Err("توکن توسط تلگرام تأیید نشد")
        self.db.set("token", token)
        self.db.set("bot_enabled", True)
        self.db.log("توکن ربات تغییر کرد")
        return J({"ok": True, "status": self.bm.status()})

    async def bot_power(self, r):
        d = await self.body(r)
        on = bool(d.get("on"))
        if on:
            if not await self.bm.start():
                self.db.set("bot_enabled", False)
                raise Err("روشن کردن ربات ناموفق بود: " + (self.bm.last_error or "توکن نامعتبر"))
            self.db.set("bot_enabled", True)
        else:
            self.db.set("bot_enabled", False)
            await self.bm.stop()
        self.db.log("ربات " + ("روشن" if on else "خاموش") + " شد")
        return J({"ok": True, "status": self.bm.status()})

    async def broadcast(self, r):
        if r.method == "GET":
            return J(self.bm.bc)
        d = await self.body(r)
        if not (d.get("text") or "").strip():
            raise Err("متن پیام خالی است")
        if len(d["text"]) > 4000:
            raise Err("متن پیام نباید بیشتر از ۴۰۰۰ کاراکتر باشد")
        if not self.bm.start_broadcast(d.get("target", "all"), d["text"], d.get("btn_text", ""), d.get("btn_url", ""), bool(d.get("pin"))):
            raise Err("ارسال ممکن نیست (ربات خاموش است یا ارسال دیگری در جریان است)")
        return J({"ok": True, **self.bm.bc})

    async def logs(self, r):
        return J(self.db.all("SELECT * FROM logs ORDER BY id DESC LIMIT 300"))

    async def backup(self, r):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            self.db.backup(path)
            with open(path, "rb") as f:
                data = f.read()
        finally:
            try:
                os.unlink(path)  # never leave temporary copies on the server disk
            except OSError:
                pass
        return web.Response(body=data, content_type="application/octet-stream",
                            headers={"Content-Disposition": f"attachment; filename=backup-{time.strftime('%Y%m%d-%H%M')}.db"})

    async def restore(self, r):
        data = await r.read()
        if not data.startswith(b"SQLite format 3"):
            raise Err("فایل انتخاب‌شده بکاپ دیتابیس نیست (باید همان فایل .db دانلودشده از پنل باشد)")
        keep = [t for t in (r.headers.get("X-Auth"), r.cookies.get("jx")) if t and self.sessions().get(t, 0) > time.time()]
        fd, path = tempfile.mkstemp(suffix=".db")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            fd = None
            await self.bm.stop()
            try:
                self.db.restore(path)
            except ValueError as e:
                raise Err(str(e))
            finally:
                if self.db.get("token") and self.db.get("bot_enabled"):
                    await self.bm.start()
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        ss = self.sessions()
        for t in keep:  # the admin who restored stays logged in
            ss[t] = int(time.time()) + 86400 * 14
        self.db.set("sessions", ss)
        self.db.log("بازیابی کامل اطلاعات از فایل بکاپ")
        return J({"ok": True})

    async def index(self, r):
        path = os.path.join(BASE_DIR, "index.html")
        if not os.path.exists(path):
            return web.Response(text="index.html not found next to main.py", status=500)
        return web.FileResponse(path, headers={"Cache-Control": "no-cache"})

    async def health(self, r):
        return web.Response(text="ok")


def build_app(db, bm, session):
    api = Api(db, bm, session)

    @web.middleware
    async def mw(request, handler):
        p = request.path
        try:
            if p.startswith("/api/") and p not in OPEN and not api.authed(request):
                return J({"error": "unauthorized"}, 401)
            resp = await handler(request)
        except Err as e:
            return J({"error": str(e)}, e.status)
        except PanelError as e:
            return J({"error": str(e)}, 400)
        except web.HTTPException:
            raise
        except Exception:
            log.exception("api error %s", p)
            return J({"error": "خطای داخلی سرور"}, 500)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    app = web.Application(client_max_size=60 * 1024 ** 2, middlewares=[mw])
    R = app.router
    R.add_get("/", api.index)
    R.add_get("/health", api.health)
    R.add_get("/api/state", api.state)
    R.add_post("/api/setup", api.setup)
    R.add_post("/api/login", api.login)
    R.add_post("/api/tg-login", api.tg_login)
    R.add_post("/api/logout", api.logout)
    R.add_post("/api/password", api.password)
    R.add_get("/api/dashboard", api.dashboard)
    R.add_get("/api/orders", api.orders)
    R.add_post("/api/orders/{id}/{act:approve|reject}", api.order_action)
    R.add_get("/api/receipt/{id}", api.receipt)
    R.add_get("/api/users", api.users)
    R.add_get("/api/users/{id}", api.user_detail)
    R.add_post("/api/users/{id}/{act}", api.user_action)
    R.add_post("/api/resellers", api.reseller_add)
    R.add_get("/api/services", api.services)
    R.add_get("/api/services/{id}/usage", api.service_usage)
    R.add_post("/api/services/{id}/extend", api.service_extend)
    R.add_delete("/api/services/{id}", api.service_delete)
    specs = {
        "plans": ({"name": "str", "category": "str", "volume_gb": "float", "days": "int", "users_limit": "int",
                   "price": "int", "server_id": "nint", "active": "bool", "sort": "int"}, "id"),
        "servers": ({"name": "str", "type": "str", "url": "str", "username": "str", "password": "str",
                     "extra": "json", "capacity": "int", "active": "bool"}, "id"),
        "cards": ({"number": "str", "owner": "str", "bank": "str", "active": "bool"}, "id"),
        "discounts": ({"code": "str", "percent": "int", "max_uses": "int", "active": "bool", "expire_at": "int"}, "code"),
    }
    for name, (fields, pk) in specs.items():
        l, c, u, d = api.crud(name, fields, pk)
        R.add_get(f"/api/{name}", l)
        R.add_post(f"/api/{name}", c)
        R.add_put(f"/api/{name}/{{id}}", u)
        R.add_delete(f"/api/{name}/{{id}}", d)
    R.add_post("/api/servers/test", api.server_test)
    R.add_post("/api/servers/{id}/test", api.server_test)
    R.add_get("/api/stock/{id}", api.stock_get)
    R.add_post("/api/stock/{id}", api.stock_add)
    R.add_delete("/api/stock/{id}", api.stock_clear)
    R.add_get("/api/tickets", api.tickets)
    R.add_get("/api/tickets/{id}", api.ticket_get)
    R.add_post("/api/tickets/{id}/reply", api.ticket_reply)
    R.add_post("/api/tickets/{id}/status", api.ticket_status)
    R.add_get("/api/admins", api.admins)
    R.add_post("/api/admins", api.admin_add)
    R.add_delete("/api/admins/{id}", api.admin_del)
    R.add_get("/api/settings", api.settings_get)
    R.add_put("/api/settings", api.settings_put)
    R.add_get("/api/bot", api.bot_get)
    R.add_post("/api/bot/token", api.bot_token)
    R.add_post("/api/bot/power", api.bot_power)
    R.add_route("*", "/api/broadcast", api.broadcast)
    R.add_get("/api/logs", api.logs)
    R.add_get("/api/backup", api.backup)
    R.add_post("/api/restore", api.restore)
    return app
