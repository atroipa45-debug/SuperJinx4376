"""Adapters for VPN management panels.

Supported: Marzban (and compatible forks), Marzneshin, 3x-ui (Sanaei), X-UI (Alireza),
Hiddify Manager (API v2), any custom HTTP API, and a manual config stock that works with any panel.
Every adapter exposes: test(), create(), renew(), usage(), delete().
"""
import asyncio
import hashlib
import base64
import datetime
import json
import math
import secrets
import time
import urllib.parse
import uuid

import re

import aiohttp

GB = 1024 ** 3
_AUTH = {}  # cached tokens / cookies: key -> (value, expires)


def _fp(pw):
    """Short fingerprint of a password so a changed password never reuses an old cached login."""
    return hashlib.sha1(str(pw or "").encode()).hexdigest()[:12]

TYPES = {
    "auto": "تشخیص خودکار (پیشنهادی)",
    "marzban": "Marzban",
    "pasarguard": "PasarGuard",
    "remnawave": "Remnawave",
    "marzneshin": "Marzneshin",
    "xui": "3x-ui (Sanaei)",
    "xui_alireza": "X-UI (Alireza)",
    "hiddify": "Hiddify Manager",
    "custom": "API سفارشی (هر پنل دیگر)",
    "stock": "کانفیگ دستی (انبار کانفیگ)",
}


class PanelError(Exception):
    pass


class AuthError(PanelError):
    """The panel was found, but it rejected the username / password / token."""


def _json(d):
    return isinstance(d, dict) and "_raw" not in d


def prune_cache():
    """Drops expired logins / cached inbounds so memory stays flat on long runs."""
    t = time.time()
    for k in [k for k, v in _AUTH.items() if v[1] <= t]:
        _AUTH.pop(k, None)
    if len(_AUTH) > 5000:
        _AUTH.clear()


_HDR = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.9,fa;q=0.8"}


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def _from_iso(s):
    if not s:
        return 0
    try:
        return int(datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


_UUID_RE = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)", re.I)


def normalize_url(url, typ=""):
    """Accepts whatever the admin pastes (dashboard links, login pages, trailing slashes)."""
    u = (url or "").strip().split("#")[0].strip()
    if u and not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    u = u.rstrip("/")
    if typ == "hiddify":
        m = _UUID_RE.search(u)
        if m:  # full admin link pasted: keep only https://domain/<admin_proxy_path>
            u = u[: m.start()].rstrip("/")
    for tail in ("/dashboard/login", "/dashboard", "/login", "/panel/inbounds", "/panel/settings", "/panel",
                 "/xui/inbounds", "/xui", "/docs", "/api", "/auth/login", "/auth"):
        if typ not in ("hiddify", "custom") and u.lower().endswith(tail):
            u = u[: -len(tail)].rstrip("/")
            break
    return u


class Base:
    def __init__(self, srv, session):
        self.srv = srv
        self.s = session
        self.url = normalize_url(srv.get("url"), srv.get("type", ""))
        self.user = srv.get("username") or ""
        self.pw = srv.get("password") or ""
        ex = srv.get("extra") or {}
        self.extra = json.loads(ex) if isinstance(ex, str) else ex
        self.ssl = False if self.extra.get("insecure", True) else True
        self.timeout = srv.get("_timeout") or 20
        self.tries = srv.get("_tries") or 3

    async def req(self, method, path, **kw):
        """HTTP call that survives Cloudflare, Railway and flaky networks: browser headers,
        automatic retries on transient failures and clear Persian errors."""
        kw.setdefault("timeout", aiohttp.ClientTimeout(total=self.timeout, sock_connect=min(8, self.timeout)))
        kw.setdefault("ssl", self.ssl)
        kw["headers"] = {**_HDR, **(kw.get("headers") or {})}
        url = path if path.startswith("http") else self.url + path
        body_req = method not in ("GET", "HEAD")
        safe = not body_req or kw.pop("_retry_ok", False)
        if body_req:
            kw.setdefault("allow_redirects", False)  # a redirect would silently turn POST into GET
        last = None
        for attempt in range(self.tries):
            if attempt:
                await asyncio.sleep(0.35 * attempt)
            try:
                async with self.s.request(method, url, **kw) as r:
                    txt = await r.text(errors="replace")
                    st = r.status
                    try:
                        data = json.loads(txt) if txt else {}
                    except ValueError:
                        data = {"_raw": txt[:300]}
                    cookies = {k: v.value for k, v in r.cookies.items()}
                    loc = r.headers.get("Location", "") if st in (301, 302, 307, 308) and hasattr(r, "headers") else ""
                    if not isinstance(data, (dict, list)):
                        data = {"_value": data}
            except asyncio.TimeoutError:
                last = PanelError("سرور پنل در زمان مقرر جواب نداد (آدرس، پورت یا فایروال سرور را بررسی کنید)")
                if not safe:
                    raise last
                continue
            except aiohttp.ClientConnectorError as e:
                last = PanelError(f"اتصال به سرور برقرار نشد؛ آدرس یا پورت اشتباه است یا سرور خاموش است ({e.__class__.__name__})")
                continue  # nothing reached the panel, always safe to retry
            except (aiohttp.ClientError, ValueError) as e:
                last = PanelError(f"خطا در اتصال به پنل ({e.__class__.__name__})")
                if not safe:
                    raise last
                continue
            if loc and body_req and attempt < self.tries - 1:
                new = urllib.parse.urljoin(url, loc)
                if new.startswith("https://") and url.startswith("http://") and not cookies:
                    # http -> https redirect (Cloudflare "Always use HTTPS", Railway): follow it and remember
                    self.url = "https://" + self.url.split("://", 1)[1]
                    url = new
                    continue
            raw = (data.get("_raw") or "").lower() if isinstance(data, dict) else ""
            if st in (403, 429, 503) and ("just a moment" in raw or "cf-chl" in raw or "challenge-platform" in raw or "attention required" in raw):
                raise PanelError("Cloudflare جلوی درخواست ربات را گرفت؛ در Cloudflare گزینه Bot Fight Mode / Under Attack را برای این دامنه خاموش کنید یا یک ساب‌دامین بدون پروکسی (ابر خاکستری) بدهید.")
            if st == 404 and "application not found" in raw:
                raise PanelError("دامنه Railway پیدا نشد؛ لینک پنل را از بخش Settings > Domains سرویس در Railway کپی کنید.")
            # 521/522/523/525/526: Cloudflare never reached the panel, so even a POST is safe to repeat
            if st in (521, 522, 523, 525, 526) or (safe and st in (502, 503, 504, 520, 524, 429)):
                last = PanelError({521: "سرور پشت Cloudflare خاموش است یا پورت پنل بسته است (خطای 521)",
                                   522: "Cloudflare به سرور پنل وصل نشد (خطای 522)؛ پورت پنل باید از پورت‌های مجاز Cloudflare باشد",
                                   525: "گواهی SSL سرور پنل با Cloudflare سازگار نیست (خطای 525)؛ حالت SSL را روی Full بگذارید",
                                   526: "گواهی SSL سرور نامعتبر است (خطای 526)؛ حالت SSL را در Cloudflare روی Full بگذارید"}.get(
                    st, f"پنل موقتاً در دسترس نیست (کد {st})" + ("؛ اپلیکیشن Railway در حال اجرا نیست" if "application failed to respond" in raw else "")))
                continue
            return st, data, cookies
        raise last

    @staticmethod
    def err(d, default="خطا در پنل", status=None):
        if isinstance(d, dict):
            for k in ("detail", "msg", "message", "error"):
                if d.get(k):
                    v = d[k]
                    return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)[:200]
        return default + (f" (کد {status})" if status else "")

    async def test(self):
        raise NotImplementedError

    async def create(self, name, gb, days, users=1):
        raise NotImplementedError

    async def renew(self, meta, gb, expire_ts, users=1):
        raise NotImplementedError

    async def usage(self, meta):
        raise NotImplementedError

    async def delete(self, meta):
        raise NotImplementedError

    CAN_REVOKE = False

    async def revoke(self, meta, users=1):
        """Invalidates the old link and returns {"link", "meta"} with a fresh one."""
        raise PanelError("تغییر لینک برای این نوع پنل پشتیبانی نمی‌شود")


# ---------------------------------------------------------------- Marzban
class Marzban(Base):
    TOKEN_PATH = "/api/admin/token"

    async def token(self, force=False):
        k = (self.TOKEN_PATH, self.url, self.user, _fp(self.pw))
        t = _AUTH.get(k)
        if t and not force and t[1] > time.time():
            return t[0]
        if not self.user and self.pw:
            return self.pw
        st, d, _ = await self.req("POST", self.TOKEN_PATH, data={"username": self.user, "password": self.pw}, _retry_ok=True)
        if st != 200 or "access_token" not in d:
            if st in (400, 401, 403, 422) and _json(d):
                raise AuthError("ورود به پنل ناموفق بود (نام کاربری یا رمز عبور اشتباه است)")
            raise PanelError(f"پنل {TYPES.get(getattr(self, 'KIND', 'marzban'), 'Marzban')} در این آدرس پیدا نشد (کد {st})")
        _AUTH[k] = (d["access_token"], time.time() + 3000)
        return d["access_token"]

    async def api(self, method, path, **kw):
        for i in range(2):
            h = {"Authorization": "Bearer " + await self.token(force=i > 0)}
            st, d, _ = await self.req(method, path, headers=h, **kw)
            if st == 401 and i == 0:
                continue
            return st, d
        raise PanelError("احراز هویت پنل ناموفق بود")

    def sub(self, d):
        u = d.get("subscription_url") or ""
        if u and not u.startswith("http"):
            u = self.url + u
        return u

    async def test(self):
        await self.token(True)
        st, d = await self.api("GET", "/api/system")
        if st == 200 and _json(d):
            return f"اتصال موفق | کاربران: {d.get('total_user', '-')} | فعال: {d.get('users_active', '-')}"
        # reseller (non-sudo) admin accounts cannot read /api/system
        st, d = await self.api("GET", "/api/admin")
        if st != 200 or not _json(d):
            raise PanelError(self.err(d, "پنل Marzban در این آدرس پیدا نشد"))
        return f"اتصال موفق با اکانت نمایندگی ({d.get('username', self.user)})"

    async def _inbounds(self):
        inb = self.extra.get("inbounds")
        if not inb:
            ck = ("inb", self.url, self.user)
            c = _AUTH.get(ck)
            if c and c[1] > time.time():
                inb = c[0]
            else:
                st, d = await self.api("GET", "/api/inbounds")
                if st == 200 and isinstance(d, dict):
                    inb = {p: [i["tag"] for i in lst] for p, lst in d.items() if isinstance(lst, list)}
                    _AUTH[ck] = (inb, time.time() + 600)
                else:
                    inb = None  # reseller accounts may not list inbounds: let the panel use its defaults
        if not inb:
            protos = self.extra.get("protocols") or ["vless"]
            return {p: ({"flow": self.extra["flow"]} if p == "vless" and self.extra.get("flow") else {}) for p in protos}, None
        proxies = {}
        for p in inb:
            proxies[p] = {"flow": self.extra["flow"]} if p == "vless" and self.extra.get("flow") else {}
        return proxies, inb

    async def create(self, name, gb, days, users=1):
        proxies, inb = await self._inbounds()
        body = {
            "username": name, "proxies": proxies,
            "data_limit": int(gb * GB) if gb else 0,
            "expire": int(time.time() + days * 86400) if days else 0,
            "data_limit_reset_strategy": "no_reset", "status": "active", "note": "",
        }
        if inb:
            body["inbounds"] = inb
        st, d = await self.api("POST", "/api/user", json=body)
        if st == 409:  # an earlier attempt already reached the panel
            st, d = await self.api("GET", f"/api/user/{name}")
        if st not in (200, 201):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود", st))
        return {"link": self.sub(d) or "\n".join(d.get("links") or []), "meta": {"name": name}}

    async def renew(self, meta, gb, expire_ts, users=1):
        n = meta["name"]
        st, d = await self.api("PUT", f"/api/user/{n}", json={
            "data_limit": int(gb * GB) if gb else 0, "expire": int(expire_ts) if expire_ts else 0, "status": "active"})
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))
        await self.api("POST", f"/api/user/{n}/reset")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/api/user/{meta['name']}")
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        return {"used": d.get("used_traffic") or 0, "total": d.get("data_limit") or 0,
                "expire": d.get("expire") or 0, "status": d.get("status"), "link": self.sub(d)}

    async def delete(self, meta):
        await self.api("DELETE", f"/api/user/{meta['name']}")

    CAN_REVOKE = True

    async def revoke(self, meta, users=1):
        st, d = await self.api("POST", f"/api/user/{meta['name']}/revoke_sub")
        if st != 200:
            raise PanelError(self.err(d, "تغییر لینک در پنل ناموفق بود", st))
        link = self.sub(d) if isinstance(d, dict) else ""
        if not link:
            st, d = await self.api("GET", f"/api/user/{meta['name']}")
            link = self.sub(d) if st == 200 else ""
        return {"link": link, "meta": meta}


# ---------------------------------------------------------------- Marzneshin
class Marzneshin(Marzban):
    TOKEN_PATH = "/api/admins/token"
    KIND = "marzneshin"

    async def test(self):
        await self.token(True)
        st, d = await self.api("GET", "/api/services")
        if st != 200 or not (isinstance(d, list) or _json(d)):
            raise PanelError(self.err(d, "پنل Marzneshin در این آدرس پیدا نشد"))
        return f"اتصال موفق | سرویس‌ها: {len(d.get('items', d) if isinstance(d, dict) else d)}"

    async def _services(self):
        ids = self.extra.get("service_ids")
        if ids:
            return [int(x) for x in ids]
        st, d = await self.api("GET", "/api/services")
        items = d.get("items", []) if isinstance(d, dict) else d
        return [i["id"] for i in items]

    def _body(self, name, gb, expire_ts, ids):
        b = {"username": name, "service_ids": ids, "data_limit": int(gb * GB) if gb else 0,
             "data_limit_reset_strategy": "no_reset", "note": ""}
        if expire_ts:
            b.update(expire_strategy="fixed_date", expire_date=_iso(expire_ts))
        else:
            b.update(expire_strategy="never")
        return b

    async def create(self, name, gb, days, users=1):
        ids = await self._services()
        st, d = await self.api("POST", "/api/users", json=self._body(name, gb, time.time() + days * 86400 if days else 0, ids))
        if st == 409:
            st, d = await self.api("GET", f"/api/users/{name}")
        if st not in (200, 201):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        return {"link": self.sub(d), "meta": {"name": name}}

    async def renew(self, meta, gb, expire_ts, users=1):
        ids = await self._services()
        st, d = await self.api("PUT", f"/api/users/{meta['name']}", json=self._body(meta["name"], gb, expire_ts, ids))
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))
        await self.api("POST", f"/api/users/{meta['name']}/reset")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/api/users/{meta['name']}")
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        return {"used": d.get("used_traffic") or 0, "total": d.get("data_limit") or 0,
                "expire": _from_iso(d.get("expire_date")), "status": "active" if d.get("enabled", True) else "disabled",
                "link": self.sub(d)}

    async def delete(self, meta):
        await self.api("DELETE", f"/api/users/{meta['name']}")

    async def revoke(self, meta, users=1):
        st, d = await self.api("POST", f"/api/users/{meta['name']}/revoke_sub")
        if st != 200:
            raise PanelError(self.err(d, "تغییر لینک در پنل ناموفق بود", st))
        link = self.sub(d) if isinstance(d, dict) else ""
        if not link:
            st, d = await self.api("GET", f"/api/users/{meta['name']}")
            link = self.sub(d) if st == 200 else ""
        return {"link": link, "meta": meta}


# ---------------------------------------------------------------- 3x-ui / x-ui
class XUI(Base):
    PREFIX = "/panel/api/inbounds"

    async def login(self, force=False):
        k = ("xui", self.url, self.user, _fp(self.pw))
        t = _AUTH.get(k)
        if t and not force and t[1] > time.time():
            return t[0]
        st, d, ck = await self.req("POST", "/login", data={"username": self.user, "password": self.pw}, _retry_ok=True)
        if not (isinstance(d, dict) and d.get("success")) or not ck:
            if _json(d) and "success" in d:
                raise AuthError("ورود به پنل ناموفق بود (نام کاربری یا رمز عبور اشتباه است)")
            raise PanelError(f"پنل X-UI در این آدرس پیدا نشد (کد {st})")
        cookie = "; ".join(f"{a}={b}" for a, b in ck.items())
        _AUTH[k] = (cookie, time.time() + 3000)
        return cookie

    async def api(self, method, path, **kw):
        for i in range(2):
            ck = await self.login(force=i > 0)
            st, d, _ = await self.req(method, self.PREFIX + path, headers={"Cookie": ck, "Accept": "application/json"}, **kw)
            if i == 0 and (st in (401, 404) or "_raw" in d):
                continue
            return st, d
        raise PanelError("احراز هویت پنل ناموفق بود")

    async def test(self):
        await self.login(True)
        st, d = await self.api("GET", "/list")
        if not d.get("success"):
            raise PanelError(self.err(d))
        return f"اتصال موفق | اینباندها: {len(d.get('obj') or [])}"

    async def _iid(self):
        if self.extra.get("inbound_id"):
            return int(self.extra["inbound_id"])
        k = ("xiid", self.url, self.user)
        c = _AUTH.get(k)
        if c and c[1] > time.time():
            return c[0]
        st, d = await self.api("GET", "/list")
        obj = d.get("obj") or []
        obj = [x for x in obj if x.get("enable", True)] or obj
        obj = [x for x in obj if x.get("protocol") in ("vless", "vmess", "trojan")] or obj
        if not obj:
            raise PanelError("هیچ اینباندی در پنل وجود ندارد")
        _AUTH[k] = (obj[0]["id"], time.time() + 300)
        return obj[0]["id"]

    async def _inbound(self, iid):
        k = ("xinb", self.url, self.user, iid)
        c = _AUTH.get(k)
        if c and c[1] > time.time():
            return c[0]
        st, d = await self.api("GET", f"/get/{iid}")
        if not d.get("success"):
            raise PanelError("اینباند یافت نشد")
        _AUTH[k] = (d["obj"], time.time() + 300)
        return d["obj"]

    def _host(self):
        return self.extra.get("host") or urllib.parse.urlparse(self.url).hostname

    def build_link(self, inb, client):
        """Best-effort direct link for vless / vmess / trojan inbounds."""
        try:
            proto = inb["protocol"]
            ss = json.loads(inb.get("streamSettings") or "{}")
            net = ss.get("network", "tcp")
            sec = ss.get("security", "none")
            host = self._host()
            port = inb["port"]
            q = {"type": net, "security": sec}
            if net == "ws":
                ws = ss.get("wsSettings", {})
                q["path"] = ws.get("path", "/")
                h = ws.get("host") or (ws.get("headers") or {}).get("Host")
                if h:
                    q["host"] = h
            elif net == "grpc":
                q["serviceName"] = ss.get("grpcSettings", {}).get("serviceName", "")
            elif net in ("httpupgrade", "xhttp", "splithttp"):
                st = ss.get(net + "Settings", {})
                q["path"] = st.get("path", "/")
                if st.get("host"):
                    q["host"] = st["host"]
            if sec == "tls":
                tl = ss.get("tlsSettings", {})
                if tl.get("serverName"):
                    q["sni"] = tl["serverName"]
                q["fp"] = (tl.get("settings") or {}).get("fingerprint", "chrome")
            elif sec == "reality":
                rs = ss.get("realitySettings", {})
                st = rs.get("settings", {})
                q["pbk"] = st.get("publicKey", "")
                q["fp"] = st.get("fingerprint", "chrome")
                q["sni"] = (rs.get("serverNames") or [""])[0]
                q["sid"] = (rs.get("shortIds") or [""])[0]
                if st.get("spiderX"):
                    q["spx"] = st["spiderX"]
            if client.get("flow"):
                q["flow"] = client["flow"]
            tag = urllib.parse.quote(client["email"])
            qs = urllib.parse.urlencode({k: v for k, v in q.items() if v not in (None, "")})
            if proto == "vless":
                return f"vless://{client['id']}@{host}:{port}?{qs}#{tag}"
            if proto == "trojan":
                return f"trojan://{client['password']}@{host}:{port}?{qs}#{tag}"
            if proto == "vmess":
                v = {"v": "2", "ps": client["email"], "add": host, "port": str(port), "id": client["id"], "aid": "0",
                     "net": net, "type": "none", "host": q.get("host", ""), "path": q.get("path", q.get("serviceName", "")),
                     "tls": sec if sec != "none" else "", "sni": q.get("sni", "")}
                return "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
        except Exception:
            return ""
        return ""

    def _client(self, proto, name, gb, expire_ts, users, cid=None, sub=None):
        c = {"email": name, "limitIp": int(users or 0), "totalGB": int(gb * GB) if gb else 0,
             "expiryTime": int(expire_ts * 1000) if expire_ts else 0, "enable": True, "tgId": "",
             "subId": sub or secrets.token_hex(8), "reset": 0}
        cid = cid or str(uuid.uuid4())
        if proto in ("trojan", "shadowsocks"):
            c["password"] = cid
        else:
            c["id"] = cid
            c["flow"] = self.extra.get("flow", "")
        if proto == "shadowsocks":
            c["method"] = ""
        return c, cid

    async def create(self, name, gb, days, users=1):
        iid = await self._iid()
        inb = await self._inbound(iid)
        client, cid = self._client(inb["protocol"], name, gb, time.time() + days * 86400 if days else 0, users)
        st, d = await self.api("POST", "/addClient", data={"id": str(iid), "settings": json.dumps({"clients": [client]})})
        if not d.get("success"):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        sub_base = (self.extra.get("sub_url") or "").rstrip("/")
        link = f"{sub_base}/{client['subId']}" if sub_base else self.build_link(inb, client)
        return {"link": link, "meta": {"name": name, "uuid": cid, "iid": iid, "proto": inb["protocol"], "sub": client["subId"]}}

    async def renew(self, meta, gb, expire_ts, users=1):
        client, _ = self._client(meta.get("proto", "vless"), meta["name"], gb, expire_ts, users, meta["uuid"], meta.get("sub"))
        st, d = await self.api("POST", f"/updateClient/{meta['uuid']}",
                               data={"id": str(meta["iid"]), "settings": json.dumps({"clients": [client]})})
        if not d.get("success"):
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))
        await self.api("POST", f"/{meta['iid']}/resetClientTraffic/{meta['name']}")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/getClientTraffics/{meta['name']}")
        o = d.get("obj")
        if not o:
            raise PanelError("سرویس در پنل یافت نشد")
        exp = o.get("expiryTime") or 0
        return {"used": (o.get("up") or 0) + (o.get("down") or 0), "total": o.get("total") or 0,
                "expire": int(exp / 1000) if exp > 0 else 0, "status": "active" if o.get("enable") else "disabled"}

    async def delete(self, meta):
        await self.api("POST", f"/{meta['iid']}/delClient/{meta['uuid']}")

    CAN_REVOKE = True

    async def revoke(self, meta, users=1):
        u = await self.usage(meta)
        inb = await self._inbound(meta["iid"])
        client, cid = self._client(meta.get("proto", "vless"), meta["name"], (u["total"] or 0) / GB, u["expire"], users)
        st, d = await self.api("POST", f"/updateClient/{meta['uuid']}",
                               data={"id": str(meta["iid"]), "settings": json.dumps({"clients": [client]})})
        if not d.get("success"):
            raise PanelError(self.err(d, "تغییر لینک در پنل ناموفق بود"))
        sub_base = (self.extra.get("sub_url") or "").rstrip("/")
        link = f"{sub_base}/{client['subId']}" if sub_base else self.build_link(inb, client)
        return {"link": link, "meta": {**meta, "uuid": cid, "sub": client["subId"]}}


class XUIAlireza(XUI):
    PREFIX = "/xui/API/inbounds"


# ---------------------------------------------------------------- Hiddify
class Hiddify(Base):
    def h(self):
        key = self.extra.get("api_key") or self.pw
        if not key:
            m = _UUID.search(self.srv.get("url") or "")
            key = m.group(0) if m else ""
        return {"Hiddify-API-Key": key, "Accept": "application/json"}

    async def test(self):
        st, d, _ = await self.req("GET", "/api/v2/panel/ping/", headers=self.h())
        if st != 200:
            if st in (401, 403) and _json(d):
                raise AuthError("کلید API پنل Hiddify نامعتبر است")
            raise PanelError("اتصال ناموفق بود؛ لینک ادمین یا API Key را بررسی کنید")
        if not _json(d):
            raise PanelError("پنل Hiddify در این آدرس پیدا نشد")
        return "اتصال موفق به Hiddify"

    def _link(self, uid):
        base = (self.extra.get("client_url") or self.url).rstrip("/")
        return f"{base}/{uid}/"

    async def create(self, name, gb, days, users=1):
        body = {"name": name, "usage_limit_GB": gb or 10000, "package_days": days or 3650, "mode": "no_reset", "enable": True}
        st, d, _ = await self.req("POST", "/api/v2/admin/user/", headers=self.h(), json=body)
        if st not in (200, 201) or not d.get("uuid"):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        return {"link": self._link(d["uuid"]), "meta": {"name": name, "uuid": d["uuid"]}}

    async def renew(self, meta, gb, expire_ts, users=1):
        days = max(1, math.ceil((expire_ts - time.time()) / 86400)) if expire_ts else 3650
        st, d, _ = await self.req("PATCH", f"/api/v2/admin/user/{meta['uuid']}/", headers=self.h(), json={
            "usage_limit_GB": gb or 10000, "package_days": days, "current_usage_GB": 0, "start_date": None, "enable": True})
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))

    async def usage(self, meta):
        st, d, _ = await self.req("GET", f"/api/v2/admin/user/{meta['uuid']}/", headers=self.h())
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        exp = 0
        if d.get("start_date"):
            try:
                sd = datetime.datetime.strptime(d["start_date"], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
                exp = int(sd.timestamp() + (d.get("package_days") or 0) * 86400)
            except ValueError:
                pass
        return {"used": int((d.get("current_usage_GB") or 0) * GB), "total": int((d.get("usage_limit_GB") or 0) * GB),
                "expire": exp, "status": "active" if d.get("enable", True) else "disabled", "link": self._link(meta["uuid"])}

    async def delete(self, meta):
        await self.req("DELETE", f"/api/v2/admin/user/{meta['uuid']}/", headers=self.h())


# ---------------------------------------------------------------- Custom HTTP API
class Custom(Base):
    """Bridge for any panel: POST {url} with JSON {action, ...} and Authorization: Bearer <password>.
    create -> {"link": "...", "meta": {...}} ; usage -> {"used": bytes, "total": bytes, "expire": unix}"""

    async def call(self, action, **kw):
        st, d, _ = await self.req("POST", "", json={"action": action, **kw}, headers={"Authorization": "Bearer " + self.pw})
        if st != 200 or (isinstance(d, dict) and d.get("error")):
            raise PanelError(self.err(d, "پاسخ نامعتبر از API"))
        return d

    async def test(self):
        await self.call("ping")
        return "اتصال موفق به API"

    async def create(self, name, gb, days, users=1):
        d = await self.call("create", username=name, volume_gb=gb, days=days, users=users)
        return {"link": d.get("link", ""), "meta": {"name": name, **(d.get("meta") or {})}}

    async def renew(self, meta, gb, expire_ts, users=1):
        await self.call("renew", meta=meta, volume_gb=gb, expire=int(expire_ts or 0), users=users)

    async def usage(self, meta):
        return await self.call("usage", meta=meta)

    async def delete(self, meta):
        await self.call("delete", meta=meta)


# ---------------------------------------------------------------- PasarGuard (Marzban successor, group based)
class PasarGuard(Marzban):
    async def test(self):
        await self.token(True)
        st, d = await self.api("GET", "/api/admin")
        if st != 200 or not _json(d):
            raise PanelError(self.err(d, "ورود ناموفق", st))
        return f"اتصال موفق به PasarGuard ({d.get('username', self.user)})"

    async def _groups(self):
        ids = self.extra.get("group_ids")
        if ids:
            return [int(x) for x in ids]
        st, d = await self.api("GET", "/api/groups")
        items = d.get("groups", []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
        return [g["id"] for g in items if not g.get("is_disabled")]

    def _body(self, name, gb, expire_ts, groups, iso):
        b = {"username": name, "group_ids": groups, "data_limit": int(gb * GB) if gb else 0,
             "data_limit_reset_strategy": "no_reset", "status": "active", "note": "", "proxy_settings": {}}
        if expire_ts:
            b["expire"] = _iso(expire_ts) if iso else int(expire_ts)
        return b

    async def create(self, name, gb, days, users=1):
        groups = await self._groups()
        exp = time.time() + days * 86400 if days else 0
        st, d = await self.api("POST", "/api/user", json=self._body(name, gb, exp, groups, True))
        if st == 422:
            st, d = await self.api("POST", "/api/user", json=self._body(name, gb, exp, groups, False))
        if st == 409:
            st, d = await self.api("GET", f"/api/user/{name}")
        if st not in (200, 201):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود", st))
        return {"link": self.sub(d), "meta": {"name": name}}

    async def renew(self, meta, gb, expire_ts, users=1):
        groups = await self._groups()
        body = self._body(meta["name"], gb, expire_ts, groups, True)
        body.pop("username", None)
        st, d = await self.api("PUT", f"/api/user/{meta['name']}", json=body)
        if st == 422:
            body = self._body(meta["name"], gb, expire_ts, groups, False)
            body.pop("username", None)
            st, d = await self.api("PUT", f"/api/user/{meta['name']}", json=body)
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود", st))
        await self.api("POST", f"/api/user/{meta['name']}/reset")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/api/user/{meta['name']}")
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        exp = d.get("expire")
        exp = _from_iso(exp) if isinstance(exp, str) else (exp or 0)
        return {"used": d.get("used_traffic") or 0, "total": d.get("data_limit") or 0, "expire": exp,
                "status": d.get("status"), "link": self.sub(d)}


# ---------------------------------------------------------------- Remnawave (API token)
class Remnawave(Base):
    async def tok(self, force=False):
        if self.extra.get("api_key") or not self.user:
            return self.extra.get("api_key") or self.pw
        k = ("rw", self.url, self.user, _fp(self.pw))
        t = _AUTH.get(k)
        if t and not force and t[1] > time.time():
            return t[0]
        st, d, _ = await self.req("POST", "/api/auth/login", json={"username": self.user, "password": self.pw}, _retry_ok=True)
        tk = (d.get("response") or {}).get("accessToken") if isinstance(d, dict) else None
        if st not in (200, 201) or not tk:
            if st in (400, 401, 403) and _json(d) and ("message" in d or "errorCode" in d):
                raise AuthError("ورود به پنل ناموفق بود (نام کاربری یا رمز عبور اشتباه است)")
            raise PanelError(f"پنل Remnawave در این آدرس پیدا نشد (کد {st})")
        _AUTH[k] = (tk, time.time() + 3000)
        return tk

    async def api(self, method, path, **kw):
        h = {"Authorization": "Bearer " + await self.tok(), "Accept": "application/json"}
        st, d, _ = await self.req(method, path, headers=h, **kw)
        if st == 401 and self.user and not self.extra.get("api_key"):
            h["Authorization"] = "Bearer " + await self.tok(True)
            st, d, _ = await self.req(method, path, headers=h, **kw)
        if st == 401:
            if _json(d) and ("message" in d or "errorCode" in d or "statusCode" in d):
                raise AuthError("توکن API پنل Remnawave نامعتبر است")
            raise PanelError("پنل Remnawave در این آدرس پیدا نشد")
        return st, (d.get("response", d) if isinstance(d, dict) else d)

    async def test(self):
        st, d = await self.api("GET", "/api/users?size=1&start=0")
        if st != 200:
            raise PanelError(self.err(d, "اتصال ناموفق", st))
        if not (isinstance(d, dict) and ("users" in d or "total" in d)):
            raise PanelError("پنل Remnawave در این آدرس پیدا نشد")  # a login page or another app answered
        return "اتصال موفق به Remnawave"

    async def _squads(self):
        if self.extra.get("squads"):
            return self.extra["squads"]
        st, d = await self.api("GET", "/api/internal-squads")
        items = d.get("internalSquads", []) if isinstance(d, dict) else []
        return [x["uuid"] for x in items]

    async def create(self, name, gb, days, users=1):
        body = {"username": name, "trafficLimitBytes": int(gb * GB) if gb else 0, "trafficLimitStrategy": "NO_RESET",
                "expireAt": _iso(time.time() + (days or 3650) * 86400), "status": "ACTIVE"}
        if users and users > 1:
            body["hwidDeviceLimit"] = int(users)
        try:
            sq = await self._squads()
            if sq:
                body["activeInternalSquads"] = sq
        except PanelError:
            pass
        st, d = await self.api("POST", "/api/users", json=body)
        if st not in (200, 201) or not d.get("uuid"):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود", st))
        return {"link": d.get("subscriptionUrl") or "", "meta": {"name": name, "uuid": d["uuid"]}}

    async def renew(self, meta, gb, expire_ts, users=1):
        st, d = await self.api("PATCH", "/api/users", json={"uuid": meta["uuid"], "trafficLimitBytes": int(gb * GB) if gb else 0,
                                                          "expireAt": _iso(expire_ts or time.time() + 3650 * 86400), "status": "ACTIVE"})
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود", st))
        await self.api("POST", f"/api/users/{meta['uuid']}/actions/reset-traffic")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/api/users/{meta['uuid']}")
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        used = d.get("usedTrafficBytes")
        if used is None:
            used = (d.get("userTraffic") or {}).get("usedTrafficBytes", 0)
        return {"used": int(used or 0), "total": int(d.get("trafficLimitBytes") or 0), "expire": _from_iso(d.get("expireAt")),
                "status": str(d.get("status", "")).lower(), "link": d.get("subscriptionUrl")}

    async def delete(self, meta):
        await self.api("DELETE", f"/api/users/{meta['uuid']}")

    CAN_REVOKE = True

    async def revoke(self, meta, users=1):
        st, d = await self.api("POST", f"/api/users/{meta['uuid']}/actions/revoke", json={})
        if st not in (200, 201):
            raise PanelError(self.err(d, "تغییر لینک در پنل ناموفق بود", st))
        return {"link": d.get("subscriptionUrl") or "", "meta": meta}


class Stock(Base):
    async def test(self):
        return "انبار کانفیگ دستی (نیازی به اتصال ندارد)"

    async def usage(self, meta):
        raise PanelError("آمار مصرف برای کانفیگ دستی در دسترس نیست")

    async def renew(self, meta, gb, expire_ts, users=1):
        raise PanelError("تمدید خودکار برای کانفیگ دستی امکان‌پذیر نیست")

    async def delete(self, meta):
        return None


ADAPTERS = {"marzban": Marzban, "pasarguard": PasarGuard, "remnawave": Remnawave, "marzneshin": Marzneshin,
            "xui": XUI, "xui_alireza": XUIAlireza, "hiddify": Hiddify, "custom": Custom, "stock": Stock}


def get_adapter(srv, session):
    cls = ADAPTERS.get(srv.get("type"))
    if not cls:
        raise PanelError("نوع پنل پشتیبانی نمی‌شود")
    return cls(srv, session)


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_CONN = ("اتصال به سرور برقرار نشد", "جواب نداد", "خطا در اتصال به پنل")


_INVIS = re.compile("[\u200b\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff\u00a0]")
_FA_DIG = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")
_KV = re.compile(r"(?i)^\s*(user(?:name)?|login|admin|نام\s*کاربری|یوزر(?:نیم)?|pass(?:word)?|pwd|رمز(?:\s*عبور)?|پسورد|token|api[\s_-]*key|توکن)\s*[:=：]\s*(.+?)\s*$")
_HOST_HINT = {}  # host -> (type, base) of the last successful detection, for instant reconnects


def _clean(v, digits=False):
    v = _INVIS.sub("", str(v or "")).strip().strip("\"'`«»")
    return v.translate(_FA_DIG) if digits else v


def _parse_paste(raw, user, pw):
    """Understands messy pastes: a whole message with link + username + password, user:pass@host links,
    ?username=&password= links, and Persian digits or hidden RTL marks copied from Telegram."""
    raw = _clean(raw)
    lines = [x for x in re.split(r"[\r\n]+", raw) if x.strip()]
    url = ""
    loose = []
    for ln in lines:
        m = _KV.match(_INVIS.sub("", ln))
        if m:
            k, v = m.group(1).lower(), _clean(m.group(2))
            if any(w in k for w in ("pass", "pwd", "رمز", "پسورد", "token", "api", "توکن")):
                pw = pw or v
            else:
                user = user or v
            continue
        for tok in ln.split():
            tok = tok.strip(",;")
            if not url and (re.match(r"(?i)^https?://", tok) or re.match(r"^[\w.-]+\.[a-z]{2,}(:\d+)?(/|$)", tok, re.I)
                            or re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?(/|$)", tok.translate(_FA_DIG))):
                url = tok
            elif tok:
                loose.append(_clean(tok))
    if not url:
        url = raw.split()[0] if raw.split() else ""
    if loose and not user and not pw and len(loose) == 2:
        user, pw = loose
    elif loose and not pw and len(loose) == 1:
        pw = loose[0]
    # host part: Persian digits -> ASCII, credentials inside the link
    m = re.match(r"(?i)^(https?://)?([^/?#]*)(.*)$", url)
    sch, host, rest = m.group(1) or "", m.group(2).translate(_FA_DIG), m.group(3)
    if "@" in host:
        cred, host = host.rsplit("@", 1)
        cu, _, cp = cred.partition(":")
        user, pw = user or urllib.parse.unquote(cu), pw or urllib.parse.unquote(cp)
    if "?" in rest:
        path, _, q = rest.partition("?")
        qs = urllib.parse.parse_qs(q.split("#")[0])
        user = user or (qs.get("username") or qs.get("user") or [""])[0]
        pw = pw or (qs.get("password") or qs.get("pass") or qs.get("token") or [""])[0]
        if any(k in qs for k in ("username", "user", "password", "pass", "token")):
            rest = path
    host = host.replace("：", ":").lower()
    return sch + host + rest, _clean(user), _clean(pw)


def _prepare(srv):
    """Reads whatever was pasted and extracts everything useful from it."""
    ex = srv.get("extra") or {}
    ex = dict(json.loads(ex) if isinstance(ex, str) else ex)
    raw, user, pw = _parse_paste(srv.get("url") or "", _clean(srv.get("username")), _clean(srv.get("password")))
    hint = None
    m = _UUID.search(raw)
    if m and not raw.lower().rstrip("/").endswith("/sub"):
        # Hiddify admin link: https://domain/<proxy_path>/<admin_uuid>/admin/
        hint = "hiddify"
        base = raw[: m.start()].rstrip("/")
        if not pw:
            pw = m.group(0)
        raw = base
    url = normalize_url(raw, "hiddify" if hint else "")
    bases = [url]
    if url and not re.match(r"^https?://", raw, re.I):
        bases.append("http://" + url.split("://", 1)[1])
    pu = urllib.parse.urlparse(url) if url else None
    if pu and pu.port and pu.port not in (443, 80):
        # Railway and Cloudflare-proxied panels are served on 443 even if the panel itself listens on another port
        bases.append(url.replace(f":{pu.port}", "", 1))
    return bases, user, pw, ex, hint


def _candidates(user, pw, hint):
    jwt = pw.startswith("eyJ") and pw.count(".") == 2
    if hint == "hiddify":
        return ["hiddify"]
    if user:
        return ["marzban", "marzneshin", "xui", "xui_alireza", "remnawave", "hiddify"]
    out = ["remnawave", "hiddify"]
    if jwt:
        out += ["marzban", "marzneshin"]
    return out


async def _probe(t, base, user, pw, ex, session):
    srv = {"type": t, "url": base, "username": user, "password": pw, "extra": ex, "_timeout": 8, "_tries": 2}
    ad = get_adapter(srv, session)
    msg = await asyncio.wait_for(ad.test(), 12)
    if t == "marzban":
        try:
            st, d = await ad.api("GET", "/api/groups")
            if st == 200 and isinstance(d, dict) and "groups" in d:
                t, ad = "pasarguard", get_adapter(dict(srv, type="pasarguard"), session)
                msg = "اتصال موفق به PasarGuard"
        except PanelError:
            pass
    return t, ad, msg


async def _discover(t, ad):
    """After login, looks around the panel and fills optional settings automatically."""
    found, info = {}, []
    try:
        if t in ("xui", "xui_alireza"):
            if t == "xui":
                ck = await ad.login()
                st, d, _ = await ad.req("POST", "/panel/setting/all", headers={"Cookie": ck, "Accept": "application/json"}, _retry_ok=True)
                o = d.get("obj") if isinstance(d, dict) else None
                if isinstance(o, dict) and o.get("subEnable"):
                    sub = (o.get("subURI") or "").rstrip("/")
                    if not sub:
                        p = urllib.parse.urlparse(ad.url)
                        host = o.get("subDomain") or p.hostname
                        sch = "https" if (o.get("subCertFile") or p.scheme == "https") else "http"
                        sub = f"{sch}://{host}:{o.get('subPort') or 2096}{(o.get('subPath') or '/sub/').rstrip('/')}"
                    found["sub_url"] = sub
                    info.append("لینک ساب پیدا شد")
        elif t == "pasarguard":
            info.append(f"{len(await ad._groups())} گروه فعال")
        elif t == "hiddify" and not ad.extra.get("client_url"):
            info.append("برای لینک ساب کاربران، آدرس کاربری (Client) را در ویرایش سرور وارد کنید")
        elif t == "remnawave":
            info.append(f"{len(await ad._squads())} اسکواد")
    except (PanelError, KeyError, TypeError, AttributeError, ValueError, asyncio.TimeoutError):
        pass
    return found, info


def _auto_name(t, url):
    host = urllib.parse.urlparse(url).hostname or ""
    return f"{TYPES.get(t, t)} | {host}"[:60]


async def smart_detect(srv, session):
    """Detects the panel from a pasted link + credentials (or token only) and returns a ready-to-save config.

    All candidate panels are probed at the same time; the first one that logs in wins, so detection
    takes about as long as a single login.
    """
    bases, user, pw, ex, hint = _prepare(srv)
    if not bases[0]:
        raise PanelError("آدرس پنل را وارد کنید")
    if not pw:
        raise PanelError("رمز عبور یا توکن API پنل را وارد کنید")
    errors, auth_fail = [], []

    gate = asyncio.Semaphore(24)  # never more than 24 connections at once, even while scanning ports

    async def guarded(t, b):
        async with gate:
            return await _probe(t, b, user, pw, ex, session)

    async def attempt(base_list):
        tasks = [asyncio.ensure_future(guarded(t, b)) for b in base_list for t in _candidates(user, pw, hint)]
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    return await fut
                except AuthError as e:
                    auth_fail.append(str(e))
                except (PanelError, asyncio.TimeoutError, KeyError, TypeError, AttributeError, ValueError) as e:
                    errors.append(str(e) or "زمان پاسخ پنل تمام شد")
        finally:
            for x in tasks:
                x.cancel()
        return None

    def unreachable():
        return errors and not auth_fail and all(any(c in e for c in _CONN) or "موقتاً" in e or "521" in e or "522" in e for e in errors)

    def not_found():
        return errors and not auth_fail and all(any(w in e.lower() for w in ("404", "not found", "پیدا نشد", "شناخته", "نامعتبر")) for e in errors)

    found = None
    pu0 = urllib.parse.urlparse(bases[0])
    cached = _HOST_HINT.get(pu0.netloc)
    if cached and hint != "hiddify":
        # reconnect to a panel seen before: one quick login instead of a full scan
        try:
            found = await asyncio.wait_for(guarded(cached[0], cached[1]), 10)
        except (PanelError, asyncio.TimeoutError, KeyError, TypeError, AttributeError, ValueError):
            found = None
    for base in ([] if found else list(dict.fromkeys(bases))):
        found = await attempt([base])
        if found or not unreachable():
            break
    if not found and not auth_fail and pu0.path.strip("/"):
        # the link pointed somewhere inside the panel: walk up the path (/a/b/c -> /a/b -> /a -> /)
        parts = pu0.path.strip("/").split("/")
        ups = [f"{pu0.scheme}://{pu0.netloc}" + ("/" + "/".join(parts[:i]) if i else "") for i in range(len(parts) - 1, -1, -1)]
        if ups and (not_found() or not unreachable()):
            errors.clear()
            found = await attempt(ups[:4])
    if not found and unreachable() and not urllib.parse.urlparse(bases[0]).port:
        # no port was given and nothing answered: try the usual panel ports all at once
        host = urllib.parse.urlparse(bases[0])
        tail = host.path.rstrip("/")
        variants = [f"{sch}://{host.hostname}:{port}{tail}" for port in (8000, 2053, 54321, 8443, 2083, 2087, 2096, 8080)
                    for sch in ("https", "http")]
        found = await attempt(variants)
    if found:
        t, ad, msg = found
        if len(_HOST_HINT) > 500:
            _HOST_HINT.clear()
        _HOST_HINT[urllib.parse.urlparse(ad.url).netloc] = (t, ad.url)
        _HOST_HINT[pu0.netloc] = (t, ad.url)
        disc, info = await _discover(t, ad)
        extra = {**ex, **{k: v for k, v in disc.items() if not ex.get(k)}}
        if t == "hiddify" and not extra.get("api_key"):
            extra["api_key"] = pw
        return {"type": t, "label": TYPES.get(t, t), "url": ad.url, "username": user, "password": pw,
                "extra": extra, "name": _auto_name(t, ad.url), "details": info,
                "msg": f"شناسایی شد: {TYPES.get(t, t)} | {msg}" + (" | " + " | ".join(info) if info else "")}
    if auth_fail and not found:
        alt = pw.translate(_FA_DIG).replace(" ", "")
        if alt != pw:
            # password typed on a Persian keyboard: retry once with English digits and no spaces
            r = await smart_detect(dict(srv, url=bases[0], username=user.translate(_FA_DIG), password=alt, extra=ex), session)
            return r
    if auth_fail:
        raise PanelError("پنل پیدا شد ولی ورود ناموفق بود؛ " + ("توکن API را بررسی کنید." if not user else "نام کاربری یا رمز عبور اشتباه است.")
                         + " (حروف بزرگ و کوچک و فاصله اضافه را چک کنید)")
    special = next((e for e in errors if "Cloudflare" in e or "Railway" in e or "SSL" in e), None)
    if special:
        raise PanelError(special)
    if errors and all(any(c in e for c in _CONN) for e in errors):
        raise PanelError(next((e for e in errors if "جواب نداد" in e), errors[0]))
    raise PanelError("در این آدرس پنل شناخته‌شده‌ای پیدا نشد. لینک را دقیق از نوار آدرس مرورگر، همان صفحه ورود پنل، کپی کنید "
                     "(همراه با پورت و مسیر مخفی؛ مثلاً https://domain.com:2053/abc123).")


async def detect(srv, session):
    r = await asyncio.wait_for(smart_detect(srv, session), 45)
    return r["type"], r["msg"]
