#!/usr/bin/env python3
"""
launch-checklist / launchcheck.py — готов ли сайт к запуску: маршрутизация, индексация,
шеринг, иконки, грубая производительность, аналитика и юридические ссылки.

Только GET-запросы (не больше 30, с паузами). Ничего не отправляет в формы и не перебирает.
Для localhost подтверждение не нужно; внешний домен — только свой, с подтверждением владения.

  python3 launchcheck.py http://localhost:3000       # прод-сборка локально: next build && next start
  python3 launchcheck.py https://мой-сайт.com         # после деплоя (спросит, твой ли это сайт)

Коды выхода: 2 — есть critical, 1 — есть warning, 0 — чисто.
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

VERSION = "1.0.0"
UA = f"launch-checklist/{VERSION} (+own-site pre-launch check)"
PAUSE = 0.2
MAX_REQUESTS = 30
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
SECTIONS = [
    ("server", "Сервер и маршрутизация"),
    ("index", "Индексация и SEO"),
    ("share", "Шеринг и иконки"),
    ("perf", "Производительность (грубо, по HTML)"),
    ("analytics", "Аналитика и мониторинг"),
    ("legal", "Юридические страницы"),
    ("security", "Безопасность"),
]
STACK_RX = re.compile(rb"(?i)Traceback \(most recent call last\)|at Object\.<anonymous>|node_modules/|"
                      rb"\n\s+at [\w.$<>]+ \(|Exception in thread|stack trace:|SQLSTATE\[|pg_query\(")


class Budget(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Fetcher:
    def __init__(self):
        self.count = 0

    def get(self, url, follow=True, limit=2_000_000, timeout=15):
        if self.count >= MAX_REQUESTS:
            raise Budget()
        if self.count:
            time.sleep(PAUSE)
        self.count += 1
        opener = urllib.request.build_opener(*([] if follow else [NoRedirect()]))
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*"})
        try:
            r = opener.open(req, timeout=timeout)
            return r.getcode(), r.headers, r.read(limit), r.geturl()
        except urllib.error.HTTPError as e:
            try:
                body = e.read(limit)
            except Exception:
                body = b""
            return e.code, e.headers, body, url


class Doc(HTMLParser):
    """Минимальный разбор HTML: title, meta, link, script, img, a, lang."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lang = None
        self.title = None
        self.metas, self.links, self.scripts, self.imgs, self.anchors = [], [], [], [], []
        self._in_title, self._title, self._script, self._a, self._in_head = False, [], None, None, False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.lang = a.get("lang")
        elif tag == "head":
            self._in_head = True
        elif tag == "title" and self.title is None:
            self._in_title = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "link":
            self.links.append(a)
        elif tag == "script":
            self._script = {"attrs": a, "text": [], "in_head": self._in_head}
        elif tag == "img":
            self.imgs.append(a)
        elif tag == "a":
            self._a = {"href": a.get("href", ""), "text": []}

    def handle_endtag(self, tag):
        if tag == "title" and self._in_title:
            self._in_title = False
            self.title = "".join(self._title).strip()
        elif tag == "head":
            self._in_head = False
        elif tag == "script" and self._script is not None:
            self._script["text"] = "".join(self._script["text"])
            self.scripts.append(self._script)
            self._script = None
        elif tag == "a" and self._a is not None:
            self._a["text"] = "".join(self._a["text"]).strip()
            self.anchors.append(self._a)
            self._a = None

    def handle_data(self, data):
        if self._in_title:
            self._title.append(data)
        if self._script is not None:
            self._script["text"].append(data)
        if self._a is not None:
            self._a["text"].append(data)

    def meta(self, key):
        key = key.lower()
        for m in self.metas:
            if (m.get("name") or m.get("property") or "").lower() == key:
                return m.get("content", "")
        return None

    def rel(self, rel):
        return [l for l in self.links if rel in l.get("rel", "").lower().split()]


def parse(body: bytes) -> Doc:
    d = Doc()
    try:
        d.feed(body.decode("utf-8", "ignore"))
    except Exception:
        pass
    return d


def noindex(doc: Doc, headers) -> bool:
    vals = [doc.meta("robots") or "", doc.meta("googlebot") or "", (headers.get("x-robots-tag") if headers else "") or ""]
    return any("noindex" in v.lower() for v in vals)


def parse_robots(text: str):
    groups, sitemaps, cur, last_agent = [], [], None, False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        k = k.lower()
        if k == "user-agent":
            if cur is None or not last_agent:
                cur = {"agents": [], "rules": []}
                groups.append(cur)
            cur["agents"].append(v.lower())
            last_agent = True
        elif k in ("allow", "disallow"):
            if cur is None:
                cur = {"agents": ["*"], "rules": []}
                groups.append(cur)
            cur["rules"].append((k, v))
            last_agent = False
        elif k == "sitemap":
            sitemaps.append(v)
        else:
            last_agent = False
    return groups, sitemaps


def strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Проверка готовности сайта к запуску (только GET)")
    ap.add_argument("url", help="http://localhost:3000 или https://твой-сайт")
    ap.add_argument("--yes-i-own-this", action="store_true", help="не спрашивать о владении внешним доменом")
    ap.add_argument("--report", default="launchcheck-report.md")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    u = urllib.parse.urlparse(base)
    if u.scheme not in ("http", "https") or not u.hostname:
        sys.exit("URL должен быть вида http(s)://хост")
    host = u.hostname
    local = host in LOCAL_HOSTS or host.endswith(".local")
    origin = f"{u.scheme}://{u.netloc}"
    if not local and not args.yes_i_own_this:
        print(f"\n⚠️  Проверяем внешний сайт: {origin}\nЗапускай только против сайта, которым владеешь.")
        if input("Это твой сайт? (yes/no): ").strip().lower() not in ("yes", "y", "да", "д", "так", "т"):
            sys.exit("Отменено.")

    F = Fetcher()
    findings = []

    def add(section, sev, title, detail="", fix=""):
        findings.append({"section": section, "severity": sev, "title": title, "detail": detail, "fix": fix})

    def ok(section, title, detail=""):
        add(section, "ok", title, detail)

    def local_url(link: str):
        """URL со страницы → URL, который можно запросить. На localhost абсолютные ссылки на прод-домен
        переводятся на локальный origin, чтобы не ходить в прод. Чужие хосты не запрашиваем."""
        p = urllib.parse.urlparse(urllib.parse.urljoin(base + "/", link))
        if p.netloc == u.netloc:
            return p.geturl()
        if local:
            return origin + (p.path or "/") + (f"?{p.query}" if p.query else "")
        return None

    try:
        # ---------------------------------------------------------------- главная
        code, h, body, final = F.get(base + "/")
        home = parse(body)
        if code == 200:
            ok("server", "Главная отвечает 200")
        else:
            add("server", "critical", f"Главная отвечает {code}", fix="Проверь URL и что запущена прод-сборка.")

        # ---------------------------------------------------------------- HTTPS и хост
        if local:
            add("server", "info", "HTTPS и единый хост не проверяются на localhost",
                fix="Повтори проверку на своём домене после деплоя.")
        elif u.scheme == "http":
            add("server", "critical", "Сайт проверяется по HTTP", fix="Включи HTTPS и постоянный редирект с HTTP.")
        else:
            try:
                c2, h2, _, _ = F.get(f"http://{u.netloc}/", follow=False)
                loc = (h2.get("location") or "") if h2 else ""
                if c2 in (301, 308) and loc.startswith("https://"):
                    ok("server", "HTTP → HTTPS постоянным редиректом", f"{c2} → {loc}")
                elif c2 in (302, 307) and loc.startswith("https://"):
                    add("server", "warning", f"HTTP → HTTPS временным редиректом ({c2})", fix="Нужен 301 или 308.")
                else:
                    add("server", "critical", "HTTP не перенаправляет на HTTPS", f"ответ {c2}",
                        fix="Постоянный редирект 301/308 на https:// (обычно одна галочка в хостинге/Cloudflare).")
            except Budget:
                raise
            except Exception:
                add("server", "info", "HTTP-версия недоступна (порт 80 закрыт?)")
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                alt = host[4:] if host.startswith("www.") else "www." + host
                try:
                    c3, h3, _, _ = F.get(f"https://{alt}/", follow=False, timeout=8)
                    loc = (h3.get("location") or "") if h3 else ""
                    if c3 in (301, 308) and urllib.parse.urlparse(loc).hostname == host:
                        ok("server", f"{alt} перенаправляет на {host}")
                    elif c3 == 200:
                        add("server", "warning", f"Сайт доступен и на {alt}, и на {host} — дубли", fix=f"301 с {alt} на {host}.")
                    elif c3 in (302, 307):
                        add("server", "info", f"{alt} перенаправляет временным редиректом", fix="Сделай 301/308.")
                except Budget:
                    raise
                except Exception:
                    ok("server", f"{alt} не отвечает (не настроен) — дублей хоста нет")

        # ---------------------------------------------------------------- 404
        probe = f"{origin}/__launchcheck-{secrets.token_hex(4)}"
        c4, h4, b4, _ = F.get(probe, follow=False)
        if c4 in (404, 410):
            ok("server", "Несуществующая страница отдаёт честный 404")
        elif c4 == 200:
            d4 = parse(b4)
            if noindex(d4, h4):
                add("server", "warning", "404-страница отдаёт статус 200 (но с noindex)",
                    "так бывает в Next.js, если notFound() вызван после начала стриминга",
                    "Вызывай notFound() до стриминга (в page, а не глубоко в компоненте под Suspense) и проверь статус curl'ом.")
            else:
                add("server", "critical", "Мягкий 404: несуществующая страница отдаёт 200",
                    "поисковик проиндексирует мусорные URL, а мониторинг не увидит битые ссылки",
                    "Верни статус 404 (Next.js: not-found.tsx + notFound(); SPA на хостинге — правило 404, а не rewrite всего на index.html).")
        elif 300 <= c4 < 400:
            add("server", "warning", f"Несуществующая страница редиректит ({c4}) вместо 404",
                fix="Редирект всех 404 на главную поисковики считают мягким 404. Отдай 404-страницу.")
        else:
            add("server", "warning", f"Несуществующая страница отдаёт {c4}", fix="Ожидается 404.")
        if b4 and STACK_RX.search(b4):
            add("security", "warning", "Страница ошибки показывает stack trace / внутренние пути",
                fix="Кастомные страницы 404/500 без деталей ошибки; детали — в лог.")

        # ---------------------------------------------------------------- robots.txt
        sitemaps = []
        cr, hr, br, _ = F.get(origin + "/robots.txt")
        rtext = br.decode("utf-8", "ignore")
        if cr != 200 or "<html" in rtext[:300].lower():
            add("index", "warning", "robots.txt не найден", fix="Next.js: app/robots.ts. Разреши публичное, укажи Sitemap.")
        else:
            groups, sitemaps = parse_robots(rtext)
            star = [g for g in groups if "*" in g["agents"]]
            blocked = any(("disallow", "/") in g["rules"] and not any(k == "allow" and v in ("/", "/*") for k, v in g["rules"])
                          for g in star)
            if blocked:
                add("index", "critical", "robots.txt закрывает весь сайт (Disallow: /)",
                    "частая ошибка: правило со стейджинга уехало в прод",
                    "На проде — Allow: /; закрывать только служебные пути. Если robots зависит от окружения, проверь на домене.")
            else:
                ok("index", "robots.txt найден и не закрывает сайт целиком")
            dis = [v for g in star for k, v in g["rules"] if k == "disallow" and v]
            if any(re.search(r"(?i)^/(_next|static|assets)/?$|\.(css|js)\$?$", v) for v in dis):
                add("index", "warning", "robots.txt закрывает CSS/JS", fix="Поисковику нужны стили и скрипты, чтобы отрисовать страницу.")
            secret_paths = [v for v in dis if re.search(r"(?i)admin|dashboard|panel|crm|internal|private|backup|secret|staff", v)]
            if secret_paths:
                add("security", "info", "robots.txt публично перечисляет служебные пути", ", ".join(secret_paths[:5]),
                    "robots.txt — не защита, а подсказка. Служебные разделы закрывай авторизацией; от индексации — noindex.")
            if sitemaps:
                ok("index", "В robots.txt указан Sitemap")
            else:
                add("index", "info", "В robots.txt нет строки Sitemap:", fix="Добавь Sitemap: https://домен/sitemap.xml.")

        # ---------------------------------------------------------------- sitemap
        locs = []
        sm_candidates = [x for x in (local_url(s) for s in sitemaps) if x] or [origin + "/sitemap.xml"]
        try:
            cs, hs, bs, _ = F.get(sm_candidates[0])
            root = ET.fromstring(bs) if cs == 200 else None
            if root is not None and strip_ns(root.tag) == "sitemapindex":
                child = next((e.text.strip() for e in root.iter() if strip_ns(e.tag) == "loc" and e.text), None)
                if child and local_url(child):
                    cs, hs, bs, _ = F.get(local_url(child))
                    root = ET.fromstring(bs) if cs == 200 else None
            if root is None:
                add("index", "warning", "sitemap.xml не найден", fix="Next.js: app/sitemap.ts; отправь в Google Search Console и Bing Webmaster Tools.")
            else:
                locs = [e.text.strip() for e in root.iter() if strip_ns(e.tag) == "loc" and e.text]
                if not locs:
                    add("index", "warning", "sitemap.xml пустой")
                else:
                    ok("index", f"sitemap.xml найден: {len(locs)} URL")
                    hosts = {urllib.parse.urlparse(x).netloc for x in locs}
                    if any(re.search(r"localhost|127\.0\.0\.1", x) for x in locs) and not local:
                        add("index", "critical", "В sitemap ссылки на localhost", fix="Базовый URL сайта — из env прода (NEXT_PUBLIC_SITE_URL).")
                    elif any(re.search(r"localhost|127\.0\.0\.1", x) for x in locs):
                        add("index", "warning", "В sitemap ссылки на localhost",
                            "локально это бывает, если базовый URL берётся из окружения",
                            "Проверь, что на проде в sitemap абсолютные URL боевого домена.")
                    elif not local and hosts != {u.netloc}:
                        add("index", "warning", "В sitemap URL другого хоста", ", ".join(sorted(hosts))[:120])
                    elif local:
                        ok("index", "URL в sitemap абсолютные", ", ".join(sorted(hosts))[:80])
                    if u.scheme == "https" and any(x.startswith("http://") for x in locs):
                        add("index", "warning", "В sitemap есть http:// ссылки", fix="Только https://.")
        except ET.ParseError:
            if re.search(rb"(?i)<!doctype html|<html", bs[:500]):
                add("index", "warning", "sitemap.xml не найден — вместо него отдаётся HTML-страница",
                    fix="Next.js: app/sitemap.ts; на SPA-хостинге — исключи sitemap.xml из rewrite на index.html.")
            else:
                add("index", "warning", "sitemap.xml не парсится как XML")

        # ---------------------------------------------------------------- страницы из sitemap
        pages = [("/", code, h, home, base + "/")]
        seen_paths = {"/"}
        for loc in locs:
            if len(pages) >= 5:
                break
            path = urllib.parse.urlparse(loc).path or "/"
            if path in seen_paths or not local_url(loc):
                continue
            seen_paths.add(path)
            cp, hp, bp, _ = F.get(local_url(loc))
            pages.append((path, cp, hp, parse(bp), loc))
        bad_status, idx_blocked, canon_mismatch = [], [], []
        for path, cp, hp, dp, loc in pages[1:]:
            if cp != 200:
                bad_status.append(f"{path} → {cp}")
                continue
            if noindex(dp, hp):
                idx_blocked.append(path)
            cn = (dp.rel("canonical") or [{}])[0].get("href", "")
            if cn and urllib.parse.urlparse(cn).path.rstrip("/") != path.rstrip("/"):
                canon_mismatch.append(f"{path} → {cn}")
        if bad_status:
            add("index", "warning", "В sitemap страницы не со статусом 200", "; ".join(bad_status),
                fix="В sitemap — только канонические индексируемые страницы с 200.")
        if idx_blocked:
            add("index", "warning", "В sitemap страницы с noindex", ", ".join(idx_blocked), fix="Убери их из sitemap или сними noindex.")
        if canon_mismatch:
            add("index", "warning", "Canonical страницы из sitemap указывает на другой URL", "; ".join(canon_mismatch)[:200])
        if len(pages) > 1 and not (bad_status or idx_blocked or canon_mismatch):
            ok("index", f"Проверено страниц из sitemap: {len(pages) - 1} — статус, noindex, canonical в порядке")

        # trailing slash
        sample = next((p for p in pages[1:] if p[1] == 200 and p[0] != "/"), None)
        if sample:
            path = sample[0]
            toggled = path.rstrip("/") if path.endswith("/") else path + "/"
            ct, ht, bt, _ = F.get(origin + toggled, follow=False)
            if ct in (301, 308):
                ok("server", "Слеш на конце URL нормализуется редиректом", f"{toggled} → {ht.get('location')}")
            elif ct in (404, 410):
                ok("server", "URL со слешем и без не дублируются")
            elif ct == 200:
                cn = (parse(bt).rel("canonical") or [{}])[0].get("href", "")
                if cn and urllib.parse.urlparse(cn).path.rstrip("/") == path.rstrip("/") and urllib.parse.urlparse(cn).path != toggled:
                    add("server", "info", "Обе версии URL (со слешем и без) отдают 200, но canonical один",
                        fix="Лучше 308-редирект на одну форму (Next.js: trailingSlash).")
                else:
                    add("server", "warning", "Дубли: URL со слешем и без отдают 200", f"{path} и {toggled}",
                        fix="Одна форма + редирект (Next.js: trailingSlash: false/true) и self-canonical.")

        # ---------------------------------------------------------------- метаданные главной
        if noindex(home, h):
            add("index", "critical", "Главная закрыта от индексации (noindex)",
                "meta robots или заголовок X-Robots-Tag", "Убери noindex на проде (часто остаётся со стейджинга/превью).")
        else:
            ok("index", "Главная не закрыта noindex")
        title = home.title or ""
        if not title:
            add("index", "critical", "Нет <title>", fix="Next.js: metadata.title / title.template в layout.")
        else:
            ok("index", "Есть <title>", f"«{title[:70]}» ({len(title)} симв.)")
            if len(title) < 15:
                add("index", "info", "Title слишком короткий", f"«{title}»", "Суть страницы + бренд: «Сантехник в Харькове — МЕРЩІЙ».")
            if len(title) > 65:
                add("index", "info", "Title длиннее ~65 символов — обрежется в выдаче")
        titles = [p[3].title for p in pages if p[1] == 200 and p[3].title]
        if len(titles) > 1 and len(set(titles)) < len(titles):
            add("index", "warning", "Одинаковые title на разных страницах", fix="Уникальный title для каждой страницы (generateMetadata).")
        desc = home.meta("description")
        if not desc:
            add("index", "warning", "Нет meta description", fix="metadata.description; 120–160 символов по сути страницы.")
        else:
            ok("index", "Есть meta description", f"{len(desc)} симв.")
            if len(desc) > 170:
                add("index", "info", "Description длиннее ~160 символов")
        canon = (home.rel("canonical") or [{}])[0].get("href", "")
        if not canon:
            add("index", "warning", "Нет canonical на главной", fix="metadata.alternates.canonical + metadataBase.")
        elif not canon.startswith(("http://", "https://")):
            add("index", "warning", "Canonical относительный", canon, "Нужен абсолютный URL (задай metadataBase).")
        elif re.search(r"localhost|127\.0\.0\.1", canon) and not local:
            add("index", "critical", "Canonical указывает на localhost", canon, "metadataBase из env прода.")
        elif not local and urllib.parse.urlparse(canon).netloc != u.netloc:
            add("index", "warning", "Canonical указывает на другой хост", canon)
        else:
            ok("index", "Canonical абсолютный", canon)
        if not home.lang:
            add("index", "warning", "Нет атрибута lang у <html>", fix="<html lang=\"uk\"> / \"de\" — для поисковиков и скринридеров.")
        else:
            ok("index", f"lang=\"{home.lang}\"")
        if not home.meta("viewport"):
            add("index", "warning", "Нет meta viewport", fix="Без него мобильная версия ломается и теряет в поиске.")
        alts = [l for l in home.rel("alternate") if l.get("hreflang")]
        if alts:
            langs = {l["hreflang"].lower() for l in alts}
            probs = []
            if "x-default" not in langs:
                probs.append("нет x-default")
            if home.lang and not any(x.split("-")[0] == home.lang.lower().split("-")[0] for x in langs):
                probs.append("нет ссылки на саму себя")
            if any(not l.get("href", "").startswith("http") for l in alts):
                probs.append("относительные URL")
            if probs:
                add("index", "warning", "Hreflang с ошибками: " + ", ".join(probs), ", ".join(sorted(langs)),
                    "Взаимные ссылки между всеми версиями, self-reference, x-default, абсолютные URL.")
            else:
                ok("index", "Hreflang настроен", ", ".join(sorted(langs)))
        ld = [s for s in home.scripts if s["attrs"].get("type", "").lower() == "application/ld+json"]
        types, broken = [], 0
        for s in ld:
            try:
                data = json.loads(s["text"])
                for item in (data if isinstance(data, list) else data.get("@graph", [data])):
                    t = item.get("@type") if isinstance(item, dict) else None
                    types += t if isinstance(t, list) else ([t] if t else [])
            except Exception:
                broken += 1
        if broken:
            add("index", "warning", f"JSON-LD не парсится ({broken} блок.)", fix="Проверь в Rich Results Test.")
        if types:
            ok("index", "Структурированные данные (JSON-LD)", ", ".join(sorted(set(map(str, types)))))
        elif not broken:
            add("index", "info", "Нет структурированных данных (JSON-LD)",
                fix="Минимум Organization + WebSite; по смыслу — BreadcrumbList, Article, Product, LocalBusiness/Service.")

        # ---------------------------------------------------------------- шеринг и иконки
        miss = [k for k in ("og:title", "og:description", "og:image", "og:url") if not home.meta(k)]
        if miss:
            add("share", "warning", "Не хватает Open Graph: " + ", ".join(miss),
                fix="metadata.openGraph (или opengraph-image.tsx): превью в Telegram, Viber, Facebook, LinkedIn.")
        else:
            ok("share", "Open Graph: title, description, image, url")
        ogi = home.meta("og:image")
        if ogi:
            if not ogi.startswith(("http://", "https://")):
                add("share", "warning", "og:image — относительный URL", ogi, "Нужен абсолютный (metadataBase).")
            target = local_url(ogi)
            if target:
                ci, hi, _, _ = F.get(target, limit=64)
                ctype = (hi.get("content-type") or "") if hi else ""
                if ci == 200 and ctype.startswith("image/"):
                    ok("share", "og:image открывается", ctype)
                else:
                    add("share", "warning", f"og:image не открывается ({ci}, {ctype or 'нет типа'})", ogi,
                        "Картинка 1200×630, доступная без авторизации.")
        if not home.meta("twitter:card"):
            add("share", "info", "Нет twitter:card", fix="summary_large_image — крупное превью в X и части мессенджеров.")

        def check_icon(rel, fallback, label, sev):
            links = home.rel(rel)
            target = local_url(links[0].get("href", "")) if links else origin + fallback
            if not target:
                return
            ci, hi, _, _ = F.get(target, limit=64)
            ctype = ((hi.get("content-type") or "") if hi else "").lower()
            if ci == 200 and not ctype.startswith("text/html"):
                ok("share", f"{label} найден")
            else:
                add("share", sev, f"{label} не найден ({ci})",
                    fix="Next.js: app/favicon.ico, app/icon.png|svg, app/apple-icon.png (180×180).")

        check_icon("icon", "/favicon.ico", "Favicon", "warning")
        check_icon("apple-touch-icon", "/apple-touch-icon.png", "Apple Touch Icon", "info")
        man = home.rel("manifest")
        if not man:
            add("share", "info", "Нет Web App Manifest", fix="app/manifest.ts — нужен для «добавить на экран» и PWA (необязательно).")
        else:
            target = local_url(man[0].get("href", ""))
            if target:
                cm, _, bm, _ = F.get(target)
                try:
                    mj = json.loads(bm)
                    sizes = " ".join(i.get("sizes", "") for i in mj.get("icons", []))
                    if (mj.get("name") or mj.get("short_name")) and "192" in sizes and "512" in sizes:
                        ok("share", "Manifest: name и иконки 192/512")
                    else:
                        add("share", "info", "Manifest неполный", fix="name/short_name, icons 192×192 и 512×512, theme_color.")
                except Exception:
                    add("share", "warning", f"Manifest не открывается или не JSON ({cm})")

        # ---------------------------------------------------------------- производительность
        size_kb = len(body) // 1024
        if size_kb > 500:
            add("perf", "warning", f"HTML главной {size_kb} КБ", fix="Слишком много данных в разметке/RSC-payload: не передавай большие объекты в клиентские компоненты.")
        else:
            ok("perf", f"HTML главной {len(body) / 1024:.1f} КБ")
        no_dims = [i.get("src", "")[:60] for i in home.imgs
                   if not (i.get("width") and i.get("height")) and i.get("data-nimg") != "fill"
                   and "position:absolute" not in i.get("style", "").replace(" ", "")]
        if no_dims:
            add("perf", "info", f"Картинки без width/height: {len(no_dims)} — риск сдвига вёрстки (CLS)",
                ", ".join(no_dims[:3]), "next/image с размерами или fill + контейнер с размером.")
        legacy = [i.get("src", "") for i in home.imgs if re.search(r"(?i)\.(png|jpe?g)(\?|$)", i.get("src", ""))
                  and "/_next/image" not in i.get("src", "")]
        if legacy:
            add("perf", "info", f"Картинки в PNG/JPEG мимо оптимизатора: {len(legacy)}", ", ".join(x[:60] for x in legacy[:3]),
                "next/image отдаёт WebP/AVIF нужного размера.")
        blocking = [s["attrs"].get("src", "")[:60] for s in home.scripts if s["in_head"] and s["attrs"].get("src")
                    and not any(k in s["attrs"] for k in ("async", "defer", "nomodule")) and s["attrs"].get("type") != "module"]
        if blocking:
            add("perf", "info", f"Блокирующие скрипты в <head>: {len(blocking)}", ", ".join(blocking[:3]),
                "async/defer или next/script со strategy=\"afterInteractive\"/\"lazyOnload\".")
        if re.search(rb"fonts\.googleapis\.com|fonts\.gstatic\.com", body):
            add("perf", "warning", "Шрифты грузятся с серверов Google",
                "лишний запрос к стороннему домену; в ЕС это ещё и передача IP в Google без согласия",
                "next/font/google скачивает шрифт при сборке и раздаёт со своего домена. Не забудь subsets: ['cyrillic'].")
        else:
            ok("perf", "Шрифты не тянутся с Google Fonts напрямую")

        # ---------------------------------------------------------------- аналитика
        trackers = {name: bool(re.search(rx, body)) for name, rx in {
            "Google Analytics/GTM": rb"googletagmanager\.com|google-analytics\.com|gtag\(",
            "Meta Pixel": rb"connect\.facebook\.net|fbq\(",
            "Яндекс.Метрика": rb"mc\.yandex\.(ru|com)",
            "Plausible": rb"plausible\.io",
            "Umami": rb"umami",
            "PostHog": rb"posthog",
        }.items()}
        found = [k for k, v in trackers.items() if v]
        consent = re.search(rb"(?i)cookiebot|usercentrics|klaro|cookieyes|onetrust|consentmanager|cookie-?consent|"
                            rb"gtag\(\s*['\"]consent['\"]|borlabs|iubenda|termly", body)
        if found:
            ok("analytics", "Аналитика подключена", ", ".join(found))
        else:
            add("analytics", "info", "Аналитики в HTML не видно", fix="GA4/GTM или без cookies (Plausible, Umami). Может грузиться из бандла — сверь с кодом.")
        if (trackers["Google Analytics/GTM"] or trackers["Meta Pixel"]) and not consent:
            add("legal", "warning", "Трекеры без видимого механизма согласия",
                "в ЕС (DSGVO, TDDDG) такие скрипты можно загружать только после согласия",
                "Consent-баннер + Google Consent Mode v2, либо аналитика без cookies.")
        if trackers["Яндекс.Метрика"]:
            add("analytics", "info", "Подключена Яндекс.Метрика",
                "в Украине сервисы Яндекса заблокированы с 2017 года; в ЕС нужны согласие и правовое основание",
                "Для украинской и европейской аудитории — Google Analytics или Plausible/Umami.")

        # ---------------------------------------------------------------- юридическое
        blob = " ".join((a["href"] + " " + a["text"]).lower() for a in home.anchors)
        privacy = re.search(r"privacy|datenschutz|конфіденц|конфиденц|персональн|політик|политик", blob)
        impressum = re.search(r"impressum|imprint|legal-notice", blob)
        terms = re.search(r"terms|agb|nutzungsbedingungen|умов|услови|оферт|правила", blob)
        german = (home.lang or "").lower().startswith("de") or host.endswith(".de")
        if german:
            if impressum:
                ok("legal", "Impressum найден")
            else:
                add("legal", "warning", "Impressum не найден",
                    fix="Для коммерческого сайта в Германии Impressum обязателен (§ 5 DDG), ссылка — с каждой страницы.")
            if privacy:
                ok("legal", "Datenschutzerklärung найдена")
            else:
                add("legal", "warning", "Datenschutzerklärung не найдена",
                    fix="Datenschutzerklärung по DSGVO: какие данные, зачем, кто обработчики (хостинг, почта, аналитика).")
        elif privacy:
            ok("legal", "Ссылка на политику конфиденциальности есть")
        else:
            add("legal", "info", "Не видно ссылки на политику конфиденциальности",
                fix="Нужна, если собираешь персональные данные (формы, регистрация, аналитика).")
        if terms:
            ok("legal", "Ссылка на условия/оферту есть")
        else:
            add("legal", "info", "Не видно ссылки на условия использования/оферту", fix="Для маркетплейса и платных услуг — обязательно.")

    except Budget:
        add("server", "info", f"Достигнут лимит запросов ({MAX_REQUESTS}) — часть проверок пропущена")
    except urllib.error.URLError as e:
        sys.exit(f"Не удалось открыть {base}: {e.reason}")

    # ---------------------------------------------------------------- отчёт
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    icon = {"critical": "🔴", "warning": "🟡", "info": "🔵", "ok": "✅"}
    c = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "warning", "info")}
    L = [f"# 🚀 launchcheck: {base}", "",
         f"**🔴 {c['critical']} критичных · 🟡 {c['warning']} важных · 🔵 {c['info']} на заметку · "
         f"✅ {sum(1 for f in findings if f['severity'] == 'ok')} в порядке** (запросов: {F.count})", ""]
    for key, name in SECTIONS:
        items = sorted([f for f in findings if f["section"] == key], key=lambda f: order[f["severity"]])
        if not items:
            continue
        L.append(f"## {name}")
        for f in items:
            line = f"- {icon[f['severity']]} {f['title']}"
            if f["detail"]:
                line += f" — {f['detail']}"
            L.append(line)
            if f["fix"] and f["severity"] != "ok":
                L.append(f"  - Как чинить: {f['fix']}")
        L.append("")
    L += ["## Вручную (скрипт этого не видит)",
          "- Core Web Vitals на реальных пользователях: PageSpeed Insights / Search Console (LCP ≤ 2,5 с, INP ≤ 200 мс, CLS ≤ 0,1).",
          "- Rich Results Test для JSON-LD; превью ссылок — Facebook Sharing Debugger, LinkedIn Post Inspector, в Telegram — @WebpageBot.",
          "- После деплоя: отправить sitemap в Google Search Console и Bing Webmaster Tools, проверить отчёт об индексации.",
          "- Служебные страницы (кабинет, админка, поиск, корзина) — noindex, а админка ещё и за авторизацией.",
          "- Мониторинг: Sentry (source maps — в Sentry, не публично), аптайм-монитор (UptimeRobot, Better Stack).",
          "- Безопасность: скилл security-audit — scripts/audit.py (код) и scripts/livecheck.py (заголовки, cookies, утечки файлов)."]
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"url": base, "counts": c, "requests": F.count, "findings": findings}, fh, ensure_ascii=False, indent=2)
    print(f"🚀 launchcheck: 🔴 {c['critical']} / 🟡 {c['warning']} / 🔵 {c['info']}, запросов: {F.count}")
    print(f"Отчёт: {args.report}")
    sys.exit(2 if c["critical"] else (1 if c["warning"] else 0))


if __name__ == "__main__":
    main()
