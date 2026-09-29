#!/usr/bin/env python3
"""
security-audit / livecheck.py — внешняя проверка ТВОЕГО задеплоенного сайта.

Только обычные GET-запросы, как у браузера (не больше 18, с паузами):
security-заголовки и качество CSP, флаги cookies, редирект HTTP→HTTPS,
не отдаются ли наружу .env / .git / дампы / source maps. Не атакует, не
перебирает, не фаззит — аналог securityheaders.com плюс пара ручных проверок.

⚠️ Запускать ТОЛЬКО против своего домена и только по явной просьбе владельца.
Скрипт требует подтверждения владения.

  python3 livecheck.py https://мой-сайт.com
  python3 livecheck.py https://мой-сайт.com --yes-i-own-this --json out.json

Основан на vibe-audit (c) 2026 ika.explains, MIT. Переписан и расширен.
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

VERSION = "2.0.0"
UA = f"security-audit-livecheck/{VERSION}"
PAUSE = 0.25

# путь, severity, описание, проверка содержимого (чтобы SPA с 200 на всё не давала ложных находок)
LEAK_PATHS = [
    (".env", "critical", "Файл .env читается из интернета — секреты доступны всем", re.compile(rb"(?m)^[A-Z_][A-Z0-9_]*\s*=")),
    (".env.local", "critical", "Файл .env.local читается из интернета", re.compile(rb"(?m)^[A-Z_][A-Z0-9_]*\s*=")),
    (".env.production", "critical", "Файл .env.production читается из интернета", re.compile(rb"(?m)^[A-Z_][A-Z0-9_]*\s*=")),
    (".git/HEAD", "critical", "Папка .git доступна — репозиторий можно выкачать с сервера", re.compile(rb"^ref: refs/|^[0-9a-f]{40}")),
    (".git/config", "critical", "Папка .git/config отдаётся наружу", re.compile(rb"\[core\]")),
    ("backup.sql", "critical", "Дамп базы лежит в открытом доступе", re.compile(rb"(?i)create table|insert into")),
    ("dump.sql", "critical", "Дамп базы лежит в открытом доступе", re.compile(rb"(?i)create table|insert into")),
    (".vscode/sftp.json", "critical", "Конфиг деплоя с доступами отдаётся наружу", re.compile(rb"(?i)\"(host|password|username)\"")),
    ("config.json", "warning", "config.json отдаётся публично — проверь, что там нет секретов", re.compile(rb"^\s*[\{\[]")),
    ("phpinfo.php", "warning", "phpinfo раскрывает конфигурацию сервера", re.compile(rb"(?i)phpinfo|php version")),
    (".DS_Store", "info", ".DS_Store виден — по нему восстанавливается структура папок", re.compile(rb"Bud1")),
]


STACK_RX = re.compile(rb"(?i)Traceback \(most recent call last\)|at Object\.<anonymous>|node_modules/|"
                      rb"\n\s+at [\w.$<>]+ \(|Exception in thread|stack trace:|SQLSTATE\[|pg_query\(")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, follow=True, limit=4096, timeout=12):
    handlers = [] if follow else [NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.getcode(), resp.headers, resp.read(limit), resp.geturl()
    except urllib.error.HTTPError as e:  # 3xx без follow, 4xx, 5xx
        try:
            body = e.read(limit)
        except Exception:
            body = b""
        return e.code, e.headers, body, url


def parse_csp(value: str) -> dict:
    out = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            out[bits[0].lower()] = [b.strip() for b in bits[1:]]
    return out


def check_csp(h, url, add):
    csp = h.get("content-security-policy")
    ro = h.get("content-security-policy-report-only")
    if not csp:
        if ro:
            add("warning", "CSP только в режиме Report-Only — ничего не блокирует", url,
                "Когда отчёты чистые — переведи в Content-Security-Policy.")
        else:
            add("warning", "Нет Content-Security-Policy", url,
                "CSP — вторая линия защиты от XSS. Добавь nonce-based политику (см. references/stacks/nextjs.md).")
        return
    d = parse_csp(csp)
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        add("warning", "CSP без script-src и default-src — скрипты не ограничены", url, "Добавь script-src.")
    else:
        s = " ".join(script)
        has_nonce = bool(re.search(r"'nonce-|'sha(256|384|512)-", s))
        if "'unsafe-inline'" in s and not has_nonce:
            add("warning", "CSP разрешает 'unsafe-inline' — инлайновые обработчики (onerror/onload) выполнятся", url,
                "nonce/hash + 'strict-dynamic' вместо 'unsafe-inline'. Проверь в браузере: инлайновый обработчик-маркер "
                "должен дать нарушение CSP в консоли.")
        if "'unsafe-eval'" in s:
            add("info", "CSP разрешает 'unsafe-eval'", url, "Убери, если библиотеки позволяют.")
        if any(x in ("*", "https:", "http:", "data:") for x in script):
            add("warning", "CSP script-src разрешает любые источники (* / https: / data:)", url,
                "Перечисли конкретные источники или используй nonce + 'strict-dynamic'.")
    if "object-src" not in d and "'none'" not in d.get("default-src", []):
        add("info", "CSP без object-src 'none'", url, "Добавь object-src 'none'.")
    if "base-uri" not in d:
        add("info", "CSP без base-uri", url, "Добавь base-uri 'self' (или 'none').")
    if "frame-ancestors" not in d and "x-frame-options" not in h:
        add("info", "Нет frame-ancestors / X-Frame-Options — сайт можно встроить в чужой iframe", url,
            "frame-ancestors 'self' (или 'none') в CSP.")


def check_cookies(h, url, add, https):
    for raw in h.get_all("Set-Cookie") or []:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip().lower() if "=" in a else "")
                 for a in raw.split(";")[1:]}
        sessionish = bool(re.search(r"(?i)sess|auth|token|sid|jwt|refresh|login", name))
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if missing:
            add("warning" if sessionish else "info", f"Cookie '{name}' без флагов: {', '.join(missing)}", url,
                "HttpOnly прячет cookie от JS (кража через XSS), Secure — только по HTTPS.")
        ss = attrs.get("samesite")
        if ss is None and sessionish:
            add("info", f"Cookie '{name}' без SameSite", url, "Явно SameSite=Lax (или Strict).")
        if ss == "none" and "secure" not in attrs:
            add("warning", f"Cookie '{name}': SameSite=None без Secure", url, "SameSite=None требует Secure.")


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Пассивная проверка СВОЕГО сайта: заголовки, cookies, утечки файлов")
    ap.add_argument("url", help="URL ТВОЕГО сайта (https://...)")
    ap.add_argument("--yes-i-own-this", action="store_true", help="пропустить вопрос о владении")
    ap.add_argument("--report", default="livecheck-report.md")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    url = args.url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        sys.exit("URL должен начинаться с http:// или https://")
    if not args.yes_i_own_this:
        print(f"\n⚠️  Ты собираешься проверить: {url}")
        print("Запускай это ТОЛЬКО против сайта, которым владеешь ты.")
        if input("Это твой сайт? (yes/no): ").strip().lower() not in ("yes", "y", "да", "д", "так", "т"):
            sys.exit("Отменено. Проверяй только свои домены.")

    findings = []

    def add(sev, title, where, fix):
        findings.append({"severity": sev, "title": title, "where": where, "fix": fix})

    https = url.startswith("https://")
    try:
        code, h, body, final = fetch(url, limit=300_000)
    except Exception as e:
        sys.exit(f"Не удалось открыть {url}: {e}")
    if code >= 400:
        add("info", f"Главная страница ответила {code}", url, "Проверь URL — дальнейшие проверки могут быть неточными.")

    # заголовки
    check_csp(h, url, add)
    if https and "strict-transport-security" not in h:
        add("warning", "Нет HSTS (Strict-Transport-Security)", url, "max-age=31536000; includeSubDomains — браузер всегда пойдёт по HTTPS.")
    if (h.get("x-content-type-options") or "").lower() != "nosniff":
        add("info", "Нет X-Content-Type-Options: nosniff", url, "nosniff мешает браузеру угадывать MIME-типы.")
    if "referrer-policy" not in h:
        add("info", "Нет Referrer-Policy", url, "strict-origin-when-cross-origin — не отдаём полные URL чужим сайтам.")
    if "permissions-policy" not in h:
        add("info", "Нет Permissions-Policy", url, "Отключи ненужное: camera=(), microphone=(), geolocation=().")
    for leaky in ("server", "x-powered-by"):
        v = h.get(leaky)
        if v and re.search(r"\d", v):
            add("info", f"Заголовок {leaky} раскрывает версию: {v[:40]}", url, "Скрой версию сервера/фреймворка.")
    acao = h.get("access-control-allow-origin")
    if acao == "*" and (h.get("access-control-allow-credentials") or "").lower() == "true":
        add("critical", "CORS: * вместе с credentials", url, "Только явный список доменов.")
    check_cookies(h, url, add, https)

    # HTTP → HTTPS
    if https:
        time.sleep(PAUSE)
        try:
            c2, h2, _, _ = fetch("http://" + url[len("https://"):], follow=False)
            loc = (h2.get("location") or "") if h2 else ""
            if not (300 <= c2 < 400 and loc.startswith("https://")):
                add("warning", "HTTP не перенаправляет на HTTPS", "http://" + url[8:], "Постоянный редирект 301/308 на https://.")
        except Exception:
            pass
    else:
        add("critical", "Сайт проверяется по HTTP", url, "Включи HTTPS и редирект с HTTP.")

    # утечки файлов
    for path, sev, desc, sig in LEAK_PATHS:
        target = f"{url}/{path}"
        time.sleep(PAUSE)
        try:
            c, fh, fb, final_url = fetch(target)
        except Exception:
            continue
        if c != 200 or not fb.strip() or final_url.rstrip("/") != target.rstrip("/"):
            continue
        if b"<html" in fb[:400].lower() or b"<!doctype" in fb[:400].lower():
            continue  # SPA отдаёт index.html на любой путь — это не утечка
        if sig.search(fb):
            add(sev, desc, target, "Закрой на уровне сервера/CDN и убери файл из веб-корня. Секреты из файла — перевыпусти.")

    # страница ошибки не должна раскрывать стек, а robots.txt — служебные пути
    time.sleep(PAUSE)
    try:
        c404, _, b404, _ = fetch(f"{url}/__livecheck-{secrets.token_hex(4)}", limit=200_000)
        if STACK_RX.search(b404):
            add("warning", "Страница ошибки показывает stack trace / внутренние пути", f"{url}/<несуществующий путь>",
                "Кастомные страницы 404/500 без деталей; детали — только в серверный лог.")
    except Exception:
        pass
    time.sleep(PAUSE)
    try:
        cr, _, br, _ = fetch(f"{url}/robots.txt", limit=100_000)
        if cr == 200 and b"<html" not in br[:300].lower():
            paths = re.findall(rb"(?im)^\s*disallow:\s*(\S*(?:admin|dashboard|panel|crm|internal|private|backup|secret|staff)\S*)", br)
            if paths:
                add("info", "robots.txt публично перечисляет служебные пути: " + ", ".join(p.decode("utf-8", "ignore") for p in paths[:5]),
                    f"{url}/robots.txt", "robots.txt — не защита, а подсказка. Служебные разделы — за авторизацией; от индексации — noindex.")
    except Exception:
        pass

    # source maps
    srcs = re.findall(rb"""<script[^>]+src=["']([^"']+\.js)(?:\?[^"']*)?["']""", body)[:3]
    for s in srcs:
        js = urllib.parse.urljoin(final + "/", s.decode("utf-8", "ignore"))
        if urllib.parse.urlparse(js).netloc != urllib.parse.urlparse(url).netloc:
            continue
        time.sleep(PAUSE)
        try:
            c, _, mb, _ = fetch(js + ".map", limit=64)
            if c == 200 and mb.lstrip().startswith(b'{"version":3'):
                add("warning", "Source maps доступны публично — исходный код фронтенда читается целиком",
                    js + ".map", "Выключи публичные source maps в прод-сборке (или отдавай их только в Sentry).")
                break
        except Exception:
            continue

    order = {"critical": 0, "warning": 1, "info": 2}
    icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
    findings.sort(key=lambda f: order[f["severity"]])
    c = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
    L = [f"# 🌐 security-audit livecheck: {url}", "",
         f"**{len(findings)} находок — 🔴 {c['critical']} / 🟡 {c['warning']} / 🔵 {c['info']}**", "",
         "_Только внешние GET-запросы. Внутреннюю логику так не проверить — это не пентест._", ""]
    for f in findings:
        L += [f"## {icon[f['severity']]} {f['title']}", f"- URL: {f['where']}", f"- Как чинить: {f['fix']}", ""]
    if not findings:
        L.append("Внешних проблем не видно. Хороший знак, но внутреннюю логику это не проверяет.")
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"url": url, "counts": c, "findings": findings}, fh, ensure_ascii=False, indent=2)
    print(f"\n🌐 livecheck: {len(findings)} находок (🔴 {c['critical']} / 🟡 {c['warning']} / 🔵 {c['info']})")
    print(f"Отчёт: {args.report}")
    sys.exit(2 if c["critical"] else (1 if c["warning"] else 0))


if __name__ == "__main__":
    main()
