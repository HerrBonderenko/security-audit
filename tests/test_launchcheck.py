#!/usr/bin/env python3
"""Тесты launchcheck.py на локальных фикстурах. Запуск: python tests/test_launchcheck.py"""
import http.server
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAUNCH = REPO / "skills" / "launch-checklist" / "scripts" / "launchcheck.py"

GOOD_INDEX = """<!doctype html><html lang="de"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Übersetzungsbüro — beglaubigte Übersetzungen</title>
<meta name="description" content="Beglaubigte Übersetzungen Ukrainisch–Deutsch für Behörden, Gerichte und Arbeitgeber in Niedersachsen.">
<link rel="canonical" href="https://example.de/">
<meta property="og:title" content="Übersetzungsbüro"><meta property="og:description" content="Beglaubigte Übersetzungen">
<meta property="og:image" content="https://example.de/og.png"><meta property="og:url" content="https://example.de/">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/favicon.ico"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"X"}</script>
</head><body><img src="/_next/image?url=a.jpg" width="100" height="50" alt="">
<a href="/about.html">Über uns</a> <a href="/impressum.html">Impressum</a> <a href="/datenschutz.html">Datenschutz</a>
<a href="/agb.html">AGB</a></body></html>"""

GOOD_ABOUT = GOOD_INDEX.replace("<title>Übersetzungsbüro — beglaubigte Übersetzungen</title>", "<title>Über uns</title>") \
    .replace('href="https://example.de/"', 'href="https://example.de/about.html"')

BAD_HOME = """<!doctype html><html><head><title>App</title>
<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>
</head><body><div id="root"></div><img src="/hero.png"></body></html>"""


def serve(handler_cls, directory=None):
    if directory:
        handler = lambda *a, **k: handler_cls(*a, directory=directory, **k)  # noqa: E731
    else:
        handler = handler_cls
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(url, tmp: Path):
    out = tmp / "lc.json"
    r = subprocess.run([sys.executable, str(LAUNCH), url, "--report", str(tmp / "lc.md"), "--json", str(out)],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    return r.returncode, json.loads(out.read_text(encoding="utf-8"))


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


class BadSPA(http.server.BaseHTTPRequestHandler):
    """SPA-хостинг, который отдаёт index.html с 200 на любой путь, и robots со стейджинга."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/robots.txt":
            body, ctype = b"User-agent: *\nDisallow: /\n", "text/plain"
        else:
            body, ctype = BAD_HOME.encode(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if self.path == "/":
            self.send_header("X-Robots-Tag", "noindex")
        self.end_headers()
        self.wfile.write(body)


class TestGoodSite(unittest.TestCase):
    def test_good_site_has_no_critical_or_warning(self):
        tmp = Path(tempfile.mkdtemp())
        site = tmp / "site"
        site.mkdir()
        (site / "index.html").write_text(GOOD_INDEX, encoding="utf-8")
        (site / "about.html").write_text(GOOD_ABOUT, encoding="utf-8")
        for name in ("impressum.html", "datenschutz.html", "agb.html"):
            (site / name).write_text("<html lang='de'><title>x</title></html>", encoding="utf-8")
        (site / "robots.txt").write_text("User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: https://example.de/sitemap.xml\n")
        (site / "sitemap.xml").write_text(
            '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>https://example.de/</loc></url><url><loc>https://example.de/about.html</loc></url></urlset>")
        (site / "og.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
        (site / "favicon.ico").write_bytes(b"\x00\x00\x01\x00")
        (site / "apple-touch-icon.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (site / "manifest.webmanifest").write_text(json.dumps({"name": "X", "icons": [
            {"src": "/i192.png", "sizes": "192x192"}, {"src": "/i512.png", "sizes": "512x512"}]}))
        srv = serve(Quiet, str(site))
        try:
            code, data = run(f"http://127.0.0.1:{srv.server_address[1]}", tmp)
            bad = [f for f in data["findings"] if f["severity"] in ("critical", "warning")]
            self.assertEqual(bad, [], json.dumps(bad, ensure_ascii=False, indent=1))
            titles = " | ".join(f["title"] for f in data["findings"])
            self.assertIn("честный 404", titles)
            self.assertIn("Impressum найден", titles)
            self.assertIn("служебные пути", titles)     # /admin в robots — подсказка атакующему
            self.assertLessEqual(data["requests"], 30)
        finally:
            srv.shutdown()
            srv.server_close()
            shutil.rmtree(tmp, ignore_errors=True)


class TestBadSite(unittest.TestCase):
    def test_bad_site_findings(self):
        tmp = Path(tempfile.mkdtemp())
        srv = serve(BadSPA)
        try:
            code, data = run(f"http://127.0.0.1:{srv.server_address[1]}", tmp)
            crit = " | ".join(f["title"] for f in data["findings"] if f["severity"] == "critical")
            warn = " | ".join(f["title"] for f in data["findings"] if f["severity"] == "warning")
            self.assertIn("Мягкий 404", crit)
            self.assertIn("robots.txt закрывает весь сайт", crit)
            self.assertIn("Главная закрыта от индексации", crit)
            for t in ("Нет canonical", "Шрифты грузятся с серверов Google", "Трекеры без видимого механизма согласия",
                      "Нет атрибута lang", "Нет meta description", "sitemap.xml", "Favicon не найден"):
                self.assertIn(t, warn)
            self.assertEqual(code, 2)
        finally:
            srv.shutdown()
            srv.server_close()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
