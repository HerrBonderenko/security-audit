#!/usr/bin/env python3
"""
Регрессионные тесты сканера. Запуск: python tests/test_audit.py  (или python -m unittest discover tests)

Фикстуры собираются во временной папке во время прогона. Фейковые ключи склеиваются
из кусков, чтобы в репозитории не лежали строки, похожие на настоящие секреты
(иначе GitHub push protection заблокирует push, а сканер будет ругаться на свои тесты).
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUDIT = REPO / "skills" / "security-audit" / "scripts" / "audit.py"
LIVE = REPO / "skills" / "security-audit" / "scripts" / "livecheck.py"

FAKE_OPENAI = "sk-" + "proj-" + "Ab3Xy9Qw" * 5
FAKE_STRIPE_SECRET = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def w(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


def git(root: Path, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                   check=True, capture_output=True)


def scan(root: Path, *extra):
    out = Path(tempfile.mkdtemp()) / "f.json"
    r = subprocess.run([sys.executable, str(AUDIT), str(root), "--report", str(out.with_suffix(".md")),
                        "--json", str(out), "--no-deps", *extra], capture_output=True, text=True, encoding="utf-8")
    data = json.loads(out.read_text(encoding="utf-8"))
    return r.returncode, data


def ids(data, sev=None):
    return {f["id"] for f in data["findings"] if sev is None or f["severity"] == sev}


def by_id(data, rid):
    return [f for f in data["findings"] if f["id"] == rid]


def make_vulnerable_next(root: Path):
    git(root, "init", "-q")
    w(root, "package.json", json.dumps({"dependencies": {"next": "^14.2.3", "@supabase/supabase-js": "^2",
                                                         "openai": "^4", "stripe": "^14", "resend": "^3"}}))
    w(root, "package-lock.json", json.dumps({"packages": {"node_modules/next": {"version": "14.2.3"}}}))
    w(root, ".gitignore", ".env*.local\nnode_modules\n")
    w(root, ".env.local", "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.x.y\nSUPABASE_SERVICE_ROLE_KEY=zzz\n")
    w(root, "middleware.ts", """
        import { NextResponse } from 'next/server'
        export function middleware() { return NextResponse.next() }
    """)
    w(root, "next.config.js", """
        module.exports = {
          productionBrowserSourceMaps: true,
          async headers() { return [{ source: '/(.*)', headers: [
            { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'" } ] }] },
        }
    """)
    w(root, "app/api/chat/route.ts", """
        import OpenAI from 'openai'
        const client = new OpenAI()
        export async function POST(req: Request) {
          const { prompt } = await req.json()
          const r = await client.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] })
          return Response.json(r)
        }
    """)
    w(root, "app/api/users/[id]/route.ts", """
        import { sql } from '@/lib/db'
        export async function GET(req: Request, { params }: { params: { id: string } }) {
          const rows = await sql.unsafe(`SELECT * FROM users WHERE id = ${params.id}`)
          return Response.json(rows)
        }
    """)
    w(root, "app/api/contact/route.ts", """
        import { Resend } from 'resend'
        import { NextResponse } from 'next/server'
        const resend = new Resend(process.env.RESEND_API_KEY)
        const hits = new Map()
        export async function POST(req: Request) {
          const ip = req.headers.get('x-forwarded-for') ?? 'anon'
          if ((hits.get(ip) ?? 0) > 5) return NextResponse.json({ error: 'too many' }, { status: 429 })
          const body = await req.json()
          try {
            await resend.emails.send({ from: 'site@x.com', to: body.email, subject: 'Hi',
              html: `<p>Спасибо, ${body.name}!</p>` })
          } catch (err: any) {
            return NextResponse.json({ error: err.message }, { status: 500 })
          }
          return NextResponse.json({ ok: true })
        }
    """)
    w(root, "app/api/webhooks/stripe/route.ts", """
        import Stripe from 'stripe'
        export async function POST(req: Request) {
          const event = await req.json()
          if (event.type === 'checkout.session.completed') { /* mark paid */ }
          return new Response('ok')
        }
    """)
    w(root, "app/actions.ts", """
        'use server'
        import { createClient } from '@/lib/supabase/server'
        export async function updateProfile(body: any) {
          const supabase = createClient()
          await supabase.from('profiles').update(body)
        }
    """)
    w(root, "components/Bio.tsx", """
        export default function Bio({ html }: { html: string }) {
          return <div dangerouslySetInnerHTML={{ __html: html }} />
        }
    """)
    w(root, "components/Keys.tsx", """
        'use client'
        const a = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
        const b = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY
        const c = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY
    """)
    w(root, "components/Login.tsx", """
        'use client'
        export async function login(t: string) {
          localStorage.setItem('access_token', t)
          await fetch('https://api.openai.com/v1/models')
        }
    """)
    w(root, "supabase/migrations/001_init.sql", """
        create table public.orders (id uuid primary key, user_id uuid, amount int);
        create table public.profiles (id uuid primary key);
        alter table public.profiles enable row level security;
        create policy "anyone" on public.profiles for all using (true);
        create or replace function public.payout(order_id uuid) returns void
        language plpgsql security definer as $$ begin update orders set amount = 0; end; $$;
    """)
    w(root, "lib/leak.ts", f'export const KEY = "{FAKE_OPENAI}"\n')
    w(root, ".env", "STRIPE_KEY=" + FAKE_STRIPE_SECRET + "\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    # ключ и .env удалены из кода, но остались в истории
    (root / "lib/leak.ts").unlink()
    git(root, "rm", "-q", "--cached", ".env")
    (root / ".env").unlink()
    git(root, "commit", "-qam", "remove secrets")


class TestVulnerableNext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.root = cls.tmp / "myapp"
        cls.root.mkdir()
        make_vulnerable_next(cls.root)
        cls.code, cls.data = scan(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_expected_findings(self):
        expected = {
            "ai_open_endpoint", "ai_no_maxtokens", "sql_js_template", "idor_suspect", "email_to_from_input",
            "email_html_interp", "ratelimit_spoofable_key", "error_message_leak", "webhook_no_signature",
            "server_action_no_auth", "mass_assignment", "xss_dangerously", "public_env_secret", "token_in_storage",
            "client_api", "supabase_rls_missing", "supabase_policy_true", "security_definer_search_path",
            "source_maps_public", "csp_unsafe_inline", "next_middleware_bypass", "gitignore_env",
            "secret_in_history", "env_in_history",
        }
        missing = expected - ids(self.data)
        self.assertFalse(missing, f"не найдено: {missing}")

    def test_critical_levels(self):
        crit = ids(self.data, "critical")
        for rid in ("ai_open_endpoint", "client_api", "next_middleware_bypass", "secret_in_history", "env_in_history"):
            self.assertIn(rid, crit)
        self.assertEqual(self.code, 2)

    def test_public_by_design_keys_not_flagged(self):
        flagged = " ".join(f["detail"] for f in by_id(self.data, "public_env_secret"))
        self.assertIn("NEXT_PUBLIC_STRIPE_SECRET_KEY", flagged)
        self.assertNotIn("ANON_KEY", flagged)
        self.assertNotIn("PUBLISHABLE", flagged)

    def test_server_route_not_treated_as_client(self):
        for f in by_id(self.data, "client_api"):
            self.assertIn("components/Login.tsx", f["where"])

    def test_rls_missing_points_to_orders_only(self):
        details = " ".join(f["detail"] for f in by_id(self.data, "supabase_rls_missing"))
        self.assertIn("orders", details)
        self.assertNotIn("profiles", details)

    def test_secrets_are_masked(self):
        blob = json.dumps(self.data, ensure_ascii=False)
        self.assertNotIn(FAKE_OPENAI, blob)
        self.assertNotIn(FAKE_STRIPE_SECRET, blob)

    def test_untracked_env_local_not_reported_as_secret(self):
        for f in self.data["findings"]:
            if f["id"] in ("env_in_git",):
                self.fail("незакоммиченный .env.local не должен считаться закоммиченным")


class TestPathUnderBuildDir(unittest.TestCase):
    """Регрессия vibe-audit: проект внутри папки build/dist/vendor сканировался как пустой."""

    def test_project_inside_build_dir_is_scanned(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            root = tmp / "build" / "vendor" / "myapp"
            root.mkdir(parents=True)
            w(root, "app/api/chat/route.ts", """
                import OpenAI from 'openai'
                export async function POST() { return Response.json(await new OpenAI().chat.completions.create({model:'x', messages:[]})) }
            """)
            _, data = scan(root, "--no-history")
            self.assertGreater(data["files_scanned"], 0)
            self.assertIn("ai_open_endpoint", ids(data))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPython(unittest.TestCase):
    def test_python_rules(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            w(tmp, "requirements.txt", "flask\n")
            w(tmp, "app.py", """
                import hashlib, pickle, subprocess, yaml
                from flask import Flask, request
                app = Flask(__name__)
                @app.route('/u')
                def u():
                    cur.execute(f"SELECT * FROM users WHERE name = '{request.args.get('n')}'")
                    data = yaml.load(request.data)
                    obj = pickle.loads(request.data)
                    subprocess.run("ls " + request.args.get('d'), shell=True)
                    h = hashlib.md5(password.encode()).hexdigest()
                    return 'ok'
                app.run(debug=True)
            """)
            _, data = scan(tmp, "--no-history")
            for rid in ("sql_py_fstring", "unsafe_deserialize", "py_shell_true", "weak_password_hash", "debug_on"):
                self.assertIn(rid, ids(data), rid)
            safe = Path(tmp / "safe.py")
            safe.write_text("import yaml\nx = yaml.load(s, Loader=yaml.SafeLoader)\n", encoding="utf-8")
            _, data2 = scan(tmp, "--no-history")
            where = [f["where"] for f in by_id(data2, "unsafe_deserialize")]
            self.assertFalse(any(x.startswith("safe.py") for x in where))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestCleanProject(unittest.TestCase):
    def test_no_critical_or_warning_on_reasonable_code(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            w(tmp, "package.json", json.dumps({"dependencies": {"next": "15.3.1", "openai": "^4"}}))
            w(tmp, ".gitignore", ".env*\n")
            w(tmp, "next.config.js", """
                module.exports = { async headers() { return [{ source: '/(.*)', headers: [
                  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'" }]}] } }
            """)
            w(tmp, "app/api/chat/route.ts", """
                import OpenAI from 'openai'
                import { auth } from '@/auth'
                import { ratelimit } from '@/lib/ratelimit'
                const client = new OpenAI()
                export async function POST(req: Request) {
                  const session = await auth()
                  if (!session) return new Response('unauthorized', { status: 401 })
                  const { success } = await ratelimit.limit(session.user.id)
                  if (!success) return new Response('slow down', { status: 429 })
                  const { prompt } = await req.json()
                  const r = await client.chat.completions.create({ model: 'gpt-4o', max_tokens: 500,
                    messages: [{ role: 'user', content: String(prompt).slice(0, 4000) }] })
                  return Response.json(r)
                }
            """)
            w(tmp, "app/api/items/[id]/route.ts", """
                import { db } from '@/lib/db'
                import { auth } from '@/auth'
                export async function GET(req: Request, { params }: { params: { id: string } }) {
                  const session = await auth()
                  const row = await db.query('SELECT * FROM items WHERE id = $1 AND user_id = $2', [params.id, session.user.id])
                  return Response.json(row)
                }
            """)
            w(tmp, "components/Name.tsx", "export const Name = ({ n }: { n: string }) => <b>{n}</b>\n")
            w(tmp, "components/Link.tsx", "export const L = () => <a href=\"/login\">Войти</a>\n")
            _, data = scan(tmp, "--no-history")
            bad = [f for f in data["findings"] if f["severity"] in ("critical", "warning")]
            self.assertEqual(bad, [], json.dumps(bad, ensure_ascii=False, indent=1))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestIgnore(unittest.TestCase):
    def test_inline_and_file_ignores(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            w(tmp, "a.ts", "el.innerHTML = html // security-audit: ignore\nel2.innerHTML = other\n")
            w(tmp, "b.ts", "el.innerHTML = html\n")
            w(tmp, "legacy/c.ts", "document.write(x)\n")
            w(tmp, ".security-audit-ignore", "# комментарий\nb.ts xss_dom_sink\nlegacy/*\n")
            _, data = scan(tmp, "--no-history")
            where = [f["where"] for f in by_id(data, "xss_dom_sink")]
            self.assertEqual(where, ["a.ts:2"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class _Handler(http.server.SimpleHTTPRequestHandler):
    error_message_format = "<html><body>Error %(code)d\n    at Object.<anonymous> (/app/node_modules/x.js:1:1)</body></html>"

    def log_message(self, *a):
        pass

    def end_headers(self):
        self.send_header("Set-Cookie", "session=abc; Path=/")
        super().end_headers()


class TestLivecheck(unittest.TestCase):
    def test_detects_exposed_env_and_missing_headers(self):
        tmp = Path(tempfile.mkdtemp())
        w(tmp, "index.html", "<!doctype html><html><body>hi</body></html>")
        w(tmp, ".env", "DATABASE_URL=x\n")
        w(tmp, ".git/HEAD", "ref: refs/heads/main\n")
        w(tmp, "robots.txt", "User-agent: *\nDisallow: /admin-panel\n")
        handler = lambda *a, **k: _Handler(*a, directory=str(tmp), **k)  # noqa: E731
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            out = tmp / "live.json"
            subprocess.run([sys.executable, str(LIVE), f"http://127.0.0.1:{srv.server_address[1]}",
                            "--yes-i-own-this", "--report", str(tmp / "live.md"), "--json", str(out)],
                           capture_output=True, text=True, timeout=120)
            data = json.loads(out.read_text(encoding="utf-8"))
            titles = " | ".join(f["title"] for f in data["findings"])
            self.assertIn(".env читается", titles)
            self.assertIn(".git", titles)
            self.assertIn("Content-Security-Policy", titles)
            self.assertIn("session", titles)
            self.assertIn("stack trace", titles)
            self.assertIn("служебные пути", titles)
        finally:
            srv.shutdown()
            srv.server_close()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
