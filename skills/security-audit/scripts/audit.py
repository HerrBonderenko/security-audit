#!/usr/bin/env python3
"""
security-audit / audit.py — статический сканер безопасности проекта.

Только чтение: ничего не меняет, секреты в отчёте маскирует, git вызывает
с отключёнными хуками, fsmonitor, ext-diff и textconv. Без внешних
зависимостей, Python 3.9+. Если установлен gitleaks — берёт его для истории git.

Запуск:
  python3 audit.py /путь/к/проекту
  python3 audit.py . --report security-audit-report.md --json findings.json
  python3 audit.py . --fail-on critical          # для CI: падать только на критичных

Коды выхода: 2 — есть critical, 1 — есть warning, 0 — чисто (с учётом --fail-on).

Находки — это КАНДИДАТЫ, найденные эвристиками. Каждую подтверждают по коду.

Основан на vibe-audit (c) 2026 ika.explains, MIT. Переписан и расширен.
"""
from __future__ import annotations

import argparse
import bisect
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import date
from pathlib import Path

VERSION = "2.0.0"

# --------------------------------------------------------------------------- обход файлов

SKIP_DIRS = {
    ".git", "node_modules", ".next", "out", "dist", "build", ".venv", "venv", "__pycache__",
    ".cache", "vendor", "Pods", ".dart_tool", "coverage", ".turbo", ".vercel", ".netlify",
    ".svelte-kit", ".nuxt", ".output", "target", ".gradle", ".idea", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", ".expo", "storybook-static",
    ".parcel-cache", ".serverless", ".terraform", "bower_components", ".wrangler",
}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
PY_EXT = {".py"}
JVM_EXT = {".java", ".kt", ".kts", ".scala", ".sc"}
HTML_EXT = {".html", ".htm"}
TPL_EXT = {".ejs", ".hbs", ".njk", ".jinja", ".j2", ".twig", ".erb"}
CODE_EXT = JS_EXT | PY_EXT | JVM_EXT | {".rb", ".php", ".go", ".rs", ".cs", ".swift", ".dart", ".sh"}
TEXT_EXT = CODE_EXT | HTML_EXT | TPL_EXT | {
    ".css", ".json", ".yml", ".yaml", ".toml", ".env", ".sql", ".md", ".txt", ".cfg", ".ini",
    ".conf", ".properties", ".xml", ".prisma", ".graphql", ".gql", ".rules", ".tf", ".hcl",
    ".gradle", ".sbt",
}
EXTRA_NAMES = {"Dockerfile", "_headers", "_redirects", ".npmrc", ".pypirc", ".netrc", "Procfile"}
SKIP_FILE_RX = re.compile(r"(\.min\.js|\.bundle\.js|\.map)$")
REPORT_NAMES = {"security-audit-report.md", "SECURITY_AUDIT_REPORT.md", "vibe-audit-report.md",
                "livecheck-report.md", "security-audit-findings.json"}
MAX_FILE = 1_000_000
SELF_DIR = Path(__file__).resolve().parent.parent  # папка скилла: сам себя не сканируем
SKILL_DIRS_RX = re.compile(r"(^|/)\.(claude|agents|codex)/skills(/|$)")


class SF:
    """Файл проекта: текст, относительный путь, быстрый поиск номера строки."""

    def __init__(self, path: Path, rel: str, text: str):
        self.path, self.rel, self.text = path, rel, text
        self.name = path.name
        self.suffix = path.suffix.lower()
        self.kind = "config"
        self._starts = None
        self._lines = None

    def line_of(self, pos: int) -> int:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer("\n", self.text)]
        return bisect.bisect_right(self._starts, pos)

    def line(self, ln: int) -> str:
        if self._lines is None:
            self._lines = self.text.split("\n")
        return self._lines[ln - 1] if 0 < ln <= len(self._lines) else ""

    def is_comment(self, ln: int) -> bool:
        s = self.line(ln).lstrip()
        if s.startswith(("//", "/*", "*", "<!--")):
            return True
        if s.startswith("--") and self.suffix == ".sql":
            return True
        if s.startswith("#") and self.suffix not in JS_EXT:
            return True
        return False

    def ignored_at(self, ln: int) -> bool:
        cur, prev = self.line(ln), self.line(ln - 1)
        return "security-audit: ignore" in cur or "security-audit: ignore-next-line" in prev


def _rel(p: Path, root: Path) -> str:
    return p.relative_to(root).as_posix()


def load_files(root: Path) -> list[SF]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        keep = []
        for name in dirnames:
            full = d / name
            if name in SKIP_DIRS or full.is_symlink():
                continue
            if (full / "pyvenv.cfg").exists():  # виртуальное окружение python
                continue
            if full.resolve() == SELF_DIR:
                continue
            if SKILL_DIRS_RX.search(_rel(full, root) + "/"):
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            p = d / name
            if name in REPORT_NAMES or SKIP_FILE_RX.search(name) or p.is_symlink():
                continue
            suffix = p.suffix.lower()
            if not (suffix in TEXT_EXT or name in EXTRA_NAMES or name.startswith(".env")
                    or name.startswith("Dockerfile")):
                continue
            try:
                if not p.resolve().is_relative_to(root) or p.stat().st_size > MAX_FILE:
                    continue
                files.append(SF(p, _rel(p, root), p.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
    return files


# --------------------------------------------------------------------------- git

def git_cmd():
    git = shutil.which("git")
    if not git:
        return None
    # чужой репозиторий не должен ничего исполнять через конфиг: хуки, fsmonitor, ext-diff
    return [git, "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
            "-c", "diff.external=", "-c", "core.pager=cat"]


def git_tracked(root: Path):
    g = git_cmd()
    if not g or not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(g + ["-C", str(root), "ls-files", "-z"], capture_output=True,
                             timeout=60).stdout.decode("utf-8", "ignore")
        return set(x for x in out.split("\0") if x)
    except Exception:
        return None


# --------------------------------------------------------------------------- контекст

class Ctx:
    def __init__(self, root: Path):
        self.root = root
        self.files: list[SF] = []
        self.tracked = None
        self.info: dict = {}
        self.findings: list[dict] = []
        self._seen = set()
        self.raw_secrets: set[str] = set()
        self.ignore_rules: list[tuple[str | None, str | None]] = []
        self.notes: list[str] = []

    def add(self, rid, sev, title, sf: SF | None = None, ln: int | None = None, *, where=None,
            detail="", fix=""):
        path = sf.rel if sf else (where or "-")
        if sf is not None and ln is not None:
            if sf.ignored_at(ln):
                return
            where = f"{sf.rel}:{ln}"
        where = where or path
        for glob, rule in self.ignore_rules:
            if (rule is None or rule == rid) and (glob is None or fnmatch.fnmatch(path, glob)):
                return
        key = (rid, where)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({"id": rid, "severity": sev, "title": title, "where": where,
                              "detail": detail, "fix": fix})


def load_ignore(ctx: Ctx, known_ids: set[str]):
    f = ctx.root / ".security-audit-ignore"
    if not f.exists():
        return
    for raw in f.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 1:
            ctx.ignore_rules.append((None, parts[0]) if parts[0] in known_ids else (parts[0], None))
        else:
            ctx.ignore_rules.append((parts[0], parts[1]))


# --------------------------------------------------------------------------- проект

USE_CLIENT = re.compile(r"""^\s*['"]use client['"]""", re.M)
USE_SERVER = re.compile(r"""^\s*['"]use server['"]""", re.M)
SERVER_PATH = re.compile(
    r"(^|/)(api|server|backend|functions|lambdas?|edge-functions|workers?|scripts|migrations|"
    r"prisma|cron|jobs|supabase|netlify)(/|$)|\.server\.[jt]sx?$|(^|/)route\.[jt]sx?$|"
    r"(^|/)(middleware|proxy)\.[jt]s$|(^|/)server\.[jt]s$|(^|/)actions?\.[jt]s$|"
    r"(^|/)[^/]+\.config\.[mc]?[jt]s$")
CLIENT_PATH = re.compile(r"(^|/)(public|client|frontend|web|static|assets)(/|$)")
SPA_SRC = re.compile(r"(^|/)(src|app|components|pages|views|hooks|lib)(/|$)")
NODE_SERVER_DEPS = {"express", "fastify", "koa", "hono", "@nestjs/core", "@hapi/hapi", "restify"}


def detect_project(ctx: Ctx):
    deps: set[str] = set()
    for sf in ctx.files:
        if sf.name == "package.json":
            try:
                pkg = json.loads(sf.text)
            except Exception:
                continue
            for k in ("dependencies", "devDependencies", "peerDependencies"):
                deps |= set((pkg.get(k) or {}).keys())
    names = {sf.rel for sf in ctx.files}
    alltext_small = " ".join(sf.text[:3000] for sf in ctx.files if sf.suffix in {".txt", ".toml"}
                             and sf.name in {"requirements.txt", "pyproject.toml"})
    ctx.info = {
        "deps": deps,
        "next": "next" in deps,
        "spa": bool(deps & {"vite", "react-scripts", "@vitejs/plugin-react", "@sveltejs/vite-plugin-svelte",
                            "@vitejs/plugin-vue", "parcel"}) and "next" not in deps,
        "node_server": bool(deps & NODE_SERVER_DEPS),
        "supabase": bool({d for d in deps if d.startswith("@supabase/")})
        or any(n.startswith("supabase/") for n in names) or "supabase" in alltext_small,
        "firebase": "firebase" in deps or "firebase-admin" in deps or "firebase.json" in names,
    }
    for sf in ctx.files:
        sf.kind = classify(sf, ctx.info)


def classify(sf: SF, info: dict) -> str:
    if sf.suffix not in JS_EXT and sf.suffix not in HTML_EXT:
        return "server" if sf.suffix in CODE_EXT else "config"
    head = sf.text[:800]
    if USE_CLIENT.search(head):
        return "client"
    if USE_SERVER.search(head):
        return "server"
    if SERVER_PATH.search(sf.rel):
        return "server"
    if sf.suffix in {".vue", ".svelte"} | HTML_EXT:
        return "client"
    if CLIENT_PATH.search(sf.rel):
        return "client"
    if info.get("spa") and not info.get("node_server") and SPA_SRC.search(sf.rel):
        return "client"
    if info.get("next"):
        return "server?"  # App Router: компоненты серверные, пока нет 'use client'
    return "unknown"


SERVERISH = {"server", "server?", "unknown"}

# --------------------------------------------------------------------------- секреты


def _mixed(s: str) -> bool:
    return any(c.isdigit() for c in s) and any(c.isupper() for c in s) and any(c.islower() for c in s)


PLACEHOLDER = re.compile(
    r"(?i)(your|example|xxxx|placeholder|changeme|change_me|replace|dummy|sample|fake|lorem|"
    r"<|\$\{|process\.env|os\.environ|getenv|\*\*\*|0000000|1234567|abcdefgh|todo|insert)")


def _real(s: str) -> bool:
    return not PLACEHOLDER.search(s) and len(set(s)) > 6


LOCAL_HOSTS = re.compile(r"(?i)^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mariadb|redis|mongo|"
                         r"mongodb|database|host\.docker\.internal|\[::1\])$")
WEAK_PASS = re.compile(r"(?i)^(password|pass|postgres|root|secret|admin|changeme|example|test|"
                       r"\$\{?\w+\}?|<[^>]+>|x+|\*+)$")


def _db_url_ok(m: re.Match) -> bool:
    return not WEAK_PASS.match(m.group(2)) and not LOCAL_HOSTS.match(m.group(3))


SECRET_FIX = ("Убери из кода, положи в переменную окружения/секрет-менеджер и ПЕРЕВЫПУСТИ ключ — "
              "если он попадал в git, он уже скомпрометирован.")
GOOGLE_FIX = ("Если это web-конфиг Firebase — ключ публичный по задумке, но ограничь его по доменам и API "
              "в Google Cloud Console. Если серверный ключ (Maps/Gemini и т.п.) — убери из кода и перевыпусти.")

# (id, severity, title, regex, validator(match) -> bool, fix)
SECRET_PATTERNS = [
    ("anthropic_key", "critical", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), None, None),
    ("stripe_live", "critical", "Stripe live/restricted key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), None, None),
    ("stripe_webhook_secret", "critical", "Stripe webhook secret", re.compile(r"\bwhsec_[A-Za-z0-9]{24,}\b"), None, None),
    ("aws_key", "critical", "AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None, None),
    ("aws_secret", "critical", "AWS Secret Access Key",
     re.compile(r"""(?i)aws_?secret_?access_?key["'\s]*[:=]\s*["']?[A-Za-z0-9/+=]{40}"""), None, None),
    ("github_token", "critical", "GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"), None, None),
    ("gitlab_token", "critical", "GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), None, None),
    ("slack_token", "critical", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), None, None),
    ("slack_webhook", "warning", "Slack incoming webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), None, None),
    ("supabase_secret", "critical", "Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}"), None, None),
    ("supabase_service", "critical", "Supabase service_role JWT",
     re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*c2VydmljZV9yb2xl[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}"), None, None),
    ("google_oauth_secret", "critical", "Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}"), None, None),
    ("google_api_key", "warning", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), None, GOOGLE_FIX),
    ("openai_key", "critical", "OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
     lambda m: _mixed(m.group(0)), None),
    ("resend_key", "critical", "Resend API key", re.compile(r"\bre_[A-Za-z0-9_]{20,}\b"), lambda m: _mixed(m.group(0)), None),
    ("sendgrid_key", "critical", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), None, None),
    ("mailgun_key", "warning", "Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), None, None),
    ("huggingface_token", "critical", "Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), lambda m: _mixed(m.group(0)), None),
    ("groq_key", "critical", "Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"), None, None),
    ("xai_key", "critical", "xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{40,}\b"), None, None),
    ("npm_token", "critical", "npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), None, None),
    ("netlify_token", "critical", "Netlify token", re.compile(r"\bnfp_[A-Za-z0-9]{36,}\b"), None, None),
    ("digitalocean_token", "critical", "DigitalOcean token", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), None, None),
    ("telegram_bot", "critical", "Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
     lambda m: _mixed(m.group(0).split(":", 1)[1]), None),
    ("private_key", "critical", "Приватный ключ (PEM)",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), None, None),
    ("db_url_password", "critical", "Строка подключения к БД с паролем",
     re.compile(r"""\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://([^\s:/@'"`]+):([^\s@'"`]+)@([^\s/'"`:?]+)"""),
     _db_url_ok, None),
    ("generic_secret", "warning", "Похоже на захардкоженный секрет",
     re.compile(r"""(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|password|passwd|"""
                r"""(?:access[_-]?|auth[_-]?)?token)\b["']?\s*[:=]\s*["']([^"'\s]{16,})["']"""),
     lambda m: _real(m.group(1)) and any(c.isdigit() for c in m.group(1)), None),
]
HISTORY_SKIP = {"generic_secret", "google_api_key", "mailgun_key", "slack_webhook"}
SECRET_PREFILTER = re.compile(
    r"sk-|_live_|whsec_|AKIA|ASIA|aws_?secret|gh[pousr]_|github_pat_|glpat-|xox|hooks\.slack|sb_secret_|eyJ|"
    r"GOCSPX-|AIza|re_|SG\.|key-|hf_|gsk_|xai-|npm_|nfp_|dop_v1_|\d{8,10}:|-----BEGIN|://", re.I)

SECRET_OK_FILES = re.compile(
    r"(\.example|\.sample|\.template|\.dist)(\.|$)|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
    r"poetry\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock|go\.sum|bun\.lock)$|\.md$|\.lock$")
TEST_FILES = re.compile(r"(\.test\.|\.spec\.|_test\.|(^|/)(tests?|__tests__|__mocks__|fixtures?|e2e|cypress)/)")


def mask(s: str) -> str:
    s = s.strip().strip("\"'")
    return s[:6] + "…" + s[-2:] if len(s) > 10 else "***"


def secret_detail(pid: str, m: re.Match) -> str:
    if pid == "db_url_password":
        scheme = m.group(0).split("://", 1)[0]
        return f"найдено: `{scheme}://{m.group(1)}:***@{m.group(3)}`"
    return f"найдено: `{mask(m.group(0))}`"


def check_secrets(ctx: Ctx):
    for sf in ctx.files:
        if SECRET_OK_FILES.search(sf.rel):
            continue
        is_env = sf.name.startswith(".env")
        if is_env and ctx.tracked is not None and sf.rel not in ctx.tracked:
            continue  # незакоммиченный .env — норма, секреты и должны жить там
        in_test = bool(TEST_FILES.search(sf.rel))
        claimed: set[int] = set()
        for pid, sev, title, rx, ok, fix in SECRET_PATTERNS:
            for m in rx.finditer(sf.text):
                if ok and not ok(m):
                    continue
                ln = sf.line_of(m.start())
                if pid == "generic_secret" and (ln in claimed or sf.is_comment(ln)):
                    continue
                claimed.add(ln)
                ctx.raw_secrets.add(m.group(0))
                s, note = sev, ""
                if in_test and s == "critical":
                    s, note = "warning", " (в тестовом файле — убедись, что это фейк)"
                if is_env and ctx.tracked is None:
                    s, note = "info", " (git не найден: если .env не коммитится — это норма)"
                ctx.add(pid, s, title, sf, ln, detail=secret_detail(pid, m) + note, fix=fix or SECRET_FIX)


def check_git_env(ctx: Ctx):
    if ctx.tracked is None:
        return
    for f in sorted(ctx.tracked):
        name = f.rsplit("/", 1)[-1]
        if name.startswith(".env") and not re.search(r"\.(example|sample|template|dist)$", name):
            ctx.add("env_in_git", "critical", ".env закоммичен в git", where=f,
                    detail="файл с секретами отслеживается git",
                    fix=f"git rm --cached {f}; добавь .env* в .gitignore; перевыпусти все ключи из файла; "
                        f"историю чисти git filter-repo (после перевыпуска, не вместо).")
    gi = ctx.root / ".gitignore"
    pats = []
    if gi.exists():
        for line in gi.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "!")):
                pats.append(line.lstrip("/").rstrip("/"))
    not_ignored = [n for n in (".env", ".env.local", ".env.production")
                   if not any(fnmatch.fnmatch(n, p) for p in pats)]
    if not_ignored:
        sev = "info" if not_ignored == [".env.production"] else "warning"
        ctx.add("gitignore_env", sev, ".env-файлы не закрыты в .gitignore", where=".gitignore",
                detail="не игнорируются: " + ", ".join(not_ignored),
                fix="Добавь в .gitignore строки `.env` и `.env*` (исключение — `!.env.example`).")


def check_history(ctx: Ctx, max_seconds=90, max_bytes=200_000_000, max_commits=5000):
    g = git_cmd()
    if not g or ctx.tracked is None:
        return
    root = str(ctx.root)
    # .env, который когда-то был закоммичен
    try:
        out = subprocess.run(g + ["-C", root, "log", "--all", "--diff-filter=A", "--name-only", "--format="],
                             capture_output=True, timeout=60).stdout.decode("utf-8", "ignore")
        for f in sorted(set(x.strip() for x in out.splitlines() if x.strip())):
            name = f.rsplit("/", 1)[-1]
            if name.startswith(".env") and not re.search(r"\.(example|sample|template|dist)$", name) \
                    and f not in ctx.tracked:
                ctx.add("env_in_history", "critical", ".env был закоммичен в прошлом", where=f,
                        detail="файл удалён из репозитория, но остался в истории git",
                        fix="Перевыпусти все ключи, которые были в этом файле. История: git filter-repo.")
    except Exception:
        pass

    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        with tempfile.TemporaryDirectory() as td:
            rep = os.path.join(td, "gl.json")
            try:
                subprocess.run([gitleaks, "detect", "--source", root, "--redact", "--no-banner",
                                "--report-format", "json", "--report-path", rep, "--exit-code", "0"],
                               capture_output=True, timeout=600)
                data = json.loads(Path(rep).read_text(encoding="utf-8") or "[]")
                for item in data[:200]:
                    ctx.add("secret_in_history", "critical", f"Секрет в истории git (gitleaks: {item.get('RuleID')})",
                            where=f"{item.get('File')} (коммит {str(item.get('Commit', ''))[:8]})",
                            detail="значение скрыто (--redact)",
                            fix="Перевыпусти ключ. Чистка истории — git filter-repo, но перевыпуск обязателен.")
                ctx.notes.append("История git проверена через gitleaks.")
                return
            except Exception as e:
                ctx.notes.append(f"gitleaks не отработал ({str(e)[:80]}), использую встроенный проход.")

    cmd = g + ["-C", root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "--no-textconv", "-U0",
               "--format=@@C %h %ad", "--date=short", f"--max-count={max_commits}"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except Exception:
        return
    start, read, commit, cdate, fname = time.time(), 0, "?", "", ""
    found: dict[str, tuple] = {}
    truncated = False
    assert proc.stdout is not None
    for bline in proc.stdout:
        read += len(bline)
        if read > max_bytes or time.time() - start > max_seconds:
            truncated = True
            break
        line = bline.decode("utf-8", "ignore")
        if line.startswith("@@C "):
            parts = line.split()
            commit, cdate = parts[1], (parts[2] if len(parts) > 2 else "")
            continue
        if line.startswith("+++ "):
            fname = line[6:].strip() if line.startswith("+++ b/") else ""
            continue
        if not line.startswith("+") or not fname or SECRET_OK_FILES.search(fname):
            continue
        if not SECRET_PREFILTER.search(line):
            continue
        for pid, _sev, title, rx, ok, _fix in SECRET_PATTERNS:
            if pid in HISTORY_SKIP:
                continue
            for m in rx.finditer(line):
                if ok and not ok(m):
                    continue
                raw = m.group(0)
                if raw in ctx.raw_secrets or raw in found:
                    continue
                found[raw] = (pid, title, fname, commit, cdate, secret_detail(pid, m))
    proc.kill()
    for raw, (pid, title, fname, commit, cdate, detail) in found.items():
        ctx.add("secret_in_history", "critical", "Секрет в истории git (удалён из кода, но не из истории)",
                where=f"{fname} (коммит {commit}, {cdate})", detail=f"{title}: {detail[9:]}",
                fix="Ключ скомпрометирован: перевыпусти его. Чистка истории — git filter-repo, но перевыпуск обязателен.")
    if truncated:
        ctx.add("history_truncated", "info", "История git просканирована частично", where=".git",
                detail="упёрся в лимит времени/объёма", fix="Поставь gitleaks и запусти: gitleaks detect --redact")


# --------------------------------------------------------------------------- публичные env и клиент

PUBLIC_ENV_RX = re.compile(r"\b(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)([A-Z0-9_]{2,})\b")
DANGEROUS_ENV = re.compile(r"(SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD|ADMIN_(KEY|TOKEN)|SIGNING|"
                           r"ENCRYPTION|MASTER_KEY|DATABASE_URL|DB_URL|DB_PASS|CONNECTION_STRING)")
PROVIDER_ENV = re.compile(r"(OPENAI|ANTHROPIC|GROQ|MISTRAL|REPLICATE|ELEVENLABS|GEMINI|RESEND|SENDGRID|MAILGUN|"
                          r"POSTMARK|TWILIO|STRIPE_(SK|SECRET)|TELEGRAM_BOT|BOT_TOKEN)")
SAFE_ENV = re.compile(r"(ANON_KEY|ANON_PUBLIC|PUBLISHABLE|PUBLIC_KEY|SITE_KEY|SITEKEY|MEASUREMENT_ID|_GA_|GTM|POSTHOG|"
                      r"SENTRY_DSN|_DSN$|VAPID_PUBLIC|MAPBOX|MAPS_API_KEY|MAPS_KEY|GOOGLE_MAPS|CLIENT_ID|APP_ID|"
                      r"PROJECT_ID|FIREBASE|ALGOLIA_(APP_ID|SEARCH)|SEARCH_ONLY|SEARCH_KEY|TURNSTILE|RECAPTCHA|"
                      r"HCAPTCHA|PLAUSIBLE|UMAMI|AMPLITUDE|MIXPANEL|SEGMENT_WRITE|INTERCOM_APP|CRISP|PUSHER_(APP_)?KEY|"
                      r"CLERK_PUBLISHABLE|PADDLE_CLIENT)")
KEYISH_ENV = re.compile(r"(KEY|TOKEN|AUTH)")


def check_public_env(ctx: Ctx):
    seen: dict[str, list] = {}
    for sf in ctx.files:
        if not (sf.suffix in CODE_EXT or sf.suffix in HTML_EXT or sf.name.startswith(".env")
                or sf.suffix in {".toml", ".yml", ".yaml", ".json"}):
            continue
        for m in PUBLIC_ENV_RX.finditer(sf.text):
            ln = sf.line_of(m.start())
            if sf.is_comment(ln):
                continue
            seen.setdefault(m.group(0), []).append((sf, ln))
    for var, locs in sorted(seen.items()):
        name = var
        if DANGEROUS_ENV.search(name) or (PROVIDER_ENV.search(name) and KEYISH_ENV.search(name)):
            sev, title = "critical", "Секрет в публичной env-переменной"
            fix = ("Префиксы NEXT_PUBLIC_/VITE_/REACT_APP_ вшивают значение в клиентский бандл. "
                   "Переименуй без префикса, используй только на сервере и перевыпусти ключ.")
        elif SAFE_ENV.search(name):
            continue  # публичный по задумке (anon key, publishable key, site key…)
        elif KEYISH_ENV.search(name):
            sev, title = "warning", "Ключ в публичной env-переменной — проверь, публичный ли он по задумке"
            fix = ("Если ключ даёт доступ к платному API или данным — уноси на сервер. Если публичный по задумке "
                   "(как anon key) — добавь его имя в .security-audit-ignore.")
        else:
            continue
        sf, ln = locs[0]
        more = f" (и ещё {len(locs) - 1} мест)" if len(locs) > 1 else ""
        ctx.add("public_env_secret", sev, title, sf, ln, detail=f"`{var}`{more}", fix=fix)


CLIENT_API_CALLS = re.compile(
    r"https?://(api\.openai\.com|api\.anthropic\.com|api\.stripe\.com|api\.groq\.com|api\.mistral\.ai|"
    r"generativelanguage\.googleapis\.com|api\.resend\.com|api\.sendgrid\.com|openrouter\.ai/api|"
    r"api\.replicate\.com|api\.elevenlabs\.io|api\.telegram\.org/bot)")
LLM_SDK_NEW = re.compile(r"\bnew\s+(OpenAI|Anthropic|Groq|GoogleGenerativeAI|Mistral)\s*\(")
SERVICE_ROLE_RX = re.compile(r"service_role|SERVICE_ROLE|SUPABASE_SERVICE|sb_secret_")


def check_client_exposure(ctx: Ctx):
    for sf in ctx.files:
        if sf.kind != "client":
            continue
        for m in CLIENT_API_CALLS.finditer(sf.text):
            ctx.add("client_api", "critical", "Платный/секретный API вызывается из браузера", sf,
                    sf.line_of(m.start()), detail=f"прямой вызов {m.group(0)} из клиентского кода — ключ виден в DevTools",
                    fix="Вынеси вызов на свой сервер/edge-функцию; ключ живёт только на сервере.")
        m = LLM_SDK_NEW.search(sf.text)
        if m:
            ctx.add("llm_sdk_client", "critical", "LLM-клиент создаётся в браузерном коде", sf, sf.line_of(m.start()),
                    detail=f"{m.group(0)} в файле с 'use client'/клиентском компоненте",
                    fix="Вызовы LLM — только на сервере, за авторизацией и лимитом.")
        m = SERVICE_ROLE_RX.search(sf.text)
        if m and not sf.is_comment(sf.line_of(m.start())):
            ctx.add("service_role_client", "critical", "Supabase service_role/secret в клиентском коде", sf,
                    sf.line_of(m.start()), detail="service_role обходит RLS — в браузере это полный доступ к БД",
                    fix="service_role — только на сервере/в edge-функциях. В клиенте — anon/publishable key + RLS.")


# --------------------------------------------------------------------------- правила по строкам

SANITIZER_RX = re.compile(r"(?i)(dompurify|sanitize-html|sanitizeHtml|rehype-sanitize|\bxss\b|sanitize\(|bleach|"
                          r"\bnh3\b|HtmlSanitizer|Jsoup\.clean)")


class Rule:
    def __init__(self, rid, sev, title, rx, fix, exts=None, kinds=None, path_rx=None, file_rx=None,
                 unless_rx=None, downgrade_rx=None, flags=0, max_per_file=3):
        self.id, self.sev, self.title, self.fix = rid, sev, title, fix
        self.rx = re.compile(rx, flags)
        self.exts, self.kinds = exts, kinds
        self.path_rx = re.compile(path_rx) if path_rx else None
        self.file_rx = re.compile(file_rx) if isinstance(file_rx, str) else file_rx
        self.unless_rx = re.compile(unless_rx) if isinstance(unless_rx, str) else unless_rx
        self.downgrade_rx = re.compile(downgrade_rx) if isinstance(downgrade_rx, str) else downgrade_rx
        self.max_per_file = max_per_file

    def applies(self, sf: SF) -> bool:
        if self.exts is not None:
            ok = sf.suffix in self.exts or (".env" in self.exts and sf.name.startswith(".env")) \
                 or ("Dockerfile" in self.exts and sf.name.startswith("Dockerfile"))
            if not ok:
                return False
        if self.kinds is not None and sf.kind not in self.kinds:
            return False
        if self.path_rx and not self.path_rx.search(sf.rel):
            return False
        if self.file_rx and not self.file_rx.search(sf.text):
            return False
        if self.unless_rx and self.unless_rx.search(sf.text):
            return False
        return True


J, P, V, H = JS_EXT, PY_EXT, JVM_EXT, HTML_EXT
MAIL_RX = (r"(?i)(resend\.emails\.send|resend\.batch|nodemailer|sendMail\s*\(|transporter\.send|sgMail\.send|"
           r"@sendgrid/mail|mailgun|postmark|SendEmailCommand|smtplib|send_mail\s*\(|EmailMessage\s*\()")
ESCAPE_RX = (r"(?i)(escapeHtml|escape_html|html\.escape|\bescape\(|sanitize|he\.encode|lodash/escape|_\.escape|"
             r"DOMPurify|html-escaper|@react-email|react-email|mjml|handlebars|render\(|escapeMarkdown|escape_markdown)")
REQ = r"(?:req\.body|request\.json\(\)|await\s+req(?:uest)?\.json\(\)|body|payload|input|values|formData\.get)"

RULES = [
    # --- инъекции
    Rule("sql_py_fstring", "warning", "SQL через f-строку",
         r"""(?i)\b(?:execute|executemany|executescript|raw|text|query|read_sql)\s*\(\s*f["'][^\n]*?\b(?:select|insert|update|delete|where|order\s+by)\b[^\n]*?\{""",
         "Параметризованный запрос (плейсхолдеры %s / ? / :name) вместо f-строки.", exts=P),
    Rule("sql_py_concat", "warning", "SQL через конкатенацию/format",
         r"""(?i)\b(?:execute|executemany|raw|text|query|read_sql)\s*\(\s*["'][^"'\n]*\b(?:select|insert|update|delete|where)\b[^"'\n]*["']\s*(?:\+|%\s*[(\w]|\.format\s*\()""",
         "Параметризованный запрос вместо склейки строк.", exts=P),
    Rule("sql_js_template", "warning", "SQL через шаблонную строку с подстановкой",
         r"""(?:\$queryRawUnsafe|\$executeRawUnsafe|\bunsafe|\braw|\bquery|\bexecute|sequelize\.query)\s*\(\s*`(?=[^`]{0,2000}?(?i:\b(?:select|insert|update|delete|where)\b))[^`]{0,2000}?\$\{""",
         "Параметры вместо подстановки: db.query('... WHERE id = $1', [id]); в Prisma — $queryRaw`...${id}` "
         "(тегированный шаблон, без скобок), в postgres.js — sql`...` без .unsafe.", exts=J),
    Rule("sql_js_concat", "warning", "SQL через конкатенацию строк",
         r"""(?i)\.(?:query|execute|raw|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*["'][^"'\n]*\b(?:select|insert|update|delete|where)\b[^"'\n]*["']\s*\+""",
         "Параметризованный запрос вместо склейки строк.", exts=J),
    Rule("sql_raw_unsafe", "info", "Сырой SQL-метод — проверь, что ввод не склеивается",
         r"""\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(|\bPrisma\.raw\s*\(|\bsql\.raw\s*\(""",
         "Если ввод попадает в строку запроса — перейди на параметры; идентификаторы (ORDER BY, колонки) — только через whitelist.",
         exts=J),
    Rule("sql_jvm_concat", "warning", "SQL через конкатенацию/интерполяцию (JVM)",
         r"""(?i)(?:createQuery|createNativeQuery|prepareStatement|executeQuery|executeUpdate|execute|queryForObject|queryForList)\s*\(\s*(?:"[^"\n]*\b(?:select|insert|update|delete|where)\b[^"\n]*"\s*\+|s"[^"\n]*\b(?:select|insert|update|delete|where)\b[^"\n]*\$)""",
         "PreparedStatement с ? / именованные параметры JPA; в Scala — sql\"\" (Doobie/Slick) вместо s\"\".", exts=V),
    Rule("nosql_filter_from_body", "warning", "Объект из запроса прямо в NoSQL-фильтр",
         r"""\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|exists)\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:body|query)|await\s+req(?:uest)?\.json\(\))\s*[,)]""",
         "Приводи поля к ожидаемому типу (String(x)) или валидируй схемой — иначе прилетят операторы $ne/$gt/$regex.",
         exts=J | P),
    Rule("cmd_injection", "warning", "Shell-команда со склейкой ввода",
         r"""\b(?:exec|execSync)\s*\(\s*(?:`[^`\n]*\$\{|["'][^"'\n]*["']\s*\+)""",
         "execFile/spawn с массивом аргументов вместо строки для shell.", exts=J, file_rx=r"child_process"),
    Rule("py_shell_true", "warning", "subprocess с shell=True",
         r"""subprocess\.\w+\([^\n]*shell\s*=\s*True""", "Список аргументов без shell=True.", exts=P),
    Rule("py_os_system", "info", "os.system/os.popen — проверь, что в команду не попадает ввод",
         r"""\bos\.(?:system|popen)\s*\(""", "subprocess.run([...]) со списком аргументов.", exts=P),
    Rule("unsafe_deserialize", "warning", "Небезопасная десериализация",
         r"""\bpickle\.loads?\s*\(|\byaml\.unsafe_load\s*\(|\byaml\.load\s*\((?![^\n]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)|new\s+ObjectInputStream\s*\(|\b(?:enableDefaultTyping|activateDefaultTyping)\s*\(|\bmarshal\.loads\s*\(""",
         "Не десериализуй недоверенные данные этими способами: yaml.safe_load, JSON, явные DTO.", exts=P | V),
    Rule("eval_js", "warning", "eval / new Function / строковый таймер",
         r"""(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["'`]""",
         "Никакого исполнения строк: JSON.parse, явный разбор, функции вместо строк.", exts=J),
    Rule("eval_py", "warning", "eval/exec в Python",
         r"""(?<![\w.])(?:eval|exec)\s*\(""", "ast.literal_eval / явный разбор вместо eval/exec.", exts=P),
    # --- XSS
    Rule("xss_dangerously", "warning", "dangerouslySetInnerHTML — вывод без экранирования",
         r"""dangerouslySetInnerHTML(?![^\n]*JSON\.stringify)(?!\s*=\s*\{\s*\{\s*__html\s*:\s*(?:[A-Z_][A-Z0-9_]*|"[^"\n]*"|'[^'\n]*')\s*,?\s*\})""",
         "Рендери текстом. Если нужен HTML — DOMPurify (актуальная версия) прямо перед выводом.",
         exts=J, downgrade_rx=SANITIZER_RX),
    Rule("jsonld_unescaped", "info", "JSON внутри <script> без экранирования <",
         r"""dangerouslySetInnerHTML[^\n]*JSON\.stringify\((?![^\n]*\.replace\()""",
         "JSON.stringify(data).replace(/</g, '\\\\u003c') — иначе </script> из данных выйдет из тега.", exts=J),
    Rule("xss_dom_sink", "info", "HTML-синк в DOM (innerHTML/insertAdjacentHTML/document.write)",
         r"""\.(?:inner|outer)HTML\s*\+?=(?!=)(?!\s*(["'`])\s*\1)|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(""",
         "textContent вместо innerHTML; если нужен HTML — DOMPurify.", exts=J | H),
    Rule("xss_template_raw", "warning", "Вывод без экранирования в шаблоне",
         r"""\bv-html\s*=|\{@html\s|\|\s*safe\b|\bmark_safe\s*\(|\bMarkup\s*\(|<%-|\{\{\{|\{%\s*autoescape\s+(?:off|false)|autoescape\s*=\s*False|\bhtml_safe\b|th:utext""",
         "Обычный экранированный вывод; HTML от пользователя — только через санитайзер.",
         exts=J | P | H | TPL_EXT | V, downgrade_rx=SANITIZER_RX),
    Rule("ssti_py", "warning", "render_template_string — риск SSTI",
         r"""\brender_template_string\s*\(""", "render_template с файлом шаблона; ввод — только как переменные.", exts=P),
    Rule("dom_xss_source", "info", "Чтение location.hash/search/referrer в клиенте",
         r"""\b(?:window\.)?location\.(?:hash|search)\b|\bdocument\.referrer\b""",
         "Проверь, куда уходит значение: в DOM только через textContent, в href — только после проверки схемы.",
         exts=J | H, kinds={"client"}),
    Rule("postmessage_no_origin", "warning", "Обработчик postMessage без проверки origin",
         r"""addEventListener\s*\(\s*["']message["']""",
         "Сверяй event.origin со списком своих доменов до любой обработки данных.", exts=J | H, unless_rx=r"\.origin\b"),
    # --- редиректы и SSRF
    Rule("open_redirect", "info", "Редирект по параметру из запроса",
         r"""(?i)(?:\bredirect|res\.redirect|NextResponse\.redirect|router\.(?:push|replace)|location\.(?:assign|replace)|window\.location(?:\.href)?\s*=)\s*\(?[^\n]{0,80}?(?:searchParams\.get\(\s*["'](?:next|redirect|redirect_?to|returnTo|return_?url|callbackUrl|continue|url|to)["']|req\.query\.(?:next|redirect|returnTo|returnUrl|callbackUrl|url)|request\.args\.get\(\s*["'](?:next|redirect|url))""",
         "Только относительные пути (начинаются с '/', но не с '//' и не с '/\\') или whitelist доменов.", exts=J | P),
    Rule("ssrf_suspect", "info", "Серверный запрос по URL из ввода",
         r"""(?:\bfetch|\baxios(?:\.(?:get|post|request))?|\bgot|\brequests\.(?:get|post|request)|\bhttpx\.(?:get|post|request)|\burlopen)\s*\(\s*(?:req\.(?:body|query|params)\.|body\.|data\.url|input\.url|searchParams\.get\(|request\.(?:args|json|form|query_params)|params\.url)""",
         "Whitelist доменов, запрет внутренних адресов (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254.169.254) после резолва DNS, без редиректов.",
         exts=J | P, kinds=SERVERISH),
    # --- сессии и авторизация
    Rule("token_in_storage", "warning", "Токен в localStorage/sessionStorage",
         r"""(?i)(?:localStorage|sessionStorage)\.setItem\(\s*["'`][^"'`]*(?:token|jwt|auth|session|access|refresh)""",
         "Сессия — в cookie HttpOnly + Secure + SameSite=Lax: localStorage читается любым XSS.", exts=J),
    Rule("jwt_alg_none", "critical", "JWT c alg:none",
         r"""["']alg["']\s*:\s*["']none["']|algorithms\s*[:=]\s*\[[^\]\n]*["']none["']""",
         "Никогда не принимай alg:none — фиксируй список алгоритмов (например ['HS256']).", exts=J | P | V),
    Rule("jwt_no_verify", "critical", "JWT декодируется без проверки подписи",
         r"""verify_signature["']?\s*:\s*False|jwt\.decode\([^\n)]*verify\s*=\s*False""",
         "jwt.decode с ключом и algorithms=[...], без отключения проверки.", exts=P),
    Rule("jwt_no_exp", "warning", "JWT принимается без проверки срока",
         r"""ignoreExpiration\s*:\s*true|["']verify_exp["']\s*:\s*False""",
         "Не отключай проверку exp — украденный токен будет жить вечно.", exts=J | P),
    Rule("weak_password_hash", "warning", "Пароль хешируется быстрым хешем",
         r"""(?i)(?:\bmd5\b|\bsha1\b|sha256|createHash\(\s*["'](?:md5|sha1|sha256)["']\))[^\n]{0,80}\bpass(?:word|wd)?\b|\bpass(?:word|wd)\b[^\n]{0,80}(?:\bmd5\b|\bsha1\b|hashlib\.sha256|createHash\()""",
         "bcrypt / argon2id / scrypt с солью.", exts=J | P | V),
    Rule("insecure_random", "warning", "Math.random/random для токенов и кодов",
         r"""(?i)Math\.random\(\)[^\n]{0,80}\b(?:token|otp|code|secret|password|reset|verif|nonce|salt)|\b(?:token|otp|code|secret|password|reset|nonce|salt)\w*\s*[:=][^\n]{0,80}(?:Math\.random\(\)|\brandom\.(?:random|randint|choice|choices)\()""",
         "crypto.randomUUID()/crypto.getRandomValues()/randomBytes; в Python — модуль secrets.", exts=J | P),
    Rule("cookie_insecure", "warning", "Cookie без защитных флагов",
         r"""(?i)\bhttpOnly\s*:\s*false|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False""",
         "Сессионные cookie: HttpOnly, Secure, SameSite=Lax (или Strict).", exts=J | P),
    Rule("role_from_client", "warning", "Роль/права берутся из запроса клиента",
         r"""(?i)\b(?:req\.body|request\.json\(\)|await\s+req(?:uest)?\.json\(\)|body|payload)\s*(?:\.|\[\s*["'])(?:role|is_?admin|is_?staff|is_?superuser|permissions)\b|formData\.get\(\s*["'](?:role|is_?admin)["']""",
         "Роль — только из проверенной сессии/БД на сервере. Клиент может прислать role: admin.",
         exts=J | P, kinds=SERVERISH),
    Rule("mass_assignment", "info", "Объект из запроса целиком уходит в БД (mass assignment)",
         r"""\.(?:update|insert|upsert|create|save|updateOne|insertOne)\s*\(\s*(?:req\.body|body|await\s+req(?:uest)?\.json\(\)|request\.json|payload|input|values)\s*[,)]|\bdata\s*:\s*(?:req\.body|body|await\s+req(?:uest)?\.json\(\)|payload|input)\s*[,}]|\.\.\.(?:req\.body|body|payload)\b""",
         "Бери из запроса только разрешённые поля (схема zod / pick). role, price, user_id, status — выставляет сервер.",
         exts=J | P, kinds=SERVERISH),
    Rule("express_trust_proxy", "info", "trust proxy = true: IP берётся из X-Forwarded-For",
         r"""app\.set\(\s*["']trust proxy["']\s*,\s*true""",
         "true доверяет любому X-Forwarded-For — rate limit по IP подделывается. Укажи число прокси (1) или их адреса.",
         exts=J),
    # --- ошибки
    Rule("error_stack_leak", "warning", "Stack trace в ответе API",
         r"""(?i)(?:\.json|\.send|Response\.json|NextResponse\.json|new\s+Response|jsonify|JSONResponse|HttpResponse|JSON\.stringify)\s*\([^\n]{0,200}\b(?:err|error|e|ex|exc|exception)\.stack\b|(?:return|jsonify|JSONResponse)[^\n]*traceback\.format_exc""",
         "Клиенту — общий текст и id ошибки, детали и стек — в серверный лог.", exts=J | P, kinds=SERVERISH),
    Rule("error_message_leak", "info", "Текст внутренней ошибки уходит клиенту",
         r"""(?i)(?:\.json|\.send|Response\.json|NextResponse\.json|new\s+Response|jsonify|JSONResponse)\s*\([^\n]{0,200}\b(?:err|error|e|ex|exc)\.message\b|JSON\.stringify\(\s*\{\s*error\s*:\s*(?:err|error|e)\.message""",
         "Сообщения БД/SDK раскрывают структуру. Клиенту — общий текст, детали — в лог.", exts=J | P, kinds=SERVERISH),
    # --- конфиги
    Rule("cors_star", "warning", "CORS открыт для всех (*)",
         r"""(?i)Access-Control-Allow-Origin["'`\s:,=>]+\*|cors\(\s*\{\s*origin\s*:\s*["']\*|CORS_ORIGIN\S*\s*=\s*["']?\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["']""",
         "Ограничь origin списком своих доменов.", exts=J | P | {".toml", ".json", ".conf", ".env", ".yml", ".yaml"}),
    Rule("cors_credentials_any", "critical", "CORS: любой origin + credentials",
         r"""origin\s*:\s*(?:true|["']\*["'])[^}]{0,300}credentials\s*:\s*true|credentials\s*:\s*true[^}]{0,300}origin\s*:\s*(?:true|["']\*["'])|allow_credentials\s*=\s*True[^)]{0,300}allow_origins\s*=\s*\[\s*["']\*|allow_origins\s*=\s*\[\s*["']\*["']\s*\][^)]{0,300}allow_credentials\s*=\s*True""",
         "С credentials origin — только явный whitelist. Иначе любой сайт делает запросы от имени пользователя.",
         exts=J | P, flags=re.S),
    Rule("debug_on", "warning", "Debug-режим включён в конфиге/коде",
         r"""\bapp\.run\([^\n]*debug\s*=\s*True|^\s*DEBUG\s*=\s*(?:True|true|1)\b|^\s*FLASK_DEBUG\s*=\s*1""",
         "Выключи debug в проде: он раскрывает стектрейсы, настройки и иногда даёт консоль.",
         exts=P | {".env", ".cfg", ".ini", ".toml"}, flags=re.M),
    Rule("tls_disabled", "warning", "Проверка TLS-сертификата отключена",
         r"""\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["'\s]*[:=]\s*["']?0|InsecureSkipVerify\s*:\s*true""",
         "Не отключай проверку сертификатов — это открывает MITM.", exts=J | P | {".go", ".env"}),
    Rule("allowed_hosts_any", "info", "ALLOWED_HOSTS = ['*']",
         r"""ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']""", "Перечисли свои домены.", exts=P),
    Rule("source_maps_public", "warning", "Source maps в продакшен-сборке",
         r"""productionBrowserSourceMaps\s*:\s*true""", "Выключи или отдавай карты только в Sentry, не публично.",
         path_rx=r"next\.config"),
    Rule("vite_sourcemap", "info", "Source maps включены в сборке Vite",
         r"""\bsourcemap\s*:\s*true""", "Для прода — 'hidden' или false.", path_rx=r"vite\.config"),
    Rule("next_svg_allowed", "warning", "next/image: dangerouslyAllowSVG",
         r"""dangerouslyAllowSVG\s*:\s*true""",
         "Без contentSecurityPolicy и contentDispositionType: 'attachment' SVG через оптимизатор — XSS-риск.",
         path_rx=r"next\.config"),
    Rule("next_images_any_host", "info", "next/image: картинки с любого хоста",
         r"""hostname\s*:\s*["']\*\*["']""", "Перечисли конкретные хосты в remotePatterns.", path_rx=r"next\.config"),
    Rule("server_actions_any_origin", "warning", "serverActions.allowedOrigins содержит *",
         r"""allowedOrigins\s*:\s*\[[^\]]*["']\*""", "Перечисли свои домены — иначе снимается защита server actions от CSRF.",
         path_rx=r"next\.config"),
    Rule("llm_in_browser", "critical", "LLM-SDK разрешён в браузере (dangerouslyAllowBrowser)",
         r"""dangerouslyAllowBrowser\s*:\s*true""", "Вызовы LLM — только с сервера, ключ — только на сервере.", exts=J),
    Rule("gha_script_injection", "warning", "GitHub Actions: пользовательский текст подставляется в скрипт",
         r"""\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|head_commit\.(?:message|author\.(?:email|name))|commits\b[^}]*message|pages\b[^}]*page_name|discussion\.(?:title|body))|head_ref)\s*\}\}""",
         "Передавай через env: и используй как \"$VAR\" — прямая подстановка ${{ }} в run: даёт инъекцию команд.",
         path_rx=r"(^|/)\.github/workflows/"),
    Rule("gha_prt_checkout", "warning", "pull_request_target + checkout кода из PR",
         r"""pull_request_target.{0,5000}?ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)""",
         "pull_request_target работает с секретами репо — не собирай и не запускай в нём код из чужого PR.",
         path_rx=r"(^|/)\.github/workflows/", flags=re.S),
    Rule("dockerfile_secret", "warning", "Секрет в ENV Dockerfile",
         r"""(?im)^\s*ENV\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*[= ]\s*\S+""",
         "Секреты — через runtime env / secrets, не в образ: слои образа читаются.", exts={"Dockerfile"}),
    # --- почта и уведомления
    Rule("email_to_from_input", "warning", "Адресат письма берётся из запроса",
         r"""(?i)\bto\s*[:=]\s*\[?\s*""" + REQ + r"""\b""",
         "Риск open relay: сервис рассылает письма на любые адреса от своего имени. Если это подтверждение "
         "отправителю — капча + лимит на адрес и IP; уведомления владельцу — фиксированный адрес.",
         exts=J | P, kinds=SERVERISH, file_rx=MAIL_RX),
    Rule("email_header_from_input", "info", "Заголовок письма (from/replyTo/subject) из ввода",
         r"""(?i)\b(?:from|replyTo|reply_to|subject)\s*[:=]\s*[^,\n]*(?:req\.body|body\.|formData\.get|data\.|input\.)""",
         "from фиксирован; replyTo/subject — отрезай переводы строк и ограничивай длину.",
         exts=J | P, kinds=SERVERISH, file_rx=MAIL_RX),
    Rule("email_html_interp", "info", "HTML письма собирается строкой с подстановкой",
         r"""html\s*[:=]\s*`[^`]{0,3000}?<[a-zA-Z][^`]{0,3000}?\$\{""",
         "Экранируй каждую подстановку (escapeHtml) или шаблонизатор с автоэкранированием (react-email). "
         "Письма — «тихое» место для stored XSS и фишинга от твоего имени.",
         exts=J, file_rx=MAIL_RX, unless_rx=ESCAPE_RX, flags=re.S, max_per_file=1),
    Rule("telegram_markup", "info", "Уведомление с HTML/Markdown-разметкой",
         r"""(?i)parse_mode["']?\s*[:=]\s*["'](?:HTML|Markdown(?:V2)?)["']""",
         "Экранируй пользовательские данные под выбранный parse_mode, иначе разметка ломается/подменяется.",
         exts=J | P, unless_rx=ESCAPE_RX, max_per_file=1),
]

# --------------------------------------------------------------------------- проверки уровня файла

AUTH_RX = re.compile(
    r"""(?ix)\bauth\s*\(\s*\)|getServerSession|\bgetSession\b|\bgetUser\b|\bgetClaims\b|currentUser|requireAuth|
    requireUser|requireAdmin|requireSession|withAuth|isAuthenticated|ensureAuth|checkAuth|assertAuth|verifyToken|
    verifyJwt|verifyIdToken|jwt\.verify|jwtVerify|\bgetToken\b|clerkClient|\bvalidateRequest\b|\bauthenticate\b|
    \bauthorize\b|login_required|permission_required|get_current_user|IsAuthenticated|@PreAuthorize|@Secured|
    @RolesAllowed|session\.user\b|req\.user\b|request\.user\b|ctx\.user\b|locals\.user\b|
    locals\.(?:session|safeGetSession)|["']authorization["']|x-api-key|supabase\.auth\.""")
RL_RX = re.compile(
    r"""(?i)express-rate-limit|express-slow-down|@upstash/ratelimit|rate-limiter-flexible|@nestjs/throttler|
    slowapi|django_ratelimit|django-ratelimit|flask_limiter|@fastify/rate-limit|koa-ratelimit|hono/rate-limit|
    next-rate-limit|@arcjet|\bRatelimit\b|\b(?:ratelimit|rateLimiter|limiter)\s*\.\s*(?:limit|consume|check|hit)\s*\(""",
    re.X)
HANDLER_RX = re.compile(
    r"""(?mx)^\s*export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|^\s*export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*=|
    \b(?:app|router|server|fastify|api)\.(?:get|post|put|patch|delete|all|route)\s*\(|
    @(?:app|router|bp|api)\.(?:get|post|put|patch|delete|route)\s*\(|export\s+default\s+(?:async\s+)?function\s+handler|
    \bDeno\.serve\s*\(|^\s*serve\s*\(\s*async|export\s+(?:const|async\s+function)\s+handler\b|
    @(?:Get|Post|Put|Patch|Delete|Request)Mapping""")
MUTATION_RX = re.compile(
    r"""(?mx)^\s*export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b|^\s*export\s+const\s+(?:POST|PUT|PATCH|DELETE)\s*=|
    \b(?:app|router|server|fastify|api)\.(?:post|put|patch|delete)\s*\(|@(?:app|router|bp|api)\.(?:post|put|patch|delete)\s*\(|
    \bDeno\.serve\s*\(|^\s*serve\s*\(\s*async|@(?:Post|Put|Patch|Delete)Mapping""")
AI_CALL_RX = re.compile(
    r"""(?i)\bnew\s+(?:OpenAI|Anthropic|Groq|Mistral|GoogleGenerativeAI)\b|\.chat\.completions\.create|\.responses\.create|
    \.messages\.create|generateContent|\b(?:generateText|streamText|generateObject|streamObject)\s*\(|@ai-sdk/|
    api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|openrouter\.ai""", re.X)
AI_INVOKE_RX = re.compile(
    r"""(?:\.chat\.completions\.create|\.responses\.create|\.messages\.create|\.completions\.create|
    generateContent(?:Stream)?|\bgenerateText|\bstreamText|\bgenerateObject|\bstreamObject)\s*\(""", re.X)
MAXTOK_RX = re.compile(r"(?i)max_tokens|maxtokens|max_output_tokens|maxoutputtokens|max_completion_tokens|maxcompletiontokens")
AUTH_ROUTE_PATH = re.compile(
    r"(?i)(^|/)(login|log-in|signin|sign-in|signup|sign-up|register|reset-password|forgot(-password)?|verify|otp|"
    r"magic-link)(/|\.|$)")
SENSITIVE_ROUTE_DECL = re.compile(
    r"""(?i)\.(?:post|put)\s*\(\s*['"`][^'"`]*(?:login|signin|sign-in|signup|sign-up|register|reset|forgot|otp|verify)[^'"`]*['"`]|
    @(?:app|router|bp|api)\.(?:post|route)\s*\(\s*['"][^'"]*(?:login|signin|signup|register|reset|forgot|otp|verify)""", re.X)
IP_HEADER_RX = re.compile(
    r"""(?i)["'](?:x-forwarded-for|x-real-ip|true-client-ip|x-client-ip|cf-connecting-ip|x-cluster-client-ip|forwarded)["']""")
RL_WORD_RX = re.compile(r"(?i)rate.?limit|ratelimit|limiter|throttl|too many")
SIG_RX = re.compile(r"(?i)signature|hmac|timingSafeEqual|compare_digest|svix|verifyWebhook|webhooks?\.verify|"
                    r"x-hub-signature|createHmac|verify_signature|constructEvent")


def _first(sf: SF, rx: re.Pattern):
    m = rx.search(sf.text)
    return sf.line_of(m.start()) if m else None


def check_endpoints(ctx: Ctx):
    info = ctx.info
    mw = [sf for sf in ctx.files if re.search(r"(^|/)(src/)?(middleware|proxy)\.[jt]s$", sf.rel)]
    mw_auth = any(AUTH_RX.search(sf.text) for sf in mw)
    has_rl_anywhere = any(RL_RX.search(sf.text) for sf in ctx.files if sf.suffix in CODE_EXT)
    supabase_auth = any(re.search(r"supabase\.auth\.(signInWithPassword|signUp|signInWithOtp|resetPasswordForEmail)",
                                  sf.text) for sf in ctx.files if sf.suffix in JS_EXT)
    auth_endpoints = []
    for sf in ctx.files:
        if sf.suffix not in CODE_EXT or sf.kind not in SERVERISH:
            continue
        text = sf.text
        is_action = bool(USE_SERVER.search(text[:800]))
        is_handler = bool(HANDLER_RX.search(text)) or is_action
        has_auth = bool(AUTH_RX.search(text))
        has_rl = bool(RL_RX.search(text))
        uses_ai = bool(AI_CALL_RX.search(text))
        is_webhook = bool(re.search(r"(?i)webhook", sf.rel))
        is_auth_route = bool(AUTH_ROUTE_PATH.search(sf.rel)) or bool(SENSITIVE_ROUTE_DECL.search(text))
        mw_note = (" Возможно, защищено в middleware — проверь matcher; middleware не должна быть "
                   "единственной защитой (обход CVE-2025-29927).") if mw_auth else ""

        # AI cost bomb
        if uses_ai and is_handler and not has_auth:
            sev = "warning" if (has_rl or mw_auth) else "critical"
            ctx.add("ai_open_endpoint", sev, "AI-эндпоинт без видимой проверки авторизации", sf,
                    _first(sf, AI_CALL_RX), detail="роут вызывает платный LLM, не видно проверки пользователя"
                    + ("" if has_rl else " и лимита запросов") + "." + mw_note,
                    fix="Закрой авторизацией + лимит запросов на пользователя + max_tokens + лимит длины входа. "
                        "Самый частый способ слить бюджет вайбкод-проекта.")
        if AI_INVOKE_RX.search(text) and not MAXTOK_RX.search(text):
            ctx.add("ai_no_maxtokens", "warning", "Вызов LLM без лимита длины ответа", sf, _first(sf, AI_INVOKE_RX),
                    detail="нет max_tokens / maxOutputTokens в файле",
                    fix="Задай max_tokens (maxOutputTokens) и ограничь длину входного текста.")
        # server actions
        if is_action and not has_auth:
            top = re.match(r"""\s*(?://[^\n]*\n\s*|/\*.*?\*/\s*)*['"]use server['"]""", text, re.S)
            via_rls = bool(re.search(r"\.from\(\s*['\"]", text)) and not SERVICE_ROLE_RX.search(text) \
                and ctx.info.get("supabase")
            sev, why = "warning", "каждая server action — публичный POST-эндпоинт, вызываемый напрямую"
            if not top:
                sev, why = "info", "инлайновая server action — проверь, что права проверены в ней самой, а не только в компоненте"
            elif via_rls:
                sev, why = "info", "запросы идут через Supabase-клиент с сессией — защиту даёт RLS; проверь политики таблиц"
            ctx.add("server_action_no_auth", sev, "Server Action без видимой проверки сессии", sf,
                    _first(sf, USE_SERVER), detail=why,
                    fix="В начале каждой action: проверка сессии и прав на объект; для публичных форм — "
                        "zod-валидация, лимит и honeypot/капча.")
        # мутирующий эндпоинт без авторизации
        elif not is_action and MUTATION_RX.search(text) and not has_auth and not uses_ai and not is_webhook \
                and not is_auth_route:
            ctx.add("mutation_no_auth", "info", "Мутирующий эндпоинт без видимой авторизации", sf,
                    _first(sf, MUTATION_RX), detail="если это публичная форма — это нормально, но нужны валидация, "
                    "лимит и honeypot/капча." + mw_note,
                    fix="Приватный эндпоинт — проверка сессии и владения объектом в самом handler'е.")
        # вебхуки
        if is_webhook and is_handler:
            if re.search(r"(?i)stripe", text) and not re.search(r"constructEvent(?:Async)?\s*\(|webhooks\.construct", text):
                ctx.add("webhook_no_signature", "warning", "Stripe-вебхук без проверки подписи", sf,
                        _first(sf, HANDLER_RX), detail="не найден stripe.webhooks.constructEvent",
                        fix="stripe.webhooks.constructEvent(rawBody, sig, whsec). Без этого любой шлёт «оплата прошла».")
            elif not SIG_RX.search(text):
                ctx.add("webhook_no_signature", "warning", "Вебхук без проверки подписи", sf, _first(sf, HANDLER_RX),
                        detail="не видно проверки подписи/HMAC",
                        fix="Проверяй подпись провайдера (HMAC + timingSafeEqual) до любой обработки.")
            if "constructEvent" in text and re.search(r"req(?:uest)?\.json\(\)", text) \
                    and not re.search(r"\.text\(\)|arrayBuffer\(\)|rawBody|raw\(|buffer\(", text):
                ctx.add("webhook_parsed_body", "info", "constructEvent получает распарсенный JSON", sf,
                        _first(sf, re.compile(r"req(?:uest)?\.json\(\)")),
                        detail="подпись Stripe считается по сырому телу", fix="await req.text() → constructEvent.")
        # лимитер по подделываемому заголовку
        m = IP_HEADER_RX.search(text)
        if m and RL_WORD_RX.search(text):
            ctx.add("ratelimit_spoofable_key", "warning", "Rate limit ключуется по заголовку от клиента (проверь запуском)",
                    sf, sf.line_of(m.start()), detail=f"используется {m.group(0)} — клиент может присылать свой",
                    fix="Бери IP из источника, который выставляет платформа и не может переписать клиент (Netlify: "
                        "context.ip / x-nf-client-connection-ip; Cloudflare: CF-Connecting-IP при закрытом origin), "
                        "и проверь тестом: N+2 запросов с меняющимся заголовком должны упереться в лимит.")
        if is_auth_route and MUTATION_RX.search(text) and not re.search(r"supabase\.auth\.", text):
            auth_endpoints.append(sf)

    if auth_endpoints and not has_rl_anywhere:
        sf = auth_endpoints[0]
        ctx.add("no_ratelimit_auth", "warning", "Auth-эндпоинты без rate limit", sf, _first(sf, HANDLER_RX),
                detail=f"эндпоинтов входа/регистрации/сброса: {len(auth_endpoints)}; библиотеки лимитов в проекте не видно",
                fix="Лимит на login/signup/reset/OTP по IP и по аккаунту (@upstash/ratelimit, express-rate-limit, slowapi). "
                    "Иначе — брутфорс и спам кодами.")
    if supabase_auth:
        ctx.add("supabase_auth_limits", "info", "Supabase Auth: проверь встроенные лимиты", where="Supabase Dashboard",
                detail="вход/регистрация через supabase.auth — лимиты задаются в проекте Supabase",
                fix="Dashboard → Authentication → Rate Limits; включи CAPTCHA (Turnstile/hCaptcha) для sign-up.")


ID_FROM_REQ = re.compile(
    r"""req\.(?:params|query)\.(?:id|\w*_?[iI]d)\b|\bparams\.(?:id|\w+Id)\b|\(await\s+params\)\.(?:id|\w+Id)\b|
    searchParams\.get\(\s*["'](?:id|\w+_?[iI]d)["']|request\.args\.get\(\s*["']\w*id["']|@PathVariable""", re.X)
DB_ACCESS = re.compile(r"""(?i)\.(?:findUnique|findFirst|findById|findOne|findMany|update|delete|destroy|select|from|
    get_object_or_404|objects\.get)\s*\(|\b(?:SELECT|UPDATE|DELETE)\b""", re.X)
OWNER_CHECK = re.compile(r"""(?i)\b(?:user_?id|owner_?id|owner|author_?id|created_?by|session\.user|auth\.uid|
    currentUser|current_user|request\.user|req\.user|getUser|belongs|can(?:Access|Edit|View)|authorize|isOwner)\b""", re.X)


def check_idor(ctx: Ctx):
    for sf in ctx.files:
        if sf.suffix not in CODE_EXT or sf.kind not in SERVERISH:
            continue
        m = ID_FROM_REQ.search(sf.text)
        if m and DB_ACCESS.search(sf.text) and not OWNER_CHECK.search(sf.text):
            ctx.add("idor_suspect", "info", "Доступ к объекту по id из запроса без видимой проверки владельца", sf,
                    sf.line_of(m.start()), detail="возможен IDOR: пользователь A читает/меняет объект пользователя B",
                    fix="Фильтруй по владельцу (WHERE id = $1 AND user_id = current_user). С Supabase — проверь "
                        "RLS-политику таблицы. Проверь запуском с двух аккаунтов.")


CSV_RX = re.compile(r"(?i)text/csv|\.csv[\"'`]|json2csv|papaparse|Papa\.unparse|csv-stringify|csv-writer|exceljs|"
                    r"\bxlsx\b|writerow|to_csv\(|csv\.writer")
FORMULA_GUARD = re.compile(r"(?i)formula|csv.?inject|sanitizeCsv|escapeCsv|safeCsv|\[=\+\\?-@\]|\^\[=")
UPLOAD_RX = re.compile(r"(?i)multer\(|formidable|busboy|instanceof\s+File\b|\.upload\(\s*[^)\n]*file|UploadFile|"
                       r"FileStorage|MultipartFile|request\.files|req\.files?\b|storage\s*\.from\([^)\n]*\)\s*\.upload")
PATH_FROM_NAME = re.compile(r"(?i)path\.(?:join|resolve)\([^)\n]*(?:originalname|originalFilename|file\.name|filename|fileName)|"
                            r"os\.path\.join\([^)\n]*(?:\.filename|filename)")


def check_misc(ctx: Ctx):
    for sf in ctx.files:
        if sf.suffix not in CODE_EXT:
            continue
        m = CSV_RX.search(sf.text)
        if m and not FORMULA_GUARD.search(sf.text) and not sf.is_comment(sf.line_of(m.start())):
            ctx.add("csv_formula_injection", "info", "Экспорт CSV/Excel — проверь защиту от formula injection", sf,
                    sf.line_of(m.start()), detail="значения, начинающиеся с = + - @, Excel исполнит как формулу",
                    fix="Префиксуй такие значения апострофом (') и экранируй кавычки; это stored-атака на того, кто открывает выгрузку.")
        m = UPLOAD_RX.search(sf.text)
        if m:
            ctx.add("file_upload", "info", "Загрузка файлов — ручная проверка", sf, sf.line_of(m.start()),
                    detail="тип по содержимому (magic bytes), лимит размера, запрет SVG/HTML, свои имена файлов",
                    fix="См. раздел «Загрузка файлов» чек-листа. Для Supabase Storage — политики бакета и лимиты.")
        m = PATH_FROM_NAME.search(sf.text)
        if m and "secure_filename" not in sf.text:
            ctx.add("upload_path_traversal", "warning", "Путь файла строится из имени, присланного клиентом", sf,
                    sf.line_of(m.start()), detail="имя вида ../../ выводит запись за пределы папки",
                    fix="Генерируй своё имя (uuid + разрешённое расширение), оригинальное храни только как метаданные.")


# --------------------------------------------------------------------------- Supabase / Firebase / Docker / Next

CREATE_TABLE = re.compile(r'(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?')
ENABLE_RLS = re.compile(r'(?i)\balter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security')
POLICY_RX = re.compile(r"(?is)\bcreate\s+policy\b.*?;")
FUNC_RX = re.compile(r"(?i)\bcreate\s+(?:or\s+replace\s+)?function\b")


def check_supabase(ctx: Ctx):
    if not ctx.info.get("supabase"):
        return
    sql = [sf for sf in ctx.files if sf.suffix == ".sql"]
    tables: dict[str, tuple] = {}
    rls: set[str] = set()
    for sf in sql:
        for m in CREATE_TABLE.finditer(sf.text):
            ln = sf.line_of(m.start())
            if sf.is_comment(ln):
                continue
            schema, name = (m.group(1) or "public").lower(), m.group(2).lower()
            if schema == "public":
                tables.setdefault(name, (sf, ln))
        for m in ENABLE_RLS.finditer(sf.text):
            if (m.group(1) or "public").lower() == "public":
                rls.add(m.group(2).lower())
        for m in POLICY_RX.finditer(sf.text):
            stmt = m.group(0)
            if re.search(r"(?i)\b(?:using|with\s+check)\s*\(\s*true\s*\)", stmt):
                write = re.search(r"(?i)\bfor\s+(insert|update|delete|all)\b", stmt) or not re.search(r"(?i)\bfor\s+select\b", stmt)
                ctx.add("supabase_policy_true", "warning" if write else "info",
                        "RLS-политика пропускает всех (true)" + (" на запись" if write else " на чтение"), sf,
                        sf.line_of(m.start()), detail=" ".join(stmt.split())[:140],
                        fix="true допустим только для намеренно публичного чтения. На запись — условие вида "
                            "(select auth.uid()) = user_id.")
        starts = [m.start() for m in FUNC_RX.finditer(sf.text)] + [len(sf.text)]
        for a, b in zip(starts, starts[1:]):
            chunk = sf.text[a:min(b, a + 8000)].lower()
            if "security definer" in chunk and "search_path" not in chunk:
                ctx.add("security_definer_search_path", "warning", "SECURITY DEFINER функция без set search_path", sf,
                        sf.line_of(a), detail="функция выполняется с правами владельца",
                        fix="Добавь SET search_path = '' (и полные имена схем) или откажись от security definer; "
                            "проверь, что функция сама проверяет права вызывающего.")
    for name, (sf, ln) in sorted(tables.items()):
        if name not in rls:
            ctx.add("supabase_rls_missing", "warning", "Таблица без RLS в миграциях", sf, ln,
                    detail=f"public.{name}: не найдено ENABLE ROW LEVEL SECURITY",
                    fix="ALTER TABLE ... ENABLE ROW LEVEL SECURITY + политики. Без RLS таблица читается и пишется "
                        "с anon key из браузера.")
    ctx.add("supabase_live_check", "info", "Supabase: проверь живую БД", where="Supabase Dashboard",
            detail="миграции в репо могут не совпадать с тем, что реально в проекте",
            fix="Dashboard → Advisors → Security Advisor; Storage → политики бакетов; Edge Functions → verify JWT.")


def check_firebase(ctx: Ctx):
    if not ctx.info.get("firebase"):
        return
    for sf in ctx.files:
        if sf.name in {"firestore.rules", "storage.rules", "database.rules.json"}:
            m = re.search(r"allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true|\"\.(?:read|write)\"\s*:\s*true", sf.text)
            if m:
                ctx.add("firebase_open", "critical", f"Firebase: открытые правила в {sf.name}", sf, sf.line_of(m.start()),
                        detail="доступ для всего интернета",
                        fix="Только аутентифицированным и только к своим данным: request.auth.uid == resource.data.owner.")
    ctx.add("firebase_rules", "info", "Firebase: проверь security rules в консоли", where="Firebase Console",
            detail="правила в репо могут не совпадать с задеплоенными",
            fix="Прогони firebase emulators + тесты правил; без анонимного полного доступа.")


def check_docker(ctx: Ctx):
    for sf in ctx.files:
        if not re.match(r"(docker-)?compose[\w.-]*\.ya?ml$", sf.name):
            continue
        m = re.search(r"(?i)(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*[:=]\s*"
                      r"[\"']?(postgres|root|password|admin|123\w*|example|secret|changeme)\b", sf.text)
        if m:
            ctx.add("default_db_pass", "critical", "Дефолтный пароль БД в docker-compose", sf, sf.line_of(m.start()),
                    detail=f"{m.group(1)}: {m.group(2)}", fix="Сгенерированный секрет через env, не в репозитории.")
        m = re.search(r"(?m)^\s*-\s*[\"']?(?!127\.0\.0\.1:)(?:(?:\d{1,3}\.){3}\d{1,3}:)?(5432|3306|27017|6379|9200|5984|1433)\s*:\s*\d+",
                      sf.text)
        if m:
            ctx.add("db_port_exposed", "warning", "Порт БД проброшен наружу", sf, sf.line_of(m.start()),
                    detail=f"порт {m.group(1)} слушает на всех интерфейсах",
                    fix="Не публикуй порт БД; если нужен локально — 127.0.0.1:5432:5432.")


def _vt(v: str):
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def next_version(ctx: Ctx):
    for sf in ctx.files:
        if sf.rel == "package-lock.json":
            try:
                d = json.loads(sf.text)
                v = ((d.get("packages") or {}).get("node_modules/next") or {}).get("version") \
                    or ((d.get("dependencies") or {}).get("next") or {}).get("version")
                if v:
                    return v, "package-lock.json"
            except Exception:
                pass
        if sf.rel == "pnpm-lock.yaml":
            m = re.search(r"(?m)^\s+/?next@(\d+\.\d+\.\d+)", sf.text)
            if m:
                return m.group(1), "pnpm-lock.yaml"
        if sf.rel == "yarn.lock":
            m = re.search(r'(?m)^"?next@[^\n]*:\n\s+version:?\s+"?(\d+\.\d+\.\d+)', sf.text)
            if m:
                return m.group(1), "yarn.lock"
    for sf in ctx.files:
        if sf.rel == "package.json":
            try:
                d = json.loads(sf.text)
                v = (d.get("dependencies") or {}).get("next") or (d.get("devDependencies") or {}).get("next")
                m = re.search(r"\d+\.\d+\.\d+", v or "")
                if m:
                    return m.group(0), "package.json (диапазон)"
            except Exception:
                pass
    return None, None


NEXT_MW_AFFECTED = [((11, 1, 4), (12, 3, 5)), ((13, 0, 0), (13, 5, 9)), ((14, 0, 0), (14, 2, 25)), ((15, 0, 0), (15, 2, 3))]
HEADER_CFG_RX = re.compile(r"(^|/)(next\.config\.[mc]?[jt]s|(src/)?(middleware|proxy)\.[jt]s|netlify\.toml|_headers|"
                           r"vercel\.json|[^/]+\.conf|nginx[^/]*)$")


def check_next_and_headers(ctx: Ctx):
    if ctx.info.get("next"):
        v, src = next_version(ctx)
        mw = [sf for sf in ctx.files if re.search(r"(^|/)(src/)?middleware\.[jt]s$", sf.rel)]
        if v and mw and any(lo <= _vt(v) < hi for lo, hi in NEXT_MW_AFFECTED):
            ctx.add("next_middleware_bypass", "critical" if "диапазон" not in src else "warning",
                    "Next.js с известным обходом middleware (CVE-2025-29927)", mw[0], 1,
                    detail=f"next {v} ({src}); в проекте есть middleware — её можно пропустить заголовком",
                    fix="Обнови next до последнего патча своей ветки (не ниже 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3) "
                        "и продублируй проверку прав в самих handler'ах/actions.")
    cfgs = [sf for sf in ctx.files if HEADER_CFG_RX.search(sf.rel)]
    helmet = any(re.search(r"\bhelmet\s*\(", sf.text) for sf in ctx.files if sf.suffix in JS_EXT)
    csp_found = False
    for sf in cfgs:
        for m in re.finditer(r"(?i)content-security-policy", sf.text):
            csp_found = True
        for m in re.finditer(r"(?i)script-src([^;\n`]{0,300})", sf.text):
            d = m.group(1)
            if "'unsafe-inline'" in d and not re.search(r"'nonce-|'sha(256|384|512)-|'strict-dynamic'", d):
                ctx.add("csp_unsafe_inline", "warning", "CSP с 'unsafe-inline' в script-src — не гасит инъекции", sf,
                        sf.line_of(m.start()), detail="инлайновые обработчики вроде onerror выполнятся",
                        fix="nonce/hash + 'strict-dynamic' вместо 'unsafe-inline'. Проверь запуском: инлайновый "
                            "обработчик-маркер должен давать нарушение CSP в консоли.")
            if "'unsafe-eval'" in d:
                ctx.add("csp_unsafe_eval", "info", "CSP разрешает 'unsafe-eval'", sf, sf.line_of(m.start()),
                        fix="Убери, если библиотеки позволяют (часто нужен только в dev).")
    web = any(sf.kind == "client" or sf.suffix in HTML_EXT for sf in ctx.files) or ctx.info.get("next")
    if web and not csp_found and not helmet:
        ctx.add("csp_missing", "info", "CSP не найдена в конфигурации", where="next.config / middleware / netlify.toml / _headers",
                detail="если заголовок ставит CDN/хостинг — проверь livecheck'ом",
                fix="Добавь Content-Security-Policy (nonce-based) + nosniff, HSTS, Referrer-Policy, Permissions-Policy, frame-ancestors.")


# --------------------------------------------------------------------------- зависимости

def _run_json(cmd, cwd, timeout=180):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="ignore")
    return json.loads(r.stdout or "{}")


def check_deps(ctx: Ctx, skip=False):
    root = ctx.root
    if (root / "package.json").exists():
        lock = next((n for n in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")
                     if (root / n).exists()), None)
        tool = {"package-lock.json": "npm", "pnpm-lock.yaml": "pnpm"}.get(lock or "")
        if skip:
            pass
        elif lock is None:
            ctx.add("deps_no_lock", "info", "Нет lock-файла — аудит зависимостей невозможен", where="package.json",
                    fix="npm i --package-lock-only && npm audit (и коммить lock-файл: без него сборки невоспроизводимы).")
        elif tool is None:
            cmd = {"yarn.lock": "yarn npm audit (Berry) / yarn audit (Classic)"}.get(lock, "bun audit")
            ctx.add("deps_manual", "info", "Проверь зависимости вручную", where=lock, fix=f"Запусти: {cmd}")
        else:
            exe = shutil.which(tool)  # на Windows это npm.cmd — нужен полный путь
            try:
                if not exe:
                    raise FileNotFoundError(tool)
                data = _run_json([exe, "audit", "--json"], root)
                if data.get("error"):
                    raise RuntimeError(str(data["error"])[:120])
                meta = (data.get("metadata") or {}).get("vulnerabilities") or {}
                crit, high = meta.get("critical", 0), meta.get("high", 0)
                if crit or high:
                    names = []
                    for name, v in (data.get("vulnerabilities") or {}).items():
                        if isinstance(v, dict) and v.get("severity") in ("critical", "high"):
                            names.append(name)
                    for adv in (data.get("advisories") or {}).values():
                        if isinstance(adv, dict) and adv.get("severity") in ("critical", "high"):
                            names.append(adv.get("module_name", "?"))
                    names = sorted(set(names))
                    ctx.add("deps_vulnerable", "critical" if crit else "warning", f"Уязвимые зависимости ({tool} audit)",
                            where=lock, detail=f"critical: {crit}, high: {high}; пакеты: {', '.join(names[:10]) or '—'}",
                            fix=f"{tool} audit fix; что не чинится — обнови мажорно или замени пакет. Фреймворк — до последнего патча ветки.")
            except Exception as e:
                ctx.add("deps_skip", "info", f"{tool} audit не запустился", where=lock, detail=str(e)[:120] or "нет сети или инструмента",
                        fix=f"Запусти локально: {tool} audit --audit-level=high")
    if any((root / n).exists() for n in ("requirements.txt", "pyproject.toml", "Pipfile")):
        ctx.add("py_deps", "info", "Проверь python-зависимости", where="requirements.txt / pyproject.toml",
                fix="pip install pip-audit && pip-audit")
    if any((root / n).exists() for n in ("pom.xml", "build.gradle", "build.gradle.kts", "build.sbt")):
        ctx.add("jvm_deps", "info", "Проверь JVM-зависимости", where="pom.xml / build.gradle / build.sbt",
                fix="OWASP Dependency-Check или Dependabot/Snyk; для sbt — sbt-dependency-check.")


# --------------------------------------------------------------------------- отчёт

SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}
SEV_ICON = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
BLIND_SPOTS = [
    "логику авторизации в глубину (кто что может на самом деле) — только эвристики IDOR/role;",
    "RLS и настройки в живой БД, облачных консолях, CDN и хостинге;",
    "бизнес-логику: гонки в платежах, повторное использование токенов, обход шагов процесса;",
    "работает ли существующая защита — это проверяется только запуском (references/dynamic-testing.md).",
]


def counts_of(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}


def write_report(ctx: Ctx, path: Path):
    findings = sorted(ctx.findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"], f["where"]))
    c = counts_of(findings)
    groups: dict[tuple, list] = {}
    for f in findings:
        groups.setdefault((f["severity"], f["id"], f["title"]), []).append(f)
    L = [f"# 🛡 security-audit: {ctx.root.name}", "",
         f"_Сканер v{VERSION}, {date.today().isoformat()}. Это кандидаты, найденные эвристиками: каждую находку "
         f"подтверди по коду (проследи поток данных) или отклони._", "",
         f"**Итог: {len(findings)} находок — 🔴 {c['critical']} критичных, 🟡 {c['warning']} важных, "
         f"🔵 {c['info']} на проверку**", ""]
    for note in ctx.notes:
        L.append(f"> {note}")
    if ctx.notes:
        L.append("")
    for (sev, rid, title), items in groups.items():
        L.append(f"## {SEV_ICON[sev]} {title} `[{rid}]`")
        if len(items) == 1:
            f = items[0]
            L.append(f"- Где: `{f['where']}`")
            if f["detail"]:
                L.append(f"- Детали: {f['detail']}")
        else:
            L.append(f"- Где ({len(items)}):")
            for f in items[:15]:
                L.append(f"  - `{f['where']}`" + (f" — {f['detail']}" if f["detail"] else ""))
            if len(items) > 15:
                L.append(f"  - …и ещё {len(items) - 15}")
        L.append(f"- Как чинить: {items[0]['fix']}")
        L.append("")
    if not findings:
        L += ["Сканер ничего не нашёл. Либо проект аккуратный, либо проверь, ту ли папку указал.", ""]
    L += ["## Чего сканер не видит", ""] + [f"- {b}" for b in BLIND_SPOTS] + ["",
          "Ложное срабатывание: комментарий `security-audit: ignore` на строке (или `ignore-next-line` строкой выше) "
          "либо строка в `.security-audit-ignore` — `<rule_id>`, `<glob>` или `<glob> <rule_id>`."]
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return c


# --------------------------------------------------------------------------- main

def all_rule_ids():
    ids = {r.id for r in RULES} | {p[0] for p in SECRET_PATTERNS}
    ids |= {"env_in_git", "gitignore_env", "env_in_history", "secret_in_history", "history_truncated",
            "public_env_secret", "client_api", "llm_sdk_client", "service_role_client", "ai_open_endpoint",
            "ai_no_maxtokens", "server_action_no_auth", "mutation_no_auth", "webhook_no_signature",
            "webhook_parsed_body", "ratelimit_spoofable_key", "no_ratelimit_auth", "supabase_auth_limits",
            "idor_suspect", "csv_formula_injection", "file_upload", "upload_path_traversal",
            "supabase_policy_true", "security_definer_search_path", "supabase_rls_missing", "supabase_live_check",
            "firebase_open", "firebase_rules", "default_db_pass", "db_port_exposed", "next_middleware_bypass",
            "csp_unsafe_inline", "csp_unsafe_eval", "csp_missing", "deps_no_lock", "deps_manual",
            "deps_vulnerable", "deps_skip", "py_deps", "jvm_deps"}
    return ids


def run_rules(ctx: Ctx):
    for rule in RULES:
        for sf in ctx.files:
            if not rule.applies(sf):
                continue
            n = 0
            for m in rule.rx.finditer(sf.text):
                ln = sf.line_of(m.start())
                if sf.is_comment(ln):
                    continue
                sev = "info" if (rule.downgrade_rx and rule.downgrade_rx.search(sf.text)) else rule.sev
                detail = "в файле подключён санитайзер — проверь его конфиг и версию" \
                    if (rule.downgrade_rx and sev == "info" and rule.sev != "info") else ""
                ctx.add(rule.id, sev, rule.title, sf, ln, detail=detail, fix=rule.fix)
                n += 1
                if n >= rule.max_per_file:
                    break


def main():
    _utf8()
    ap = argparse.ArgumentParser(description="security-audit: статический сканер безопасности (только чтение)")
    ap.add_argument("path", help="корень проекта")
    ap.add_argument("--report", default="security-audit-report.md", help="куда писать Markdown-отчёт")
    ap.add_argument("--json", dest="json_out", help="дополнительно сохранить находки в JSON")
    ap.add_argument("--fail-on", choices=["critical", "warning", "never"], default="warning",
                    help="с какого уровня возвращать ненулевой код (для CI)")
    ap.add_argument("--no-history", action="store_true", help="не сканировать историю git")
    ap.add_argument("--no-deps", action="store_true", help="не запускать npm/pnpm audit")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        sys.exit(f"Нет такой папки: {root}")
    ctx = Ctx(root)
    load_ignore(ctx, all_rule_ids())
    ctx.files = load_files(root)
    ctx.tracked = git_tracked(root)
    detect_project(ctx)

    checks = [check_secrets, check_git_env, check_public_env, check_client_exposure, run_rules,
              check_endpoints, check_idor, check_misc, check_supabase, check_firebase, check_docker,
              check_next_and_headers]
    if not args.no_history:
        checks.append(check_history)
    for check in checks:
        try:
            check(ctx)
        except Exception as e:  # одна упавшая проверка не должна ронять весь аудит
            ctx.add("check_error", "info", f"Проверка {check.__name__} упала", where="-", detail=str(e)[:200],
                    fix="Сообщи об ошибке в репозиторий скилла.")
    try:
        check_deps(ctx, skip=args.no_deps)
    except Exception as e:
        ctx.add("check_error", "info", "Проверка зависимостей упала", where="-", detail=str(e)[:200], fix="-")

    report = Path(args.report)
    if not report.is_absolute():
        report = Path.cwd() / report
    c = write_report(ctx, report)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"version": VERSION, "project": root.name, "counts": c,
                                                   "files_scanned": len(ctx.files), "findings": ctx.findings},
                                                  ensure_ascii=False, indent=2), encoding="utf-8")
    total = sum(c.values())
    print(f"🛡 security-audit: {total} находок (🔴 {c['critical']} / 🟡 {c['warning']} / 🔵 {c['info']}), "
          f"файлов просмотрено: {len(ctx.files)}")
    for f in [f for f in ctx.findings if f["severity"] == "critical"][:3]:
        print(f"   🔴 {f['title']} — {f['where']}")
    print(f"Отчёт: {report}")
    level = 2 if c["critical"] else (1 if c["warning"] else 0)
    if args.fail_on == "never":
        level = 0
    elif args.fail_on == "critical":
        level = 2 if c["critical"] else 0
    sys.exit(level)


def _utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


if __name__ == "__main__":
    main()
