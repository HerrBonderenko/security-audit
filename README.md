# security-audit

Два скилла для Claude (Claude Code и claude.ai), один набор правил для всех проектов:

- **security-audit** — аудит безопасности веб-проекта: от быстрой проверки перед деплоем до полного аудита уровня senior AppSec с отчётом, риском и исправлениями;
- **launch-checklist** — готовность сайта к запуску: редиректы, честные 404, robots/sitemap/canonical, метатеги и превью ссылок, иконки, производительность, аналитика, Impressum и cookie-согласие. Блок безопасности отдаёт в security-audit.

Внутри security-audit:
- **методика** — разведка, 15 разделов чек-листа, проверка защиты запуском, риск «вероятность × влияние», отчёт `SECURITY_AUDIT_REPORT.md`, тесты и CI после аудита;
- **сканер** `audit.py` — статический поиск кандидатов без зависимостей (Python 3.9+), работает и на Windows;
- **livecheck** `livecheck.py` — пассивная проверка заголовков и утечек своего задеплоенного сайта;
- **справочники по стеку**: Next.js, Supabase, Netlify/Cloudflare/Vercel, платежи, почта и уведомления, Python, JVM.

## Источники

| Источник | Что взято |
|---|---|
| [vibe-audit](https://github.com/haraldalder-vibemogger/vibe-audit) (ika.explains, MIT) | идея скилла, сканер и livecheck как основа, принципы «секреты не цитировать», «проблема → фикс», подтверждение владения доменом |
| ТЗ на аудит веб-приложения | роль и контекст инцидента, этап 0, чек-лист 5.1–5.13 с критериями достаточной защиты, методика риска, формат отчёта, критерии готовности |
| Методика «проверять запуском, а не чтением» | главный принцип, раздел «Не проверено», блок «что оставить после себя»: тесты, CI, Dependabot, доверенные данные |
| Чек-лист перед деплоем (инфраструктура, SEO, шеринг, производительность, аналитика) | основа launch-checklist; пункты о безопасности перенесены в security-audit. Исправлены неточности: «закрыть админку в robots.txt» не защищает и подсказывает пути, `Disallow` конфликтует с `noindex`, Яндекс.Вебмастер не нужен для украинской и европейской аудитории, `X-Frame-Options` заменён `frame-ancestors`. Добавлены Impressum/Datenschutz, cookie-согласие до загрузки трекеров, Google Fonts со своего домена, мягкий 404 при стриминге в Next.js |

Противоречия между источниками решены так:

| Конфликт | Решение |
|---|---|
| «Только код» (ТЗ) и «запусти и проверь» | сначала статика, затем проверка запуском **локально**; «Защищено» — только при наблюдаемом результате, иначе «Не проверено» |
| «Не трогай прод» и livecheck по живому домену | livecheck — только по явной просьбе, только свой домен, только пассивные GET, с подтверждением владения |
| «Не меняй код» и «оставь тесты и CI» | тесты и CI предлагаются после отчёта и делаются после подтверждения |
| Уровни 🔴🟡🔵 сканера и риск 1–25 из ТЗ | severity сканера — предварительная сортировка кандидатов; итоговая оценка — только по методике риска |
| «Ничего исполняемого» и проверка CSP обработчиком `onerror` | единственный исполняемый маркер: пишет строку в консоль, только на localhost |

## Что исправлено и добавлено относительно vibe-audit

Проблемы находились тестами, каждая закрыта регрессионным тестом в `tests/test_audit.py`:

- проект внутри папки `build/`, `dist/` или `vendor/` сканировался как пустой: пропуск папок проверял абсолютный путь;
- `NEXT_PUBLIC_SUPABASE_ANON_KEY` и `STRIPE_PUBLISHABLE_KEY` давали ложные critical — теперь есть список «публичных по задумке», а серверные ключи с публичным префиксом ловятся;
- Next.js App Router был не виден: route handlers, server actions, «серверный по умолчанию» компонент без `'use client'`;
- добавлено: секреты в **истории git** (или через gitleaks), когда-то закоммиченный `.env`; SQL через шаблонные строки в JS; XSS-синки; IDOR; mass assignment; rate limit по подделываемому заголовку; вебхуки без подписи; адресат письма из запроса; RLS, `using (true)` и `security definer` в миграциях Supabase; CSP с `unsafe-inline`; обход middleware Next.js (CVE-2025-29927) по lock-файлу; инъекции в GitHub Actions; `pnpm audit`;
- Windows: `npm.cmd` находится корректно, вывод в UTF-8;
- ложные срабатывания гасятся: `security-audit: ignore` в строке или файл `.security-audit-ignore`;
- `--json` и `--fail-on` для CI.

launchcheck проверен на настоящей прод-сборке Next.js 16: дефолтный шаблон даёт 4 предупреждения (нет robots, sitemap, canonical, Open Graph), правильно настроенный сайт проходит чисто.

Сканер проверен на реальных репозиториях `vercel/nextjs-subscription-payments` и `vercel/ai-chatbot`: 0,7 и 2,3 секунды соответственно, все предупреждения по делу. Среди них — устаревший Next.js с middleware, `security definer` без `search_path` и server action, отдающая данные по чужому id.

## Установка

### Claude Code (глобально, для всех проектов) — Windows, Git Bash
```bash
git clone https://github.com/HerrBonderenko/security-audit.git
mkdir -p ~/.claude/skills
cp -r security-audit/skills/* ~/.claude/skills/
```
Обновление: `cd security-audit && git pull && cp -r skills/* ~/.claude/skills/`.

Только для одного проекта — положи папки в `<проект>/.claude/skills/`.

### claude.ai
Собери архивы (`python build.py`) и загрузи `dist/security-audit.zip` и `dist/launch-checklist.zip` в настройках, в разделе Skills. Файлы `.skill` — те же архивы, их можно открыть прямо в чате.

### Другие агенты с поддержкой Agent Skills
Скопируй папку `skills/security-audit` в их каталог скиллов — формат стандартный (`SKILL.md` + ресурсы).

## Использование

Просто попроси:
- «проверь безопасность перед деплоем» — быстрая проверка: сканер, подтверждение находок, чек-лист;
- «проведи полный аудит безопасности» — этапы 0–5, отчёт `SECURITY_AUDIT_REPORT.md`;
- «проверь заголовки на моём сайте https://…» — livecheck (спросит подтверждение владения);
- «проверь сайт перед запуском» / «почему не индексируется» / «не показывается превью ссылки» — launch-checklist.

Сканер можно запускать и напрямую:
```bash
python ~/.claude/skills/security-audit/scripts/audit.py .                        # отчёт security-audit-report.md
python ~/.claude/skills/security-audit/scripts/audit.py . --json out.json --fail-on critical
python ~/.claude/skills/security-audit/scripts/livecheck.py https://мой-сайт
python ~/.claude/skills/launch-checklist/scripts/launchcheck.py http://localhost:3000   # после npm run build && npm run start
```
Коды выхода: 2 — есть critical, 1 — есть warning, 0 — чисто.

### CI в своих проектах
Скопируй `skills/security-audit/assets/github-workflow.yml` → `.github/workflows/security.yml`, а `assets/dependabot.yml` → `.github/dependabot.yml`. В workflow сканер скачивается по зафиксированному тегу — после публикации репозитория поставь тег `v2.0.0` (`git tag v2.0.0 && git push --tags`).

## Структура
```
skills/security-audit/
├── SKILL.md                       # принципы, режимы, этапы аудита
├── checklist.md                   # чек-лист перед деплоем
├── scripts/
│   ├── audit.py                   # статический сканер
│   └── livecheck.py               # проверка своего домена
├── references/
│   ├── audit-checklist.md         # 15 разделов: что искать и когда защиты достаточно
│   ├── dynamic-testing.md         # рецепты проверки запуском
│   ├── risk-and-report.md         # методика риска и формат отчёта
│   ├── hardening.md               # тесты, CI, Dependabot, доверенные данные
│   └── stacks/                    # nextjs, supabase, hosting, payments, email-notifications, python, jvm
└── assets/
    ├── report-template.md
    ├── github-workflow.yml
    └── dependabot.yml
skills/launch-checklist/
├── SKILL.md                       # порядок проверки, блокеры запуска, частые неточности
├── scripts/launchcheck.py         # проверка прод-сборки или своего домена (только GET)
└── references/
    ├── checklist.md               # 8 разделов: сервер, SEO, шеринг, CWV, безопасность, аналитика, право, после запуска
    └── nextjs.md                  # готовые решения для Next.js 16 (metadata, robots.ts, sitemap.ts, manifest, 404…)
tests/                             # регрессионные тесты сканера, livecheck и launchcheck
build.py                           # сборка dist/<скилл>.zip и .skill
```

## Разработка
```bash
python -m unittest discover -s tests -p "test_*.py"   # все тесты (фикстуры собираются во временной папке)
python build.py                 # пересобрать архивы
```
CI гоняет тесты на Ubuntu и Windows, Python 3.9 и 3.12. Новое правило сканера добавляется в `RULES` в `audit.py` вместе с тестом: одна фикстура, где правило срабатывает, и проверка, что оно молчит на нормальном коде (`TestCleanProject`).

## Ограничения
Это структурированный аудит силами ИИ и эвристический сканер, а не пентест и не гарантия. Логику доступа в глубину, живую БД и настройки облачных консолей сканер не видит — для этого методика и проверка запуском. Для прода с деньгами и персональными данными стоит хотя бы раз позвать живого специалиста.

## Лицензия
MIT. Copyright (c) 2026 ika.explains (vibe-audit), (c) 2026 Oleg Bondarenko.
