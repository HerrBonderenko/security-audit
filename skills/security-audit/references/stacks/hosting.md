# Хостинг: Netlify, Cloudflare, Vercel

## Откуда брать IP клиента для rate limit
Это главный вопрос раздела. Рецепт проверки — `dynamic-testing.md`, раздел 3.

| Где работает код | Надёжный источник IP | Ненадёжно |
|---|---|---|
| Netlify Functions / Edge Functions | `context.ip`, заголовок `x-nf-client-connection-ip` | сырой `X-Forwarded-For`, `X-Real-IP` |
| Cloudflare Workers / Pages Functions | `CF-Connecting-IP` (его выставляет сам Cloudflare) | `X-Forwarded-For` |
| Vercel | `ipAddress(request)` из `@vercel/functions` (Vercel сам выставляет заголовки на своём edge) | заголовки, если перед Vercel стоит ещё один прокси |
| Свой сервер за nginx | `X-Real-IP`, который выставляет **nginx** (`proxy_set_header X-Real-IP $remote_addr`), и `trust proxy` = число прокси | `app.set('trust proxy', true)` |

**Cloudflare перед Netlify/Vercel** (домен проксируется через Cloudflare, сайт хостится на Netlify):
- платформа увидит IP Cloudflare, а не клиента — лимит по `context.ip` станет общим на всех;
- `CF-Connecting-IP` можно подделать, если origin доступен напрямую (`*.netlify.app`, `*.vercel.app`) — атакующий пойдёт мимо Cloudflare со своим заголовком;
- варианты: лимит на уровне Cloudflare (WAF → Rate limiting rules); или Cloudflare добавляет секретный заголовок (Transform Rules), приложение принимает `CF-Connecting-IP` только вместе с ним; плюс закрыть прямой доступ к origin-домену.

Для лимитов по аккаунту IP не нужен: ключуй по `user.id` из проверенной сессии — это надёжнее.

## Заголовки безопасности
- Netlify: `netlify.toml` → `[[headers]]` или файл `_headers` в папке публикации.
- Cloudflare Pages: `_headers`; для Workers — выставляются в коде ответа. Transform Rules могут добавлять заголовки на уровне зоны.
- Vercel: `vercel.json` → `headers`, либо `next.config.js`.
- Если заголовки задаются в двух местах (Next и хостинг), проверь итог в браузере или через `curl -sI`: иногда приходит две CSP, и браузер применяет обе — самую строгую комбинацию, что ломает сайт, — или не приходит ни одной.

## Ловушка: сборка не запускает тесты
Build command хостинга — обычно `next build` или `npm run build`. Тесты при деплое не выполняются. Проверь в UI (Site configuration → Build & deploy) или в `netlify.toml` (`[build] command`). Решение — CI в GitHub с защитой ветки (`hardening.md`).

## Переменные окружения
- Netlify: у переменной есть **scopes** (Builds / Functions / Runtime / Post processing) и **deploy contexts** (Production / Deploy Previews / Branch deploys). Боевые ключи — только Production; превью — тестовые.
- Vercel: Production / Preview / Development — то же правило.
- Переменная, нужная только функциям, не должна быть в scope Builds: иначе её легко случайно вшить в бандл.
- Deploy previews — публичные URL. Если там незавершённые функции или тестовые данные, включи защиту паролем или ограничь доступ.

## Функции
- Логи функций (Netlify → Logs → Functions) — это место, где видны атаки. Проверь, что туда пишутся отклонённые запросы и не пишутся пароли и токены.
- Таймауты и лимиты памяти ограничивают DoS, но не расходы на AI: за вызовы LLM платишь ты, а не хостинг.
- Scheduled functions и фоновые задачи не должны быть доступны по публичному URL без секрета.

## Cloudflare
- SSL/TLS режим **Full (strict)**. Flexible означает, что от Cloudflare до origin трафик идёт по HTTP.
- Bot Fight Mode / Turnstile на формах — дешёвая защита от ботов из инцидента на 16-й секунде.
- WAF managed rules ловят типовые SQLi/XSS-пробы, но это страховка, а не замена экранированию.
