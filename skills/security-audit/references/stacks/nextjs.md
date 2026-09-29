# Next.js

## Где что искать
- **Route handlers:** `app/**/route.ts` — каждый экспорт `GET/POST/PUT/PATCH/DELETE` это публичный HTTP-эндпоинт.
- **Server actions:** файлы с `'use server'` и инлайновые `'use server'` внутри функций. Любую action можно вызвать напрямую POST-запросом с её id, минуя UI. Проверка сессии и прав на объект нужна **внутри каждой action**.
- **Pages Router:** `pages/api/**` — то же, что route handlers; `getServerSideProps` — серверный код.
- **Middleware:** `middleware.ts` (в Next 16 — `proxy.ts`). Это удобный фильтр, но **не единственная защита**: `matcher` легко промахивается мимо нового маршрута, а в прошлом существовал обход целиком (ниже).
- **Server Components** по умолчанию серверные: `process.env.SECRET` там безопасен, пока значение не уходит в props клиентского компонента. Проверь, что в props `'use client'`-компонентов не передаются целые объекты из БД с лишними полями.

## Известные уязвимости фреймворка
- **CVE-2025-29927 — обход middleware** заголовком `x-middleware-subrequest`. Затронуты 11.1.4–15.2.2, исправлено в 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3. Сканер ловит это по lock-файлу.
- **CVE-2025-55182 — RCE в React Server Components** (декабрь 2025, критическая). Затрагивает App Router на React 19 и Next.js 15/16. После неё выходили дополнительные патчи. Правило: `next`, `react`, `react-dom` — на последнем патче своей ветки; `npm audit` не должен показывать critical/high по ним.
- Общее правило: не держи фреймворк на версии, которой больше пары месяцев без патчей.

## Секреты и бандл
- `NEXT_PUBLIC_*` вшивается в клиентский JS при сборке. Публичными по задумке бывают anon/publishable ключи, site key капчи, DSN Sentry. Всё остальное — без префикса.
- После сборки проверь бандл: `grep -rE "sk_live|sk-|service_role|re_[A-Za-z0-9]" .next/static` — должно быть пусто.
- `productionBrowserSourceMaps: true` публикует исходники фронтенда.

## Заголовки и CSP
- Заголовки задаются в `next.config.js` → `headers()` или в middleware. Для строгой CSP с nonce используй middleware: генерируй nonce на запрос, отдавай `script-src 'self' 'nonce-…' 'strict-dynamic'`; Next подставит nonce в свои скрипты. Страницы с nonce рендерятся динамически.
- Если CSP ставит хостинг (`netlify.toml`, `_headers`), проверь, что она не конфликтует с заголовками из Next и что итоговый заголовок один.
- Минимум: `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'self'`, плюс `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`, `Permissions-Policy`.

## Конфиг
- `experimental.serverActions.allowedOrigins` / `serverActions.allowedOrigins` — без `*`.
- `images.remotePatterns` — конкретные хосты, не `**`; `dangerouslyAllowSVG` — только вместе с `contentSecurityPolicy` и `contentDispositionType: 'attachment'`.

## Частые ошибки вывода
- JSON-LD: `<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />` — если в `data` есть пользовательский текст, строка `</script>` выйдет из тега. Лечится: `JSON.stringify(data).replace(/</g, '\\u003c')`.
- `generateMetadata` с пользовательскими данными — React экранирует, но проверь OpenGraph-изображения, которые генерируются из текста.
- `redirect(searchParams.get('next'))` — open redirect; разрешай только пути, начинающиеся с `/` и не с `//`.
- `revalidatePath`/`revalidateTag` в публичном эндпоинте без секрета — любой может сбрасывать кэш (DoS по стоимости).

## Ошибки
В проде Next скрывает детали ошибок Server Components, но **твой** `return NextResponse.json({ error: err.message })` уйдёт как есть. Клиенту — общий текст, детали — в лог.
