# Next.js (App Router): как закрыть пункты чек-листа

Проверено на Next.js 16. Отличия от 15 отмечены.

## Базовые метаданные — `app/layout.tsx`
```tsx
import type { Metadata } from 'next'

const SITE = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://mershiy.com'

export const metadata: Metadata = {
  metadataBase: new URL(SITE),                  // все относительные URL (canonical, og:image) станут абсолютными
  title: { default: 'МЕРЩІЙ — майстри для дому', template: '%s — МЕРЩІЙ' },
  description: 'Перевірені майстри для ремонту та побутових послуг…',
  alternates: { canonical: '/' },
  openGraph: { type: 'website', locale: 'uk_UA', siteName: 'МЕРЩІЙ', images: ['/og.png'] },
  twitter: { card: 'summary_large_image' },
  robots: process.env.SITE_ENV === 'production' ? undefined : { index: false, follow: false },
}
```
`SITE_ENV` задай в переменных хостинга для каждого окружения: `production` только для прода. Альтернатива — встроенные переменные платформы (у Netlify — `CONTEXT`, у Vercel — `VERCEL_ENV`), но своя переменная надёжнее при смене хостинга.

## Метаданные страницы — `generateMetadata`
```tsx
export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params                  // Next 15+: params — Promise
  const master = await getMaster(slug)
  if (!master) notFound()
  return {
    title: `${master.name}, ${master.city}`,
    description: master.about.slice(0, 155),
    alternates: { canonical: `/masters/${slug}` },
    openGraph: { images: [master.photoUrl] },
  }
}
```

## Мультиязычность — hreflang
```tsx
alternates: {
  canonical: `/uk/${path}`,
  languages: { uk: `/uk/${path}`, de: `/de/${path}`, en: `/en/${path}`, 'x-default': `/uk/${path}` },
}
```
Тот же набор — на **каждой** языковой версии, включая ссылку на саму себя. `<html lang>` — из параметра локали в `app/[lang]/layout.tsx`.

## robots.txt — `app/robots.ts`
```ts
import type { MetadataRoute } from 'next'
export default function robots(): MetadataRoute.Robots {
  if (process.env.SITE_ENV !== 'production') return { rules: { userAgent: '*', disallow: '/' } }
  return {
    rules: { userAgent: '*', allow: '/' },
    sitemap: `${process.env.NEXT_PUBLIC_SITE_URL}/sitemap.xml`,
  }
}
```
Админку и кабинет сюда не вписывай: они закрываются `robots: { index: false }` в их layout и авторизацией.

## sitemap.xml — `app/sitemap.ts`
```ts
import type { MetadataRoute } from 'next'
export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const base = process.env.NEXT_PUBLIC_SITE_URL!
  const masters = await getPublicMasters()       // только публичные, опубликованные
  return [
    { url: `${base}/`, changeFrequency: 'daily', priority: 1 },
    ...masters.map(m => ({ url: `${base}/masters/${m.slug}`, lastModified: m.updatedAt })),
  ]
}
```
Больше 50 000 URL — `generateSitemaps()`. Мультиязычный сайт — поле `alternates.languages` у записей.

## Иконки и manifest — файловые соглашения
- `app/favicon.ico`, `app/icon.png` или `app/icon.svg`, `app/apple-icon.png` (180×180) — Next сам добавит `<link>`.
- `app/manifest.ts`:
```ts
import type { MetadataRoute } from 'next'
export default function manifest(): MetadataRoute.Manifest {
  return { name: 'МЕРЩІЙ', short_name: 'МЕРЩІЙ', start_url: '/', display: 'standalone', theme_color: '#111111',
    background_color: '#ffffff', icons: [{ src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }] }
}
```
- OG-картинка: `app/opengraph-image.png` (1200×630) или генерация в `opengraph-image.tsx` через `ImageResponse` из `next/og` — можно на уровне сегмента (своя картинка для страницы мастера).

## 404 и ошибки
- `app/not-found.tsx` — своя страница; `notFound()` в странице или `generateMetadata` отдаёт 404.
- Вызывай `notFound()` **до** стриминга: в самой странице или в `generateMetadata`, а не в компоненте под `Suspense`. Иначе ответ уже ушёл со статусом 200, и Next только добавит `noindex`. `launchcheck.py` это ловит.
- `app/error.tsx` (обязательно `'use client'`) и `app/global-error.tsx` — без `error.message` и стека на экране; `error.digest` можно показать как номер обращения.

## Редиректы и слеш
```ts
// next.config.ts
const config = {
  trailingSlash: false,                          // одна форма URL; вторая получит 308
  async redirects() {
    return [{ source: '/old-services/:slug', destination: '/services/:slug', permanent: true }]  // 308
  },
}
```
`permanent: true` отдаёт 308 — поисковики считают его равным 301. Редирект `www` ↔ без `www` и HTTP → HTTPS делай на уровне хостинга или Cloudflare, а не в Next.

## noindex для превью
Заголовок на всё, если это не прод:
```ts
async headers() {
  return process.env.SITE_ENV === 'production' ? [] :
    [{ source: '/:path*', headers: [{ key: 'X-Robots-Tag', value: 'noindex, nofollow' }] }]
}
```

## JSON-LD
```tsx
export function JsonLd({ data }: { data: Record<string, unknown> }) {
  return <script type="application/ld+json"
    dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\\u003c') }} />
}
// <JsonLd data={{ '@context': 'https://schema.org', '@type': 'Organization', name: 'МЕРЩІЙ', url: SITE, logo: `${SITE}/logo.png` }} />
```
`.replace(/</g, '\\u003c')` обязателен, если в данных есть пользовательский текст (имена, отзывы) — иначе `</script>` из данных выйдет из тега.

## Картинки и шрифты
```tsx
import Image from 'next/image'
<Image src={hero} alt="…" preload sizes="100vw" />   // LCP-картинка; в Next ≤ 15 — priority
<Image src={m.photoUrl} alt={m.name} width={320} height={320} />
```
```ts
import { Inter } from 'next/font/google'          // скачивается при сборке, раздаётся со своего домена
const inter = Inter({ subsets: ['latin', 'cyrillic'], display: 'swap' })
```
Удалённые картинки — `images.remotePatterns` с конкретными хостами (например, домен Supabase Storage).

## Сторонние скрипты
```tsx
import Script from 'next/script'
<Script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX" strategy="afterInteractive" />
```
Для ЕС — грузить только после согласия (условный рендер по состоянию consent) и настроить Consent Mode v2. Или `@next/third-parties/google` + consent-баннер.

## Middleware → proxy (Next 16)
В Next 16 файл `middleware.ts` переименован в `proxy.ts` (codemod: `npx @next/codemod@canary middleware-to-proxy .`). Для чек-листа это важно только тем, что редиректы и заголовки могут жить там — ищи в обоих местах.
