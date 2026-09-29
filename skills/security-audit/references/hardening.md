# Что оставить после себя

Отчёт описывает один день. Чтобы защита не развалилась молча, после отчёта предложи четыре вещи и делай их только после подтверждения пользователя.

## 1. Регрессионные тесты на каждую находку
Критерий полезности один: **тест падает, если защиту убрали**. Перед сдачей проверь это руками — временно закомментируй защиту и убедись, что тест покраснел. Тест, который зелёный в обоих случаях, бесполезен.

Используй тестовый стек проекта (vitest/jest, Playwright, pytest). Примеры:

**Экранирование в письме (vitest):**
```ts
import { renderContactEmail } from '@/lib/email'
it('экранирует ввод в HTML письма', () => {
  const html = renderContactEmail({ name: '<b>audit-marker</b> " \' &' })
  expect(html).not.toContain('<b>audit-marker</b>')
  expect(html).toContain('&lt;b&gt;audit-marker&lt;/b&gt;')
})
```

**Rate limit не обходится подменой заголовка (route handler напрямую):**
```ts
import { POST } from '@/app/api/contact/route'
const req = (ip: string) => new Request('http://localhost/api/contact', {
  method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
  body: JSON.stringify({ name: 'audit-marker', email: 'a@example.com', message: 'x' }) })
it('лимит не сбрасывается сменой X-Forwarded-For', async () => {
  const codes = []
  for (let i = 0; i < 7; i++) codes.push((await POST(req(`10.0.0.${i}`))).status)
  expect(codes.slice(-2)).toEqual([429, 429])
})
```
Если лимитер во внешнем хранилище (Upstash/Redis), в тесте используй его in-memory вариант или мок с тем же ключом.

**IDOR — два пользователя:**
```ts
it('B не читает заказ A', async () => {
  const order = await createOrderAs(userA)
  const res = await getOrderAs(userB, order.id)
  expect([403, 404]).toContain(res.status)
})
```
Для Supabase — тест на RLS: два клиента с JWT разных пользователей (`supabase start` локально), select/update чужой строки возвращает пусто или ошибку.

**CSP гасит инлайновый обработчик (Playwright):**
```ts
test('CSP блокирует inline-обработчик', async ({ page }) => {
  const logs: string[] = []
  page.on('console', m => logs.push(m.text()))
  await page.goto('/')
  await page.evaluate(() => document.body.insertAdjacentHTML('beforeend',
    '<img src="/nonexistent.png" onerror="console.log(\'csp-audit-marker\')">'))
  await page.waitForTimeout(500)
  expect(logs.join('\n')).not.toContain('csp-audit-marker')
})
```
Гоняй на прод-сборке (`next build && next start` в `webServer` конфига Playwright).

**Серверная цена:** тест, что заказ с подменённой ценой в теле создаётся по цене из БД.

## 2. CI на каждое изменение
Шаблон — `assets/github-workflow.yml` (линтер, типы, тесты, `npm audit --audit-level=high`, сканер этого скилла с `--fail-on critical`). Положи его в `.github/workflows/security.yml` и подстрой команды под `package.json`.

**Ловушка хостинга.** Сборка на Netlify/Vercel/Cloudflare Pages запускает только build-команду (`next build`) — тесты там не выполняются никогда. Проверь это явно:
- открой build command в настройках хостинга или в `netlify.toml` (`[build] command = ...`);
- если там только сборка — либо CI в GitHub + защита ветки (Settings → Branches → Require status checks), либо build command `npm run lint && npm test && npm run build`. Первый вариант лучше: быстрее и не блокирует деплой хотфиксов.

Запиши в отчёт, что именно запускается на хостинге. Это наблюдаемый факт, а не предположение.

## 3. Слежение за зависимостями
- Шаблон — `assets/dependabot.yml` → `.github/dependabot.yml`.
- **Включи граф зависимостей**: Settings → Security → Code security → Dependency graph, затем Dependabot alerts и Dependabot security updates. Пока граф выключен, оповещения об уязвимостях часто не приходят, даже если dependabot.yml лежит в репо.
- Проверь, что lock-файл закоммичен: без него аудит зависимостей не работает.
- Для Python — `pip-audit` в CI; для JVM — OWASP Dependency-Check или Dependabot для Maven/Gradle.

## 4. Доверенные данные — в файл инструкций проекта
Добавь в `CLAUDE.md` / `AGENTS.md` (или создай) раздел. Он защищает от того, что следующий человек или агент подключит внешний источник туда, где это сломает весь расчёт:

```markdown
## Доверенные и недоверенные данные

Недоверенные (всегда валидировать на сервере и экранировать при выводе):
- всё из запроса: body, query, path-параметры, заголовки (включая X-Forwarded-For), cookies;
- данные вебхуков до проверки подписи;
- ответы внешних API и LLM — как пользовательский ввод;
- содержимое загруженных файлов.

Доверенные (и почему):
- сессия/пользователь — только из <auth()/supabase.auth.getUser()> на сервере, не из тела запроса;
- цены, скидки, комиссии — только из таблицы <prices>, клиент присылает id;
- IP для лимитов — только из <context.ip / x-nf-client-connection-ip>, а не из X-Forwarded-For;
- статус оплаты — только из проверенного вебхука <stripe>, не из redirect-параметров.

Правила:
- service_role / секретные ключи — только в серверном коде и edge-функциях, никогда с NEXT_PUBLIC_;
- каждая новая таблица Supabase — сразу с RLS и политиками на select/insert/update/delete;
- каждая server action и route handler сами проверяют сессию и права на объект, middleware — не единственная защита;
- защиты, покрытые тестами (не ломать): <список из раздела «Защищено» отчёта>.
```
Заполни угловые скобки реальными именами из проекта.
