# Java / Kotlin / Scala

## Инъекции
- JDBC: `PreparedStatement` с `?`; конкатенация в `Statement.execute*` или `createNativeQuery` — находка. JPA/JPQL — именованные параметры.
- Scala: Doobie `sql"..."`/`fr"..."` и Slick `sql"..."` параметризуют сами; `s"SELECT ... $x"` в `executeQuery`, `Fragment.const(userInput)` — находка.
- Динамические `ORDER BY`/колонки — whitelist.
- XML: парсеры с отключёнными DTD/внешними сущностями (XXE): `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- Шаблоны: Thymeleaf `th:utext`, FreeMarker `?no_esc` — сырой вывод.

## Десериализация
- `ObjectInputStream` на недоверенных данных — RCE-класс уязвимостей.
- Jackson: без `enableDefaultTyping`/`activateDefaultTyping` на недоверенном вводе; полиморфизм — только с явным whitelist подтипов.

## Spring
- Spring Security: `authorizeHttpRequests` с явными правилами и `anyRequest().authenticated()` в конце; `@PreAuthorize` на методах сервисов для проверки владения.
- CSRF включён для cookie-сессий; отключение (`csrf().disable()`) обосновать (чистый stateless API с Bearer-токенами).
- Actuator: наружу только `health`; `env`, `heapdump`, `configprops` раскрывают секреты.
- `@CrossOrigin("*")` вместе с credentials — критично.
- Mass assignment: входные DTO вместо entity в `@RequestBody`.

## Play / http4s / Akka HTTP
- Проверка аутентификации — в каждом action/route (Play `SecuredAction`, http4s `AuthMiddleware`), а не только в UI.
- Play CSRF filter и headers filter (CSP, nosniff) включены; `play.filters.hosts.allowed` — конкретные домены.
- http4s: CORS middleware с явным списком origin; лимит размера тела (`EntityLimiter`).

## Прочее
- Секреты — из окружения или vault, не в `application.conf`/`application.yml` в репо.
- Логи: без паролей и токенов в `toString()` DTO (Lombok `@ToString.Exclude`, case class с переопределённым `toString`).
- Зависимости: OWASP Dependency-Check (Maven/Gradle), `sbt-dependency-check`, Dependabot для Maven/Gradle.
