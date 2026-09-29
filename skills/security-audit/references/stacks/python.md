# Python: Django, Flask, FastAPI

## Общее
- SQL: только параметры (`cursor.execute("... WHERE id = %s", [id])`, SQLAlchemy `text(":id")` с bind-параметрами). f-строки, `%` и `.format` в SQL — находка. Django `.raw()`/`.extra()` — проверить.
- Десериализация: `pickle`, `marshal`, `yaml.load` без `SafeLoader` на недоверенных данных дают выполнение кода.
- Команды: `subprocess` со списком аргументов, без `shell=True`; `os.system` — нет.
- Секреты: `SECRET_KEY` и ключи — из окружения; `DEBUG = False` в проде.
- Случайность для токенов — модуль `secrets`, не `random`.
- Зависимости: `pip-audit` в CI; lock (`poetry.lock`, `requirements.txt` с пинами).

## Django
- `DEBUG = False`, `ALLOWED_HOSTS` — конкретные домены.
- `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT`, `SECURE_CONTENT_TYPE_NOSNIFF`; `python manage.py check --deploy` — обязательный прогон.
- `mark_safe`, `|safe`, `{% autoescape off %}` — места, где выключено экранирование.
- `@csrf_exempt` — каждое использование обосновать (вебхуки — да, с проверкой подписи).
- DRF: `permission_classes` на каждом ViewSet, `get_queryset` фильтрует по пользователю (IDOR), сериализаторы с явным `fields` (не `__all__` на запись — mass assignment).

## Flask
- `app.run(debug=True)` в проде — это консоль Werkzeug.
- `render_template_string` с вводом — SSTI.
- Сессии Flask подписаны, но не зашифрованы: не клади туда секреты.
- CSRF — Flask-WTF/CSRFProtect; лимиты — Flask-Limiter (ключ — см. `hosting.md`).

## FastAPI
- Зависимости авторизации (`Depends(get_current_user)`) на каждом роуте, где нужны; проверка владения объектом — внутри.
- Pydantic-модели с явными полями; `extra = "forbid"` для входных моделей против mass assignment.
- CORS: `allow_origins=["*"]` вместе с `allow_credentials=True` — критично.
- Ответы при ошибках — без `str(e)` и трейсбеков; кастомный exception handler.
- Лимиты — slowapi.
