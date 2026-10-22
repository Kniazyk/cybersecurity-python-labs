# Лабораторна робота №3, варіант 10: облік навантаження серверних ресурсів

Web API на FastAPI та SQLite (без ORM) для обліку вимірювань використання серверних ресурсів.

## Предметна область

- Категорії (`categories`): `cpu`, `memory`, `disk` (id 1, 2, 3).
- Записи (`records`): «Вимірювання сервера» з полями `code`, `title`, `category_id`, `value`, `status`.
- `value` — використання ресурсу у відсотках (`percent`), скінченне число від 0 до 100 включно.
- Поріг 80.0 — довідковий; значення понад 80 до 100 коректні.
- `status`: `new`, `in_progress`, `done`.

## Встановлення

З кореня репозиторію (потрібен Python 3.10+):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Початкове заповнення

```bash
python -m labs.lab03.seed
```

Створює таблиці та додає 3 категорії і 8 записів із `data/seed.json`. Для непорожньої бази змін не вносить.

## Запуск API

```bash
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

Документація: http://127.0.0.1:8000/docs

## Приклади запитів

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i -X POST "http://127.0.0.1:8000/records" -H "Content-Type: application/json" \
  -d '{"code":"V10-11","title":"Вимірювання сервера 11","category_id":1,"value":73.5,"status":"new"}'
curl -i -X POST "http://127.0.0.1:8000/records/bulk" -H "Content-Type: application/json" \
  -d '[{"code":"V10-12","title":"Вимірювання сервера 12","category_id":2,"value":60.0,"status":"new"}]'
```

## Перевірка стилю

```bash
ruff check labs/lab03
ruff format --check labs/lab03
```