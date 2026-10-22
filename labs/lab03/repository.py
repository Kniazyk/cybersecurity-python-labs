"""Параметризовані SQL-запити (без залежності від FastAPI)."""

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager

from .database import get_connection

logger = logging.getLogger(__name__)

RECORD_SELECT = (
    "SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name, "
    "r.value, r.status "
    "FROM records AS r "
    "JOIN categories AS c ON c.id = r.category_id"
)


class RepositoryError(Exception):
    """Базова помилка шару доступу до даних."""


class NotFoundError(RepositoryError):
    """Запис або категорію не знайдено."""


class ConflictError(RepositoryError):
    """Дублікат значення або заборонене видалення."""


class ConstraintError(RepositoryError):
    """Дані порушують інші обмеження бази."""


class DatabaseError(RepositoryError):
    """Технічна помилка бази даних."""


def _integrity_to_error(error: sqlite3.IntegrityError) -> RepositoryError:
    message = str(error)
    if "records.code" in message:
        return ConflictError("Запис із таким code вже існує")
    if "categories.name" in message:
        return ConflictError("Категорія з такою назвою вже існує")
    if "FOREIGN KEY" in message:
        return ConflictError("Операція порушує зв’язок категорії із записами")
    return ConstraintError("Дані порушують обмеження бази даних")


@contextmanager
def _translate_errors() -> Iterator[None]:
    """Перетворити помилки sqlite3 на власні винятки без технічних деталей."""
    try:
        yield
    except sqlite3.IntegrityError as error:
        logger.warning("Порушення обмеження SQLite: %s", error)
        raise _integrity_to_error(error) from error
    except sqlite3.Error as error:
        logger.exception("Технічна помилка SQLite")
        raise DatabaseError("Помилка роботи з базою даних") from error


@contextmanager
def _read_connection() -> Iterator[sqlite3.Connection]:
    """З’єднання для читання; завжди закривається."""
    with _translate_errors(), closing(get_connection()) as connection:
        connection.row_factory = sqlite3.Row
        yield connection


@contextmanager
def _write_connection() -> Iterator[sqlite3.Connection]:
    """З’єднання із транзакцією: commit за успіху, rollback за винятку."""
    with _read_connection() as connection, connection:
        yield connection


def _require_category(connection: sqlite3.Connection, category_id: int) -> None:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("Категорію не знайдено")


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> dict | None:
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    return dict(row) if row is not None else None


def _require_record(connection: sqlite3.Connection, record_id: int) -> dict:
    record = _fetch_record(connection, record_id)
    if record is None:
        raise NotFoundError("Запис не знайдено")
    return record


def _insert_record(
    connection: sqlite3.Connection,
    *,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> int:
    cursor = connection.execute(
        "INSERT INTO records (code, title, category_id, value, status) "
        "VALUES (?, ?, ?, ?, ?)",
        (code, title, category_id, value, status),
    )
    return int(cursor.lastrowid)


# ---------- Категорії ----------


def create_category(name: str) -> dict:
    """Створити категорію."""
    with _write_connection() as connection:
        cursor = connection.execute("INSERT INTO categories (name) VALUES (?)", (name,))
        return {"id": cursor.lastrowid, "name": name}


def list_categories() -> list[dict]:
    """Повернути категорії за зростанням id."""
    with _read_connection() as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with _write_connection() as connection:
        _require_category(connection, category_id)
        used = connection.execute(
            "SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)
        ).fetchone()[0]
        if used:
            raise ConflictError("Категорія містить записи, її не можна видалити")
        connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))


# ---------- Записи ----------


def create_record(
    *, code: str, title: str, category_id: int, value: float, status: str
) -> dict:
    """Створити запис і повернути його разом із category_name."""
    with _write_connection() as connection:
        _require_category(connection, category_id)
        record_id = _insert_record(
            connection,
            code=code,
            title=title,
            category_id=category_id,
            value=value,
            status=status,
        )
        return _require_record(connection, record_id)


def get_record(record_id: int) -> dict:
    """Отримати запис за id."""
    with _read_connection() as connection:
        return _require_record(connection, record_id)


def list_records(
    *,
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Список записів: фільтри через AND, сортування за id."""
    conditions: list[str] = []
    params: list[object] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = RECORD_SELECT
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _read_connection() as connection:
        rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]


def update_record(
    record_id: int,
    *,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict:
    """Повністю замінити змінювані поля; id не змінюється."""
    with _write_connection() as connection:
        _require_record(connection, record_id)
        _require_category(connection, category_id)
        connection.execute(
            "UPDATE records SET code = ?, title = ?, category_id = ?, "
            "value = ?, status = ? WHERE id = ?",
            (code, title, category_id, value, status, record_id),
        )
        return _require_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис."""
    with _write_connection() as connection:
        _require_record(connection, record_id)
        connection.execute("DELETE FROM records WHERE id = ?", (record_id,))


def create_records_bulk(records: list[dict]) -> list[dict]:
    """Додати пакет записів в одній транзакції (все або нічого)."""
    with _write_connection() as connection:
        for category_id in sorted({item["category_id"] for item in records}):
            _require_category(connection, category_id)
        new_ids = [_insert_record(connection, **item) for item in records]
        return [_require_record(connection, record_id) for record_id in new_ids]


# ---------- Початкове заповнення ----------


def seed_if_empty(categories: list[dict], records: list[dict]) -> bool:
    """Додати початкові дані в одній транзакції, якщо база порожня."""
    with _write_connection() as connection:
        total = connection.execute(
            "SELECT (SELECT COUNT(*) FROM categories) + (SELECT COUNT(*) FROM records)"
        ).fetchone()[0]
        if total:
            return False
        for category in categories:
            connection.execute(
                "INSERT INTO categories (id, name) VALUES (?, ?)",
                (category["id"], category["name"]),
            )
        for record in records:
            _insert_record(connection, **record)
        return True
