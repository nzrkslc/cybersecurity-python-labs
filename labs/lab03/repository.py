"""Шар доступу до даних SQLite з параметризованими SQL-запитами та транзакціями."""

import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

_RECORD_SELECT_SQL = """
SELECT
    r.id,
    r.code,
    r.title,
    r.category_id,
    c.name AS category_name,
    r.value,
    r.status
FROM records AS r
JOIN categories AS c ON c.id = r.category_id
"""


class NotFoundError(Exception):
    """Запитаний запис або категорія відсутні в базі даних."""


class ConflictError(Exception):
    """Порушення унікальності або посилальної цілісності даних."""


def _open_connection() -> sqlite3.Connection:
    """Відкрити з’єднання SQLite із рядковим відображенням результатів."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _ensure_category_exists(connection: sqlite3.Connection, category_id: int) -> None:
    """Перевірити існування категорії за ідентифікатором."""
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?",
        (category_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Категорію з id={category_id} не знайдено.")


def _ensure_record_exists(connection: sqlite3.Connection, record_id: int) -> None:
    """Перевірити існування запису за ідентифікатором."""
    row = connection.execute(
        "SELECT 1 FROM records WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Запис з id={record_id} не знайдено.")


def _fetch_record_by_id(
    connection: sqlite3.Connection,
    record_id: int,
) -> dict[str, Any] | None:
    """Прочитати запис із назвою категорії за ідентифікатором."""
    row = connection.execute(
        f"{_RECORD_SELECT_SQL} WHERE r.id = ?",
        (record_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def list_categories() -> list[dict[str, Any]]:
    """Повернути список усіх категорій, відсортований за зростанням id."""
    with closing(_open_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id ASC",
        ).fetchall()
        return [dict(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створити нову категорію в базі даних."""
    with closing(_open_connection()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)",
                    (name,),
                )
                category_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"Категорія з назвою '{name}' уже існує.") from exc

        row = connection.execute(
            "SELECT id, name FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()
        return dict(row)


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію за ідентифікатором."""
    with closing(_open_connection()) as connection, connection:
        _ensure_category_exists(connection, category_id)
        try:
            connection.execute(
                "DELETE FROM categories WHERE id = ?",
                (category_id,),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                f"Неможливо видалити категорію з id={category_id}, "
                "оскільки вона містить пов’язані записи."
            ) from exc


def list_records(
    *,
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Отримати список записів із фільтрацією, сортуванням за id та пагінацією."""
    clauses: list[str] = []
    params: list[Any] = []

    if category_id is not None:
        clauses.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        clauses.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        clauses.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        clauses.append("instr(r.title, ?) > 0")
        params.append(q)

    where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"{_RECORD_SELECT_SQL}{where_sql} ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(_open_connection()) as connection:
        rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def get_record_by_id(record_id: int) -> dict[str, Any]:
    """Отримати один запис за його ідентифікатором."""
    with closing(_open_connection()) as connection:
        record = _fetch_record_by_id(connection, record_id)
        if record is None:
            raise NotFoundError(f"Запис з id={record_id} не знайдено.")
        return record


def create_record(
    *,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict[str, Any]:
    """Створити один запис знахідки аудиту."""
    with closing(_open_connection()) as connection:
        try:
            with connection:
                _ensure_category_exists(connection, category_id)
                cursor = connection.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (code, title, category_id, value, status),
                )
                record_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"Запис із кодом '{code}' уже існує.") from exc

        record = _fetch_record_by_id(connection, record_id)
        if record is None:
            raise NotFoundError(f"Запис з id={record_id} не знайдено.")
        return record


def replace_record(
    record_id: int,
    *,
    code: str,
    title: str,
    category_id: int,
    value: float,
    status: str,
) -> dict[str, Any]:
    """Повністю оновити змінювані поля запису зі збереженням id."""
    with closing(_open_connection()) as connection:
        try:
            with connection:
                _ensure_record_exists(connection, record_id)
                _ensure_category_exists(connection, category_id)
                connection.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (code, title, category_id, value, status, record_id),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(f"Запис із кодом '{code}' уже існує.") from exc

        record = _fetch_record_by_id(connection, record_id)
        if record is None:
            raise NotFoundError(f"Запис з id={record_id} не знайдено.")
        return record


def delete_record(record_id: int) -> None:
    """Видалити запис за його ідентифікатором."""
    with closing(_open_connection()) as connection, connection:
        _ensure_record_exists(connection, record_id)
        connection.execute(
            "DELETE FROM records WHERE id = ?",
            (record_id,),
        )


def create_records_bulk(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Атомарно створити пакет записів у межах однієї транзакції."""
    if not items:
        return []

    created_ids: list[int] = []
    with closing(_open_connection()) as connection:
        with connection:
            for item in items:
                _ensure_category_exists(connection, item["category_id"])
                try:
                    cursor = connection.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item["code"],
                            item["title"],
                            item["category_id"],
                            item["value"],
                            item["status"],
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError(
                        f"Запис із кодом '{item['code']}' дублює наявний або "
                        "попередній запис у пакеті."
                    ) from exc
                created_ids.append(int(cursor.lastrowid))

        placeholders = ", ".join("?" for _ in created_ids)
        rows = connection.execute(
            f"{_RECORD_SELECT_SQL} WHERE r.id IN ({placeholders}) ORDER BY r.id ASC",
            created_ids,
        ).fetchall()
        return [dict(row) for row in rows]
