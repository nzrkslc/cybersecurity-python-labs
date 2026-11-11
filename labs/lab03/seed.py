"""Початкове заповнення бази даних SQLite навчальними даними з JSON."""

import json
import logging
import sqlite3
import sys
from contextlib import closing

from pydantic import ValidationError

from labs.lab03.database import BASE_DIR, get_connection, initialize_database
from labs.lab03.schemas import SeedData

SEED_PATH = BASE_DIR / "data" / "seed.json"
logger = logging.getLogger(__name__)


def seed_database() -> bool:
    """Ініціалізувати схему та виконати початкове заповнення бази даних."""
    try:
        initialize_database()
        raw_text = SEED_PATH.read_text(encoding="utf-8")
        raw_data = json.loads(raw_text)
        payload = SeedData.model_validate(raw_data)
    except OSError as exc:
        logger.error("Не вдалося прочитати файл початкових даних: %s", exc)
        print("Помилка читання початкових даних JSON.")
        return False
    except json.JSONDecodeError as exc:
        logger.error("Некоректний синтаксис JSON у файлі %s: %s", SEED_PATH.name, exc)
        print("Помилка: файл seed.json містить некоректний JSON.")
        return False
    except ValidationError as exc:
        logger.error("Помилка валідації seed.json: %s", exc)
        print("Помилка: початкові дані не відповідають вимогам моделі варіанта.")
        return False
    except sqlite3.Error as exc:
        logger.error("Помилка ініціалізації бази даних: %s", exc)
        print("Помилка ініціалізації схеми бази даних.")
        return False

    try:
        with closing(get_connection()) as connection:
            categories_count = connection.execute(
                "SELECT COUNT(*) FROM categories",
            ).fetchone()[0]
            records_count = connection.execute(
                "SELECT COUNT(*) FROM records",
            ).fetchone()[0]

            if categories_count > 0 or records_count > 0:
                print(
                    "База даних уже містить дані "
                    f"(категорій: {categories_count}, записів: {records_count}). "
                    "Повторне заповнення пропущено без змін."
                )
                return True

            with connection:
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(cat.id, cat.name) for cat in payload.categories],
                )
                connection.executemany(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (rec.code, rec.title, rec.category_id, rec.value, rec.status)
                        for rec in payload.records
                    ],
                )

            print(
                f"Базу даних успішно заповнено: додано {len(payload.categories)} "
                f"категорії та {len(payload.records)} записів."
            )
            return True
    except sqlite3.IntegrityError as exc:
        logger.error("Порушення обмежень під час заповнення бази: %s", exc)
        print(
            "Помилка цілісності даних під час заповнення бази. Усі зміни транзакції скасовано."
        )
        return False
    except sqlite3.Error as exc:
        logger.error("Помилка SQLite під час початкового заповнення: %s", exc)
        print("Помилка роботи з базою даних під час заповнення. Зміни скасовано.")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(0 if seed_database() else 1)
