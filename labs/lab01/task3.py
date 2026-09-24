"""Завдання 3: Хешування, CSV-база та JSON-логування (Варіант 13)."""

import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Налаштування шляхів та констант варіанта 13
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CSV_FILE_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_FILE_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 14  # Варіант 13
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)  # "00013"


class ValidationError(Exception):
    """Власний виняток для валідації довжини пароля."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш sha3_256 для конкатенації пароля та солі."""
    if password is None or password == "" or salt is None or salt == "":
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий! Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    salted = password + salt
    return hashlib.sha3_256(salted.encode("utf-8")).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з персональною сіллю."""
    pwd_hash = generate_hash(password, salt=PERSONAL_SALT)
    return username, pwd_hash


def create_users(users_list: list[tuple[str, str]]) -> bool:
    """Записує список користувачів у файл CSV з локальною обробкою винятків."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            for username, password in users_list:
                u_name, p_hash = create_user(username, password)
                writer.writerow([u_name, p_hash])
        return True
    except PermissionError as err:
        print(f"[create_users] Помилка прав доступу при створенні CSV: {err}")
    except OSError as err:
        print(f"[create_users] Помилка вводу/виводу при записі в CSV: {err}")
    return False


def read_users_db(verbose: bool = True) -> list[tuple[str, str]]:
    """Зчитує користувачів з CSV з дотриманням пріоритету винятків."""
    users_db: list[tuple[str, str]] = []

    try:
        with open(CSV_FILE_PATH, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # Пропуск заголовка
            for row in reader:
                if row:
                    users_db.append((row[0], row[1]))

        if verbose:
            print(f"{'Логін':<20} | {'Хеш пароля (SHA3-256)'}")
            print("-" * 79)
            for u_name, u_hash in users_db:
                print(f"{u_name:<20} | {u_hash}")

    except FileNotFoundError as err:
        print(f"[read_users_db] Файл бази не знайдено: {err}")
    except PermissionError as err:
        print(f"[read_users_db] Відмовлено в доступі до файлу бази: {err}")
    except OSError as err:
        print(f"[read_users_db] Системна помилка вводу/виводу: {err}")

    return users_db


def log_event(func):
    """Декоратор для безпечного логування спроб автентифікації у JSON-файл."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if len(args) > 0 else kwargs.get("username", "unknown")
        result = "failure"
        try:
            success = func(*args, **kwargs)
            result = "success" if success else "failure"
            return success
        except Exception:
            result = "failure"
            raise
        finally:
            # Маскування чутливих даних (CWE-532)
            sanitized_args = []
            for idx, arg in enumerate(args):
                if idx == 1:
                    sanitized_args.append("********")
                elif isinstance(arg, list):
                    sanitized_args.append(f"<users_db: {len(arg)} records>")
                else:
                    sanitized_args.append(str(arg))

            sanitized_kwargs = {
                k: ("********" if "pass" in k.lower() else str(v))
                for k, v in kwargs.items()
            }

            log_entry = {
                "event": "login",
                "user": str(username),
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": sanitized_args,
                "kwargs": sanitized_kwargs,
            }

            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                existing_logs = []
                if os.path.exists(LOG_FILE_PATH):
                    try:
                        with open(LOG_FILE_PATH, mode="r", encoding="utf-8") as jf:
                            existing_logs = json.load(jf)
                    except (json.JSONDecodeError, OSError):
                        existing_logs = []

                existing_logs.append(log_entry)
                with open(LOG_FILE_PATH, mode="w", encoding="utf-8") as jf:
                    json.dump(existing_logs, jf, indent=4, ensure_ascii=False)

            except PermissionError as log_err:
                print(f"[log_event] Немає прав для запису логу: {log_err}")
            except OSError as log_err:
                print(f"[log_event] Помилка файлової системи при логуванні: {log_err}")

    return wrapper


@log_event
def login(
    username: str,
    password: str,
    users_db: list[tuple[str, str]] | None = None,
) -> bool:
    """Автентифікує користувача, перевіряючи відповідність соленого хешу."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми")

    if users_db is None:
        users_db = read_users_db(verbose=False)

    try:
        calculated_hash = generate_hash(password, salt=PERSONAL_SALT)
    except ValidationError:
        return False

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == calculated_hash:
            return True
    return False


def run_task3() -> None:
    """Головна точка демонстрації: не містить низькорівневих файлових try-except."""
    print("=" * 79)
    print(f"Завдання 3 | Студент: {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    print(
        f"Алгоритм: SHA3-256 | Сіль: {PERSONAL_SALT} | Мін. довжина: {MIN_PASSWORD_LENGTH}"
    )
    print("=" * 79)

    users_to_register = (
        ("admin_sec", "SuperStr0ngP@ssw0rd!14"),
        ("ai_researcher", "Compli4nc3#Ch3ck2026"),
        ("ml_lead", "M@chineLe@rningSec99"),
        ("data_custodian", "BigD@taProtection#2026"),
        ("threat_analyst", "Adv3rsari@lT3st!Key1"),
        ("cloud_gate", "Cl0udDef3nse#SecSystem"),
        ("soc_watcher", "SOCM0nit0ring@Safe99"),
        ("devops_spec", "Pip3lineSecur3#Pass12"),
        ("crypto_user", "Qu@ntumCryptoSafe2026"),
        ("audit_officer", "Fin@lCompliance!Report"),
    )

    print("\n1. Створення бази користувачів у CSV...")
    if create_users(list(users_to_register)):
        print("База успішно створена.")

    print("\n2. Зчитування та відображення бази:")
    users_db = read_users_db(verbose=True)

    print("\n3. Тестування автентифікації та логування подій:")

    # Успішний вхід
    u1, p1 = "ai_researcher", "Compli4nc3#Ch3ck2026"
    res1 = login(u1, p1, users_db)
    print(f"Вхід '{u1}': {'УСПІХ' if res1 else 'ВІДМОВА'}")

    # Невірний пароль
    u2, p2 = "ai_researcher", "WrongPasswordHere!12"
    res2 = login(u2, p2, users_db)
    print(f"Вхід '{u2}' (невірний пароль): {'УСПІХ' if res2 else 'ВІДМОВА'}")

    # Неіснуючий користувач
    u3, p3 = "unknown_user", "SomeVeryLongPassword123!"
    res3 = login(u3, p3)
    print(f"Вхід '{u3}': {'УСПІХ' if res3 else 'ВІДМОВА'}")

    # Демонстрація перехоплення винятків бізнес-логіки (валідація даних)
    print("\n4. Демонстрація перехоплення винятків валідації:")
    try:
        generate_hash("short", PERSONAL_SALT)
    except ValidationError as e:
        print(f"  [Перехоплено ValidationError]: {e}")

    try:
        generate_hash("", PERSONAL_SALT)
    except ValueError as e:
        print(f"  [Перехоплено ValueError]: {e}")

    print(f"\nЖурнал логів оновлено у: {LOG_FILE_PATH}")
    print("=" * 79 + "\n")


if __name__ == "__main__":
    run_task3()
