"""Завдання 1: Комплексний аналізатор надійності паролів (Варіант 13)."""

import os
import random
import string
import sys

# Додавання кореня проекту до sys.path для імпорту shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанта 13
PASSWORDS = [
    "Compli4nc3@Check",
    "weak",
    "Risk@Ass3ssment",
    "guest",
    "Vulner4bility@Scan",
    "temp",
    "P3netration@Test",
    "demo",
    "S3curity@Audit",
    "trial",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"weak", "guest", "temp", "demo", "trial", "password"}
SPECIAL_CHARS = set(string.punctuation)


def evaluate_password(password: str, all_passwords: list[str]) -> str:
    """Оцінює надійність пароля за визначеними критеріями безпеки."""
    min_length = CRITERIA["min_length"]

    # 1. Заборонений
    if password in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_special = any(c in SPECIAL_CHARS for c in password)
    has_lower = any(c.islower() for c in password)

    satisfies_all_groups = (
        has_digit
        and has_upper
        and has_special
        and (not CRITERIA.get("require_lower", False) or has_lower)
    )

    satisfies_any_group = has_digit or has_upper or has_special or has_lower

    # 2. Перевірка на сильність
    if satisfies_all_groups:
        is_unique = all_passwords.count(password) == 1
        if len(password) >= min_length + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    # 3. Середній: достатня довжина та часткове виконання груп
    if len(password) >= min_length and satisfies_any_group:
        return "Середній"

    # 4. Слабкий
    if satisfies_any_group:
        return "Слабкий"

    return "Заборонений"


def run_task1() -> None:
    """Виконує аналіз паролів та виводить звіт у вигляді таблиці."""
    print("=" * 79)
    print(f"Завдання 1 | Студент: {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    print("=" * 79)

    passwords_list = PASSWORDS.copy()

    # Генерація 3 випадкових повторів
    random.seed(VARIANT_NUMBER)  # Фіксація для стабільності демонстрації
    random_indices = [random.randint(0, len(passwords_list) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords_list.append(passwords_list[idx])

    print(
        f"Початкова кількість: {len(PASSWORDS)}, з дублікатами: {len(passwords_list)}\n"
    )
    print(f"{'№':<4} | {'Пароль':<24} | {'Довжина':<8} | {'Оцінка надійності'}")
    print("-" * 79)

    for i, pwd in enumerate(passwords_list, 1):
        status = evaluate_password(pwd, passwords_list)
        print(f"{i:<4} | {pwd:<24} | {len(pwd):<8} | {status}")
    print("=" * 79 + "\n")


if __name__ == "__main__":
    run_task1()
