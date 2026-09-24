"""Завдання 2: Багаторівнева система контролю доступу (Варіант 13)."""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для Варіанта 13
USERS = {
    "ai_security_expert": {
        "role": "ai_security",
        "clearance": 4,
        "department": "AI Security",
        "active": True,
    },
    "ml_engineer": {
        "role": "ml_engineer",
        "clearance": 3,
        "department": "Machine Learning",
        "active": True,
    },
    "data_engineer": {
        "role": "data_engineer",
        "clearance": 2,
        "department": "Data Engineering",
        "active": True,
    },
    "research_assistant": {
        "role": "researcher",
        "clearance": 2,
        "department": "Research",
        "active": True,
    },
    "training_bot": {
        "role": "bot_account",
        "clearance": 1,
        "department": "Automation",
        "active": False,
    },
}

RESOURCES = [
    ("ai_models", 4),
    ("training_datasets", 3),
    ("data_pipelines", 2),
    ("research_notebooks", 2),
    ("model_artifacts", 4),
    ("synthetic_data", 1),
    ("adversarial_tests", 3),
    ("model_registry", 4),
    ("feature_stores", 2),
    ("public_models", 1),
]

SECURITY_LEVELS = (
    "Open Source",
    "Internal Research",
    "Proprietary",
    "Trade Secret",
)

BLOCKED_USERS = {"training_bot", "model_theft", "data_poisoning_acc"}


def check_access(username: str, resource_name: str, res_level: int) -> str:
    """Перевіряє доступ конкретного користувача до ресурсу за алгоритмом."""
    if username not in USERS:
        return "DENY (User not found)"

    if username in BLOCKED_USERS:
        return "DENY (User is blocked)"

    user = USERS[username]
    if not user.get("active", False):
        return "DENY (Account inactive)"

    if user.get("clearance", 0) >= res_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


def run_task2() -> None:
    """Виконує симуляцію контролю доступу."""
    print("=" * 79)
    print(f"Завдання 2 | Студент: {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    print("=" * 79)

    print("Список зареєстрованих ресурсів системи:")
    for res_name, lvl in RESOURCES:
        lvl_name = SECURITY_LEVELS[lvl - 1]
        print(f"  - {res_name:<22} -> Рівень: {lvl} ({lvl_name})")

    print("\nРезультати перевірки доступу:")
    print("-" * 79)

    # Список користувачів для перевірки (включаючи стороннього тестового)
    test_users = list(USERS.keys()) + ["unregistered_user"]

    for username in test_users:
        for res_name, res_lvl in RESOURCES:
            verdict = check_access(username, res_name, res_lvl)
            print(f"user={username:<20} resource={res_name:<20} -> {verdict}")
    print("=" * 79 + "\n")


if __name__ == "__main__":
    run_task2()
