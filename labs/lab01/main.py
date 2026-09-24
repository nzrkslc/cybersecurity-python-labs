"""Головний модуль запуску Лабораторної роботи №1."""

import os
import sys

# Додаємо корінь проекту до sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import run_task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main() -> None:
    """Запускає демонстрацію всіх трьох завдань лабораторної роботи."""
    print("#" * 79)
    print(f"# Лабораторна робота №1 | Варіант {VARIANT_NUMBER}")
    print(f"# Студент: {STUDENT_NAME} | Група: {GROUP_NAME}")
    print("#" * 79 + "\n")

    run_task1()
    run_task2()
    run_task3()

    print("Всі завдання виконано успішно.")


if __name__ == "__main__":
    main()
