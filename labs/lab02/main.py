"""Головний CLI-модуль для запуску Завдання 1 (demo) та Завдання 2 (analyze)."""

import argparse
import sys

from labs.lab02.task1 import run_demo
from labs.lab02.task2 import run_analysis


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Лабораторна робота №2: Консольні утиліти для кібербезпеки (Варіант 13)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Доступні команди")

    # Підкоманда demo (Завдання 1)
    subparsers.add_parser("demo", help="Запустити демонстрацію ООП моделі (Завдання 1)")

    # Підкоманда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser(
        "analyze", help="Запустити CLI-сканер PII витоків (Завдання 2)"
    )
    analyze_parser.add_argument(
        "--scan-dir",
        type=str,
        default="labs/lab02/data/data_v13",
        help="Шлях до директорії сканування",
    )
    analyze_parser.add_argument(
        "--patterns",
        type=str,
        choices=["all", "cards", "emails", "phones", "ips"],
        default="all",
        help="Тип конфіденційних даних для пошуку",
    )
    analyze_parser.add_argument(
        "--no-mask",
        action="store_false",
        dest="mask",
        help="Вимкнути маскування PII у виводі",
    )
    analyze_parser.add_argument(
        "--out-json",
        type=str,
        default="labs/lab02/data/pii_scan_summary.json",
        help="Шлях до JSON файлу з результатами",
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analysis(
            scan_dir=args.scan_dir,
            patterns=args.patterns,
            mask=args.mask,
            out_json=args.out_json,
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
