"""CLI-утиліта для перегляду й аналізу запису CVE з NVD API або локального JSON."""

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> Any:
    """Прочитати локальний UTF-8 JSON-файл із відповіддю NVD API."""
    content = Path(path).read_text(encoding="utf-8")
    return json.loads(content)


def _validate_cve_arg(value: str) -> str:
    """Перевірити точний формат ідентифікатора CVE для аргументу --cve."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "Ідентифікатор --cve має точно відповідати шаблону CVE-YYYY-NNNN (мінімум 4 цифри)."
        )
    return value


def _build_parser() -> argparse.ArgumentParser:
    """Створити парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        description="Отримання та аналіз запису CVE з NVD API 2.0 або локального JSON-файлу."
    )
    parser.add_argument(
        "--cve",
        required=True,
        type=_validate_cve_arg,
        help="Ідентифікатор вразливості у форматі CVE-YYYY-NNNN.",
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Необов'язковий шлях до локального JSON-файлу з відповіддю NVD.",
    )
    return parser


def _is_valid_variant(variant: Any) -> bool:
    """Перевірити, що номер варіанта є цілим числом від 1 до 15 (не bool)."""
    return (
        not isinstance(variant, bool)
        and isinstance(variant, int)
        and 1 <= variant <= 15
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входу CLI; повертає код завершення (0, 1 або 2)."""
    if not _is_valid_variant(VARIANT_NUMBER):
        print(
            "Помилка конфігурації: VARIANT_NUMBER має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.input is not None:
        try:
            payload = load_response(args.input)
        except (OSError, UnicodeDecodeError):
            print(
                "Помилка читання локального JSON-файлу відповіді NVD.", file=sys.stderr
            )
            return 1
        except json.JSONDecodeError:
            print(
                "Помилка розбору JSON: локальний файл не є коректним JSON.",
                file=sys.stderr,
            )
            return 1
    else:
        try:
            payload = api_client.fetch_response(args.cve)
        except requests.exceptions.Timeout:
            print("Перевищено час очікування відповіді від NVD API.", file=sys.stderr)
            return 1
        except requests.exceptions.ConnectionError:
            print(
                "Не вдалося встановити мережеве з'єднання з NVD API.", file=sys.stderr
            )
            return 1
        except requests.exceptions.HTTPError as exc:
            status_code = (
                exc.response.status_code if exc.response is not None else "невідомо"
            )
            print(
                f"NVD API повернув HTTP-помилку зі статусом {status_code}.",
                file=sys.stderr,
            )
            return 1
        except api_client.UnexpectedStatusError as exc:
            print(
                f"NVD API повернув неочікуваний HTTP-статус {exc.status_code}.",
                file=sys.stderr,
            )
            return 1
        except json.JSONDecodeError:
            print(
                "Помилка розбору JSON: відповідь NVD API не є коректним JSON.",
                file=sys.stderr,
            )
            return 1
        except requests.exceptions.RequestException:
            print(
                "Виникла мережева помилка під час звернення до NVD API.",
                file=sys.stderr,
            )
            return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        print(f"Помилка перевірки структури даних відповіді: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
