import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any

# Налаштування формату логування
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("PIIScanner")

# Регулярні вирази для пошуку PII
REGEX_EMAIL = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
REGEX_CARD = r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
REGEX_PHONE = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
REGEX_IPV4 = r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"


def mask_pii(text: str, pii_type: str) -> str:
    """Маскує знайдені конфіденційні дані для безпечного показу."""
    if pii_type == "Credit Card Numbers":
        digits = re.sub(r"\D", "", text)
        if len(digits) == 16:
            return f"{digits[:4]}-****-****-{digits[-4:]}"
        return "****-****-****-****"
    if pii_type == "Email Addresses":
        parts = text.split("@")
        if len(parts) == 2 and len(parts[0]) > 2:
            return f"{parts[0][0]}****{parts[0][-1]}@{parts[1]}"
        return "u****r@example.com"
    if pii_type == "Phone Numbers":
        return re.sub(r"\d", "*", text[:-4]) + text[-4:]
    if pii_type == "IPv4 Addresses":
        octets = text.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.{octets[1]}.*.*"
    return "*****"


def scan_pii_in_directory(
    target_dir: Path, pattern_type: str = "all", mask_output: bool = True
) -> dict[str, Any]:
    """Рекурсивно сканує каталоги та файли на наявність PII."""
    if not target_dir.exists() or not target_dir.is_dir():
        raise FileNotFoundError(f"Каталог не знайдено: {target_dir}")

    logger.info(f"Scanning directory {target_dir} for unmasked PII data...")

    patterns = {}
    if pattern_type in ("all", "emails"):
        patterns["Email Addresses"] = REGEX_EMAIL
    if pattern_type in ("all", "cards"):
        patterns["Credit Card Numbers"] = REGEX_CARD
    if pattern_type in ("all", "phones"):
        patterns["Phone Numbers"] = REGEX_PHONE
    if pattern_type in ("all", "ips"):
        patterns["IPv4 Addresses"] = REGEX_IPV4

    counter: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    scanned_files_count = 0

    for file_path in target_dir.rglob("*"):
        if file_path.is_file() and not file_path.name.startswith("."):
            scanned_files_count += 1
            try:
                with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                    for line_idx, line in enumerate(f, 1):
                        for label, pii_regex in patterns.items():
                            matches = re.findall(pii_regex, line)
                            for match in matches:
                                counter[label] += 1
                                display_val = (
                                    mask_pii(match, label) if mask_output else match
                                )
                                findings.append(
                                    {
                                        "file": str(file_path),
                                        "line": line_idx,
                                        "type": label,
                                        "value": display_val,
                                    }
                                )
            except (OSError, UnicodeError) as e:
                logger.warning(f"Не вдалося прочитати файл {file_path}: {e}")

    logger.info(f"Scanned {scanned_files_count} files.")

    return {
        "scanned_files": scanned_files_count,
        "summary": dict(counter),
        "findings": findings,
    }


def print_formatted_report(results: dict[str, Any]) -> None:
    """Форматує та виводить результати сканування у консоль."""
    summary = results.get("summary", {})
    findings = results.get("findings", [])

    print("\n=== Detected Sensitive Data (PII) ===")
    print(f"Email Addresses    : {summary.get('Email Addresses', 0)} matches")
    print(f"Credit Card Numbers: {summary.get('Credit Card Numbers', 0)} matches")
    print(f"Phone Numbers      : {summary.get('Phone Numbers', 0)} matches")
    print(f"IPv4 Addresses     : {summary.get('IPv4 Addresses', 0)} matches")

    print("\n=== Sample Findings (Masked for Display) ===")
    for finding in findings[:5]:
        print(
            f"[PII FOUND] File: {finding['file']} (Line {finding['line']})\n"
            f"  Type : {finding['type']}\n"
            f"  Value: {finding['value']}"
        )

    if any(summary.values()):
        logger.warning("Unmasked PII found in plaintext logs!")


def run_analysis(
    scan_dir: str,
    patterns: str = "all",
    mask: bool = True,
    out_json: str | None = None,
) -> None:
    """Точка входу для проведення аналізу PII."""
    target_path = Path(scan_dir)
    results = scan_pii_in_directory(
        target_path, pattern_type=patterns, mask_output=mask
    )

    print_formatted_report(results)

    if out_json:
        out_path = Path(out_json)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            logger.info(f"Sanitized report saved to {out_path}")
        except OSError as e:
            logger.error(f"Не вдалося зберегти звіт у файл {out_path}: {e}")
