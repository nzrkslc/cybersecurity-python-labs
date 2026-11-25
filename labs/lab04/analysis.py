"""Перевірка структури відповіді NVD API та аналіз за правилом варіанта."""

import math
from typing import Any

ALLOWED_CVSS_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}


def _contract_error(message: str) -> ValueError:
    """Створити виняток ValueError для порушення контракту вхідних даних."""
    return ValueError(message)


def _require_dict(value: Any, field_name: str) -> dict[str, Any]:
    """Перевірити, що значення є словником."""
    if not isinstance(value, dict):
        raise _contract_error(f"Поле '{field_name}' має бути словником.")
    return value


def _require_list(value: Any, field_name: str) -> list[Any]:
    """Перевірити, що значення є списком."""
    if not isinstance(value, list):
        raise _contract_error(f"Поле '{field_name}' має бути списком.")
    return value


def _require_non_empty_str(value: Any, field_name: str) -> str:
    """Перевірити, що значення є непорожнім рядком."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле '{field_name}' має бути непорожнім рядком.")
    return value


def _extract_optional_non_empty_str(
    container: dict[str, Any], key: str, field_name: str
) -> str | None:
    """Отримати необов'язковий непорожній рядок або None, якщо ключ відсутній."""
    if key not in container:
        return None
    return _require_non_empty_str(container[key], field_name)


def _extract_english_description(cve: dict[str, Any]) -> str | None:
    """Перевірити descriptions та повернути перший непорожній опис англійською."""
    if "descriptions" not in cve:
        return None
    descriptions = _require_list(cve["descriptions"], "cve.descriptions")

    first_english: str | None = None
    for entry in descriptions:
        item = _require_dict(entry, "cve.descriptions[]")
        if "lang" not in item or not isinstance(item["lang"], str):
            raise ValueError(
                "Елемент 'cve.descriptions' має містити рядкове поле 'lang'."
            )
        if "value" not in item or not isinstance(item["value"], str):
            raise ValueError(
                "Елемент 'cve.descriptions' має містити рядкове поле 'value'."
            )
        if first_english is None and item["lang"] == "en" and item["value"].strip():
            first_english = item["value"]
    return first_english


def _select_cvss_v31_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибрати метрику CVSS v3.1 (пріоритет Primary, інакше перша) або повернути None."""
    if "metrics" not in cve:
        return None
    metrics = _require_dict(cve["metrics"], "cve.metrics")
    if "cvssMetricV31" not in metrics:
        return None
    metric_list = _require_list(metrics["cvssMetricV31"], "cve.metrics.cvssMetricV31")
    if not metric_list:
        return None

    validated_items = [_require_dict(item, "cvssMetricV31[]") for item in metric_list]
    for item in validated_items:
        if item.get("type") == "Primary":
            return item
    return validated_items[0]


def _validate_base_score(value: Any) -> float:
    """Перевірити, що baseScore є скінченним числом у діапазоні 0..10 (не bool)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _contract_error("Поле 'cvssData.baseScore' має бути числом.")
    if not math.isfinite(value) or value < 0 or value > 10:
        raise ValueError("Поле 'cvssData.baseScore' має бути в межах від 0 до 10.")
    return float(value)


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевірити відповідь NVD API та витягти нормалізований внутрішній запис.

    Формат внутрішнього запису (``dict``) або ``None``, якщо запис не знайдено:
    - ``vuln_status`` (``str | None``): статус вразливості з ``cve.vulnStatus``.
    - ``description`` (``str | None``): перший непорожній англійський опис.
    - ``cvss_version`` (``str | None``): версія CVSS (``"3.1"``) або ``None``.
    - ``score`` (``float | None``): базова оцінка CVSS v3.1 або ``None``.
    - ``score_source`` (``str | None``): джерело вибраної оцінки або ``None``.
    - ``vector`` (``str | None``): вектор CVSS або ``None``.
    - ``cvss_data`` (``dict[str, Any] | None``): копія ``cvssData`` вибраної оцінки або ``None``.
    """
    _require_non_empty_str(cve_id, "cve_id")
    root = _require_dict(payload, "payload")

    if "vulnerabilities" not in root:
        raise ValueError("Поле 'vulnerabilities' має бути списком.")
    vulnerabilities = _require_list(root["vulnerabilities"], "vulnerabilities")
    if len(vulnerabilities) > 1:
        raise ValueError("Очікується не більше одного елемента у 'vulnerabilities'.")
    if not vulnerabilities:
        return None

    wrapper = _require_dict(vulnerabilities[0], "vulnerabilities[0]")
    cve = _require_dict(wrapper.get("cve"), "vulnerabilities[0].cve")
    if cve.get("id") != cve_id:
        raise ValueError("Ідентифікатор 'cve.id' не збігається із запитаним CVE.")

    vuln_status = _extract_optional_non_empty_str(cve, "vulnStatus", "cve.vulnStatus")
    description = _extract_english_description(cve)

    base_record: dict[str, Any] = {
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": None,
    }

    if vuln_status is None or vuln_status == "Rejected":
        return base_record

    selected_metric = _select_cvss_v31_metric(cve)
    if selected_metric is None:
        return base_record

    cvss_data = _require_dict(selected_metric.get("cvssData"), "cvssData")

    score = _validate_base_score(cvss_data.get("baseScore"))
    cvss_version = _extract_optional_non_empty_str(
        cvss_data, "version", "cvssData.version"
    )
    if cvss_version is not None and cvss_version != "3.1":
        raise ValueError("Поле 'cvssData.version' має дорівнювати '3.1'.")

    vector = _extract_optional_non_empty_str(
        cvss_data, "vectorString", "cvssData.vectorString"
    )
    score_source = _extract_optional_non_empty_str(selected_metric, "source", "source")

    return {
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": cvss_version,
        "score": score,
        "score_source": score_source,
        "vector": vector,
        "cvss_data": dict(cvss_data),
    }


def _validate_variant(variant: Any) -> int:
    """Перевірити, що номер варіанта є цілим числом від 1 до 15 (не bool)."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not (1 <= variant <= 15)
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")
    return variant


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосувати правило варіанта до внутрішнього запису та сформувати словник звіту."""
    _require_non_empty_str(cve_id, "cve_id")
    validated_variant = _validate_variant(variant)
    rule = dict(VARIANT_RULES[validated_variant])

    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": validated_variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return report

    validated_record = _require_dict(record, "record")

    vuln_status = validated_record.get("vuln_status")
    description = validated_record.get("description")
    report["description"] = description
    report["vuln_status"] = vuln_status

    if vuln_status == "Rejected":
        report["decision"] = "rejected"
        return report

    if vuln_status is None:
        report["decision"] = "insufficient_data"
        return report

    raw_cvss_data = validated_record.get("cvss_data")
    score = validated_record.get("score")
    if raw_cvss_data is None or score is None:
        report["decision"] = "insufficient_data"
        return report

    cvss_data = _require_dict(raw_cvss_data, "record.cvss_data")

    report["cvss_version"] = validated_record.get("cvss_version")
    report["score"] = score
    report["score_source"] = validated_record.get("score_source")
    report["vector"] = validated_record.get("vector")

    field_name = rule["field"]
    if field_name not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss_data[field_name]
    allowed_values = ALLOWED_CVSS_VALUES[field_name]
    if not isinstance(observed, str) or observed not in allowed_values:
        raise ValueError(f"Недопустиме значення поля '{field_name}' у cvssData.")

    report["observed"] = observed
    if score >= rule["threshold"] and observed == rule["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
