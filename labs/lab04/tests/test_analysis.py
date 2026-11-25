"""Модульні тести перевірки даних і правила Варіанта 13 (labs.lab04.analysis)."""

import copy
from typing import Any

import pytest

from labs.lab04.analysis import build_report, extract_record

VARIANT = 13
CVE_ID = "CVE-2099-10001"


def _with_cvss_changes(
    payload: dict[str, Any],
    *,
    base_score: Any = 9.8,
    integrity_impact: Any = "HIGH",
) -> dict[str, Any]:
    """Змінити лише baseScore та integrityImpact у копії синтетичного payload."""
    cvss_data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    cvss_data["baseScore"] = base_score
    cvss_data["integrityImpact"] = integrity_impact
    return payload


def test_synthetic_sample_gives_other_for_variant_13(
    sample_payload: dict[str, Any],
) -> None:
    """Спільний синтетичний файл має integrityImpact=HIGH, тому для варіанта 13 дає other."""
    original = copy.deepcopy(sample_payload)
    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert sample_payload == original
    assert report == {
        "cve_id": CVE_ID,
        "variant": 13,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {
            "threshold": 6.0,
            "field": "integrityImpact",
            "expected": "LOW",
        },
        "observed": "HIGH",
        "decision": "other",
    }


@pytest.mark.parametrize(
    ("score", "impact", "expected_decision"),
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (6.1, "LOW", "review"),
        (9.8, "LOW", "review"),
        (9.8, "HIGH", "other"),
        (9.8, "NONE", "other"),
    ],
)
def test_variant_13_threshold_and_field_decisions(
    sample_payload: dict[str, Any],
    score: float,
    impact: str,
    expected_decision: str,
) -> None:
    """Перевірка межі порога (5.9, 6.0, 6.1) та відповідності integrityImpact."""
    modified = _with_cvss_changes(
        sample_payload, base_score=score, integrity_impact=impact
    )
    record = extract_record(modified, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == expected_decision
    assert report["score"] == score
    assert report["observed"] == impact


def test_not_found_empty_vulnerabilities(sample_payload: dict[str, Any]) -> None:
    """Порожній список vulnerabilities формує стан not_found з null-полями запису."""
    sample_payload["vulnerabilities"] = []
    record = extract_record(sample_payload, CVE_ID)
    assert record is None

    report = build_report(record, CVE_ID, VARIANT)
    assert report == {
        "cve_id": CVE_ID,
        "variant": 13,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": 6.0,
            "field": "integrityImpact",
            "expected": "LOW",
        },
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_status_skips_metrics_analysis(sample_payload: dict[str, Any]) -> None:
    """Статус Rejected дає decision=rejected без аналізу навіть високої оцінки."""
    _with_cvss_changes(sample_payload, base_score=9.8, integrity_impact="LOW")
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cve["vulnStatus"] = "Rejected"
    cve["metrics"] = {"cvssMetricV31": "invalid-when-rejected"}

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None
    assert report["cvss_version"] is None
    assert report["score_source"] is None
    assert report["vector"] is None


def test_missing_vuln_status_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Відсутній vulnStatus формує insufficient_data без аналізу оцінок."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    del cve["vulnStatus"]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize("mode", ["no_metrics", "no_v31", "empty_v31"])
def test_missing_cvss_v31_gives_insufficient_data(
    sample_payload: dict[str, Any], mode: str
) -> None:
    """Відсутні metrics, cvssMetricV31 або порожній список дають insufficient_data."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    if mode == "no_metrics":
        del cve["metrics"]
    elif mode == "no_v31":
        cve["metrics"] = {}
    else:
        cve["metrics"]["cvssMetricV31"] = []

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_variant_field_gives_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    """Відсутність integrityImpact у cvssData означає insufficient_data без помилки."""
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    del cvss_data["integrityImpact"]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


def test_primary_metric_has_priority_over_earlier_secondary(
    sample_payload: dict[str, Any],
) -> None:
    """Перша оцінка Primary має пріоритет над попередньою Secondary."""
    primary = copy.deepcopy(
        sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    )
    primary["source"] = "primary@nist.gov"
    primary["type"] = "Primary"
    primary["cvssData"]["baseScore"] = 6.5
    primary["cvssData"]["integrityImpact"] = "LOW"

    secondary = copy.deepcopy(primary)
    secondary["source"] = "secondary@example.org"
    secondary["type"] = "Secondary"
    secondary["cvssData"]["baseScore"] = 9.0
    secondary["cvssData"]["integrityImpact"] = "HIGH"

    later_primary = copy.deepcopy(primary)
    later_primary["source"] = "later-primary@example.org"
    later_primary["cvssData"]["baseScore"] = 8.0
    later_primary["cvssData"]["integrityImpact"] = "HIGH"

    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary,
        primary,
        later_primary,
    ]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["score"] == 6.5
    assert report["score_source"] == "primary@nist.gov"
    assert report["observed"] == "LOW"
    assert report["decision"] == "review"


def test_first_metric_selected_when_no_primary(sample_payload: dict[str, Any]) -> None:
    """За відсутності Primary вибирається перша оцінка зі списку."""
    first = copy.deepcopy(
        sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    )
    first["type"] = "Secondary"
    first["source"] = "first@example.org"
    first["cvssData"]["baseScore"] = 6.0
    first["cvssData"]["integrityImpact"] = "LOW"

    second = copy.deepcopy(first)
    second["source"] = "second@example.org"
    second["cvssData"]["baseScore"] = 9.0
    second["cvssData"]["integrityImpact"] = "HIGH"

    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        first,
        second,
    ]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["score"] == 6.0
    assert report["score_source"] == "first@example.org"
    assert report["observed"] == "LOW"
    assert report["decision"] == "review"


def test_optional_description_and_cvss_metadata_handling(
    sample_payload: dict[str, Any],
) -> None:
    """Вибір першого непорожнього англійського опису та опціональних полів CVSS."""
    cve = sample_payload["vulnerabilities"][0]["cve"]
    cve["descriptions"] = [
        {"lang": "uk", "value": "Український опис"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "First non-empty English description."},
        {"lang": "en", "value": "Second English description."},
    ]
    metric = cve["metrics"]["cvssMetricV31"][0]
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]

    record = extract_record(sample_payload, CVE_ID)
    report = build_report(record, CVE_ID, VARIANT)

    assert report["description"] == "First non-empty English description."
    assert report["cvss_version"] is None
    assert report["score_source"] is None
    assert report["vector"] is None


@pytest.mark.parametrize("bad_impact", [None, "", "CRITICAL", "low", 123, True])
def test_invalid_variant_field_raises_value_error(
    sample_payload: dict[str, Any], bad_impact: Any
) -> None:
    """Некоректний тип або значення integrityImpact у cvssData викликає ValueError."""
    _with_cvss_changes(sample_payload, base_score=7.0, integrity_impact=bad_impact)
    record = extract_record(sample_payload, CVE_ID)
    with pytest.raises(ValueError):
        build_report(record, CVE_ID, VARIANT)


@pytest.mark.parametrize(
    "bad_score",
    [None, True, False, "9.8", -0.1, 10.1, float("nan"), float("inf"), float("-inf")],
)
def test_invalid_base_score_raises_value_error(
    sample_payload: dict[str, Any], bad_score: Any
) -> None:
    """Некоректна оцінка baseScore (bool, рядок, NaN, Inf, поза 0..10) викликає ValueError."""
    _with_cvss_changes(sample_payload, base_score=bad_score, integrity_impact="LOW")
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p.pop("vulnerabilities"),
        lambda p: p.__setitem__("vulnerabilities", "bad"),
        lambda p: p["vulnerabilities"].append(copy.deepcopy(p["vulnerabilities"][0])),
        lambda p: p["vulnerabilities"][0]["cve"].__setitem__("id", "CVE-2099-99999"),
        lambda p: p["vulnerabilities"][0]["cve"].__setitem__("vulnStatus", None),
        lambda p: p["vulnerabilities"][0]["cve"].__setitem__("vulnStatus", "  "),
        lambda p: p["vulnerabilities"][0]["cve"].__setitem__("descriptions", None),
        lambda p: p["vulnerabilities"][0]["cve"]["descriptions"].__setitem__(
            0, {"lang": "en"}
        ),
        lambda p: p["vulnerabilities"][0]["cve"].__setitem__("metrics", None),
        lambda p: p["vulnerabilities"][0]["cve"]["metrics"].__setitem__(
            "cvssMetricV31", None
        ),
        lambda p: p["vulnerabilities"][0]["cve"]["metrics"].__setitem__(
            "cvssMetricV31", ["bad"]
        ),
        lambda p: p["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
            0
        ].__setitem__("cvssData", None),
        lambda p: p["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
            "cvssData"
        ].__setitem__("version", "3.0"),
        lambda p: p["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
            "cvssData"
        ].__setitem__("vectorString", ""),
        lambda p: p["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
            0
        ].__setitem__("source", None),
    ],
)
def test_malformed_payload_raises_value_error(
    sample_payload: dict[str, Any], mutator: Any
) -> None:
    """Порушення контракту структури відповіді NVD викликає ValueError."""
    mutator(sample_payload)
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE_ID)
