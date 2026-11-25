"""Інтеграційні тести CLI та взаємодії модулів (labs.lab04.main)."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client
from labs.lab04 import main as main_module


def test_cli_local_input_runs_offline_and_outputs_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Локальний запуск із --input формує JSON-звіт без звернень до мережі."""
    monkeypatch.setattr(
        main_module.api_client,
        "fetch_response",
        Mock(side_effect=AssertionError("Network should not be called")),
    )
    sample_file = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"

    exit_code = main_module.main(
        ["--cve", "CVE-2099-10001", "--input", str(sample_file)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 13
    assert report["score"] == 9.8
    assert report["observed"] == "HIGH"
    assert report["decision"] == "other"


def test_cli_local_input_review_from_tmp_path(
    tmp_path: Path,
    sample_payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Локальний JSON-файл із граничним значенням 6.0 та integrityImpact=LOW дає review."""
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["baseScore"] = 6.0
    cvss_data["integrityImpact"] = "LOW"

    json_file = tmp_path / "review.json"
    json_file.write_text(json.dumps(sample_payload), encoding="utf-8")

    exit_code = main_module.main(["--cve", "CVE-2099-10001", "--input", str(json_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["decision"] == "review"
    assert report["score"] == 6.0
    assert report["observed"] == "LOW"


def test_cli_missing_input_file_returns_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Відсутній локальний файл завершується кодом 1 та повідомленням у stderr."""
    missing = tmp_path / "does_not_exist.json"
    exit_code = main_module.main(["--cve", "CVE-2099-10001", "--input", str(missing)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""
    assert "Traceback" not in captured.err


def test_cli_invalid_json_file_returns_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Некоректний JSON у локальному файлі завершується кодом 1 та помилкою у stderr."""
    bad_file = tmp_path / "broken.json"
    bad_file.write_text("{invalid json", encoding="utf-8")

    exit_code = main_module.main(["--cve", "CVE-2099-10001", "--input", str(bad_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "JSON" in captured.err
    assert "Traceback" not in captured.err


def test_cli_cve_mismatch_in_local_file_returns_1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Невідповідність --cve до запису у локальному файлі дає код 1."""
    sample_file = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
    exit_code = main_module.main(
        ["--cve", "CVE-2099-10002", "--input", str(sample_file)]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert captured.err.strip() != ""


def test_cli_api_mode_success(
    monkeypatch: pytest.MonkeyPatch,
    sample_payload: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Успішний режим API виводить єдиний JSON-об'єкт у stdout і повертає 0."""
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]["integrityImpact"] = "LOW"
    monkeypatch.setattr(
        main_module.api_client,
        "fetch_response",
        Mock(return_value=sample_payload),
    )

    exit_code = main_module.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["decision"] == "review"


@pytest.mark.parametrize(
    ("exc_factory", "expected_fragment"),
    [
        (lambda: requests.exceptions.Timeout("secret-timeout-detail"), "очікування"),
        (
            lambda: requests.exceptions.ConnectionError("secret-conn-detail"),
            "з'єднання",
        ),
        (
            lambda: requests.exceptions.JSONDecodeError("secret-json-detail", "{", 1),
            "JSON",
        ),
        (
            lambda: api_client.UnexpectedStatusError(302),
            "302",
        ),
    ],
)
def test_cli_handles_client_errors_without_leaking_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exc_factory: Any,
    expected_fragment: str,
) -> None:
    """Мережеві та JSON-помилки дають код 1 і зрозуміле повідомлення без витоку деталей."""
    monkeypatch.setattr(
        main_module.api_client,
        "fetch_response",
        Mock(side_effect=exc_factory()),
    )

    exit_code = main_module.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert expected_fragment in captured.err
    assert "secret-" not in captured.err
    assert "Traceback" not in captured.err


def test_cli_http_error_reports_status_without_body(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """HTTP-помилка показує статус-код, але не тіло відповіді чи заголовки."""
    resp = Mock(spec=requests.Response)
    resp.status_code = 404
    resp.text = "SECRET_RESPONSE_BODY_DO_NOT_PRINT"
    exc = requests.exceptions.HTTPError("HTTP 404 SECRET_HEADER", response=resp)

    monkeypatch.setattr(main_module.api_client, "fetch_response", Mock(side_effect=exc))

    exit_code = main_module.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "404" in captured.err
    assert "SECRET_" not in captured.err


@pytest.mark.parametrize(
    "bad_argv",
    [
        [],
        ["--cve", "cve-2021-44228"],
        ["--cve", "CVE-2021-123"],
        ["--cve", "CVE-21-44228"],
        ["--cve", "CVE-2021-44228-extra"],
    ],
)
def test_cli_invalid_arguments_exit_with_code_2(
    capsys: pytest.CaptureFixture[str],
    bad_argv: list[str],
) -> None:
    """Неправильні аргументи завершуються SystemExit(2) та повідомленням у stderr."""
    with pytest.raises(SystemExit) as exc_info:
        main_module.main(bad_argv)

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.err.strip() != ""


@pytest.mark.parametrize("bad_variant", [0, 16, -1, True, False, "13", None])
def test_cli_invalid_variant_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    bad_variant: Any,
) -> None:
    """Некоректний VARIANT_NUMBER завершується кодом 2 без виконання запитів."""
    monkeypatch.setattr(main_module, "VARIANT_NUMBER", bad_variant)
    exit_code = main_module.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err.strip() != ""


def test_cli_can_test_another_variant_via_monkeypatch(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Тимчасова підміна VARIANT_NUMBER у main застосовує правило іншого варіанта."""
    monkeypatch.setattr(main_module, "VARIANT_NUMBER", 1)
    sample_file = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"

    exit_code = main_module.main(
        ["--cve", "CVE-2099-10001", "--input", str(sample_file)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["variant"] == 1
    assert report["decision"] == "review"
