"""Тести HTTP-клієнта NVD API (labs.lab04.api_client)."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_key() -> None:
    """Без змінної NVD_API_KEY повертається лише заголовок Accept."""
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("raw_key", ["", "   ", "\t\n"])
def test_build_headers_ignores_blank_key(
    monkeypatch: pytest.MonkeyPatch, raw_key: str
) -> None:
    """Порожнє або пробільне значення NVD_API_KEY не додає заголовок apiKey."""
    monkeypatch.setenv("NVD_API_KEY", raw_key)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_strips_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Непорожній ключ очищається від крайніх пробілів та передається в apiKey."""
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key-123",
    }


def test_fetch_uses_expected_request_without_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Перевіряє URL, параметри, заголовки без ключа, таймаут і allow_redirects=False."""
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response("CVE-2099-10001") == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_passes_api_key_in_header_not_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ключ передається лише в заголовку apiKey, а не в параметрах URL."""
    payload = {"vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    monkeypatch.setenv("NVD_API_KEY", "dummy-api-key")

    assert api_client.fetch_response("CVE-2021-44228") == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2021-44228"},
        headers={"Accept": "application/json", "apiKey": "dummy-api-key"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.Timeout("Read timed out"),
        requests.exceptions.ConnectionError("Connection refused"),
    ],
)
def test_fetch_propagates_network_errors(
    monkeypatch: pytest.MonkeyPatch, exc: requests.exceptions.RequestException
) -> None:
    """Мережеві помилки та таймаут не приховуються клієнтом."""
    fake_get = Mock(side_effect=exc)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(type(exc)):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_propagates_http_error_via_raise_for_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP-помилка піднімається через raise_for_status()."""
    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "404 Not Found", response=response
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.response is response


def test_fetch_rejects_unexpected_non_200_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Перенаправлення або інший не-200 статус без raise_for_status викликає помилку."""
    response = Mock(spec=requests.Response)
    response.status_code = 302
    response.raise_for_status.return_value = None

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(api_client.UnexpectedStatusError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.status_code == 302


def test_fetch_propagates_invalid_json_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Некоректний JSON у тілі відповіді викликає JSONDecodeError."""
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_real_network_requests_are_blocked() -> None:
    """Автоматична фікстура conftest блокує незамокані запити Requests."""
    with pytest.raises(AttributeError):
        api_client.fetch_response("CVE-2099-10001")
