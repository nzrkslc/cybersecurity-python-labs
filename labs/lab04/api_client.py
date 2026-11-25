"""HTTP-клієнт для взаємодії з NVD CVE API 2.0."""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = (3.05, 10)
API_KEY_ENV_VAR = "NVD_API_KEY"


class UnexpectedStatusError(RuntimeError):
    """Помилка неочікуваного HTTP-статусу відповіді від NVD API."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Очікувано HTTP-статус 200, отримано {status_code}.")


def build_headers() -> dict[str, str]:
    """Сформувати HTTP-заголовки для запиту до NVD API."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv(API_KEY_ENV_VAR)
    if api_key is not None:
        cleaned_key = api_key.strip()
        if cleaned_key:
            headers["apiKey"] = cleaned_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконати один GET-запит до NVD API за вказаним CVE і повернути JSON-дані."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
