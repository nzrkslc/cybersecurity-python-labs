"""Спільні фікстури та ізоляція середовища для тестів ЛР №4."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
_SAMPLE_TEMPLATE: dict[str, Any] = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Видалити ключ API та заблокувати реальні HTTP-запити Requests."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Повернути свіжу глибоку копію синтетичної відповіді NVD."""
    return copy.deepcopy(_SAMPLE_TEMPLATE)
