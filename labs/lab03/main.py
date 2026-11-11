"""Головний модуль FastAPI-застосунку для Лабораторної роботи №3 (Варіант 13)."""

import logging
import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from labs.lab03.config import APP_DESCRIPTION, APP_TITLE, APP_VERSION
from labs.lab03.database import initialize_database
from labs.lab03.routers.categories import router as categories_router
from labs.lab03.routers.records import router as records_router
from labs.lab03.schemas import PingResponse, StudentResponse
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def _sanitize_validation_value(value: Any) -> Any:
    """Перетворити нескінченні float та NaN у рядки для JSON-відповіді 422."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _sanitize_validation_value(val) for key, val in value.items()}
    if isinstance(value, list | tuple):
        return [_sanitize_validation_value(item) for item in value]
    return value


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці SQLite під час запуску без перезапису даних."""
    initialize_database()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
def validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Повернути коректну JSON-відповідь 422 навіть для NaN/Infinity."""
    sanitized = _sanitize_validation_value(exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": jsonable_encoder(sanitized)},
    )


app.include_router(categories_router)
app.include_router(records_router)


@app.get(
    "/ping",
    response_model=PingResponse,
    tags=["Система"],
    summary="Перевірка доступності API",
    description="Повертає статус доступності вебсервісу.",
)
def ping() -> PingResponse:
    """Перевірити доступність застосунку."""
    return PingResponse(status="ok")


@app.get(
    "/student",
    response_model=StudentResponse,
    tags=["Система"],
    summary="Інформація про студента та варіант",
    description="Повертає ПІБ студента, групу та номер варіанта із модуля shared/student.py.",
)
def get_student() -> StudentResponse:
    """Повернути дані студента з пакета shared.student."""
    return StudentResponse(
        student_name=STUDENT_NAME,
        group_name=GROUP_NAME,
        variant_number=VARIANT_NUMBER,
    )
