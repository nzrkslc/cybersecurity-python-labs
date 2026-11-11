"""Маршрути для CRUD-операцій і пакетного створення знахідок аудиту."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response, status

from labs.lab03 import repository
from labs.lab03.config import (
    BULK_MAX_ITEMS,
    BULK_MIN_ITEMS,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    QUERY_MAX_LEN,
    QUERY_MIN_LEN,
    VALUE_MAX,
    VALUE_MIN,
)
from labs.lab03.routers import repository_error_handler
from labs.lab03.schemas import (
    ErrorResponse,
    RecordCreate,
    RecordRead,
    RecordReplace,
    RecordStatus,
)

router = APIRouter(prefix="/records", tags=["Записи аудиту"])


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Отримати список записів із фільтрами",
    description=(
        "Повертає знахідки аудиту хмарної конфігурації з можливістю фільтрації "
        "за категорією, статусом, мінімальною оцінкою ризику, підрядком у назві "
        "та поділом на сторінки. Сортування завжди за зростанням id."
    ),
)
def get_records(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Фільтр за ідентифікатором категорії (> 0)"),
    ] = None,
    status_filter: Annotated[
        RecordStatus | None,
        Query(
            alias="status", description="Фільтр за статусом (new, in_progress, done)"
        ),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="Мінімальна оцінка ризику в діапазоні 0–10 score",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=QUERY_MIN_LEN,
            max_length=QUERY_MAX_LEN,
            description="Буквальний підрядок у назві (title) з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1, le=MAX_LIMIT, description="Максимальна кількість записів у відповіді"
        ),
    ] = DEFAULT_LIMIT,
    offset: Annotated[
        int,
        Query(ge=0, description="Кількість пропущених записів для пагінації"),
    ] = 0,
) -> list[RecordRead]:
    """Отримати відфільтрований список знахідок аудиту."""
    with repository_error_handler():
        return repository.list_records(
            category_id=category_id,
            status=status_filter,
            min_value=min_value,
            q=q,
            limit=limit,
            offset=offset,
        )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис за id",
    description="Повертає одну знахідку аудиту разом із назвою її категорії.",
    responses={
        404: {"model": ErrorResponse, "description": "Запис не знайдено"},
    },
)
def get_record(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
) -> RecordRead:
    """Отримати один запис за його ідентифікатором."""
    with repository_error_handler():
        return repository.get_record_by_id(record_id)


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити новий запис",
    description="Реєструє нову знахідку аудиту хмарної конфігурації.",
    responses={
        404: {"model": ErrorResponse, "description": "Вказану категорію не знайдено"},
        409: {"model": ErrorResponse, "description": "Запис із таким code уже існує"},
    },
)
def create_record(payload: RecordCreate) -> RecordRead:
    """Створити один запис знахідки аудиту."""
    with repository_error_handler():
        return repository.create_record(
            code=payload.code,
            title=payload.title,
            category_id=payload.category_id,
            value=payload.value,
            status=payload.status,
        )


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити поля запису",
    description="Повністю оновлює всі змінювані поля запису зі збереженням незмінного id.",
    responses={
        404: {"model": ErrorResponse, "description": "Запис або категорію не знайдено"},
        409: {"model": ErrorResponse, "description": "Запис із таким code уже існує"},
    },
)
def replace_record(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
    payload: RecordReplace,
) -> RecordRead:
    """Повністю оновити змінювані поля наявного запису."""
    with repository_error_handler():
        return repository.replace_record(
            record_id,
            code=payload.code,
            title=payload.title,
            category_id=payload.category_id,
            value=payload.value,
            status=payload.status,
        )


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    description="Видаляє знахідку аудиту за її ідентифікатором.",
    responses={
        404: {"model": ErrorResponse, "description": "Запис не знайдено"},
    },
)
def delete_record(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
) -> Response:
    """Видалити запис за ідентифікатором."""
    with repository_error_handler():
        repository.delete_record(record_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів",
    description=(
        "Атомарно додає від 1 до 100 записів у межах однієї транзакції. "
        "Якщо будь-який елемент порушує обмеження або посилається на неіснуючу категорію, "
        "скасовується весь пакет."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "Категорію одного з елементів не знайдено",
        },
        409: {
            "model": ErrorResponse,
            "description": "Дублікат code у базі даних або всередині пакета",
        },
    },
)
def create_records_bulk(
    items: Annotated[
        list[RecordCreate],
        Body(
            min_length=BULK_MIN_ITEMS,
            max_length=BULK_MAX_ITEMS,
            description="JSON-масив записів для атомарного створення (1–100 елементів)",
        ),
    ],
) -> list[RecordRead]:
    """Створити пакет записів у межах однієї транзакції SQLite."""
    with repository_error_handler():
        return repository.create_records_bulk([item.model_dump() for item in items])
