"""Маршрути для роботи з категоріями перевірок хмарної конфігурації."""

from typing import Annotated

from fastapi import APIRouter, Path, Response, status

from labs.lab03 import repository
from labs.lab03.routers import repository_error_handler
from labs.lab03.schemas import CategoryCreate, CategoryRead, ErrorResponse

router = APIRouter(prefix="/categories", tags=["Категорії"])


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Отримати список категорій",
    description="Повертає всі категорії напрямів перевірки, відсортовані за зростанням id.",
)
def get_categories() -> list[CategoryRead]:
    """Отримати список усіх категорій."""
    with repository_error_handler():
        return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    description="Додає нову категорію напряму перевірки. Назва має бути унікальною.",
    responses={
        409: {
            "model": ErrorResponse,
            "description": "Категорія з такою назвою вже існує",
        },
    },
)
def create_category(payload: CategoryCreate) -> CategoryRead:
    """Створити нову категорію."""
    with repository_error_handler():
        return repository.create_category(payload.name)


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    description=(
        "Видаляє категорію за її ідентифікатором. "
        "Категорію, яка містить пов’язані записи, видалити неможливо."
    ),
    responses={
        404: {"model": ErrorResponse, "description": "Категорію не знайдено"},
        409: {
            "model": ErrorResponse,
            "description": "Категорія містить пов’язані записи",
        },
    },
)
def delete_category(
    category_id: Annotated[int, Path(gt=0, description="Ідентифікатор категорії")],
) -> Response:
    """Видалити порожню категорію за ідентифікатором."""
    with repository_error_handler():
        repository.delete_category(category_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
