"""Pydantic-моделі запитів, відповідей та початкових даних для Варіанта 13."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from labs.lab03.config import (
    CATEGORY_NAME_MAX_LEN,
    CATEGORY_NAME_MIN_LEN,
    RECORD_CODE_MAX_LEN,
    RECORD_CODE_MIN_LEN,
    RECORD_TITLE_MAX_LEN,
    RECORD_TITLE_MIN_LEN,
    VALUE_MAX,
    VALUE_MIN,
)

RecordStatus = Literal["new", "in_progress", "done"]


def _reject_bool(value: Any) -> Any:
    """Відхилити булеві значення для числових полів."""
    if value is True or value is False:
        raise ValueError("Булеве значення неприпустиме для числового поля.")
    return value


class CategoryCreate(BaseModel):
    """Модель створення категорії аудиту хмарної конфігурації."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    name: str = Field(
        min_length=CATEGORY_NAME_MIN_LEN,
        max_length=CATEGORY_NAME_MAX_LEN,
        description="Назва напряму перевірки (2–40 символів, наприклад: iam, storage, network)",
    )


class CategoryRead(CategoryCreate):
    """Модель відповіді з даними категорії."""

    id: int = Field(gt=0, description="Унікальний ідентифікатор категорії")


class RecordCreate(BaseModel):
    """Модель створення запису знахідки аудиту хмарної конфігурації."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    code: str = Field(
        min_length=RECORD_CODE_MIN_LEN,
        max_length=RECORD_CODE_MAX_LEN,
        description="Унікальний код знахідки (3–40 символів, наприклад: V13-01)",
    )
    title: str = Field(
        min_length=RECORD_TITLE_MIN_LEN,
        max_length=RECORD_TITLE_MAX_LEN,
        description="Назва знахідки аудиту (3–120 символів)",
    )
    category_id: int = Field(
        gt=0,
        description="Ідентифікатор категорії перевірки (ціле число > 0)",
    )
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        description="Навчальна оцінка ризику в діапазоні 0–10 (score)",
    )
    status: RecordStatus = Field(
        description="Стан опрацювання знахідки (new, in_progress, done)",
    )

    @field_validator("category_id", "value", mode="before")
    @classmethod
    def validate_not_bool(cls, raw_value: Any) -> Any:
        """Заборонити передавання True/False замість чисел."""
        return _reject_bool(raw_value)


class RecordReplace(RecordCreate):
    """Модель повного оновлення змінюваних полів запису (PUT)."""


class RecordRead(RecordCreate):
    """Модель відповіді з повною інформацією про знахідку аудиту."""

    id: int = Field(gt=0, description="Унікальний ідентифікатор запису")
    category_name: str = Field(description="Назва категорії перевірки")


class PingResponse(BaseModel):
    """Модель відповіді перевірки доступності сервісу."""

    status: str = Field(description="Статус доступності API")


class StudentResponse(BaseModel):
    """Модель відповіді з даними студента та варіанта."""

    student_name: str = Field(description="Прізвище та ім’я студента")
    group_name: str = Field(description="Академічна група")
    variant_number: int = Field(description="Номер індивідуального варіанта")


class ErrorResponse(BaseModel):
    """Модель повідомлення про помилку API."""

    detail: str = Field(description="Опис причини помилки")


class SeedCategory(CategoryCreate):
    """Модель категорії в початковому файлі seed.json."""

    id: int = Field(gt=0, description="Фіксований ідентифікатор початкової категорії")

    @field_validator("id", mode="before")
    @classmethod
    def validate_id_not_bool(cls, raw_value: Any) -> Any:
        """Заборонити булеве значення для ідентифікатора."""
        return _reject_bool(raw_value)


class SeedData(BaseModel):
    """Модель початкового набору даних для заповнення бази з JSON."""

    model_config = ConfigDict(extra="forbid")

    categories: list[SeedCategory] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)
