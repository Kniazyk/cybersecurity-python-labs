"""Pydantic-моделі запитів і відповідей."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import VALUE_MAX, VALUE_MIN

RecordStatus = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Дані для створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(
        min_length=2,
        max_length=40,
        description="Назва ресурсу",
        examples=["network"],
    )


class CategoryRead(CategoryCreate):
    """Категорія у відповіді."""

    id: int


class RecordCreate(BaseModel):
    """Дані для створення вимірювання (id задає база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(
        min_length=3,
        max_length=40,
        description="Унікальний код запису",
        examples=["V10-11"],
    )
    title: str = Field(
        min_length=3,
        max_length=120,
        description="Назва вимірювання",
        examples=["Вимірювання сервера 11"],
    )
    category_id: int = Field(gt=0, description="Id наявної категорії")
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        description="Використання ресурсу, відсотки (0–100 включно)",
        examples=[72.5],
    )
    status: RecordStatus = Field(description="Стан перевірки спостереження")


class RecordReplace(RecordCreate):
    """Повна заміна: усі п’ять змінюваних полів обов’язкові."""


class RecordRead(RecordCreate):
    """Запис у відповіді."""

    id: int
    category_name: str


class StudentRead(BaseModel):
    """Дані студента з shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int
