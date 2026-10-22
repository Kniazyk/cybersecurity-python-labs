"""Маршрути для ресурсу records."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response

from .. import repository
from ..config import VALUE_MAX, VALUE_MIN
from ..schemas import RecordCreate, RecordRead, RecordReplace, RecordStatus

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[
    int, Path(gt=0, description="Ідентифікатор запису (додатне ціле число)")
]

NOT_FOUND = {404: {"description": "Запис не знайдено"}}
CATEGORY_NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CODE_CONFLICT = {409: {"description": "Запис із таким code вже існує"}}


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами",
    description=(
        "Фільтри поєднуються через AND. Сортування за id за зростанням. "
        "Пошук q — буквальний підрядок у title з урахуванням регістру."
    ),
)
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    status: Annotated[
        RecordStatus | None, Query(description="Лише записи з цим статусом")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="Мінімальне значення: value >= min_value",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(min_length=1, max_length=120, description="Підрядок у title"),
    ] = None,
    limit: Annotated[
        int, Query(ge=1, le=100, description="Максимальна кількість записів")
    ] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
) -> list[dict]:
    """Список записів."""
    return repository.list_records(
        category_id=category_id,
        status=status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    description="Від 1 до 100 записів; зберігаються всі або жоден.",
    responses={
        404: {"description": "Одна з категорій не існує"},
        409: {"description": "Дублікат code у базі або всередині пакета"},
    },
)
def create_records_bulk(
    records: Annotated[
        list[RecordCreate],
        Body(min_length=1, max_length=100, description="Масив записів (1–100)"),
    ],
) -> list[dict]:
    """Створити пакет записів в одній транзакції."""
    return repository.create_records_bulk([item.model_dump() for item in records])


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис за id",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Один запис."""
    return repository.get_record(record_id)


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    responses={**CATEGORY_NOT_FOUND, **CODE_CONFLICT},
)
def create_record(record: RecordCreate) -> dict:
    """Створити запис."""
    return repository.create_record(**record.model_dump())


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити змінювані поля запису",
    responses={**CATEGORY_NOT_FOUND, **CODE_CONFLICT},
)
def replace_record(record_id: RecordId, record: RecordReplace) -> dict:
    """Замінити всі п’ять змінюваних полів; id лишається."""
    return repository.update_record(record_id, **record.model_dump())


@router.delete(
    "/{record_id}",
    status_code=204,
    response_class=Response,
    summary="Видалити запис",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис."""
    repository.delete_record(record_id)
    return Response(status_code=204)
