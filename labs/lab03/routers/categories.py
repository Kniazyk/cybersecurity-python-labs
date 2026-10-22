"""Маршрути для ресурсу categories."""

from typing import Annotated

from fastapi import APIRouter, Path, Response

from .. import repository
from ..schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])

CategoryId = Annotated[
    int, Path(gt=0, description="Ідентифікатор категорії (додатне ціле число)")
]


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Отримати список категорій",
    description="Повертає всі категорії за зростанням id.",
)
def list_categories() -> list[dict]:
    """Список категорій."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(category: CategoryCreate) -> dict:
    """Створити категорію."""
    return repository.create_category(category.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    response_class=Response,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> Response:
    """Видалити категорію без записів."""
    repository.delete_category(category_id)
    return Response(status_code=204)
