"""FastAPI-застосунок: облік навантаження серверних ресурсів."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

from . import repository
from .config import DOMAIN_DESCRIPTION, DOMAIN_NAME, THRESHOLD, UNIT
from .database import initialize_database
from .routers import categories, records
from .schemas import StudentRead


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску (дані не змінюються)."""
    initialize_database()
    yield


app = FastAPI(
    title=DOMAIN_NAME,
    description=(
        f"{DOMAIN_DESCRIPTION} Одиниця вимірювання: {UNIT}. "
        f"Довідковий поріг: {THRESHOLD}; допустимі значення value: від 0 до 100."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["service"], summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    """Повернути статус сервісу."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["service"],
    summary="Дані студента",
)
def get_student() -> dict:
    """Повернути дані з shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }


@app.exception_handler(repository.NotFoundError)
def handle_not_found(_request: Request, error: repository.NotFoundError):
    """404 для відсутнього запису або категорії."""
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(repository.ConflictError)
def handle_conflict(_request: Request, error: repository.ConflictError):
    """409 для дублікатів і заборонених видалень."""
    return JSONResponse(status_code=409, content={"detail": str(error)})


@app.exception_handler(repository.ConstraintError)
def handle_constraint(_request: Request, error: repository.ConstraintError):
    """422 для даних, що порушують обмеження бази."""
    return JSONResponse(status_code=422, content={"detail": str(error)})


@app.exception_handler(repository.DatabaseError)
def handle_database(_request: Request, error: repository.DatabaseError):
    """500 без технічних деталей."""
    return JSONResponse(status_code=500, content={"detail": str(error)})
