"""Початкове заповнення бази з data/seed.json."""

import json
import sys
from pathlib import Path

from . import repository
from .database import initialize_database
from .schemas import CategoryCreate, RecordCreate

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def load_seed_file(path: Path = SEED_PATH) -> object:
    """Прочитати JSON-файл із початковими даними."""
    return json.loads(path.read_text(encoding="utf-8"))


def parse_seed_data(raw: object) -> tuple[list[dict], list[dict]]:
    """Перевірити структуру й значення початкових даних."""
    if not isinstance(raw, dict) or set(raw) != {"categories", "records"}:
        raise ValueError("JSON має бути об’єктом із ключами categories і records")
    raw_categories = raw["categories"]
    raw_records = raw["records"]
    if not isinstance(raw_categories, list) or not isinstance(raw_records, list):
        raise TypeError("categories і records мають бути масивами")

    categories: list[dict] = []
    category_ids: set[int] = set()
    for item in raw_categories:
        if not isinstance(item, dict) or set(item) != {"id", "name"}:
            raise ValueError("Категорія має містити лише поля id та name")
        category_id = item["id"]
        if type(category_id) is not int or category_id <= 0:
            raise ValueError(f"Некоректний id категорії: {category_id!r}")
        if category_id in category_ids:
            raise ValueError(f"Повторний id категорії: {category_id}")
        name = CategoryCreate.model_validate({"name": item["name"]}).name
        category_ids.add(category_id)
        categories.append({"id": category_id, "name": name})

    records: list[dict] = []
    for item in raw_records:
        record = RecordCreate.model_validate(item)
        if record.category_id not in category_ids:
            raise ValueError(
                f"Запис {record.code} посилається на невідому категорію "
                f"{record.category_id}"
            )
        records.append(record.model_dump())
    return categories, records


def seed_database() -> bool:
    """Заповнити порожню базу. Повернути True, якщо дані додано."""
    initialize_database()
    categories, records = parse_seed_data(load_seed_file())
    return repository.seed_if_empty(categories, records)


def main() -> int:
    """Запустити заповнення та вивести зрозуміле повідомлення."""
    try:
        seeded = seed_database()
    except (OSError, ValueError, repository.RepositoryError) as error:
        print(f"Помилка початкового заповнення, зміни скасовано: {error}")
        return 1
    if seeded:
        print("Базу заповнено: додано 3 категорії та 8 записів.")
    else:
        print("База вже містить дані: зміни не вносилися.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
