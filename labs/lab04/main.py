"""Консольна утиліта: перегляд запису CVE з NVD та JSON-звіт за варіантом."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


class InputError(Exception):
    """Помилка отримання або читання даних (код завершення 1)."""


def cve_id_type(value: str) -> str:
    """Перевіряє повний збіг ідентифікатора з шаблоном CVE."""
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "очікується формат CVE-РРРР-NNNN (чутливий до регістру)"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Перегляд запису про вразливість із NVD та аналіз за варіантом.",
    )
    parser.add_argument("--cve", required=True, type=cve_id_type, help="ID CVE")
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="локальна відповідь NVD (UTF-8 JSON); мережевий запит не виконується",
    )
    return parser


def load_response(path: str | Path) -> Any:
    """Читає UTF-8 JSON-файл із відповіддю NVD."""
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _load_local(path: Path) -> Any:
    """Читає локальний файл, перетворюючи збої на InputError."""
    try:
        return load_response(path)
    except json.JSONDecodeError:
        raise InputError("файл не містить коректного JSON.") from None
    except UnicodeDecodeError:
        raise InputError("файл не є коректним UTF-8.") from None
    except OSError:
        raise InputError(f"не вдалося прочитати файл {path}.") from None


def _load_remote(cve_id: str) -> Any:
    """Отримує відповідь NVD, перетворюючи збої на InputError."""
    try:
        return api_client.fetch_response(cve_id)
    except requests.exceptions.JSONDecodeError:
        raise InputError("відповідь NVD не є коректним JSON.") from None
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        suffix = f" (статус {status})" if status is not None else ""
        raise InputError(f"NVD повернув HTTP-помилку{suffix}.") from None
    except api_client.UnexpectedStatusError as exc:
        raise InputError(
            f"NVD повернув неочікуваний HTTP-статус {exc.status_code}."
        ) from None
    except requests.exceptions.Timeout:
        raise InputError("перевищено час очікування відповіді NVD.") from None
    except requests.exceptions.ConnectionError:
        raise InputError("не вдалося встановити з'єднання з NVD.") from None
    except requests.exceptions.RequestException:
        raise InputError("не вдалося виконати запит до NVD.") from None


def main(argv: list[str] | None = None) -> int:
    """Запускає утиліту й повертає код завершення (0, 1 або 2)."""
    if not analysis.is_valid_variant(VARIANT_NUMBER):
        print(
            "Помилка: VARIANT_NUMBER має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2
    args = build_parser().parse_args(argv)
    try:
        if args.input is not None:
            payload = _load_local(args.input)
        else:
            payload = _load_remote(args.cve)
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except InputError as exc:
        print(f"Помилка отримання даних: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Помилка перевірки даних: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
