"""Завдання 2 (Варіант 10): монітор термінів дії SSL/TLS сертифікатів.

Утиліта читає JSON-файл із даними про SSL/TLS-сертифікати (Domain, Issuer,
ValidFrom, ValidTo, KeyLength, SignatureAlgorithm), рахує кількість днів до
закінчення терміну дії, шукає прострочені сертифікати та слабкі алгоритми
підпису, агрегує сертифікати за видавцями та формує звіт у JSON або CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Алгоритми підпису, які вважаються застарілими/слабкими.
WEAK_ALGORITHM_PATTERN: re.Pattern[str] = re.compile(r"(?i)\b(sha1|md5)")

STATUS_EXPIRED = "EXPIRED"
STATUS_WARNING = "WARNING"
STATUS_OK = "OK"

# Поля, які записуються у звіт (і заголовок CSV-файлу).
REPORT_FIELDS = [
    "domain",
    "issuer",
    "valid_to",
    "days_left",
    "status",
    "signature_algorithm",
    "weak_algorithm",
    "key_length",
]

# Обов'язкові поля, яких очікуємо в кожному записі вхідного JSON.
REQUIRED_FIELDS = (
    "domain",
    "issuer",
    "validFrom",
    "validTo",
    "keyLength",
    "signatureAlgorithm",
)


def configure_logging(level: int = logging.INFO) -> None:
    """Налаштовує базове логування у stdout."""
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        stream=sys.stdout,
    )


def load_certificates(path: Path) -> list[dict]:
    """Читає JSON-файл із сертифікатами та повертає список записів."""
    if not path.exists():
        raise FileNotFoundError(f"Файл із сертифікатами не знайдено: {path}")

    with path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Файл {path} не є коректним JSON: {exc}") from exc

    if not isinstance(data, list):
        raise TypeError("Очікується JSON-масив об'єктів сертифікатів")

    for index, cert in enumerate(data):
        missing = [field for field in REQUIRED_FIELDS if field not in cert]
        if missing:
            raise KeyError(f"У записі #{index} відсутні обов'язкові поля: {missing}")

    return data


def parse_date(value: str) -> date:
    """Перетворює рядок дати формату YYYY-MM-DD (ISO-8601) в об'єкт date."""
    return date.fromisoformat(value)


def calculate_days_left(valid_to: date, today: date) -> int:
    """Кількість днів до закінчення терміну дії (від'ємне — прострочено)."""
    return (valid_to - today).days


def classify_status(days_left: int, days_warning: int) -> str:
    """Визначає статус сертифіката за кількістю днів, що залишились."""
    if days_left < 0:
        return STATUS_EXPIRED
    if days_left <= days_warning:
        return STATUS_WARNING
    return STATUS_OK


def is_weak_algorithm(signature_algorithm: str) -> bool:
    """Перевіряє, чи алгоритм підпису вважається застарілим/слабким."""
    return WEAK_ALGORITHM_PATTERN.search(signature_algorithm) is not None


def build_report_rows(
    certificates: list[dict], days_warning: int, today: date
) -> list[dict]:
    """Обчислює для кожного сертифіката дні до закінчення, статус і алгоритм."""
    rows = []
    for cert in certificates:
        domain = cert["domain"]
        issuer = cert["issuer"]
        valid_to = parse_date(cert["validTo"])
        signature_algorithm = cert["signatureAlgorithm"]

        days_left = calculate_days_left(valid_to, today)
        status = classify_status(days_left, days_warning)
        weak = is_weak_algorithm(signature_algorithm)

        if status == STATUS_EXPIRED:
            logger.warning(
                "Сертифікат %s прострочений %d дн. тому", domain, abs(days_left)
            )
        elif status == STATUS_WARNING:
            logger.warning("Сертифікат %s спливає через %d дн.", domain, days_left)
        if weak:
            logger.warning(
                "Сертифікат %s використовує застарілий алгоритм підпису: %s",
                domain,
                signature_algorithm,
            )

        rows.append(
            {
                "domain": domain,
                "issuer": issuer,
                "valid_to": cert["validTo"],
                "days_left": days_left,
                "status": status,
                "signature_algorithm": signature_algorithm,
                "weak_algorithm": weak,
                "key_length": cert["keyLength"],
            }
        )
    return rows


def aggregate_by_issuer(rows: list[dict]) -> Counter:
    """Рахує кількість сертифікатів за кожним видавцем."""
    return Counter(row["issuer"] for row in rows)


def print_summary(rows: list[dict], issuer_counts: Counter) -> None:
    """Виводить у консоль таблицю статусів та статистику за видавцями."""
    print("=== Certificate Expiry & Safety Status ===")
    header = (
        f"{'Domain':<32}{'Issuer':<15}{'Days Left':<12}{'Status':<10}{'Signature Alg'}"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['domain']:<32}{row['issuer']:<15}{row['days_left']:<12}"
            f"{row['status']:<10}{row['signature_algorithm']}"
        )

    print("\n=== Issuer Statistics ===")
    for issuer, count in issuer_counts.most_common():
        print(f"{issuer} : {count}")

    expired_count = sum(1 for r in rows if r["status"] == STATUS_EXPIRED)
    warning_count = sum(1 for r in rows if r["status"] == STATUS_WARNING)
    weak_count = sum(1 for r in rows if r["weak_algorithm"])
    print(
        f"\n[WARNING] {expired_count} certificate(s) EXPIRED! "
        f"{warning_count} certificate(s) expiring soon! "
        f"{weak_count} certificate(s) with weak signature algorithm!"
    )


def write_report(rows: list[dict], output_path: Path, fmt: str) -> None:
    """Записує звіт у форматі JSON або CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        with output_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    else:
        raise ValueError(f"Непідтримуваний формат звіту: {fmt}")

    logger.info("Звіт збережено: %s", output_path)


def run_analyze(
    certs_data: Path,
    days_warning: int,
    output_report: Path | None,
    fmt: str,
) -> list[dict]:
    """Виконує повний цикл аналізу сертифікатів. Повертає рядки звіту."""
    logger.info("Завантаження сертифікатів з %s...", certs_data)
    certificates = load_certificates(certs_data)
    logger.info("Оброблено %d сертифікатів.", len(certificates))

    today = datetime.now(timezone.utc).date()
    rows = build_report_rows(certificates, days_warning, today)
    issuer_counts = aggregate_by_issuer(rows)

    print_summary(rows, issuer_counts)

    if output_report is not None:
        write_report(rows, output_report, fmt)

    return rows


def build_arg_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка для самостійного запуску."""
    parser = argparse.ArgumentParser(
        description="Монітор термінів дії SSL/TLS сертифікатів (Варіант 10)."
    )
    parser.add_argument(
        "--certs-data",
        required=True,
        type=Path,
        help="Шлях до JSON-файлу з даними сертифікатів",
    )
    parser.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="Поріг днів для попередження (за замовчуванням 30)",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        default=None,
        help="Шлях до файлу звіту (якщо не вказано, звіт не зберігається)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Формат звіту: json або csv",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Точка входу при запуску task2.py напряму (для налагодження)."""
    configure_logging()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        run_analyze(args.certs_data, args.days_warning, args.output_report, args.format)
    except (FileNotFoundError, ValueError, KeyError, TypeError) as exc:
        logger.error("Помилка виконання: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
