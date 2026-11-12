"""Перевірка відповіді NVD і правило аналізу за варіантом.

Функції цього модуля не читають файлів і змінних середовища, не виконують
HTTP-запитів, нічого не друкують та не змінюють отриманий payload.
"""

from __future__ import annotations

import math
from typing import Any

Record = dict[str, Any]
Report = dict[str, Any]

CVSS_VERSION = "3.1"
REJECTED_STATUS = "Rejected"

ALLOWED_VALUES: dict[str, tuple[str, ...]] = {
    "attackVector": ("NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"),
    "attackComplexity": ("LOW", "HIGH"),
    "privilegesRequired": ("NONE", "LOW", "HIGH"),
    "userInteraction": ("NONE", "REQUIRED"),
    "scope": ("UNCHANGED", "CHANGED"),
    "confidentialityImpact": ("NONE", "LOW", "HIGH"),
    "integrityImpact": ("NONE", "LOW", "HIGH"),
    "availabilityImpact": ("NONE", "LOW", "HIGH"),
}

# Варіант -> (поріг T, поле cvssData, очікуване значення).
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


def _require(condition: bool, message: str) -> None:
    """Піднімає ValueError із повідомленням, якщо умову контракту порушено."""
    if not condition:
        raise ValueError(message)


def is_valid_variant(variant: Any) -> bool:
    """Перевіряє, що variant — ціле (не bool) число від 1 до 15."""
    return (
        isinstance(variant, int)
        and not isinstance(variant, bool)
        and variant in VARIANT_RULES
    )


def get_rule(variant: int) -> dict[str, Any]:
    """Повертає правило варіанта: threshold, field, expected."""
    _require(
        is_valid_variant(variant),
        "Номер варіанта має бути цілим числом від 1 до 15.",
    )
    threshold, field, expected = VARIANT_RULES[variant]
    return {"threshold": threshold, "field": field, "expected": expected}


def _optional_string(container: dict[str, Any], key: str) -> str | None:
    """Повертає рядок за ключем, None якщо ключа немає; інакше ValueError."""
    if key not in container:
        return None
    value = container[key]
    _require(
        isinstance(value, str) and bool(value),
        f"Поле {key} має бути непорожнім рядком.",
    )
    return value


def _select_description(cve: dict[str, Any]) -> str | None:
    """Перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    _require(isinstance(descriptions, list), "Поле descriptions має бути списком.")
    selected: str | None = None
    for item in descriptions:
        _require(isinstance(item, dict), "Елементи descriptions мають бути об'єктами.")
        lang, value = item.get("lang"), item.get("value")
        _require(
            isinstance(lang, str) and isinstance(value, str),
            "Поля lang і value в descriptions мають бути рядками.",
        )
        if selected is None and lang == "en" and value:
            selected = value
    return selected


def _select_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає першу оцінку Primary, інакше першу; None, якщо оцінок немає."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _require(isinstance(metrics, dict), "Поле metrics має бути об'єктом.")
    if "cvssMetricV31" not in metrics:
        return None
    items = metrics["cvssMetricV31"]
    _require(isinstance(items, list), "Поле cvssMetricV31 має бути списком.")
    if not items:
        return None
    _require(
        all(isinstance(item, dict) for item in items),
        "Елементи cvssMetricV31 мають бути об'єктами.",
    )
    for item in items:
        if item.get("type") == "Primary":
            return item
    return items[0]


def _validate_score(score: Any) -> float | int:
    """Перевіряє baseScore: скінченне число 0–10, не bool."""
    _require(
        isinstance(score, (int, float)) and not isinstance(score, bool),
        "Поле baseScore має бути числом.",
    )
    _require(
        math.isfinite(score) and 0 <= score <= 10,
        "Поле baseScore має бути скінченним числом від 0 до 10.",
    )
    return score


def extract_record(payload: Any, cve_id: str) -> Record | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    Внутрішній запис — словник із ключами:
      cve_id, vuln_status (str | None), description (str | None),
      cvss_version ("3.1" | None), score (число | None),
      score_source (str | None), vector (str | None),
      cvss_data — копія наявних серед восьми метрик полів вибраної оцінки
      (attackVector, ..., availabilityImpact) у вихідному вигляді.
    Для Rejected і відсутнього статусу оцінки не аналізуються.
    Порушення контракту піднімають ValueError.
    """
    _require(isinstance(payload, dict), "Відповідь NVD має бути JSON-об'єктом.")
    vulnerabilities = payload.get("vulnerabilities")
    _require(
        isinstance(vulnerabilities, list), "Поле vulnerabilities має бути списком."
    )
    if not vulnerabilities:
        return None
    _require(
        len(vulnerabilities) == 1,
        "Для точного cveId очікується не більше одного запису.",
    )
    item = vulnerabilities[0]
    _require(
        isinstance(item, dict) and isinstance(item.get("cve"), dict),
        "Елемент vulnerabilities має містити об'єкт cve.",
    )
    cve = item["cve"]
    _require(
        cve.get("id") == cve_id,
        "Ідентифікатор у відповіді не збігається із запитаним.",
    )

    status = _optional_string(cve, "vulnStatus")
    record: Record = {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": _select_description(cve),
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": {},
    }
    if status is None or status == REJECTED_STATUS:
        return record

    selected = _select_metric(cve)
    if selected is None:
        return record
    cvss_data = selected.get("cvssData")
    _require(isinstance(cvss_data, dict), "Поле cvssData має бути об'єктом.")
    record["score"] = _validate_score(cvss_data.get("baseScore"))
    version = _optional_string(cvss_data, "version")
    _require(
        version is None or version == CVSS_VERSION,
        "Підтримується лише CVSS версії 3.1.",
    )
    record["cvss_version"] = version
    record["vector"] = _optional_string(cvss_data, "vectorString")
    record["score_source"] = _optional_string(selected, "source")
    record["cvss_data"] = {k: cvss_data[k] for k in ALLOWED_VALUES if k in cvss_data}
    return record


def build_report(record: Record | None, cve_id: str, variant: int) -> Report:
    """Застосовує правило варіанта до запису й повертає словник звіту."""
    rule = get_rule(variant)
    report: Report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == REJECTED_STATUS:
        report["decision"] = "rejected"
        return report
    if record["vuln_status"] is None or record["score"] is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = record["cvss_version"]
    report["score"] = record["score"]
    report["score_source"] = record["score_source"]
    report["vector"] = record["vector"]
    field = rule["field"]
    if field not in record["cvss_data"]:
        report["decision"] = "insufficient_data"
        return report

    observed = record["cvss_data"][field]
    _require(
        isinstance(observed, str) and observed in ALLOWED_VALUES[field],
        f"Поле {field} має недопустиме значення.",
    )
    report["observed"] = observed
    matches = record["score"] >= rule["threshold"] and observed == rule["expected"]
    report["decision"] = "review" if matches else "other"
    return report
