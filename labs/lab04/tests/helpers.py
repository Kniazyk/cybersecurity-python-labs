"""Допоміжні функції для побудови тестових відповідей NVD."""

from typing import Any

CVE_ID = "CVE-2099-10001"
DELETE = object()


def make_metric(
    score: Any = 9.8,
    privileges: Any = "LOW",
    *,
    type_: str = "Primary",
    source: str = "nvd@nist.gov",
) -> dict[str, Any]:
    """Елемент cvssMetricV31 з повним набором полів cvssData."""
    return {
        "source": source,
        "type": type_,
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": privileges,
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "baseScore": score,
        },
    }


def make_payload(
    metrics: list[Any] | None = None,
    *,
    status: str | None = "Analyzed",
    cve_id: str = CVE_ID,
) -> dict[str, Any]:
    """Мінімальна відповідь NVD з одним записом (status=None — без статусу)."""
    cve: dict[str, Any] = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": "Test description."}],
    }
    if status is not None:
        cve["vulnStatus"] = status
    if metrics is not None:
        cve["metrics"] = {"cvssMetricV31": metrics}
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": cve}],
    }


def cve_of(payload: dict[str, Any]) -> dict[str, Any]:
    """Об'єкт cve першого запису."""
    return payload["vulnerabilities"][0]["cve"]


def first_metric(payload: dict[str, Any]) -> dict[str, Any]:
    """Перша оцінка cvssMetricV31."""
    return cve_of(payload)["metrics"]["cvssMetricV31"][0]


def cvss_data(payload: dict[str, Any]) -> dict[str, Any]:
    """cvssData першої оцінки."""
    return first_metric(payload)["cvssData"]


def mutate(payload: dict[str, Any], where: str, key: str, value: Any) -> None:
    """Змінює (або видаляє, якщо value is DELETE) поле в частині payload."""
    targets = {
        "root": payload,
        "item": payload["vulnerabilities"][0],
        "cve": cve_of(payload),
        "metrics": cve_of(payload).get("metrics"),
        "metric": first_metric(payload) if "metrics" in cve_of(payload) else None,
        "cvss": cvss_data(payload) if "metrics" in cve_of(payload) else None,
    }
    target = targets[where]
    if value is DELETE:
        del target[key]
    else:
        target[key] = value
