"""HTTP-клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

from __future__ import annotations

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервіс повернув HTTP-статус, відмінний від очікуваного 200."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Unexpected HTTP status: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту; apiKey додається, лише якщо ключ заданий."""
    headers = {"Accept": "application/json"}
    api_key = (os.getenv("NVD_API_KEY") or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD і повертає декодований JSON.

    Мережеві винятки Requests, HTTPError та JSONDecodeError не перехоплюються:
    їх обробляє командний інтерфейс. Статус, відмінний від 200, піднімає
    UnexpectedStatusError.
    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
