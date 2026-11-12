"""Тести HTTP-клієнта: підміняється requests.get, мережа не використовується."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAYLOAD = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}


def make_response(status_code=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = PAYLOAD if payload is None else payload
    return response


def patch_get(monkeypatch, **kwargs):
    fake_get = Mock(**kwargs)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", " ", "   \t\n"])
def test_blank_key_means_no_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key_use_api_key_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_key_is_stripped(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123 \n")
    assert api_client.build_headers()["apiKey"] == "fake-key-123"


def test_key_is_read_at_call_time(monkeypatch):
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    assert "apiKey" in api_client.build_headers()
    monkeypatch.delenv("NVD_API_KEY")
    assert "apiKey" not in api_client.build_headers()


def test_fetch_uses_expected_request(monkeypatch):
    response = make_response()
    fake_get = patch_get(monkeypatch, return_value=response)
    assert api_client.fetch_response("CVE-2099-10001") == PAYLOAD
    fake_get.assert_called_once_with(
        URL,
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_fake_key_only_in_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    fake_get = patch_get(monkeypatch, return_value=make_response())
    api_client.fetch_response("CVE-2099-10001")
    args, kwargs = fake_get.call_args
    assert kwargs["headers"] == {"Accept": "application/json", "apiKey": "fake-key-123"}
    assert kwargs["params"] == {"cveId": "CVE-2099-10001"}
    assert "fake-key-123" not in str(args)
    assert "fake-key-123" not in str(kwargs["params"])


def test_http_error_is_raised_and_body_not_decoded(monkeypatch):
    response = make_response(status_code=404)
    error = requests.exceptions.HTTPError("404", response=response)
    response.raise_for_status.side_effect = error
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.response.status_code == 404
    response.json.assert_not_called()


@pytest.mark.parametrize("status_code", [204, 301, 304])
def test_unexpected_non_error_status_raises(monkeypatch, status_code):
    response = make_response(status_code=status_code)
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(api_client.UnexpectedStatusError) as exc_info:
        api_client.fetch_response("CVE-2099-10001")
    assert exc_info.value.status_code == status_code
    response.json.assert_not_called()


def test_invalid_json_raises(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, return_value=response)
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError("boom"),
        requests.exceptions.ConnectTimeout("boom"),
        requests.exceptions.ReadTimeout("boom"),
    ],
)
def test_network_errors_propagate(monkeypatch, error):
    patch_get(monkeypatch, side_effect=error)
    with pytest.raises(type(error)):
        api_client.fetch_response("CVE-2099-10001")


def test_real_requests_are_blocked_by_fixture():
    with pytest.raises(AttributeError):
        requests.get("https://example.invalid/")
