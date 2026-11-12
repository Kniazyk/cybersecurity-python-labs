"""Тести командного інтерфейсу: локальний режим, помилки, коди завершення."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main
from labs.lab04.tests.helpers import CVE_ID

SAMPLE_REPORT_10 = {
    "cve_id": "CVE-2099-10001",
    "variant": 10,
    "description": "Synthetic vulnerability for offline API testing.",
    "vuln_status": "Analyzed",
    "cvss_version": "3.1",
    "score": 9.8,
    "score_source": "nvd@nist.gov",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rule": {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    "observed": "NONE",
    "decision": "other",
}


def run_main(capsys, argv):
    code = main.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_json(tmp_path, data, name="response.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def forbid_network(monkeypatch):
    fake_fetch = Mock(side_effect=AssertionError("network must not be used"))
    fake_get = Mock(side_effect=AssertionError("network must not be used"))
    monkeypatch.setattr(main.api_client, "fetch_response", fake_fetch)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_fetch, fake_get


def test_local_mode_prints_report_without_network(monkeypatch, capsys, sample_path):
    fake_fetch, fake_get = forbid_network(monkeypatch)
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(sample_path)])
    assert code == 0
    assert err == ""
    assert json.loads(out) == SAMPLE_REPORT_10
    fake_fetch.assert_not_called()
    fake_get.assert_not_called()


def test_other_variant_is_taken_from_imported_name(monkeypatch, capsys, sample_path):
    monkeypatch.setattr(main, "VARIANT_NUMBER", 1)
    code, out, _ = run_main(capsys, ["--cve", CVE_ID, "--input", str(sample_path)])
    report = json.loads(out)
    assert code == 0
    assert report["variant"] == 1
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "attackVector",
        "expected": "NETWORK",
    }
    assert report["decision"] == "review"


def test_output_keeps_non_ascii_characters(capsys, tmp_path, sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "en", "value": "Тестовий опис"}
    ]
    path = write_json(tmp_path, sample_payload)
    code, out, _ = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    assert code == 0
    assert "Тестовий опис" in out
    assert "\\u" not in out


def test_not_found_exits_with_zero(capsys, tmp_path):
    path = write_json(tmp_path, {"vulnerabilities": []})
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    report = json.loads(out)
    assert (code, err) == (0, "")
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID


def test_rejected_exits_with_zero(capsys, tmp_path, sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    path = write_json(tmp_path, sample_payload)
    code, out, _ = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    assert code == 0
    assert json.loads(out)["decision"] == "rejected"


def test_invalid_json_file_reports_error(capsys, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    assert code == 1
    assert out == ""
    assert "JSON" in err
    assert "Traceback" not in err


def test_missing_file_reports_error(capsys, tmp_path):
    path = tmp_path / "missing.json"
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    assert code == 1
    assert out == ""
    assert "Помилка" in err
    assert "Traceback" not in err


def test_directory_as_input_reports_error(capsys, tmp_path):
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(tmp_path)])
    assert (code, out) == (1, "")
    assert "Traceback" not in err


def test_non_utf8_file_reports_error(capsys, tmp_path):
    path = tmp_path / "latin.json"
    path.write_bytes(b'{"a": "\xff\xfe"}')
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    assert (code, out) == (1, "")
    assert "UTF-8" in err


@pytest.mark.parametrize("content", [{}, [], {"vulnerabilities": "x"}])
def test_invalid_structure_reports_error(capsys, tmp_path, content):
    path = write_json(tmp_path, content)
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(path)])
    assert (code, out) == (1, "")
    assert "перевірки даних" in err


@pytest.mark.parametrize("cve", ["CVE-2099-10002", "CVE-2099-1234567"])
def test_valid_cve_with_mismatching_file_reports_error(capsys, sample_path, cve):
    code, out, err = run_main(capsys, ["--cve", cve, "--input", str(sample_path)])
    assert (code, out) == (1, "")
    assert "перевірки даних" in err


@pytest.mark.parametrize(
    "cve",
    [
        "cve-2099-10001",
        "CVE-99-10001",
        "CVE-2099-123",
        "CVE-2099-ABCD",
        "CVE-2099-10001 ",
        "CVE-2099-10001\n",
        " CVE-2099-10001",
        "XCVE-2099-10001",
        "CVE-2099-10001-1",
        "",
    ],
)
def test_invalid_cve_format_exits_with_2(capsys, sample_path, cve):
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", cve, "--input", str(sample_path)])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err != ""


def test_missing_cve_exits_with_2(capsys, sample_path):
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--input", str(sample_path)])
    assert exc_info.value.code == 2
    assert capsys.readouterr().err != ""


@pytest.mark.parametrize("variant", [0, 16, -1, True, "10", 10.0, None])
def test_invalid_variant_returns_2(monkeypatch, capsys, sample_path, variant):
    fake_fetch, _ = forbid_network(monkeypatch)
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    code, out, err = run_main(capsys, ["--cve", CVE_ID, "--input", str(sample_path)])
    assert code == 2
    assert out == ""
    assert "VARIANT_NUMBER" in err
    fake_fetch.assert_not_called()


def test_network_mode_calls_fetch_with_cve(monkeypatch, capsys, sample_payload):
    fake_fetch = Mock(return_value=sample_payload)
    monkeypatch.setattr(main.api_client, "fetch_response", fake_fetch)
    code, out, err = run_main(capsys, ["--cve", CVE_ID])
    assert (code, err) == (0, "")
    assert json.loads(out) == SAMPLE_REPORT_10
    fake_fetch.assert_called_once_with(CVE_ID)


def http_error(status_code):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    return requests.exceptions.HTTPError("secret-detail", response=response)


@pytest.mark.parametrize(
    "error, expected_text",
    [
        (requests.exceptions.ConnectionError("secret-detail"), "з'єднання"),
        (requests.exceptions.ConnectTimeout("secret-detail"), "час очікування"),
        (requests.exceptions.ReadTimeout("secret-detail"), "час очікування"),
        (http_error(404), "404"),
        (http_error(503), "503"),
        (api_client.UnexpectedStatusError(204), "204"),
        (requests.exceptions.JSONDecodeError("secret-detail", "{", 1), "JSON"),
        (requests.exceptions.RequestException("secret-detail"), "запит"),
    ],
)
def test_network_errors_give_exit_1_and_safe_message(
    monkeypatch, capsys, error, expected_text
):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    monkeypatch.setattr(main.api_client, "fetch_response", Mock(side_effect=error))
    code, out, err = run_main(capsys, ["--cve", CVE_ID])
    assert code == 1
    assert out == ""
    assert expected_text in err
    assert "secret-detail" not in err
    assert "fake-key-123" not in err
    assert "Traceback" not in err
    assert "not_found" not in err


def test_real_client_http_500_does_not_leak_key_or_body(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    response = Mock(spec=requests.Response)
    response.status_code = 500
    response.text = "SECRET-BODY"
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Server Error: SECRET-BODY", response=response
    )
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    code, out, err = run_main(capsys, ["--cve", CVE_ID])
    assert (code, out) == (1, "")
    assert "500" in err
    for secret in ("fake-key-123", "SECRET-BODY", "apiKey"):
        assert secret not in err
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == "fake-key-123"


def test_real_client_success_through_cli(monkeypatch, capsys, sample_payload):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = sample_payload
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    code, out, err = run_main(capsys, ["--cve", CVE_ID])
    assert (code, err) == (0, "")
    assert json.loads(out) == SAMPLE_REPORT_10
    assert fake_get.call_args.kwargs["params"] == {"cveId": CVE_ID}
    assert "apiKey" not in fake_get.call_args.kwargs["headers"]


def run_module(args):
    repo_root = Path(__file__).resolve().parents[3]
    env = {k: v for k, v in os.environ.items() if k != "NVD_API_KEY"}
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "labs.lab04.main", *args],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_module_entry_point_success(sample_path):
    result = run_module(["--cve", CVE_ID, "--input", str(sample_path)])
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == SAMPLE_REPORT_10


def test_module_entry_point_error_code(tmp_path):
    missing = tmp_path / "missing.json"
    result = run_module(["--cve", CVE_ID, "--input", str(missing)])
    assert result.returncode == 1
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


def test_module_entry_point_argument_error():
    assert run_module(["--cve", "bad"]).returncode == 2
