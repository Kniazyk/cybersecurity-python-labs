"""Тести перевірки даних і правила варіанта 10."""

import copy
import json

import pytest

from labs.lab04 import analysis
from labs.lab04.tests.helpers import (
    CVE_ID,
    DELETE,
    cve_of,
    cvss_data,
    make_metric,
    make_payload,
    mutate,
)

REPORT_KEYS = {
    "cve_id",
    "variant",
    "description",
    "vuln_status",
    "cvss_version",
    "score",
    "score_source",
    "vector",
    "rule",
    "observed",
    "decision",
}
RULE_10 = {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"}


def run(payload, variant=10, cve_id=CVE_ID):
    record = analysis.extract_record(payload, cve_id)
    return analysis.build_report(record, cve_id, variant)


@pytest.mark.parametrize(
    "score, privileges, expected",
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (6, "LOW", "review"),
        (6.1, "LOW", "review"),
        (9.8, "LOW", "review"),
        (0, "LOW", "other"),
        (10, "LOW", "review"),
        (9.8, "NONE", "other"),
        (9.8, "HIGH", "other"),
        (6.0, "NONE", "other"),
        (5.9, "NONE", "other"),
    ],
)
def test_decision_by_threshold_and_privileges(score, privileges, expected):
    payload = make_payload([make_metric(score, privileges)])
    assert run(payload)["decision"] == expected


def test_full_report_for_review():
    payload = make_payload([make_metric(6.0, "LOW")])
    assert run(payload) == {
        "cve_id": CVE_ID,
        "variant": 10,
        "description": "Test description.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 6.0,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "rule": RULE_10,
        "observed": "LOW",
        "decision": "review",
    }


def test_not_found_has_null_data_fields():
    report = run({"vulnerabilities": []})
    assert set(report) == REPORT_KEYS
    assert report == {
        "cve_id": CVE_ID,
        "variant": 10,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE_10,
        "observed": None,
        "decision": "not_found",
    }


def test_extract_returns_none_for_empty_results():
    assert analysis.extract_record({"vulnerabilities": []}, CVE_ID) is None


def test_rejected_ignores_high_score():
    payload = make_payload([make_metric(9.8, "LOW")], status="Rejected")
    report = run(payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Test description."
    for key in ("cvss_version", "score", "score_source", "vector", "observed"):
        assert report[key] is None


def test_rejected_does_not_validate_scores():
    payload = make_payload([make_metric("not-a-number", "LOW")], status="Rejected")
    assert run(payload)["decision"] == "rejected"


def test_missing_status_is_insufficient_without_score_analysis():
    payload = make_payload([make_metric(9.8, "LOW")], status=None)
    report = run(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] == "Test description."
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize(
    "where, key, value",
    [
        ("cve", "metrics", DELETE),
        ("cve", "metrics", {}),
        ("metrics", "cvssMetricV31", DELETE),
        ("metrics", "cvssMetricV31", []),
    ],
)
def test_missing_scores_are_insufficient_data(where, key, value):
    payload = make_payload([make_metric(9.8, "LOW")])
    mutate(payload, where, key, value)
    report = run(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None
    assert report["observed"] is None


def test_only_other_cvss_versions_is_insufficient_data():
    payload = make_payload()
    cve_of(payload)["metrics"] = {"cvssMetricV30": [make_metric(9.8, "LOW")]}
    assert run(payload)["decision"] == "insufficient_data"


def test_missing_required_field_is_insufficient_data_with_score():
    payload = make_payload([make_metric(9.8, "LOW")])
    del cvss_data(payload)["privilegesRequired"]
    report = run(payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


@pytest.mark.parametrize("bad", [None, "MEDIUM", "low", 5, True, ["LOW"], ""])
def test_invalid_required_field_raises(bad):
    payload = make_payload([make_metric(9.8, bad)])
    with pytest.raises(ValueError):
        run(payload)


def test_invalid_value_of_other_field_is_ignored():
    payload = make_payload([make_metric(9.8, "LOW")])
    cvss_data(payload)["attackVector"] = "SOMETHING_ELSE"
    assert run(payload)["decision"] == "review"


def test_primary_has_priority_over_earlier_secondary():
    payload = make_payload(
        [
            make_metric(9.9, "NONE", type_="Secondary", source="other@example.com"),
            make_metric(6.5, "LOW", type_="Primary", source="nvd@nist.gov"),
        ]
    )
    report = run(payload)
    assert report["decision"] == "review"
    assert report["score"] == 6.5
    assert report["score_source"] == "nvd@nist.gov"


def test_first_score_is_used_without_primary():
    payload = make_payload(
        [
            make_metric(7.0, "LOW", type_="Secondary", source="a@example.com"),
            make_metric(5.0, "NONE", type_="Secondary", source="b@example.com"),
        ]
    )
    report = run(payload)
    assert report["score"] == 7.0
    assert report["score_source"] == "a@example.com"
    assert report["decision"] == "review"


def test_first_of_several_primary_is_used():
    payload = make_payload(
        [
            make_metric(5.0, "LOW", source="first@example.com"),
            make_metric(9.0, "LOW", source="second@example.com"),
        ]
    )
    report = run(payload)
    assert report["score"] == 5.0
    assert report["decision"] == "other"


def test_score_and_field_come_from_same_selected_score():
    payload = make_payload(
        [
            make_metric(9.0, "NONE", type_="Primary"),
            make_metric(9.0, "LOW", type_="Secondary"),
        ]
    )
    report = run(payload)
    assert report["observed"] == "NONE"
    assert report["decision"] == "other"


def test_description_prefers_first_non_empty_english():
    payload = make_payload([make_metric()])
    cve_of(payload)["descriptions"] = [
        {"lang": "es", "value": "Hola"},
        {"lang": "en", "value": ""},
        {"lang": "en", "value": "Second"},
        {"lang": "en", "value": "Third"},
    ]
    assert run(payload)["description"] == "Second"


def test_description_without_english_or_field_is_none():
    payload = make_payload([make_metric()])
    cve_of(payload)["descriptions"] = [{"lang": "es", "value": "Hola"}]
    assert run(payload)["description"] is None
    del cve_of(payload)["descriptions"]
    assert run(payload)["description"] is None


NAN = float("nan")
INF = float("inf")

INVALID_PAYLOADS = [
    pytest.param("cvss", "baseScore", "9.8", id="score-string"),
    pytest.param("cvss", "baseScore", True, id="score-true"),
    pytest.param("cvss", "baseScore", False, id="score-false"),
    pytest.param("cvss", "baseScore", None, id="score-null"),
    pytest.param("cvss", "baseScore", NAN, id="score-nan"),
    pytest.param("cvss", "baseScore", INF, id="score-inf"),
    pytest.param("cvss", "baseScore", -INF, id="score-minus-inf"),
    pytest.param("cvss", "baseScore", -0.1, id="score-below-0"),
    pytest.param("cvss", "baseScore", 10.1, id="score-above-10"),
    pytest.param("cvss", "baseScore", [9.8], id="score-list"),
    pytest.param("cvss", "baseScore", DELETE, id="score-missing"),
    pytest.param("cvss", "version", "3.0", id="version-3.0"),
    pytest.param("cvss", "version", 3.1, id="version-number"),
    pytest.param("cvss", "version", None, id="version-null"),
    pytest.param("cvss", "version", "", id="version-empty"),
    pytest.param("cvss", "vectorString", "", id="vector-empty"),
    pytest.param("cvss", "vectorString", None, id="vector-null"),
    pytest.param("cvss", "vectorString", 5, id="vector-number"),
    pytest.param("metric", "source", "", id="source-empty"),
    pytest.param("metric", "source", None, id="source-null"),
    pytest.param("metric", "cvssData", None, id="cvssData-null"),
    pytest.param("metric", "cvssData", [], id="cvssData-list"),
    pytest.param("metric", "cvssData", DELETE, id="cvssData-missing"),
    pytest.param("cve", "metrics", None, id="metrics-null"),
    pytest.param("cve", "metrics", [], id="metrics-list"),
    pytest.param("metrics", "cvssMetricV31", None, id="v31-null"),
    pytest.param("metrics", "cvssMetricV31", {}, id="v31-dict"),
    pytest.param("metrics", "cvssMetricV31", "x", id="v31-string"),
    pytest.param("metrics", "cvssMetricV31", [1], id="v31-item-not-object"),
    pytest.param("cve", "vulnStatus", "", id="status-empty"),
    pytest.param("cve", "vulnStatus", None, id="status-null"),
    pytest.param("cve", "vulnStatus", 5, id="status-number"),
    pytest.param("cve", "descriptions", "text", id="descriptions-string"),
    pytest.param("cve", "descriptions", None, id="descriptions-null"),
    pytest.param("cve", "descriptions", [1], id="descriptions-item-not-object"),
    pytest.param("cve", "descriptions", [{"lang": "en"}], id="description-no-value"),
    pytest.param("cve", "descriptions", [{"value": "x"}], id="description-no-lang"),
    pytest.param(
        "cve", "descriptions", [{"lang": 1, "value": "x"}], id="description-lang-int"
    ),
    pytest.param(
        "cve", "descriptions", [{"lang": "en", "value": None}], id="description-null"
    ),
    pytest.param("cve", "id", "CVE-2099-10002", id="id-mismatch"),
    pytest.param("cve", "id", DELETE, id="id-missing"),
    pytest.param("item", "cve", None, id="cve-null"),
    pytest.param("item", "cve", DELETE, id="cve-missing"),
    pytest.param("root", "vulnerabilities", None, id="vulnerabilities-null"),
    pytest.param("root", "vulnerabilities", {}, id="vulnerabilities-dict"),
    pytest.param("root", "vulnerabilities", ["x"], id="vulnerability-not-object"),
    pytest.param("root", "vulnerabilities", DELETE, id="vulnerabilities-missing"),
]


@pytest.mark.parametrize("where, key, value", INVALID_PAYLOADS)
def test_contract_violations_raise_value_error(where, key, value):
    payload = make_payload([make_metric(9.8, "LOW")])
    mutate(payload, where, key, value)
    with pytest.raises(ValueError):
        run(payload)


@pytest.mark.parametrize("payload", [None, [], "text", 5, {}])
def test_non_object_or_empty_payload_raises(payload):
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_more_than_one_record_raises():
    payload = make_payload([make_metric()])
    payload["vulnerabilities"].append(copy.deepcopy(payload["vulnerabilities"][0]))
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


@pytest.mark.parametrize("variant", [0, 16, -1, True, "10", 10.0, None])
def test_invalid_variant_raises(variant):
    record = analysis.extract_record(make_payload([make_metric()]), CVE_ID)
    with pytest.raises(ValueError):
        analysis.build_report(record, CVE_ID, variant)


def test_functions_do_not_mutate_payload(sample_payload):
    before = copy.deepcopy(sample_payload)
    run(sample_payload)
    assert sample_payload == before


def test_report_is_json_serializable_with_all_keys(sample_payload):
    report = run(sample_payload)
    assert set(report) == REPORT_KEYS
    assert json.loads(json.dumps(report, ensure_ascii=False)) == report


def test_sample_report_for_variant_10(sample_payload):
    assert run(sample_payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 10,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": RULE_10,
        "observed": "NONE",
        "decision": "other",
    }


@pytest.mark.parametrize(
    "variant, expected",
    [(v, "review") for v in range(1, 8)] + [(v, "other") for v in range(8, 16)],
)
def test_sample_decisions_for_all_variants(sample_payload, variant, expected):
    assert run(sample_payload, variant)["decision"] == expected
