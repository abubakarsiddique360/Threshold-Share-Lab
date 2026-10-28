import json

import pytest

from threshold_share_lab.cli import main
from threshold_share_lab.experiments import (
    below_threshold_spread,
    size_table,
    subset_count_table,
    verify_all_subsets,
)
from threshold_share_lab.report import (
    render_below_threshold,
    render_json,
    render_shares,
    render_size_table,
    render_subset_report,
    render_summary,
)

SECRET = b"a-shared-secret"


def test_verify_all_subsets_is_total():
    report = verify_all_subsets(SECRET, threshold=3, shares=6)
    assert report.subsets_tested == 20
    assert report.subsets_ok == 20
    assert report.success == 1.0


def test_verify_respects_limit():
    report = verify_all_subsets(SECRET, threshold=2, shares=5, limit=3)
    assert report.subsets_tested == 3


def test_below_threshold_produces_distinct_wrong_secrets():
    distinct = below_threshold_spread(SECRET, threshold=3, shares=5, trials=24)
    assert distinct >= 20


def test_size_table_shape():
    rows = size_table((16,), (2, 3))
    assert len(rows) == 2
    assert rows[0]["share_bytes"] == 17
    assert rows[1]["combinations"] == 10


def test_subset_count_table():
    assert subset_count_table(5, 3) == 10
    assert subset_count_table(5, 1) == 5


def test_reports_render():
    from threshold_share_lab.shamir import split as split_secret

    report = verify_all_subsets(SECRET, threshold=3, shares=5)
    assert "Subset verification" in render_subset_report(report)
    assert "share x=1" in render_shares(split_secret(SECRET, threshold=2, shares=3))
    assert "expansion" in render_size_table(size_table())
    assert "distinct results" in render_below_threshold([(2, 32, 31)])
    assert "Split summary" in render_summary(SECRET, 3, 5)
    assert json.loads(render_json({"a": 1}))["a"] == 1


def test_cli_split_text(capsys):
    assert main(["split", "--secret", "hello", "-k", "2", "-n", "3"]) == 0
    output = capsys.readouterr().out
    assert "2 of 3" in output
    assert "share x=3" in output


def test_cli_split_json(capsys):
    assert main(["split", "--secret", "hello", "-k", "2", "-n", "3", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["threshold"] == 2
    assert len(payload["shares_hex"]) == 3


def test_cli_split_hex_secret(capsys):
    assert main(["split", "--secret-hex", "00112233", "-k", "2", "-n", "2"]) == 0
    assert "4 bytes" in capsys.readouterr().out


def test_cli_split_random_secret_is_sized(capsys):
    assert main(["split", "--secret-bytes", "24", "-k", "2", "-n", "3"]) == 0
    assert "24 bytes" in capsys.readouterr().out


def test_cli_split_bad_hex(capsys):
    assert main(["split", "--secret-hex", "zz", "-k", "2", "-n", "3"]) == 2
    assert "not hex" in capsys.readouterr().err


def test_cli_split_bad_parameters(capsys):
    assert main(["split", "--secret", "x", "-k", "1", "-n", "3"]) == 2
    assert "at least 2" in capsys.readouterr().err


def test_cli_verify(capsys):
    assert main(["verify", "--secret", "hello", "-k", "3", "-n", "5"]) == 0
    output = capsys.readouterr().out
    assert "10" in output
    assert "100.0%" in output


def test_cli_verify_json(capsys):
    assert main(["verify", "--secret", "hello", "-k", "2", "-n", "4", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["subsets_ok"] == payload["subsets_tested"] == 6


@pytest.fixture
def shares_text(capsys):
    assert main(["split", "--secret", "recover-me", "-k", "3", "-n", "4", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    return [f"{entry['x']}:{entry['payload']}" for entry in payload["shares_hex"]]


def test_cli_combine_round_trip(shares_text, capsys):
    argv = ["combine"]
    for share in shares_text[:3]:
        argv.extend(["--share", share])
    assert main(argv) == 0
    assert capsys.readouterr().out.strip() == "recover-me"


def test_cli_combine_bad_share(capsys):
    assert main(["combine", "--share", "bad"]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_sizes(capsys):
    assert main(["sizes"]) == 0
    assert "expansion" in capsys.readouterr().out


def test_cli_sizes_json(capsys):
    assert main(["sizes", "--format", "json"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), list)


def test_cli_below_threshold(capsys):
    assert main(["below-threshold", "-k", "3", "-n", "5", "--trials", "8"]) == 0
    assert "distinct results" in capsys.readouterr().out


def test_cli_below_threshold_bad_parameters(capsys):
    assert main(["below-threshold", "-k", "1", "-n", "5"]) == 2
    assert "error:" in capsys.readouterr().err
