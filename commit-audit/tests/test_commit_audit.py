import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from worker.workflows.commit_audit import (
    CommitAudit,
    Finding,
    build_report,
    commits_between,
    parse_audit_json,
    truncate_patch,
)


def _commit(sha: str) -> dict:
    return {"sha": sha}


def test_truncate_patch_short_is_kept():
    assert truncate_patch("abc") == "abc"


def test_truncate_patch_long_is_cut():
    out = truncate_patch("x" * 5000, limit=100)
    assert len(out) < 5000 and out.endswith("[truncated]")


def test_truncate_patch_none():
    assert truncate_patch(None) == ""


def test_commits_between_stops_at_since_and_reverses():
    commits = [_commit("c"), _commit("b"), _commit("a")]  # newest first from API
    out = commits_between(commits, "a", 10)
    assert [c["sha"] for c in out] == ["b", "c"]


def test_commits_between_without_since_takes_max():
    commits = [_commit("c"), _commit("b"), _commit("a")]
    out = commits_between(commits, None, 2)
    assert [c["sha"] for c in out] == ["b", "c"]


def test_parse_audit_json_plain():
    parsed = parse_audit_json('{"risk": "low", "findings": []}')
    assert parsed["risk"] == "low"


def test_parse_audit_json_embedded_in_prose():
    parsed = parse_audit_json('Here you go:\n{"risk": "high", "summary": "x"}\nthanks')
    assert parsed["risk"] == "high"


def test_parse_audit_json_invalid_raises():
    try:
        parse_audit_json("no json at all")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_build_report_empty():
    report = build_report("o", "r", "main", [], "head", "since")
    assert "No new commits" in report
    assert "since..head" in report


def test_build_report_with_finding():
    audit = CommitAudit(
        sha="abc123",
        short="abc123",
        message="fix: thing",
        author="dev",
        date="2026-11-10T10:00:00Z",
        files=["apps/api/src/x.ts"],
        risk="high",
        summary="bad",
        findings=[Finding(severity="high", area="auth", description="bypass", files=["x.ts"])],
        verdict="block",
        pr={"number": 1, "checks": [{"name": "CI", "conclusion": "failure"}]},
    )
    report = build_report("o", "r", "main", [audit], "head", "since")
    assert "`abc123`" in report
    assert "**high**" in report
    assert "bypass" in report
    assert "PR #1" in report and "CI" in report
