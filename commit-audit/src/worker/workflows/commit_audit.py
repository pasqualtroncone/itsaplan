import json
import os
import re
from typing import Any

import httpx
import pydantic
import mistralai.workflows as workflows

GITHUB_API = "https://api.github.com"
AUDIT_MODEL = os.environ.get("AUDIT_MODEL", "mistral-large-latest")
MAX_DIFF_CHARS = 60_000
MAX_FILE_PATCH_CHARS = 4_000
STATE_PATH = "commit-audit/state.json"

AUDIT_SYSTEM_PROMPT = """You are a security and correctness reviewer for commits landing in the main branch of a production, self-hosted issue tracker (TypeScript, Bun, Elysia API + Next.js web + PostgreSQL).

Review the commit (message, changed files, diff) and report only real issues. Look for:
- auth/authorization bypasses, permission checks that can be skipped, public share/link access-control or expiry flaws
- XSS: dangerouslySetInnerHTML / innerHTML without sanitization on user-controlled content
- SQL injection: raw SQL built by string concatenation instead of parameterized queries
- SSRF: server-side fetch of a user-supplied URL that bypasses the SSRF guard (@repo/net)
- hardcoded secrets, tokens, keys in code or tests that look real
- race conditions on state-changing writes (read-then-write without a guard)
- logical contradictions between related checks (e.g. a feature flag checked in one place but not the other)
- unsafe migrations (non-additive changes, data rewrites without backup)
- CI status of the linked PR: note if required checks (Test suite, CodeQL) are missing or failed

Return ONLY a JSON object, no prose:
{"risk": "high|medium|low|info", "summary": "one or two sentences", "findings": [{"severity": "high|medium|low|info", "area": "auth|share|email|xss|sql|ssrf|secrets|race|logic|migration|ci|other", "description": "what and why, with file references", "files": ["path"] }], "verdict": "safe|needs-attention|block"}

If nothing notable: risk "info", empty findings, verdict "safe".
"""


class AuditInput(pydantic.BaseModel):
    owner: str = "croffasia"
    repo: str = "itsaplan"
    branch: str = "main"
    since_sha: str | None = None
    max_commits: int = 10


class Finding(pydantic.BaseModel):
    severity: str
    area: str
    description: str
    files: list[str] = []


class CommitAudit(pydantic.BaseModel):
    sha: str
    short: str
    message: str
    author: str
    date: str
    files: list[str]
    risk: str = "info"
    summary: str = ""
    findings: list[Finding] = []
    verdict: str = "safe"
    pr: dict[str, Any] | None = None


class AuditOutput(pydantic.BaseModel):
    report: str
    new_head: str
    commits_reviewed: int
    high_findings: int
    state_saved: bool


def gh_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "itsaplan-commit-audit",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def gh_get(client: httpx.AsyncClient, path: str, params: dict | None = None) -> Any:
    resp = await client.get(f"{GITHUB_API}{path}", params=params, headers=gh_headers(), timeout=30)
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise RuntimeError("GitHub API rate limit exceeded; set GITHUB_TOKEN")
    resp.raise_for_status()
    return resp.json()


async def gh_put(
    client: httpx.AsyncClient, path: str, body: dict, params: dict | None = None
) -> Any:
    resp = await client.put(
        f"{GITHUB_API}{path}", params=params, headers=gh_headers(), json=body, timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def truncate_patch(patch: str | None, limit: int = MAX_FILE_PATCH_CHARS) -> str:
    if not patch:
        return ""
    return patch if len(patch) <= limit else patch[:limit] + "\n... [truncated]"


def commits_between(
    commits: list[dict], since_sha: str | None, max_commits: int
) -> list[dict]:
    out: list[dict] = []
    for c in commits:
        if since_sha and c["sha"] == since_sha:
            break
        out.append(c)
        if len(out) >= max_commits:
            break
    out.reverse()
    return out


def parse_audit_json(raw: str) -> dict:
    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        raise ValueError(f"model returned no JSON: {raw[:200]}")
    return json.loads(match.group(0))


def build_report(
    owner: str,
    repo: str,
    branch: str,
    audits: list[CommitAudit],
    new_head: str,
    since_sha: str | None,
) -> str:
    lines = [
        f"# Commit audit: {owner}/{repo}@{branch}",
        "",
        f"- Window: `{since_sha or 'start of history'}..{new_head}`",
        f"- Commits reviewed: {len(audits)}",
        "",
    ]
    if not audits:
        lines.append("No new commits since the last reviewed SHA. Nothing to audit.")
        return "\n".join(lines)
    for a in audits:
        icon = {"high": "\ud83d\udd34", "medium": "\ud83d\udfe0", "low": "\ud83d\udfe1", "info": "\u26aa"}.get(a.risk, "\u26aa")
        lines.append(f"## {icon} `{a.short}` {a.message.splitlines()[0]}")
        lines.append(f"- risk: **{a.risk}** · verdict: **{a.verdict}** · by {a.author} on {a.date[:10]}")
        if a.pr:
            checks = a.pr.get("checks") or []
            failed = [c["name"] for c in checks if c.get("conclusion") not in ("success", None)]
            lines.append(
                f"- PR #{a.pr['number']} · checks: {len(checks)} run, failed: {failed or 'none'}"
            )
        lines.append(f"- files: {len(a.files)} changed")
        if a.summary:
            lines.append(f"- {a.summary}")
        for f in a.findings:
            lines.append(
                f"  - [{f.severity}/{f.area}] {f.description}"
                + (f" (`{', '.join(f.files)}`)" if f.files else "")
            )
        lines.append("")
    return "\n".join(lines)


@workflows.activity()
async def load_state(owner: str, repo: str, branch: str, path: str) -> str | None:
    async with httpx.AsyncClient() as client:
        try:
            data = await gh_get(
                client, f"/repos/{owner}/{repo}/contents/{path}", params={"ref": branch}
            )
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 404:
                return None
            raise
        import base64

        content = json.loads(base64.b64decode(data["content"]).decode())
        return content.get("last_reviewed_sha")


@workflows.activity()
async def list_new_commits(
    owner: str, repo: str, branch: str, since_sha: str | None, max_commits: int
) -> tuple[list[dict], str]:
    async with httpx.AsyncClient() as client:
        page = 1
        all_commits: list[dict] = []
        while len(all_commits) < 500:
            batch = await gh_get(
                client,
                f"/repos/{owner}/{repo}/commits",
                params={"sha": branch, "per_page": 100, "page": page},
            )
            if not batch:
                break
            all_commits.extend(batch)
            if since_sha and any(c["sha"] == since_sha for c in batch):
                break
            page += 1
        head = all_commits[0]["sha"] if all_commits else ""
        selected = commits_between(all_commits, since_sha, max_commits)
        slim = [
            {
                "sha": c["sha"],
                "short": c["sha"][:8],
                "message": c["commit"]["message"],
                "author": c["commit"]["author"]["name"],
                "date": c["commit"]["author"]["date"],
            }
            for c in selected
        ]
        return slim, head


@workflows.activity()
async def fetch_commit_detail(owner: str, repo: str, sha: str) -> dict:
    async with httpx.AsyncClient() as client:
        detail = await gh_get(client, f"/repos/{owner}/{repo}/commits/{sha}")
        files = [
            {
                "filename": f["filename"],
                "status": f["status"],
                "patch": truncate_patch(f.get("patch")),
            }
            for f in detail.get("files", [])
        ]
        diff_text = ""
        for f in files:
            diff_text += f"\n--- {f['filename']} ({f['status']})\n{f['patch']}\n"
        if len(diff_text) > MAX_DIFF_CHARS:
            diff_text = diff_text[:MAX_DIFF_CHARS] + "\n... [diff truncated]"
        pr_info = None
        try:
            pulls = await gh_get(client, f"/repos/{owner}/{repo}/commits/{sha}/pulls")
            if pulls:
                pr = pulls[0]
                checks = await gh_get(
                    client,
                    f"/repos/{owner}/{repo}/commits/{sha}/check-runs",
                    params={"per_page": 100},
                )
                pr_info = {
                    "number": pr["number"],
                    "title": pr["title"],
                    "merged": pr.get("merged_at") is not None,
                    "checks": [
                        {"name": c["name"], "conclusion": c.get("conclusion"), "status": c["status"]}
                        for c in checks.get("check_runs", [])
                    ],
                }
        except httpx.HTTPStatusError:
            pr_info = None
        return {
            "files": files,
            "file_names": [f["filename"] for f in files],
            "diff": diff_text,
            "pr": pr_info,
        }


@workflows.activity()
async def audit_commit(
    model: str, owner: str, repo: str, commit: dict, detail: dict
) -> CommitAudit:
    from mistralai import Mistral

    user_msg = (
        f"Repository: {owner}/{repo}\n"
        f"Commit: {commit['sha']}\n"
        f"Author: {commit['author']} <{commit['date']}>\n"
        f"Message:\n{commit['message']}\n\n"
        f"Changed files: {', '.join(detail['file_names'])}\n\n"
        f"Diff:\n{detail['diff']}\n\n"
        f"Linked PR info: {json.dumps(detail['pr']) if detail['pr'] else 'none (direct push)'}\n"
    )
    client = Mistral()
    response = await client.chat.complete_async(
        model=model,
        messages=[
            {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        response_format={"type": "json_object"},
        temperature=0,
    )
    raw = response.choices[0].message.content or "{}"
    parsed = parse_audit_json(raw)
    return CommitAudit(
        sha=commit["sha"],
        short=commit["short"],
        message=commit["message"],
        author=commit["author"],
        date=commit["date"],
        files=detail["file_names"],
        risk=parsed.get("risk", "info"),
        summary=parsed.get("summary", ""),
        findings=[Finding(**f) for f in parsed.get("findings", [])],
        verdict=parsed.get("verdict", "safe"),
        pr=detail["pr"],
    )


@workflows.activity()
async def save_state(
    owner: str, repo: str, branch: str, path: str, head_sha: str, report: str
) -> bool:
    import base64

    async with httpx.AsyncClient() as client:
        existing_sha = None
        try:
            data = await gh_get(
                client, f"/repos/{owner}/{repo}/contents/{path}", params={"ref": branch}
            )
            existing_sha = data["sha"]
        except httpx.HTTPStatusError as err:
            if err.response.status_code != 404:
                raise
        content = base64.b64encode(
            json.dumps(
                {"last_reviewed_sha": head_sha, "last_report": report[:4000]}, indent=2
            ).encode()
        ).decode()
        body = {
            "message": f"chore(commit-audit): update audit state to {head_sha[:8]}",
            "content": content,
            "branch": branch,
        }
        if existing_sha:
            body["sha"] = existing_sha
        try:
            await gh_put(client, f"/repos/{owner}/{repo}/contents/{path}", body)
            return True
        except httpx.HTTPStatusError:
            return False


@workflows.workflow.define(
    name="itsaplan-commit-audit",
    workflow_display_name="Itsaplan commit audit",
    workflow_description=(
        "Reviews new commits on a watched branch of a GitHub repo for security and "
        "logic issues, and reports per-commit findings. State (last reviewed SHA) is "
        "stored in commit-audit/state.json of this repository."
    ),
)
class CommitAuditWorkflow:
    @workflows.workflow.entrypoint
    async def run(self, input: AuditInput) -> AuditOutput:
        since = input.since_sha or await load_state(
            input.owner, input.repo, input.branch, STATE_PATH
        )
        commits, head = await list_new_commits(
            input.owner, input.repo, input.branch, since, input.max_commits
        )
        audits: list[CommitAudit] = []
        for c in commits:
            detail = await fetch_commit_detail(input.owner, input.repo, c["sha"])
            audits.append(
                await audit_commit(AUDIT_MODEL, input.owner, input.repo, c, detail)
            )
        report = build_report(input.owner, input.repo, input.branch, audits, head, since)
        state_saved = False
        if head:
            state_saved = await save_state(
                input.owner, input.repo, input.branch, STATE_PATH, head, report
            )
        high = sum(1 for a in audits for f in a.findings if f.severity == "high")
        return AuditOutput(
            report=report,
            new_head=head,
            commits_reviewed=len(audits),
            high_findings=high,
            state_saved=state_saved,
        )
