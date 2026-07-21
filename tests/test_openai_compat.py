from __future__ import annotations

import json
from pathlib import Path

import httpx

from indexguard.git_watcher import GitDiffEvent, GitDiffEventType, GitDiffSnapshot
from indexguard.openai_compat import OpenAICompatibleClient, OpenAICompatibleSettings


def _event() -> GitDiffEvent:
    snapshot = GitDiffSnapshot(
        repository_root=Path("C:/repository"),
        head_sha="a" * 40,
        branch="main",
        staged_files=(),
        unstaged_files=("policy.txt",),
        untracked_files=(),
        changed_files=("policy.txt",),
        supported_document_files=(),
        staged_patch="",
        unstaged_patch="-before\n+after\n",
        patch_truncated=False,
        dirty=True,
        digest="b" * 64,
    )
    return GitDiffEvent(
        type=GitDiffEventType.DIRTY,
        detected_at="2026-07-21T00:00:00+00:00",
        previous_digest=None,
        snapshot=snapshot,
    )


def test_git_diff_summary_uses_openai_chat_completions_without_auth_for_empty_key() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers.get("authorization")
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "변경 요약"}}]})

    client = OpenAICompatibleClient(
        OpenAICompatibleSettings(base_url="http://100.102.81.122:8000/v1", model="demo-model"),
        transport=httpx.MockTransport(handler),
    )

    assert client.summarize_git_diff(_event()) == "변경 요약"
    assert captured["authorization"] is None
    assert captured["path"] == "/v1/chat/completions"
    assert captured["body"]["model"] == "demo-model"  # type: ignore[index]


def test_model_is_discovered_when_not_configured() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "discovered-model"}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "분석"}}]})

    client = OpenAICompatibleClient(
        OpenAICompatibleSettings(base_url="http://100.102.81.122:8000/v1"),
        transport=httpx.MockTransport(handler),
    )

    assert client.analyze_agent_task(task="검토", evidence={"diff": "safe"}) == "분석"
    assert paths == ["/v1/models", "/v1/chat/completions"]
