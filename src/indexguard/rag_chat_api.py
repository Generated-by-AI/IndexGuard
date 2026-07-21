"""Standalone intranet question-answering page over the approved RAG index."""

from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from indexguard.openai_compat import OpenAICompatibleClient, OpenAICompatibleSettings
from indexguard.errors import ExternalServiceError
from indexguard.rag.indexer import SqliteIndexer

logger = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=5, ge=1, le=8)


class Citation(BaseModel):
    document_id: str
    sha256: str
    chunk_index: int


class ChatResponse(BaseModel):
    answer: str
    citations: list[Citation]


def create_rag_chat_app(runtime_dir: Path | None = None) -> FastAPI:
    """Serve the independent, read-only intranet RAG chat on port 8010."""

    configured_runtime = Path(
        os.getenv(
            "INDEXGUARD_RAG_RUNTIME_DIR",
            os.getenv("INDEXGUARD_RUNTIME_DIR", "data/runtime"),
        )
    )
    # 8010 is often launched from a terminal whose working directory is not
    # the repository. Resolve relative runtime settings against the project,
    # otherwise the chat service silently opens a fresh, empty SQLite index.
    selected_runtime = runtime_dir or (
        configured_runtime
        if configured_runtime.is_absolute()
        else _PROJECT_ROOT / configured_runtime
    )
    indexer = SqliteIndexer(selected_runtime / "index.db")

    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        try:
            yield
        finally:
            indexer.close()

    app = FastAPI(title="IndexGuard Intranet RAG Chat", lifespan=lifespan)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def page() -> HTMLResponse:
        return HTMLResponse(_PAGE)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "intranet-rag-chat"}

    @app.post("/api/v1/chat", response_model=ChatResponse)
    def chat(request: ChatRequest) -> ChatResponse:
        hits = indexer.search(request.question, limit=request.limit)
        citations = [
            Citation(document_id=hit.document_id, sha256=hit.sha256, chunk_index=hit.chunk_index)
            for hit in hits
        ]
        if not hits:
            return ChatResponse(
                answer="승인되어 색인된 문서에서 질문과 일치하는 근거를 찾지 못했습니다.",
                citations=[],
            )
        evidence = [
            {
                "citation_id": f"S{position}",
                "document_id": hit.document_id,
                "sha256": hit.sha256,
                "chunk_index": hit.chunk_index,
                "text": hit.text,
                "lexical_score": hit.score,
            }
            for position, hit in enumerate(hits, start=1)
        ]
        try:
            answer = OpenAICompatibleClient(
                OpenAICompatibleSettings.from_environment()
            ).answer_rag_question(
                question=request.question,
                history=[],
                evidence=evidence,
            )
        except ExternalServiceError:
            logger.exception("intranet RAG model request failed")
            raise HTTPException(
                status_code=503,
                detail="사내 언어 모델에 연결할 수 없어 답변을 생성하지 못했습니다.",
            ) from None
        return ChatResponse(answer=answer, citations=citations)

    return app


app = create_rag_chat_app()


def run() -> None:
    uvicorn.run("indexguard.rag_chat_api:app", host="127.0.0.1", port=8010)


_PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>IndexGuard 사내 지식 질의응답</title>
<style>body{margin:0;background:#f4f7fb;color:#172033;font-family:"Noto Sans KR","Malgun Gothic",sans-serif}main{max-width:860px;margin:0 auto;padding:48px 20px}.card{background:#fff;border:1px solid #dbe3ef;border-radius:16px;box-shadow:0 12px 30px #17203312;padding:28px}h1{margin:0 0 8px;font-size:25px}p{color:#536174;line-height:1.55}label{display:block;margin-top:18px;font-size:14px;font-weight:650}textarea{box-sizing:border-box;width:100%;min-height:104px;margin-top:7px;border:1px solid #bdc9d9;border-radius:9px;padding:11px;font:inherit;resize:vertical}button{margin-top:16px;background:#2457d6;color:#fff;border:0;border-radius:9px;padding:11px 16px;font:inherit;font-weight:650;cursor:pointer}button:disabled{opacity:.6;cursor:wait}#result{display:none;margin-top:24px;border-top:1px solid #dbe3ef;padding-top:20px;white-space:pre-wrap;line-height:1.6}#sources{color:#536174;font-size:13px;margin-top:12px}#error{color:#af1b1b;margin-top:16px}.notice{font-size:13px;margin-top:18px}</style>
</head><body><main><section class="card"><h1>사내 지식 질의응답</h1><p>승인되어 현재 색인된 문서만 검색합니다. 답변에는 검색된 출처 청크를 함께 표시합니다.</p><label for="question">질문</label><textarea id="question" placeholder="예: 현재 승인 한도는 얼마인가요?"></textarea><button id="send" type="button">질문하기</button><div id="error" role="alert"></div><div id="result"><strong>답변</strong><div id="answer"></div><div id="sources"></div></div><p class="notice">대시보드와 분리된 읽기 전용 사내망 서비스입니다.</p></section></main><script>const button=document.getElementById('send');button.addEventListener('click',async()=>{const question=document.getElementById('question').value.trim(),error=document.getElementById('error'),result=document.getElementById('result');error.textContent='';result.style.display='none';if(!question){error.textContent='질문을 입력하세요.';return}button.disabled=true;button.textContent='검색 및 답변 생성 중…';try{const response=await fetch('/api/v1/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question,limit:5})}),payload=await response.json();if(!response.ok)throw new Error(payload.detail||'요청을 완료하지 못했습니다.');document.getElementById('answer').textContent=payload.answer;document.getElementById('sources').textContent=payload.citations.length?'출처: '+payload.citations.map(item=>`${item.document_id} · ${item.sha256.slice(0,10)} · 청크 ${item.chunk_index}`).join(', '):'일치하는 승인 문서가 없습니다.';result.style.display='block'}catch(exception){error.textContent=exception.message||'요청을 완료하지 못했습니다.'}finally{button.disabled=false;button.textContent='질문하기'}});</script></body></html>"""
