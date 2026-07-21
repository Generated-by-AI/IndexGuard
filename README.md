# IndexGuard

> 문서가 RAG의 지식이 되기 전에 검증한다.

IndexGuard는 **PDF·DOCX·HWPX 문서를 정규화·비교하고, 독립 AI 위험 분석 서비스의 판정을 검증해 숫자·정책 왜곡과 간접 프롬프트 인젝션이 RAG에 들어가기 전에 차단하는 보안 게이트**입니다.

## 24시간 MVP

이번 제출물의 완성 기준은 기능 수가 아니라 아래 한 흐름의 종단간 동작입니다.

1. 정상 정책 HWPX가 RAG에 등록되어 있다.
2. 변경 문서에서 핵심 숫자·정책이 왜곡되고 숨겨진 악성 지시문이 삽입된다.
3. IndexGuard가 원본과 변경본을 비교해 위험 근거를 만든다.
4. 시스템이 `ALLOW / REVIEW / BLOCK`을 판정한다.
5. `BLOCK` 문서는 `QUARANTINE`되어 실제 색인 경로에 들어가지 않는다.
6. 게이트가 없을 때의 오염된 답변과 게이트 적용 후의 정상 답변을 비교한다.

HWPX는 한컴 후원 맥락을 보여주는 **대표 입력 형식(P0)** 입니다. PDF와 DOCX도 같은 분석 파이프라인으로 지원하지만, 레거시 바이너리 `.hwp`는 이번 MVP에서 다루지 않습니다.

## 핵심 파이프라인

```text
PDF / DOCX / HWPX
    -> 안전한 형식 검증과 텍스트·구조 추출
    -> 원본/변경본 정규화 및 Diff
    -> 정적 탐지(숫자, 숨김 텍스트, 활성 콘텐츠)
    -> 독립 B 서비스의 AI 위험 판정
    -> A의 판정 무결성 검증
    -> C 운영자 승인
    -> INDEX / HOLD / QUARANTINE
    -> 감사 화면과 RAG 전후 비교
```

중요한 불변식은 하나입니다.

> B가 `ALLOW + INDEX`를 반환하고 C가 같은 후보 SHA-256을 확인해 `APPROVE`한 문서만 색인할 수 있다.

## 구현된 GitHub 구조

```text
IndexGuard/
├─ apps/
│  └─ api/                       # FastAPI 호환 진입점
├─ src/indexguard/
│  ├─ contracts.py               # 팀 공통 스키마의 단일 기준
│  ├─ pipeline.py                # 종단간 분석 오케스트레이션
│  ├─ operations.py              # B 요청과 C 명령 상태 머신
│  ├─ audit.py                   # SQLite 감사 해시 체인과 provenance
│  ├─ scanner.py / watcher.py    # 문서 폴더 스냅샷과 지속 감시
│  ├─ git_watcher.py             # staged/unstaged Git diff 직접 감시
│  ├─ risk_client.py             # 독립 B HTTP 분석기 어댑터
│  ├─ mcp_server.py              # AI 호스트용 B 전용 MCP 어댑터
│  ├─ extractors/                # PDF/DOCX/HWPX 입력 어댑터
│  ├─ detectors/                 # 결정적 Diff와 숫자 변경 추출
│  └─ rag/                       # 정책 게이트와 단일 SQLite 색인기
├─ tests/                        # 계약·파서·감사·API·MCP 통합 테스트
├─ data/                         # 데모용 합성 데이터와 기대 결과
├─ docs/
└─ .github/
```

세부 경계와 파일 단위 책임은 [아키텍처](docs/ARCHITECTURE.md), 고정된 응답 형식은 [API 계약](docs/API_CONTRACT.md)을 따릅니다.

## 문서

- [24시간 실행 전략](docs/STRATEGY.md)
- [아키텍처와 목표 GitHub 구조](docs/ARCHITECTURE.md)
- [공통 API·판정 계약](docs/API_CONTRACT.md)
- [HWPX MVP 범위와 보안 기준](docs/HWPX_MVP.md)
- [A 문서 게이트웨이 구현과 API](docs/A_GATEWAY.md)
- [팀 채팅방 공유용 메시지](docs/TEAM_BRIEF.md)
- [Git 협업 규칙](CONTRIBUTING.md)

## A 게이트웨이 구현 상태

- 감시 폴더의 PDF/DOCX/HWPX `CREATED / MODIFIED / DELETED` 감지
- 세 형식의 공통 텍스트·구조 정규화와 결정적 Diff
- 원본/정규화 SHA-256, 문서 버전, 시각, 변경 주체 감사 기록
- B 분석 요청 자동 생성, HTTP push 또는 MCP pull 방식 전달
- B의 결과가 `ALLOW + INDEX`여도 C가 승인하기 전까지 `HOLD`
- C의 `APPROVE / HOLD / REANALYZE` 명령과 idempotency 감사
- 승인되지 않은 후보의 RAG 색인 차단과 이전 안전 버전 복원

## 이번에 만들지 않는 것

- 레거시 바이너리 `.hwp` 파싱
- 복잡한 Git 기반 문서 버전 관리와 watcher 이벤트의 자동 baseline 선택
- OCR과 복잡한 도형의 완전한 시각 판정
- 로그인·권한 관리 UI
- 여러 벡터 DB 연동
- A 게이트웨이 내부의 LLM 실행과 위험 점수 계산

기획안의 폐쇄망 보안 원칙은 유지하되, 24시간 안에 심사위원이 직접 확인할 수 있는 **HWPX 위험 탐지와 실제 색인 차단**에 범위를 집중합니다.

## A 문서 게이트웨이 실행

```powershell
uv sync --extra dev
uv run indexguard-api
```

API는 `http://127.0.0.1:8000`에서 실행되며 상세 흐름은 [A 게이트웨이 문서](docs/A_GATEWAY.md)를 따릅니다.

지속 폴더 감시는 별도 프로세스로 실행합니다.

```powershell
uv run indexguard-watch .\incoming --state data\runtime\scan-state.json --interval 1
```

Git 저장소의 working tree diff를 직접 감시할 수도 있습니다.

```powershell
uv run indexguard-watch-git . --interval 1
uv run indexguard-watch-git . --once
```

변경 시 `DIRTY / DIFF_CHANGED / CLEAN / HEAD_CHANGED` JSON 이벤트가 발생하며 staged·unstaged 패치, 미추적 파일명, 변경된 PDF/DOCX/HWPX 경로를 제공합니다. 미추적 파일 내용과 바이너리 payload는 출력하지 않고 패치 크기는 기본 1MiB로 제한합니다. 이 감시는 변경 증거를 제공할 뿐 자동 승인이나 RAG 색인을 수행하지 않습니다.

## AI 호스트용 MCP

MCP 서버는 모델을 내장 실행하는 서버가 아니라, AI 호스트가 B 역할로 안전한 분석 입력을 읽고 결과를 제출하게 하는 **얇은 B 전용 어댑터**입니다. API와 같은 `data/runtime`을 사용해야 동일한 대기 요청을 볼 수 있습니다.

```powershell
$env:INDEXGUARD_RUNTIME_DIR = "data/runtime"
uv run indexguard-mcp          # stdio, 권장
uv run indexguard-mcp-http     # 별도 실행 시 127.0.0.1:8001/mcp
```

제공 도구는 `list_pending_analyses`, `get_analysis_input`, `submit_policy_result`, `get_analysis_status`입니다. 원본 blob·임의 파일 경로·RAG 검색/색인·C 운영자 명령에는 접근할 수 없습니다.

> Streamable HTTP MCP에는 자체 인증이 없습니다. `127.0.0.1` 밖으로 직접 노출하지 말고, 원격 연결이 꼭 필요하면 인증 프록시 또는 OAuth 계층 뒤에 두십시오.
