# IndexGuard

> 문서가 RAG의 지식이 되기 전에 검증한다.

IndexGuard는 **PDF·DOCX·HWPX 문서를 정규화·비교하고, 독립 AI 위험 분석 서비스의 판정을 검증해 숫자·정책 왜곡과 간접 프롬프트 인젝션이 RAG에 들어가기 전에 차단하는 보안 게이트**입니다.

## 실행 가능한 데모 사이트

> **로컬 데모:** [IndexGuard 운영자 콘솔](http://localhost:8501) · [A API 문서](http://127.0.0.1:8000/docs) · [B API 문서](http://127.0.0.1:9000/docs)

현재 공개 배포 URL은 없으며, 위 링크는 아래 세 프로세스를 실행하면 활성화됩니다. 먼저 저장소
루트에서 `uv sync --extra dev --extra dashboard`를 한 번 실행합니다.

터미널 1 — B 위험 분석 서비스:

```powershell
$env:INDEXGUARD_B_SERVICE_TOKEN = "indexguard-a-to-b-demo"
$env:INDEXGUARD_B_LLM_ENABLED = "false"
uv run indexguard-risk-api
```

터미널 2 — A 문서 게이트웨이:

```powershell
$env:INDEXGUARD_OPERATOR_TOKEN = "indexguard-operator-demo"
$env:INDEXGUARD_B_ANALYZE_URL = "http://127.0.0.1:9000/analyze"
$env:INDEXGUARD_B_OUTBOUND_TOKEN = "indexguard-a-to-b-demo"
uv run indexguard-api
```

터미널 3 — C 운영자 콘솔:

```powershell
$env:INDEXGUARD_API_URL = "http://127.0.0.1:8000"
$env:INDEXGUARD_OPERATOR_TOKEN = "indexguard-operator-demo"
$env:INDEXGUARD_OPERATOR_ACTOR = "demo-operator"
uv run --extra dashboard streamlit run apps/dashboard/app.py
```

실행 후 [http://localhost:8501](http://localhost:8501)에서 PDF·DOCX·HWPX 기준본과 변경본을
올려 Diff, 숫자 변경, 추출 흔적, B 분석 결과와 실제 색인 상태를 확인할 수 있습니다. B가 중지되거나
잘못된 응답을 반환하면 A는 위험 분석을 실패 상태로 유지하고 문서를 색인하지 않습니다.

## 24시간 MVP

이번 제출물의 완성 기준은 기능 수가 아니라 아래 한 흐름의 종단간 동작입니다.

1. 정상 정책 HWPX가 RAG에 등록되어 있다.
2. 변경 문서에서 핵심 숫자·정책이 왜곡되고 숨겨진 악성 지시문이 삽입된다.
3. IndexGuard가 원본과 변경본을 비교해 위험 근거를 만든다.
4. 시스템이 `ALLOW / REVIEW / BLOCK`을 판정한다.
5. `BLOCK` 문서는 `QUARANTINE`되어 실제 색인 경로에 들어가지 않는다.
6. 게이트가 없을 때의 오염된 답변과 게이트 적용 후의 정상 답변을 비교한다.

HWPX는 한컴 후원 맥락을 보여주는 **대표 입력 형식(P0)** 입니다. PDF와 DOCX도 같은 분석 파이프라인으로 지원하지만, 레거시 바이너리 `.hwp`는 이번 MVP에서 다루지 않습니다.

PDF는 OpenDataLoader PDF의 읽기 순서 기반 Markdown 정규화를 우선 사용하고, PyMuPDF로 활성 콘텐츠와 숨김·투명·가림 텍스트를 별도로 검사합니다. OpenDataLoader PDF는 Java 11+가 필요합니다. Java 또는 도구가 준비되지 않은 실행 환경에서는 보안 검사를 유지하기 위해 PyMuPDF 정규화로 안전하게 되돌아갑니다. HWPX는 먼저 기존 OWPML ZIP/XML 보안 파서로 검증한 뒤, LibreOffice headless로 임시 PDF를 만들고 OpenDataLoader PDF 정규화를 적용합니다. LibreOffice 또는 OpenDataLoader를 사용할 수 없거나 변환 결과가 숨김 텍스트를 다시 포함하면, HWPX는 네이티브 보안 파서의 정규화 결과로 안전하게 되돌아갑니다.

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
│  ├─ api/                       # FastAPI 호환 진입점
│  └─ dashboard/                 # C Streamlit 운영자 증거 워크벤치
├─ src/indexguard/
│  ├─ contracts.py               # 팀 공통 스키마의 단일 기준
│  ├─ pipeline.py                # 종단간 분석 오케스트레이션
│  ├─ operations.py              # B 요청과 C 명령 상태 머신
│  ├─ audit.py                   # SQLite 감사 해시 체인과 provenance
│  ├─ scanner.py / watcher.py    # 문서 폴더 스냅샷과 지속 감시
│  ├─ git_watcher.py             # staged/unstaged Git diff 직접 감시
│  ├─ risk_client.py             # A에서 독립 B로 보내는 HTTP 어댑터
│  ├─ risk_engine.py             # B 정적 규칙·선택적 LLM·2차 감사와 판정
│  ├─ risk_api.py                # B /analyze 독립 FastAPI 서비스
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

## B 위험 분석 서비스 실행

B는 A가 제공한 정규화 전후 텍스트·Diff·artifact만 분석하며 원본 파일, RAG 색인기, C 명령에는
접근하지 않습니다. 정적 규칙은 항상 실행되고, LLM은 위험 점수를 올리거나 근거를 추가할 수 있지만
hard-block을 해제할 수 없습니다. 정적 또는 1차 LLM 점수가 70 이상이면 독립적인 2차 감사 프롬프트가
한 번 더 실행됩니다.

```powershell
$env:INDEXGUARD_B_SERVICE_TOKEN = "<same-value-as-A-outbound-token>"
$env:INDEXGUARD_B_LLM_ENABLED = "false"  # 로컬 LLM 연결 시 true
uv run indexguard-risk-api
```

기본 주소는 `http://127.0.0.1:9000`이고 분석 endpoint는 `POST /analyze`입니다. LLM을 켜면
`INDEXGUARD_OPENAI_BASE_URL`, `INDEXGUARD_OPENAI_MODEL`, 선택적인 `INDEXGUARD_OPENAI_API_KEY`를
사용합니다. LLM 오류·잘못된 JSON·위험 근거와 점수의 모순은 자동 승인으로 이어지지 않습니다.

합성 fixture 평가는 다음 명령으로 재현합니다. 출력 수치는 이 5개 fixture에만 해당하며 일반화된
성능 주장으로 사용하지 않습니다.

```powershell
uv run indexguard-risk-eval
uv run indexguard-risk-eval --output data/runtime/risk-evaluation.json
```

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
$env:INDEXGUARD_OPERATOR_TOKEN = "<operator-token>"
$env:INDEXGUARD_B_ANALYZE_URL = "http://127.0.0.1:9000/analyze"
$env:INDEXGUARD_B_OUTBOUND_TOKEN = "<same-value-as-B-service-token>"
uv sync --extra dev --extra dashboard
uv run indexguard-api
```

API는 `http://127.0.0.1:8000`에서 실행되며 상세 흐름은 [A 게이트웨이 문서](docs/A_GATEWAY.md)를 따릅니다.

## C 운영자 콘솔 실행

콘솔은 A의 큐·분석 증거·정책 결과·게이트웨이 결과를 표시하고, A가 현재 상태에서 허용한
`APPROVE / HOLD / REANALYZE` 명령만 전송합니다. 브라우저에서 위험을 계산하거나 저장소와
색인기에 직접 접근하지 않습니다.

```powershell
$env:INDEXGUARD_API_URL = "http://127.0.0.1:8000"
$env:INDEXGUARD_OPERATOR_TOKEN = "<same-operator-token-as-A>"
$env:INDEXGUARD_OPERATOR_ACTOR = "<audit-actor-label>"  # 선택 사항
uv sync --extra dev --extra dashboard
uv run --extra dashboard streamlit run apps/dashboard/app.py
```

기본 주소는 `http://localhost:8501`이며 프로젝트 설정이 콘솔을 `127.0.0.1`에만 바인딩합니다.
외부 인증·접근 제어 없이 이 바인딩을 공용 인터페이스로 변경하지 않습니다. 루프백이 아닌 A
주소는 HTTPS여야 하며 토큰을 URL에 넣지 않습니다. 운영자 토큰이 없으면 공개 상태 큐는 볼 수
있지만 상세 증거와 명령은 fail-closed로 차단됩니다. `ALLOW + INDEX` 정책 결과, 요청된 액션,
실제 색인 결과는 화면에서 별도 사실로 표시됩니다.

지속 폴더 감시는 별도 프로세스로 실행합니다.

```powershell
uv run indexguard-watch .\incoming --state data\runtime\scan-state.json --interval 1
```

Git 저장소의 working tree diff를 직접 감시할 수도 있습니다.

```powershell
uv run indexguard-watch-git . --interval 1
uv run indexguard-watch-git . --once
```

제품 시연에서는 OpenAI 호환 API를 이용해 각 Git diff 이벤트의 요약을 함께 출력할 수 있습니다.
기본 API 주소는 `http://100.102.81.122:8000/v1`이며 API 키는 빈 값으로 둡니다. 모델 이름을
지정하지 않으면 서버의 `/models` 응답에서 첫 모델을 선택합니다.

```powershell
uv run indexguard-watch-git . --once --summarize
```

`OpenAICompatibleClient`는 이후 에이전트 분석에도 같은 연결을 사용합니다. 모델에는 요약 또는
분석 텍스트만 요청하며, Git diff·문서 evidence에 포함된 지시문을 실행하지 않고 도구 접근이나
색인 승인 권한도 부여하지 않습니다.

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
