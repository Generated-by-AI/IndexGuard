# A 문서 수집·무결성·색인 게이트웨이

A는 문서를 수집·정규화하고 변경 근거를 만든 뒤, 독립 B 서비스의 결과와 C 운영자 명령을 검증해 RAG 색인을 집행합니다. A는 LLM을 실행하거나 위험 점수를 계산하지 않습니다.

## 구현 상태

| A 책임 | 상태 | 현재 구현 |
|---|---|---|
| 감시 폴더 생성·수정 감지 | 완료 | content hash 기반 `CREATED / MODIFIED / DELETED`, 지속 polling과 종료 신호 |
| PDF/DOCX/HWPX 정규화 | 완료 | 실제 형식 교차검증, 텍스트 단위·위치·스타일·숨김 의심·활성 콘텐츠 evidence |
| 이전 버전 Diff | 완료 | 결정적 텍스트 변경 구간과 숫자 변경 추출 |
| 무결성·버전 provenance | 완료 | 원본/정규화 SHA-256, 단조 증가 버전, 준비 시각, 변경 주체, 파일 mtime, 코드 revision |
| B 분석 요청 전달 | 완료 | 준비 즉시 요청 생성, 인증 HTTP push 또는 MCP pull |
| 안전한 색인 집행 | 완료 | B `ALLOW + INDEX`와 C `APPROVE`가 모두 있어야 색인 |
| HOLD 대기 | 완료 | 승인 전·`REVIEW`·운영자 `HOLD`는 색인하지 않고 이전 안전 버전 유지 |
| C 운영 명령 | 완료 | `APPROVE / HOLD / REANALYZE`, 후보 SHA 결속, idempotency, 감사 이벤트 |

레거시 바이너리 `.hwp`, 암호화·손상 문서, 형식 위장, 과대 압축 ZIP은 fail-closed로 처리합니다.

## 책임 경계와 상태 흐름

```text
watch/upload
  -> content-addressed 원본 보관
  -> PDF/DOCX/HWPX 공통 정규화
  -> baseline/candidate Diff
  -> 버전·해시·시각·주체 감사 기록
  -> ANALYSIS_REQUESTED
  -> B PolicySubmission
       ALLOW + INDEX  -> AWAITING_APPROVAL -> C APPROVE -> INDEXED
       REVIEW + HOLD  -> HOLD              -> C REANALYZE 가능
       BLOCK + QUARANTINE -> QUARANTINED   -> C REANALYZE 가능
       오류/timeout/불일치 -> ANALYSIS_FAILED 또는 거부, 색인 없음
```

C의 `APPROVE`는 B의 결정을 상향하거나 새로 만들지 않습니다. 최신 B 결과가 정확히 `ALLOW + INDEX`인 경우에만 같은 후보 SHA-256을 색인합니다. `REVIEW`나 `BLOCK`은 `REANALYZE` 후 새 B 요청에서 `ALLOW`가 나와야 승인할 수 있습니다.

## 실행과 환경 변수

```powershell
uv sync --extra dev
$env:INDEXGUARD_RUNTIME_DIR = "data/runtime"
$env:INDEXGUARD_B_TOKEN = "replace-with-inbound-b-token"
$env:INDEXGUARD_OPERATOR_TOKEN = "replace-with-c-operator-token"
uv run indexguard-api
```

API 기본 주소는 `http://127.0.0.1:8000`입니다. 토큰이 설정되지 않은 역할 보호 API는 열리는 대신 `503 SERVICE_NOT_CONFIGURED`로 닫힙니다.

### 독립 B HTTP 서비스로 push

아래 변수를 추가하면 C가 `/dispatch`를 호출할 때 A가 정규화 텍스트와 Diff만 B로 전송합니다.

```powershell
$env:INDEXGUARD_B_ANALYZE_URL = "http://127.0.0.1:9000/analyze"
$env:INDEXGUARD_B_OUTBOUND_TOKEN = "replace-with-outbound-token"  # 선택
$env:INDEXGUARD_B_TIMEOUT_SECONDS = "15"                          # 0초 초과, 최대 60초
```

B 응답은 요청 ID를 그대로 포함한 완전한 `PolicySubmission`이어야 합니다. A는 redirect, non-2xx, 잘못된 JSON/스키마, 다른 `request_id`, 다른 후보 SHA를 모두 거부합니다.
평문 HTTP는 `localhost`와 loopback 주소에만 허용되며 원격 B 엔드포인트는 HTTPS여야 합니다. B/C 인바운드 토큰도 서로 다른 값을 사용해야 합니다.

## 폴더 감시

지속 감시는 scanner의 원자적 상태 파일을 사용합니다.

```powershell
uv run indexguard-watch .\incoming --state data\runtime\scan-state.json --interval 1
```

한 번만 확인하려면 다음 중 하나를 사용합니다.

```powershell
uv run indexguard-watch .\incoming --state data\runtime\scan-state.json --once
uv run indexguard-scan .\incoming --state data\runtime\scan-state.json
```

watcher는 감지 이벤트를 JSON Lines로 출력합니다. baseline 선택과 `/prepare` 업로드는 명시적으로 수행하므로 감시 폴더의 임의 파일이 자동으로 신뢰되거나 색인되지 않습니다.

### Git diff 직접 감시

저장소의 `HEAD`, staged diff, unstaged diff, untracked 파일 목록을 주기적으로 비교하고 스냅샷 digest가 달라질 때만 이벤트를 출력합니다.

```powershell
uv run indexguard-watch-git . --interval 1
uv run indexguard-watch-git . --once
```

이벤트는 `SNAPSHOT / DIRTY / DIFF_CHANGED / CLEAN / HEAD_CHANGED` 중 하나이며 다음 정보를 포함합니다.

- staged·unstaged 변경 파일과 bounded patch
- 미추적 파일명(내용은 읽거나 출력하지 않음)
- 변경된 PDF/DOCX/HWPX 경로
- 현재 branch, `HEAD` commit ID, 전체 diff digest

Git 외부 diff와 textconv는 실행하지 않으며 패치는 staged/unstaged 각각 기본 1MiB로 제한됩니다. 바이너리와 미추적 파일 내용은 MCP나 B 요청으로 자동 전달되지 않습니다. 이 기능도 변경 증거 감시에 한정되며 baseline 선택·B 분석·C 승인을 우회하지 않습니다.

추적 중인 텍스트 파일의 patch에는 해당 파일 내용이 포함될 수 있으므로 watcher 출력을 공개 로그로 전송하지 마십시오. 비밀 파일은 Git 추적 대상에서 제외하고 별도의 secret scanner 정책을 적용해야 합니다.

## REST 종단간 예시

### 1. A가 문서를 준비하고 B 요청을 생성

```bash
curl -sS http://127.0.0.1:8000/api/v1/prepare \
  -F 'document_id=expense-policy' \
  -F 'changed_by=demo-attacker' \
  -F 'baseline_file=@samples/policy-v1.hwpx' \
  -F 'candidate_file=@samples/policy-v2.hwpx'
```

응답에서 `analysis_id`와 `candidate.sha256`을 저장합니다. 기존 `document_id`라면 baseline SHA-256이 현재 신뢰 색인 버전과 일치해야 합니다.

### 2. B가 정규화된 입력을 조회하고 판정을 제출

```bash
curl -sS \
  -H 'X-IndexGuard-B-Token: replace-with-inbound-b-token' \
  http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/analysis-request
```

```bash
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-IndexGuard-B-Token: replace-with-inbound-b-token' \
  http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/policy-results \
  -d '{
    "request_id": "req_...",
    "submitted_by": "risk-engine-v1",
    "policy": {
      "decision": "ALLOW",
      "risk_score": 4,
      "findings": [],
      "index_action": "INDEX",
      "candidate_sha256": "CANDIDATE_SHA256"
    }
  }'
```

이 시점의 상태는 `AWAITING_APPROVAL`이며 아직 색인되지 않습니다. B push를 사용한다면 C가 다음 요청으로 2단계를 대신 시작할 수 있습니다.

```bash
curl -sS -X POST \
  -H 'X-IndexGuard-Operator-Token: replace-with-c-operator-token' \
  http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/dispatch
```

### 3. C가 같은 후보를 승인

```bash
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-IndexGuard-Operator-Token: replace-with-c-operator-token' \
  http://127.0.0.1:8000/api/v1/analyses/ANALYSIS_ID/commands \
  -d '{
    "action": "APPROVE",
    "actor": "operator@example.com",
    "reason": "B 근거와 변경 내용을 확인함",
    "idempotency_key": "approve-demo-001",
    "expected_candidate_sha256": "CANDIDATE_SHA256"
  }'
```

`HOLD`는 후보를 색인하지 않고 대기 상태로 두며, `REANALYZE`는 원 분석을 `SUPERSEDED`로 만들고 같은 문서 버전에 새 `analysis_id`, 증가한 attempt, 새 B 요청을 생성합니다.

## AI를 연결하는 MCP 서버

MCP는 모델을 자체 실행하는 위험 엔진이 아니라, AI 호스트가 B 역할을 수행하도록 연결하는 **얇은 어댑터**입니다. API와 MCP가 동일한 런타임 디렉터리를 사용해야 준비된 요청과 감사 상태를 공유합니다.

```powershell
$env:INDEXGUARD_RUNTIME_DIR = "data/runtime"
uv run indexguard-mcp
```

일반적인 stdio MCP 설정은 다음 형태입니다. `--directory`와 환경 변수에는 저장소의 절대 경로를 사용하십시오.

```json
{
  "mcpServers": {
    "indexguard-b": {
      "command": "uv",
      "args": ["--directory", "C:\\absolute\\path\\to\\IndexGuard", "run", "indexguard-mcp"],
      "env": {
        "INDEXGUARD_RUNTIME_DIR": "C:\\absolute\\path\\to\\IndexGuard\\data\\runtime"
      }
    }
  }
}
```

로컬 Streamable HTTP가 필요한 경우:

```powershell
$env:INDEXGUARD_RUNTIME_DIR = "data/runtime"
$env:INDEXGUARD_MCP_PORT = "8001"
uv run indexguard-mcp-http
# endpoint: http://127.0.0.1:8001/mcp
```

MCP 도구:

- `list_pending_analyses(limit)`: 아직 적용된 B 결과가 없는 요청 목록
- `get_analysis_input(analysis_id, request_id)`: 현재 요청 ID와 결속된 정규화 텍스트·Diff·evidence
- `submit_policy_result(analysis_id, submission)`: 요청 ID와 후보 SHA가 결속된 B 결과 제출
- `get_analysis_status(analysis_id)`: A가 소유한 수명주기 상태 확인

MCP에는 원본 blob, 임의 파일 경로, RAG 검색/색인, `APPROVE / HOLD / REANALYZE` 도구가 없습니다. 따라서 B 역할의 AI가 자신을 승인하거나 RAG를 직접 조작할 수 없습니다.

> Streamable HTTP MCP에는 자체 인증이 구현되어 있지 않습니다. 서버는 코드상 `127.0.0.1`에만 bind됩니다. 포트 포워딩이나 프록시로 외부에 그대로 공개하지 말고, 원격 사용이 필요하면 인증 프록시 또는 OAuth 계층 뒤에 배치하십시오. 로컬 AI 연결에는 stdio를 권장합니다.

## API 목록과 인증

| 메서드·경로 | 역할/헤더 | 용도 |
|---|---|---|
| `POST /api/v1/prepare` | 로컬 수집 | 문서 준비와 B 요청 자동 생성 |
| `GET /api/v1/analyses` | 상태 조회 | 최근 분석 상태 목록 |
| `GET /api/v1/analyses/{id}/status` | 상태 조회 | 분석 상태·허용 명령·감사 체인 확인 |
| `GET /api/v1/analyses/{id}/analysis-request` | `X-IndexGuard-B-Token` | B용 정규화 입력 조회 |
| `POST /api/v1/analyses/{id}/policy-results` | `X-IndexGuard-B-Token` | B 결과 제출 |
| `POST /api/v1/analyses/{id}/dispatch` | `X-IndexGuard-Operator-Token` | 설정된 B HTTP 서비스 호출 |
| `POST /api/v1/analyses/{id}/commands` | `X-IndexGuard-Operator-Token` | C 운영 명령 |
| `GET /api/v1/analyses/{id}` | B 또는 C 토큰 | 전체 준비 레코드 조회 |
| `GET /api/v1/index/search?q=...&document_id=...` | `X-IndexGuard-Operator-Token` | 현재 승인 색인과 조회 시점 SHA 검색 |
| `GET /api/v1/index/current?document_id=...` | `X-IndexGuard-Operator-Token` | 문서의 현재 승인 색인 SHA 조회 |
| `POST /api/v1/analyses/{id}/finalize` | B 토큰 | 하위 호환 전용, deprecated; 직접 색인 불가 |

## 보안 불변식

- 업로드 파일명과 MCP 입력은 저장 경로로 사용하지 않습니다.
- 확장자, magic, ZIP 내부 signature가 모두 일치해야 합니다.
- ZIP을 디스크에 해제하지 않으며 크기·항목 수·압축률 한도를 적용합니다.
- 원본 blob과 정규화 본문 모두 SHA-256으로 결속하고 색인 직전에 다시 검증합니다.
- 기존 문서는 baseline SHA-256이 현재 신뢰 버전과 같아야 합니다.
- 동시 변경은 색인 트랜잭션의 SHA compare-and-swap으로 오래된 분석을 거부합니다.
- 모든 B 결과는 최신 `request_id`와 정확한 후보 SHA-256에 결속됩니다.
- B `ALLOW`만으로는 색인되지 않으며 C `APPROVE`가 위험 결정을 변경할 수 없습니다.
- 보조 evidence와 원본 바이트는 RAG 본문에 넣지 않습니다.
- indexer 오류는 transaction rollback 후 청크 `0`을 보장합니다.
- 보류·격리는 후보 청크를 제거하고 이전에 승인된 안전 버전을 유지합니다.
- 감사 이벤트는 `previous_hash`와 `event_hash`로 연결됩니다.
- 색인 검색과 current SHA 조회는 C 운영 토큰 없이는 노출하지 않습니다.
- `q`는 1–2,000자, `document_id`는 1–200자입니다. 문서 ID는 `/`를 포함할 수 있으므로 current 조회는 path segment가 아닌 query parameter를 사용합니다.
- 문서 범위 검색은 current SHA와 검색 행을 한 indexer lock에서 읽고, 모든 결과를 해당 문서·SHA에 결속합니다.
