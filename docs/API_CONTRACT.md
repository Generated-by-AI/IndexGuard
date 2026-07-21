# API 및 판정 계약 v0.1

이 문서는 A 문서 게이트웨이, B AI 위험 분석, C 운영 콘솔 사이의 현재 구현 계약입니다. 모든 JSON 모델은 선언되지 않은 필드를 거부합니다.

## 1. 역할과 권한

- **A**: 원본 보관, 정규화, Diff, provenance, 감사, B 요청, 상태 머신, 색인 집행
- **B**: 정규화된 변경 입력 분석, 위험 점수·근거·`ALLOW / REVIEW / BLOCK` 산출
- **C**: 상태와 근거 확인, `APPROVE / HOLD / REANALYZE` 명령

A는 위험 점수를 계산하지 않습니다. B는 원본 blob과 RAG에 접근하지 않으며, C는 B의 위험 결정을 직접 수정할 수 없습니다.

REST에서 B 전용 요청은 `X-IndexGuard-B-Token`, C 명령과 B HTTP dispatch는 `X-IndexGuard-Operator-Token`으로 보호합니다. 각 기대 토큰은 `INDEXGUARD_B_TOKEN`, `INDEXGUARD_OPERATOR_TOKEN`에서 설정합니다. 미설정은 `503`, 누락·불일치는 `401`로 fail-closed 처리합니다.

## 2. A 문서 준비

```http
POST /api/v1/prepare
Content-Type: multipart/form-data
```

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `document_id` | string | 예 | 문서의 안정적인 논리 ID |
| `baseline_file` | PDF/DOCX/HWPX | 예 | 신뢰하는 이전 버전 |
| `candidate_file` | PDF/DOCX/HWPX | 예 | 색인 후보 버전 |
| `changed_by` | string | 아니요 | 변경 주체, 기본값 `api-user` |

두 파일은 같은 실제 형식이어야 합니다. 기존 `document_id`는 baseline SHA-256이 현재 신뢰 색인 버전과 일치해야 합니다. A는 다음 정보를 담은 `PreparedAnalysis`를 저장·반환하고 즉시 B 요청을 한 번 생성합니다.

- `analysis_id`, `document_id`, 단조 증가 `version`, `analysis_attempt`
- 원본 SHA-256과 정규화 본문 SHA-256
- PDF/DOCX/HWPX 공통 `DocumentSnapshot`
- 결정적 `DiffReport`와 숫자 변경
- `changed_by`, `prepared_at`, 파일 수집 시 `source_mtime_ns`, `code_revision`
- 색인 compare-and-swap용 `expected_current_sha256`

업로드 원본은 content-addressed blob으로 격리되며 이 단계에서는 절대 색인되지 않습니다.

## 3. A → B 분석 요청

B는 인증 REST API, 설정된 B HTTP endpoint, 또는 B 전용 MCP에서 같은 `RiskAnalysisRequest`를 받습니다.

```json
{
  "schema_version": "0.1",
  "request_id": "req_...",
  "analysis_id": "anl_...",
  "document_id": "expense-policy",
  "version": 2,
  "attempt": 1,
  "requested_at": "2026-07-21T03:00:00Z",
  "changed_by": "demo-attacker",
  "baseline_sha256": "...",
  "candidate_sha256": "...",
  "baseline_normalized_sha256": "...",
  "candidate_normalized_sha256": "...",
  "before_text": "승인 한도는 1,000만 원이다.",
  "after_text": "승인 한도는 1억 원이다.",
  "diff": {
    "baseline_sha256": "...",
    "candidate_sha256": "...",
    "normalization_version": "1",
    "changes": [],
    "numeric_changes": []
  },
  "candidate_units": [],
  "candidate_artifacts": []
}
```

이 요청에는 정규화된 전후 텍스트, Diff, 구조 단위, 안전하게 추출된 evidence만 포함합니다. 원본 바이트, content-addressed blob 경로, 임의 호스트 파일 경로, RAG 데이터는 포함하지 않습니다.

REST pull:

```http
GET /api/v1/analyses/{analysis_id}/analysis-request
X-IndexGuard-B-Token: ...
```

HTTP push는 C가 다음 endpoint를 호출할 때 실행됩니다.

```http
POST /api/v1/analyses/{analysis_id}/dispatch
X-IndexGuard-Operator-Token: ...
```

필요 환경 변수는 `INDEXGUARD_B_ANALYZE_URL`, 선택적인 `INDEXGUARD_B_OUTBOUND_TOKEN`, `INDEXGUARD_B_TIMEOUT_SECONDS`입니다. B adapter는 redirect를 따르지 않으며 timeout은 최대 60초입니다.

저장소에 포함된 독립 B 서비스는 `uv run indexguard-risk-api`로 실행하며 기본 주소는
`http://127.0.0.1:9000`입니다.

```http
POST /analyze
Authorization: Bearer ${INDEXGUARD_B_SERVICE_TOKEN}
Content-Type: application/json
```

요청은 위의 `RiskAnalysisRequest`, 응답은 아래의 `PolicySubmission` 계약을 그대로 사용합니다.
`INDEXGUARD_B_SERVICE_TOKEN`은 A의 `INDEXGUARD_B_OUTBOUND_TOKEN`과 같은 값이어야 합니다. B는
Diff와 요청의 baseline/candidate SHA가 다르면 `FAILED + BLOCK + QUARANTINE`을 반환합니다.
정적 규칙은 항상 실행되며 `INDEXGUARD_B_LLM_ENABLED=true`일 때만 OpenAI 호환 로컬 모델을
1차 문맥 판정과 고위험 2차 감사에 사용합니다. LLM은 decision과 index action을 직접 만들지 못하고
정적 hard-block 또는 더 높은 위험 점수를 낮출 수 없습니다.

## 4. B → A 정책 제출

```http
POST /api/v1/analyses/{analysis_id}/policy-results
X-IndexGuard-B-Token: ...
Content-Type: application/json
```

본문은 raw `PolicyResult`가 아니라 요청과 결속된 전체 `PolicySubmission`입니다.

```json
{
  "request_id": "req_...",
  "submitted_by": "risk-engine-v1",
  "policy": {
    "schema_version": "0.1",
    "analysis_status": "COMPLETED",
    "decision": "BLOCK",
    "risk_score": 92,
    "findings": [
      {
        "type": "POLICY_NUMBER_CHANGE",
        "before": "1,000만 원",
        "after": "1억 원",
        "reason": "승인 기준이 10배 완화됨",
        "severity": "HIGH",
        "source": "LLM"
      }
    ],
    "index_action": "QUARANTINE",
    "candidate_sha256": "..."
  }
}
```

`request_id`는 해당 분석의 최신 요청과 같아야 하고 `candidate_sha256`은 모든 판정에서 준비된 후보의 원본 SHA-256과 정확히 같아야 합니다. A는 누락·불일치 값을 합성하거나 덮어쓰지 않고 거부합니다. 한 요청에 서로 다른 두 결과를 제출할 수도 없습니다.

허용 조합은 다음뿐입니다.

| B decision | index_action | A의 즉시 상태 | 실제 색인 |
|---|---|---|---|
| `ALLOW` | `INDEX` | `AWAITING_APPROVAL` | 아니요 |
| `REVIEW` | `HOLD` | `HOLD` | 아니요 |
| `BLOCK` | `QUARANTINE` | `QUARANTINED` | 아니요 |

`analysis_status=FAILED`는 반드시 `BLOCK + QUARANTINE`이어야 합니다. B 분석 오류, HTTP 오류, JSON/스키마 오류도 A에서 `ALLOW`로 변환되지 않습니다.

`POST /api/v1/analyses/{analysis_id}/finalize`는 기존 클라이언트용 deprecated endpoint입니다. B 토큰이 필요하고 내부적으로 최신 요청의 `PolicySubmission`으로 감싸며, 더 이상 B가 직접 색인하게 하지 않습니다.

## 5. C 운영 명령

```http
POST /api/v1/analyses/{analysis_id}/commands
X-IndexGuard-Operator-Token: ...
Content-Type: application/json
```

```json
{
  "action": "APPROVE",
  "actor": "operator@example.com",
  "reason": "변경 및 B 근거 검토 완료",
  "idempotency_key": "approve-demo-001",
  "expected_candidate_sha256": "..."
}
```

- `APPROVE`: 최신 B 결과가 `ALLOW + INDEX`이고 후보 SHA가 일치할 때만 색인
- `HOLD`: 후보를 색인하지 않고 이전 안전 버전을 유지
- `REANALYZE`: 원 분석을 보류·`SUPERSEDED` 처리하고 새 `analysis_id`, 증가한 attempt, 새 B 요청 생성

`idempotency_key`는 최소 8자입니다. 같은 키와 같은 명령은 기존 결과를 반환하고, 같은 키를 다른 명령에 재사용하면 거부합니다. C 명령에는 위험 점수나 decision 필드가 없습니다.

성공한 색인 결과 예:

```json
{
  "analysis_id": "anl_...",
  "document_id": "expense-policy",
  "candidate_sha256": "...",
  "indexed": true,
  "chunk_count": 3,
  "action": "INDEX",
  "reason": "POLICY_ALLOW"
}
```

## 6. 조회와 상태

| 경로 | 응답 |
|---|---|
| `GET /health` | 서비스 health |
| `GET /api/v1/analyses?limit=100` | `AnalysisStatusView[]` |
| `GET /api/v1/analyses/{id}/status` | 상태, 최신 요청·정책·결과, 허용 명령, 감사 체인 검증 |
| `GET /api/v1/analyses/{id}` | 전체 `PreparedAnalysis`; B 또는 C 토큰 필요 |
| `GET /api/v1/index/search?q=...&limit=5` | 승인된 현재 색인 검색 |

상태 enum은 `PREPARED`, `ANALYSIS_REQUESTED`, `ANALYSIS_FAILED`, `AWAITING_APPROVAL`, `HOLD`, `INDEXED`, `QUARANTINED`, `SUPERSEDED`입니다.

## 7. MCP 계약

API와 MCP는 동일한 `INDEXGUARD_RUNTIME_DIR=data/runtime`을 사용해야 합니다.

- `list_pending_analyses(limit)`
- `get_analysis_input(analysis_id, request_id)`
- `submit_policy_result(analysis_id, submission)`
- `get_analysis_status(analysis_id)`

MCP는 B 전용 얇은 adapter이며 원본 blob, 임의 파일 접근, RAG 조작, C 운영 명령을 노출하지 않습니다. stdio가 기본이고 `indexguard-mcp-http`는 `127.0.0.1:${INDEXGUARD_MCP_PORT:-8001}/mcp`에서만 실행됩니다.

> HTTP MCP 자체에는 인증이 없습니다. 외부에 직접 노출하지 말고 원격 사용 시 인증 프록시 또는 OAuth 계층을 사용하십시오.

## 8. B 판정 규칙과 책임

B는 팀 합의에 따라 수치·날짜·정책 키워드 변경, 숨김 콘텐츠, 활성 콘텐츠, 프롬프트 인젝션 근거를 분석하고 `risk_score`와 `findings`를 산출합니다. 권장 점수 구간은 `0–29 ALLOW`, `30–69 REVIEW`, `70–100 BLOCK`입니다.

A가 강제하는 것은 점수 계산 방식이 아니라 다음 보안 계약입니다.

1. 허용된 decision/action 조합만 수신한다.
2. `FAILED`는 반드시 `BLOCK + QUARANTINE`이다.
3. 최신 요청 ID와 후보 SHA가 모두 일치해야 한다.
4. `ALLOW`도 C 승인 전에는 색인하지 않는다.
5. 파서·B·감사·색인 오류는 색인 성공으로 처리하지 않는다.
6. 원격 B 전송은 HTTPS만 허용하고 B/C 서비스 토큰은 서로 분리한다.

## 9. fail-closed 오류 응답

A의 오류 envelope는 B의 점수처럼 보이지 않도록 `risk_score`를 `null`로 반환합니다.

```json
{
  "analysis_status": "FAILED",
  "decision": "BLOCK",
  "risk_score": null,
  "risk_score_source": "not_calculated_by_gateway",
  "findings": [
    {
      "type": "UNSUPPORTED_LEGACY_HWP",
      "before": null,
      "after": null,
      "reason": "레거시 HWP는 분석할 수 없습니다. HWPX로 다시 저장해 주세요."
    }
  ],
  "index_action": "QUARANTINE",
  "error": {
    "code": "UNSUPPORTED_LEGACY_HWP",
    "message": "레거시 HWP는 분석할 수 없습니다. HWPX로 다시 저장해 주세요.",
    "retryable": false
  }
}
```

대표 코드는 `UNSUPPORTED_FORMAT`, `UNSUPPORTED_LEGACY_HWP`, `FORMAT_MISMATCH`, `FILE_TOO_LARGE`, `MALFORMED_ARCHIVE`, `ENCRYPTED_DOCUMENT`, `INTEGRITY_MISMATCH`, `STALE_BASELINE_VERSION`, `WORKFLOW_CONFLICT`, `RISK_SERVICE_ERROR`, `AUTHENTICATION_FAILED`, `SERVICE_NOT_CONFIGURED`입니다.
