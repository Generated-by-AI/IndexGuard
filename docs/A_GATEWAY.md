# A 문서 수집·무결성·색인 게이트웨이

이 서비스는 문서를 안전하게 준비하고 외부 AI 위험 분석 결과를 검증한 뒤 색인을 실행하거나 보류합니다. 위험 점수 계산, LLM 프롬프트, 대시보드는 구현하지 않습니다.

## 책임 경계

```text
업로드/scan-once
  -> 실제 형식과 확장자 교차검증
  -> SHA-256 content-addressed staging
  -> PDF/DOCX/HWPX 정규화
  -> baseline/candidate 결정적 Diff
  -> append-only 감사 해시 체인
  -> B의 PolicyResult 수신
  -> ALLOW + INDEX일 때만 원자적 색인
```

지원 형식은 PDF, DOCX, HWPX입니다. `.hwp`, 암호화 문서, 손상 문서, 과대 압축 ZIP은 fail-closed로 처리합니다.

## 실행

```powershell
uv sync --extra dev
uv run indexguard-api
```

기본 런타임 경로는 `data/runtime/`이며 Git에 포함되지 않습니다. 변경하려면 `INDEXGUARD_RUNTIME_DIR`을 지정합니다.

## 두 단계 API

### 1. 분석 준비

```http
POST /api/v1/prepare
Content-Type: multipart/form-data
```

필드:

- `document_id`
- `baseline_file`
- `candidate_file`

두 파일은 같은 형식이어야 합니다. 응답의 `PreparedAnalysis`를 B 서비스가 분석합니다.

이미 현재 색인 버전이 있는 `document_id`는 `baseline_file`의 SHA-256이 그 버전과 같아야 합니다. 최초 버전만 신뢰된 운영자가 bootstrap하며, 이후 요청자가 임의의 baseline을 골라 Diff를 우회할 수 없습니다.

### 2. 정책 결과 집행

```http
POST /api/v1/analyses/{analysis_id}/finalize?index_if_allowed=true
Content-Type: application/json
```

본문은 `PolicyResult`입니다. 허용 조합은 다음뿐입니다.

- `ALLOW + INDEX`
- `REVIEW + HOLD`
- `BLOCK + QUARANTINE`

후보 SHA 불일치, 분석 실패, 기술 hard blocker, 계약 위반은 모두 색인하지 않습니다.

### 확인 API

- `GET /health`
- `GET /api/v1/analyses/{analysis_id}`
- `GET /api/v1/index/search?q=...`

## 디렉터리 감지

실시간 watcher 대신 한 번만 실행되는 안전한 스캔을 제공합니다.

```powershell
uv run indexguard-scan .\incoming --state data\runtime\scan-state.json
```

지원 확장자의 `CREATED / MODIFIED / DELETED` 이벤트와 SHA-256을 JSON으로 출력합니다. 분석과 색인은 명시적인 API 호출로만 수행됩니다.

## 보안 불변식

- 업로드 파일명은 저장 경로로 사용하지 않습니다.
- 확장자, magic, ZIP 내부 signature가 모두 일치해야 합니다.
- ZIP을 디스크에 해제하지 않습니다.
- 분석 전 원본과 색인 직전 blob의 SHA-256이 같아야 합니다.
- 기존 문서는 baseline SHA-256이 현재 신뢰 버전과 같아야 합니다.
- 준비 후 현재 버전이 바뀌면 색인 트랜잭션의 SHA CAS가 stale 분석을 거부합니다.
- `ALLOW + INDEX` 정책은 후보 SHA-256과 결속되어야 합니다.
- 보조 evidence와 원본 바이트는 RAG 본문에 넣지 않습니다.
- indexer 오류는 transaction rollback 후 청크 `0`을 보장합니다.
- 보류·격리 판정은 같은 후보가 이전에 색인됐더라도 해당 청크를 원자적으로 제거합니다.
- 감사 이벤트는 `prev_event_hash`와 `event_hash`로 연결됩니다.
