# IndexGuard

> 문서가 RAG의 지식이 되기 전에 검증한다.

IndexGuard는 **PDF·DOCX·HWPX 문서의 변경을 규칙과 로컬 LLM으로 분석해 숫자·정책 왜곡, 숨겨진 콘텐츠, 간접 프롬프트 인젝션을 임베딩 전에 차단하는 RAG 보안 게이트**입니다.

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
    -> 로컬 LLM 위험 판정
    -> 정책 엔진
    -> INDEX / HOLD / QUARANTINE
    -> 감사 화면과 RAG 전후 비교
```

중요한 불변식은 하나입니다.

> 색인기는 정책 엔진이 `ALLOW + INDEX`를 반환한 문서만 받을 수 있다.

## 목표 저장소 구조

```text
IndexGuard/
├─ apps/
│  ├─ api/                       # FastAPI 진입점
│  └─ dashboard/                 # Streamlit 감사·데모 화면
├─ src/indexguard/
│  ├─ contracts.py               # 팀 공통 스키마의 단일 기준
│  ├─ pipeline.py                # 종단간 분석 오케스트레이션
│  ├─ decision.py                # 점수, 판정, 격리 정책
│  ├─ extractors/                # PDF/DOCX/HWPX 입력 어댑터
│  ├─ detectors/                 # Diff, 숫자, 숨김, 인젝션 탐지
│  ├─ llm/                       # 로컬 LLM 판정과 프롬프트
│  └─ rag/                       # 단일 로컬 색인기와 비교 데모
├─ tests/
│  ├─ unit/
│  ├─ integration/
│  ├─ e2e/
│  └─ fixtures/                  # 테스트가 동적으로 만드는 최소 문서
├─ data/                         # 데모용 합성 데이터와 기대 결과
├─ scripts/                      # 데모·평가 원클릭 실행
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

## 이번에 만들지 않는 것

- 레거시 바이너리 `.hwp` 파싱
- 실시간 폴더 감시와 복잡한 Git 기반 문서 버전 관리
- OCR과 복잡한 도형의 완전한 시각 판정
- 로그인·권한 관리 UI
- 멀티에이전트와 여러 벡터 DB 연동
- 외부 LLM·임베딩 API 의존

기획안의 폐쇄망 보안 원칙은 유지하되, 24시간 안에 심사위원이 직접 확인할 수 있는 **HWPX 위험 탐지와 실제 색인 차단**에 범위를 집중합니다.

## A 문서 게이트웨이 실행

```powershell
uv sync --extra dev
uv run indexguard-api
```

API는 `http://127.0.0.1:8000`에서 실행되며 상세 흐름은 [A 게이트웨이 문서](docs/A_GATEWAY.md)를 따릅니다.
