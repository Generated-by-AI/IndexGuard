# 팀 채팅방 공유용

아래 구분선 안의 내용을 그대로 공유하면 됩니다.

---

팀 여러분, 남은 24시간의 방향, GitHub 구조, 역할을 확정하겠습니다.

우리의 목표는 기능을 많이 만드는 것이 아니라, **심사위원이 한 번에 이해하고 실제 작동을 확인할 수 있는 완성된 결과물**을 제출하는 것입니다.

## 제품 정의

제품명은 `IndexGuard`로 통일합니다.

> IndexGuard는 PDF·DOCX·HWPX 문서 변경을 규칙과 로컬 LLM으로 분석해 숫자·정책 왜곡, 숨겨진 콘텐츠, 간접 프롬프트 인젝션을 임베딩 전에 차단하는 RAG 보안 게이트입니다.

핵심 메시지는 **“문서가 RAG의 지식이 되기 전에 검증한다”**입니다.

한컴이 후원사인 만큼 **HWPX는 선택 기능이 아니라 P0 핵심 입력**으로 둡니다. 레거시 바이너리 HWP는 제외하되, 정상/공격 HWPX 한 쌍이 전체 데모를 통과하게 만듭니다. PDF와 DOCX는 같은 파이프라인을 사용하는 호환 포맷입니다.

## 최종 데모

1. 정상 정책 HWPX가 RAG에 등록되어 있음
2. 공격자가 승인 기준을 `1,000만 원`에서 `1억 원`으로 바꾸고 흰색 글자로 악성 지시문을 삽입
3. IndexGuard가 숫자 Diff, 숨김 텍스트, 프롬프트 인젝션과 위험 근거를 탐지
4. `ALLOW / REVIEW / BLOCK` 중 하나로 판정
5. 고위험 문서는 `QUARANTINE`되어 실제로 색인되지 않음
6. 게이트가 없을 때의 잘못된 RAG 답변과 차단 후의 정상 답변을 비교

이 흐름이 처음부터 끝까지 실제 작동하는 것이 결과물의 기준입니다.

## GitHub 기본 구조

```text
IndexGuard/
├─ apps/api/                 # FastAPI
├─ apps/dashboard/           # Streamlit 감사 화면
├─ src/indexguard/
│  ├─ contracts.py           # 공통 JSON 스키마
│  ├─ pipeline.py            # 종단간 흐름
│  ├─ decision.py            # 점수·판정·격리
│  ├─ extractors/            # PDF/DOCX/HWPX
│  ├─ detectors/             # Diff·숫자·숨김·인젝션
│  ├─ llm/                   # 로컬 LLM 판정
│  └─ rag/                   # 색인기·비교 데모
├─ tests/                    # unit/integration/e2e/fixtures
├─ data/                     # 합성 정상·공격 데이터와 기대값
├─ scripts/                  # 데모·평가 실행
└─ docs/                     # 전략·API·아키텍처·발표 근거
```

`contracts.py`와 공통 JSON은 H1에 동결합니다. 입력 형식이 PDF, DOCX, HWPX 중 무엇이든 추출 이후에는 같은 분석·판정·색인 경로를 사용합니다.

## 역할

### 1. 기술 리드

- PDF/DOCX/HWPX 텍스트·구조·숨김 요소 추출
- HWPX ZIP/XML 안전 검사와 스크립트 payload, OLE, 암호화 탐지
- 이전/변경 버전 Diff
- 숫자 변경, 숨겨진 텍스트 등 정적 탐지
- 위험 점수와 격리 정책
- 분석·색인 제어 API
- `BLOCK` 문서 미색인 E2E 테스트

### 2. 제품·기획 리드

- H0–H1 제품 범위와 사용자 흐름 동결
- 감사 대시보드와 결과 화면
- 백엔드·AI 결과 통합
- HWPX 형식 배지와 `QUARANTINED / NOT INDEXED` 상태 강조
- 서비스 배포와 데모 영상
- README, PPT, GitHub, 최종 제출 총괄
- 기능 추가·삭제 최종 결정

### 3. AI·레드팀·평가 리드

- 로컬 LLM 위험 판정 프롬프트와 JSON 출력
- 정상·숫자 변조·정책 왜곡·숨김 인젝션 HWPX와 PDF/DOCX 호환성 문서 제작
- 공격 문서와 RAG 질문 준비
- 탐지율, 정상 통과율, 분석 시간 평가
- 오탐·미탐 정리
- PPT와 README의 AI·보안 근거 제공

## 공통 데이터 형식

```json
{
  "decision": "BLOCK",
  "risk_score": 92,
  "findings": [
    {
      "type": "POLICY_NUMBER_CHANGE",
      "before": "1,000만 원",
      "after": "1억 원",
      "reason": "승인 기준이 10배 완화됨"
    }
  ],
  "index_action": "QUARANTINE"
}
```

허용 조합은 `ALLOW + INDEX`, `REVIEW + HOLD`, `BLOCK + QUARANTINE`뿐입니다. 색인기는 반드시 이 결과를 다시 검사하며, UI에서 버튼만 막는 방식은 인정하지 않습니다.

## Git 전략

- 복잡한 `develop` 없이 `main`과 짧은 기능 브랜치만 사용
- 예: `feat/hwpx-extractor`, `feat/risk-engine`, `feat/dashboard`, `eval/attack-cases`
- 3시간마다 작은 PR로 `main` 통합
- `main`은 항상 대표 데모가 가능한 상태 유지
- PR에는 “최종 데모의 어느 장면에 연결되는가”를 반드시 작성
- H18 기능 동결 후 `demo-v0.1` 태그 생성

## 시간 계획

- `H0–H1`: 제품 문장, HWPX 대표 시나리오, JSON, 화면 동결
- `H1–H4`: 정상 HWPX 추출부터 화면까지 첫 종단간 연결
- `H4–H10`: 실제 탐지·판정·격리 완성
- `H10–H14`: RAG 전후 비교와 평가
- `H14–H18`: 배포, 오류 처리, UI와 데모 안정화
- `H18`: 기능 동결
- `H18–H21`: 영상, README, PPT
- `H21–H23`: 다른 환경에서 실행·제출물 검증
- `H23–H24`: 제출과 비상 버퍼

## 이번에 만들지 않는 것

레거시 HWP, 실시간 폴더 감시, 복잡한 Git 문서 버전 관리, OCR, 로그인, 멀티에이전트, 여러 벡터 DB 연동, 외부 LLM API 의존은 제외합니다.

일정이 밀리면 통계 화면, PDF 케이스 수, LLM 설명의 풍부함부터 줄입니다. **HWPX 입력, 위험 근거, 실제 색인 차단은 줄이지 않습니다.**

3시간마다 실제 통합 상태를 확인하고, 각자 만든 결과가 최종 데모에 연결되지 않으면 즉시 범위를 줄입니다.

**우리의 승부처는 “위험해 보인다”는 분석 화면이 아니라, 오염된 HWPX가 잘못된 RAG 답변을 만들기 전에 실제로 차단되는 장면입니다.** 이 한 장면을 완성하는 데 세 명 모두 집중합시다.

---
