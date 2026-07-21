# 협업 규칙

## 브랜치

`main`과 짧은 기능 브랜치만 사용합니다. `develop`이나 장기 브랜치는 만들지 않습니다.

- `feat/hwpx-extractor`
- `feat/risk-engine`
- `feat/dashboard`
- `eval/attack-cases`
- `fix/index-gate`
- `docs/demo-script`

한 브랜치는 한 데모 장면 또는 한 계약 변경만 포함합니다.

## 커밋

Conventional Commits의 최소 접두사만 사용합니다.

- `feat:` 기능
- `fix:` 오류 수정
- `test:` 테스트·fixture
- `docs:` 문서
- `chore:` 설정·도구

예: `feat: detect hidden prompts in hwpx runs`

## Pull Request

- 3시간마다 통합 가능한 크기로 올립니다.
- `main`을 깨는 미완성 경로는 feature flag 또는 격리된 모듈 뒤에 둡니다.
- 공통 계약을 바꾸면 생산자·소비자·fixture를 같은 PR에서 수정합니다.
- 최소 한 명이 코드나 결과를 확인한 뒤 병합합니다.
- PR 설명에 최종 데모의 어느 단계와 연결되는지 적습니다.

## 디렉터리 소유권

- A 문서 게이트웨이: `src/indexguard/extractors`, `detectors/document_diff.py`, `rag/gate.py`, `apps/api`, 핵심 테스트
- 제품·기획 리드: `apps/dashboard`, 배포, `README.md`, 발표·제출 문서
- AI·레드팀 리드: `src/indexguard/llm`, 위험 탐지기, `tests/fixtures`, `data`, 평가 스크립트
- 공동 잠금: `contracts.py`, `docs/API_CONTRACT.md`

GitHub 계정명이 확정되면 이 규칙을 `.github/CODEOWNERS`로 옮깁니다. 임의의 계정명을 넣어 두지는 않습니다.

## 병합 전 확인

```text
[ ] 정상 HWPX 경로가 깨지지 않았는가?
[ ] 공격 HWPX가 여전히 색인되지 않는가?
[ ] 공통 JSON 계약을 지켰는가?
[ ] 합성 데이터만 커밋했는가?
[ ] 외부 API 없이 핵심 경로가 동작하는가?
```

실제 사내 문서, 개인정보, API 키, 로컬 모델 파일, 벡터 인덱스, 격리 원본은 커밋하지 않습니다.

## 기능 동결

H18부터는 새 기능을 받지 않습니다. 데모 안정화, 오류 메시지, 테스트, README, 영상에 필요한 변경만 허용하며 안정 버전에 `demo-v0.1` 태그를 붙입니다.
