# HWPX MVP 범위와 보안 기준

## 1. 제품 포지셔닝

레거시 `.hwp`와 `.hwpx`를 구분합니다.

- `.hwp`: 바이너리 형식. 이번 MVP에서 제외합니다.
- `.hwpx`: ZIP 패키지 안의 XML 기반 개방형 형식. PDF와 함께 P0 입력으로 지원합니다.

따라서 팀의 범위 문구는 다음으로 통일합니다.

> 레거시 HWP는 제외하지만 HWPX 텍스트·스타일 추출, 변경 비교, 위험 판정, 색인 통제는 핵심 범위에 포함한다.

## 2. 최소 파서 책임

`src/indexguard/extractors/hwpx.py`는 다음 순서만 책임집니다.

1. 확장자, ZIP 매직, 내부 `mimetype`를 교차 검증합니다.
2. ZIP 항목명과 압축 크기 제한을 검사합니다.
3. `Contents/content.hpf`의 `spine` 순서로 section을 찾습니다.
4. `Contents/section*.xml`의 `hp:p -> hp:run -> hp:t` 텍스트를 위치와 함께 추출합니다.
5. manifest가 참조하는 나머지 XML도 보안 스캔해 머리말·꼬리말·마스터 페이지 등 보조 영역의 텍스트를 별도 evidence로 보존합니다.
6. run의 `charPrIDRef`를 `Contents/header.xml`의 글자 모양과 연결합니다.
7. 텍스트 색상, 크기, 제어문자에 기반해 숨김 의심 표시를 남깁니다.
8. `Scripts/` 안의 비어 있지 않은 스크립트 payload, OLE/미확인 바이너리, 암호화, 변경 추적의 존재를 artifact로 보고합니다.
9. PDF 추출기와 같은 `DocumentSnapshot`을 반환합니다.

본문 읽기 순서를 따르는 section 텍스트만 RAG용 정규 본문에 넣습니다. 보조 XML에서 찾은 텍스트는 공격 탐지 evidence로 사용하되 본문에 임의로 섞지 않습니다.

한컴 프로그램을 자동 실행하거나 HWPX 내부 콘텐츠를 실행하지 않습니다.

## 3. 지원 범위

### 확실히 지원

- 모든 section의 XML 본문 텍스트
- 표·글상자 안의 XML 텍스트
- manifest가 참조하는 보조 XML의 텍스트 보안 스캔
- 제목, 작성자, 생성일 등 기본 메타데이터
- 텍스트 색상·크기와 위치 참조
- 비어 있지 않은 스크립트 payload 존재 여부
- 이미지가 아닌 `BinData`/OLE 존재 여부
- 암호화 표시와 변경 추적 설정 존재 여부

### 휴리스틱 지원

- 흰색 또는 배경과 거의 같은 색의 텍스트
- 1pt 이하처럼 비정상적으로 작은 텍스트
- 제로폭 문자와 bidi 제어문자
- 외부 URL·파일 참조
- Preview 텍스트와 실제 본문 사이의 큰 불일치

### 제외

- 화면 밖 또는 다른 도형 뒤 텍스트의 완전한 렌더링 판정
- 이미지 OCR
- 복잡한 도형, 그룹, 차트의 시각적 의미 복원
- 암호화 문서 복호화
- 모든 변경 추적 이력의 완전한 재구성
- 레거시 `.hwp` 파싱

## 4. fail-closed 정책

| 조건 | 판정 | 동작 |
|---|---|---|
| 정상 HWPX | `ALLOW` | `INDEX` |
| 흰색·극소 텍스트 | 최소 `REVIEW` | `HOLD` |
| 숨김 텍스트 안의 인젝션 | `BLOCK` | `QUARANTINE` |
| 비어 있지 않은 스크립트 payload | `BLOCK` | `QUARANTINE` |
| OLE·검사 불가능 바이너리 | `BLOCK` | `QUARANTINE` |
| 암호화되어 검사 불가 | `BLOCK` | `QUARANTINE` |
| 손상, 과대 압축, 형식 불일치 | `BLOCK` | `QUARANTINE` |
| 변경 추적만 존재 | `REVIEW` | `HOLD` |

## 5. 파서 자체의 보안

HWPX는 ZIP+XML이므로 분석기도 공격 대상입니다. MVP 기본 제한은 다음과 같습니다.

- 업로드 파일: 20MB 이하
- ZIP 항목: 1,000개 이하
- 전체 해제 크기: 100MB 이하
- XML 파일 하나: 10MB 이하
- 항목별 압축률: 100배 이하
- 전체 분석 timeout 적용

구현 규칙:

- `extractall()`을 사용하지 않고 필요한 멤버만 스트림으로 읽습니다.
- 절대 경로, `..`, 백슬래시, 중복 정규화 경로를 거부합니다.
- `defusedxml`처럼 DTD와 ENTITY를 허용하지 않는 XML 파서를 사용합니다.
- 외부 URI와 XInclude를 요청하지 않습니다.
- 스크립트 payload와 OLE를 실행하지 않습니다.
- 제한 초과, 암호화, 파싱 실패는 안전하게 차단합니다.

## 6. fixture와 합격 기준

```text
tests/fixtures/hwpx/
├─ clean.hwpx
├─ number_changed.hwpx
├─ hidden_prompt.hwpx
├─ with_script.hwpx
└─ malformed.hwpx
```

합격 기준:

- 정상 HWPX의 section과 표 텍스트가 문서 순서대로 추출됩니다.
- `1,000만 원 -> 1억 원`이 `POLICY_NUMBER_CHANGE`로 탐지됩니다.
- 흰색 악성 지시문이 `HIDDEN_TEXT`와 `PROMPT_INJECTION`으로 탐지됩니다.
- 비어 있지 않은 스크립트 payload가 있는 문서는 색인되지 않습니다.
- 암호화·손상·과대 압축 문서가 서버를 죽이지 않고 격리됩니다.
- 경로 조작 ZIP이 서버 파일을 만들지 못합니다.
- 대표 정상 문서는 `ALLOW`, 공격 문서는 `BLOCK`, 경계 사례는 `REVIEW`입니다.
- `BLOCK` 결과의 색인 청크 수는 항상 `0`입니다.
- 20MB 이하 데모 문서의 정적 파싱은 개발 장비에서 2초 이내를 목표로 합니다.

## 7. 공식 참고 자료

- [한컴테크: HWPX 포맷 구조](https://tech.hancom.com/hwpxformat/)
- [한컴테크: Python을 통한 HWPX 파싱 1편](https://tech.hancom.com/python-hwpx-parsing-1/)
- [한컴테크: Python을 통한 HWPX 파싱 2편](https://tech.hancom.com/python-hwpx-parsing-2/)
- [e나라 표준인증: KS X 6101](https://standard.go.kr/KSCI/standardIntro/getStandardSearchView.do?ksNo=KSX6101&menuId=503&tmprKsNo=KSX6101&topMenuId=502)
- [한컴 개발자 포럼: HWP/HWPX MIME type](https://forum.developer.hancom.com/t/hwp-hwpx-mime-type-whitelist/1641)
- [Python: ZIP 압축 해제 보안 주의](https://docs.python.org/3/library/zipfile.html#decompression-pitfalls)
- [Python: XML 보안](https://docs.python.org/3/library/xml.html#xml-security)
