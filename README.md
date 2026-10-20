# 내 소개 페이지 · 패스키 과제 8 (카드 1)

기존 GitHub Pages [소개 페이지](https://dfdfewqk.github.io/my-intro-page/)와 원본 index.html을 변경하지 않았습니다. 이 독립 저장소은 동일한 공개 원본을 iframe으로 보여주는 별도 Vercel 사이트와 **서버 인증 경계**를 제공합니다.

## 현재 상태 (카드 1 전용)

- 공개 소개: 모든 방문자가 열람 가능 (원본 사이트 링크도 제공)
- 비공개 영역: 잠금 UI와 서버에서 거절하는 `GET /api/private`
- 실제 비공개 예시 기록 3건: Vercel의 서버 전용 환경변수 `T08_PRIVATE_NOTES_JSON`에만 저장 (공개 GitHub 소스에 내용 없음)
- 공개 메타데이터 `GET /api/status`: 비공개 기록 **개수만** 보고
- 패스키 등록 / 2개 관리 / 로그인 / 로그아웃 / challenge 재사용 방지: **아직 구현하지 않음**

**주의:** 카드 1에서는 패스키를 설치하기 전이므로 누구도 비공개 본문을 열 수 없습니다. 쿠키가 존재한다는 이유만으로 접근을 허용하지 않습니다.

## 개발/테스트

```bash
npm test
```

서버와 페이지를 함께 실행하려면 Vercel 프로젝트의 Root Directory는 저장소 루트(`.`)로 설정합니다. `/api/private`는 Vercel 서버 함수이므로 GitHub Pages의 정적 경로에서는 실행되지 않습니다.

## 시험할 요청

```bash
curl -i https://<Vercel-도메인>/api/private
curl -i -H "Cookie: passkeySession=forged" https://<Vercel-도메인>/api/private
curl -i https://<Vercel-도메인>/api/status
```

첫 두 요청: HTTP 401. 세 번째 요청: 공개 플래그와 기록 개수만 반환하며 본문 없음.

## 카드 1 점검

- T08-C13: 공개/비공개 구획 UI 구현
- T08-C14: 환경변수에 보관된 더미 기록 3건을 메타데이터 개수로 확인할 수 있음 (진짜 열람은 후속 카드)
- T08-C15: 비인증 공개 화면에 기록 본문 없음
- T08-C16~17: 직접 요청 시 401
- T08-C18: 비인증 HTML에 기록 본문 없음
- 과제 전체 체크리스트의 패스키 등록/서명 검증/두 개 분실 복구/남의 패스키 거절은 **미실시**

## 다음 카드에서 할 일

공식 WebAuthn의 서명 검증 라이브러리 + 영속 저장소 + 안전한 최초 소유자 등록 정책을 연결하고, 유효한 서버 검증 세션에서만 위 환경변수를 읽도록 확장합니다. 특히 서버가 발급한 challenge를 1회 사용 후 폐기하고, 공개키만 저장하며, 개인키는 서버에 전송하지 않습니다. 인증을 단순 화면 표시/쿠키 존재만으로 통과시키지 마세요.

## 과제 제출 초안 (카드 1 시점)

- 어디로 가나요: https://my-intro-t08.vercel.app/ 에서 비공개 영역 및 검사 버튼을 엽니다.
- 세 단계 안에 무엇을 하나요: ① 비공개 영역 확인 ② API 상태 검사 클릭 ③ 페이지 소스와 직접 API 응답 검사
- 무엇이 보이면 통과인가요: 원본 공개 소개는 열리고 보호 API 응답은 401이며 소스에 더미 본문이 없습니다.
- 안 될 때는 무엇이 보이나요: 401이 아닌 HTTP 코드/연결 실패 메시지가 표시됩니다.

AI와 내 판단 3줄은 본인이 한 실제 판단이 확인된 뒤 최종 제출에서 작성해야 합니다.


## 배포 주소

- 공개 결과물: https://my-intro-t08.vercel.app/
- 비공개 API: https://my-intro-t08.vercel.app/api/private (미인증 시 HTTP 401 의도)
- 공개 상태 API: https://my-intro-t08.vercel.app/api/status
- 배포 확인: Vercel 프로덕션 빌드 READY. 실제 배포 HTTP 응답의 외부 도구 검증은 별도 필요.

## 저장소 분리

- 현재 GitHub 소스: https://github.com/dfdfewqk/my-intro-passkey-t08
- 1번 원본: https://github.com/dfdfewqk/my-intro-page
- 8번 과제의 서버/화면/테스트는 본 독립 저장소 루트에서 관리합니다.
