# 8번 과제 카드 2 — WebAuthn 패스키 등록

## 서버와 저장소
- 공개 화면: `index.html` / `client/enroll.js`
- 동일 출처 요청: `api/enroll.js`
- 서버 인증: `supabase/functions/t08-register/index.ts`
- 데이터베이스: `t08_registration_challenges`, `t08_passkeys`, `t08_enrollment_invites`, `t08_registration_audit`
- 기존 비공개 자료 API `/api/private`: 카드 3 이전까지 HTTP 401 유지

## 순서
1. 서버에서 소유자에게 주어진 1회성 초대 링크로 접속한다. 공개 소개 내용은 누구나 볼 수 있다.
2. `options` 요청 때 서버가 challenge를 만들고 데이터베이스에 3분간 보관한다.
3. HTTPS에서 WebAuthn `navigator.credentials.create()`를 호출하면 기기가 키 쌍을 생성한다.
4. 서버에서 `verifyRegistrationResponse()`로 challenge, origin, RP ID, 사용자 인증 여부를 검증한다.
5. 원자적으로 challenge를 삭제한 뒤 서버 DB 트랜잭션에 공개키와 이름, 저장 위치를 기록하고 초대 링크를 사용 처리한다.
6. 취소 시 `cancel`을 보내 challenge만 폐기한다. 공개키 기록은 생성하지 않는다.

## C19~C26 확인표
- C19: options 서버 발급 + DB 보관, 3분 제한 (코드/DB)
- C20: 질문 2회 비교 버튼을 눌러 SHA-256 지문 서로 다름을 기록
- C21: 패스키 등록 성공 후 DB `t08_passkeys.public_key_base64url` 존재 여부 확인
- C22: 등록 후 표시되는 값은 비밀번호가 아닌 COSE 형식 공개키(base64url)
- C23: 요청 본문에는 attestationObject, clientDataJSON, credential ID가 있으나 privateKey는 없음
- C24: 이름 지정 후 목록에서 확인
- C25: 등록 취소 시 사용자에게 안내, 새 패스키 저장 없음
- C26: 실제 저장 위치는 사용자 본인이 기기 창에서 확인하고 선택한다. UI는 공급자를 자동 탐지하지 않음

## 주의
- 사용자 초대 링크는 비밀이므로 공개 GitHub 소스나 평가 제출문에 포함하지 않는다.
- 취소할 때 challenge 기록은 감사 기록에 해시로 남을 수 있지만 패스키/공개키 행은 생기지 않는다.
- 패스키 등록과 로그인은 다르다. 카드 3 이전에 비공개 내용 열람을 허용하지 않는다.
- 등록 성공으로 실제 장치에 패스키가 생성되었다는 사용자의 증거는 본인 브라우저에서만 확보할 수 있다.

## 검증
`npm test`로 게이트웨이 및 기존 접근 차단의 단위 테스트를 실행한다.
