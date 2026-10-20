# 과제 8 · 카드 3 — 실제 WebAuthn 로그인

## 구현 상태 (2026-10-20)

등록 완료된 **horse** 패스키와 서버에 저장한 공개키를 사용합니다. 새 비밀번호 입력 창, 비밀번호 저장은 없습니다.

- 브라우저: `client/login.js` — `navigator.credentials.get()`, 성공/실패 증거, 안전한 로그아웃
- Vercel 인증 API: `api/auth.js` — 로그인·세션 관리, `__Host-t08_session` 쿠키
- Supabase WebAuthn 서버: `supabase/functions/t08-login/index.ts` — challenge 발급·소비·서명 검증
- 인증 후 자료 조회: `api/private.js` — 매 조회마다 세션 유효성 검증 후 서버 전용 더미 기록 3건 반환
- Supabase DB: `t08_login_challenges`, `t08_login_sessions`, `t08_login_audit`, 기존 `t08_passkeys`

## 동작과 보안

1. 로그인 버튼 → 서버가 **매번 다른 challenge**를 발급하고 DB에 2분 기한으로 보관.
2. 기기가 자신이 가진 개인키로 서명하여 WebAuthn assertion 반환. 개인키는 서버로 전송하지 않음.
3. 서버가 보관했던 challenge를 원자적으로 **1회 소비**하고, 등록된 credential ID 및 공개키로 assertion의 challenge·origin·RP ID·사용자 검증·서명을 확인.
4. 성공한 경우에만 DB 트랜잭션으로 서명 카운터를 갱신하고 임의 세션 토큰의 **SHA-256 해시만 서버 DB에 저장**. 브라우저에는 `HttpOnly; Secure; SameSite=Strict` 세션 쿠키가 설정되며 JavaScript는 원문을 읽지 못함.
5. `GET /api/private`는 서버에서 쿠키를 확인하고 유효한 서버 세션인지 재검사 후 더미 메모를 전송.
6. 로그아웃 시 DB 세션에 폐기 시각을 기록하고 브라우저 쿠키 삭제. 폐기한 **동일 세션값**으로 서버에서 다시 `validate`를 호출하여 반환된 HTTP 코드를 안전하게 기록. 세션 원문이나 해시는 화면/제출문에 포함하지 않음.
7. 인증 실패 시 세션 쿠키를 발급하지 않으며 기존 공개 소개는 누구나 볼 수 있음.

## 과제 T08-C27~C35

| 기준 | 증거 | 현재 |
| --- | --- | --- |
| C27 매 로그인 새 challenge | `options` 호출 → DB 일회용 challenge | 서버 구현 및 실제 발급 확인 |
| C28 서로 다른 질문 | 발급 지문 `f852b37af5f5f2f8` / `b10f9d946c0ea69e` | 실제 서비스 2회 차이 확인 |
| C29 공개키 서명 검증 후 통과 | `verifyAuthenticationResponse` + 공개키 DB 조회 + 검증 뒤에만 세션 발급 | **실제 패스키 로그인 성공 + DB 검증 성공 1건** |
| C30 성공과 실패 나란히 | 로그인 성공 기록, `틀린 서명 · 재사용 검사` 실패 HTTP 401 | **실제 성공 1건 / 실패 2건 확인** |
| C31 질문 재사용 거절 | 동일 challenge ID로 2회 `verify` | HTTP 409 `challenge_expired_or_replayed` 확인 |
| C32 사용자 인식 수단 | 서버 세션, 해시화된 토큰을 DB 보관, HttpOnly 쿠키 | 코드 및 테스트 확인 |
| C33 로그아웃 뒤 동일 값 거절 | 로그아웃 서버가 같은 세션을 다시 `validate` | 단위 테스트에서 HTTP 401; 실제 기기 성공 후 실서비스 재확인 필요 |
| C34 세션·토큰 가림 | 로그는 `[가림]`만 표시, 서버 응답에도 원문 없음 | 코드/테스트 확인 |
| C35 비밀번호 입력란 없음 | HTML 및 JavaScript에서 비밀번호 입력 없이 패스키 인증 | 코드 확인 |

## 실서비스 검증 기록 (개인키·비밀값 없는 기록)

- `POST /api/auth`, `action=status` → HTTP **200**, `authenticated:false`
- `GET /api/private` (로그인 없음) → HTTP **401**
- `POST /api/auth`, `action=options` **2회** → HTTP **200/200**, 서로 다른 지문
- 등록되지 않은 credential 응답 → HTTP **401** `unknown_credential`
- **등록된 credential ID**를 사용하되 무효 서명 데이터 전달 → HTTP **401** `invalid_signature`
- 같은 질문 ID로 재요청 → HTTP **409** `challenge_expired_or_replayed`
- 위조 쿠키의 자료 요청 → HTTP **401**
- 다른 Origin 요청 → HTTP **403** `origin_not_allowed`
- `POST /api/auth`, `action=logout` (세션 없음) → HTTP **401**
- Node.js 테스트 `npm test`: **17개 통과, 실패 0개** (보안 쿠키·서명 실패·로그아웃 세션 재검증 포함)

위 자동 테스트와 초기 라이브 기록에는 성공 로그인이 없었으나, **2026-10-20 10:11:44 KST 소유자 기기의 horse 패스키로 실제 WebAuthn 서명 검증에 성공**했고 서버 세션이 정상 발급되었습니다. 테스트용 세션 삽입이나 서명 검증 우회는 사용하지 않았습니다.

## 실제 기기에서 마무리하는 검증 (3단계)

1. <https://my-intro-t08.vercel.app/>에 접속해 **로그인 질문 2회 비교**와 **틀린 서명·재사용 검사** 버튼 실행.
2. **패스키로 로그인**을 눌러 등록한 `horse` 패스키 인증. 성공 시 연습용 비공개 메모 3건 표시되고 로그인 성공 로그에 HTTP 200.
3. **로그아웃 · 재사용 검사** 클릭. 결과는 동일 세션값 검증 401, 로그아웃 뒤 자료 조회 401이어야 함.

이후 운영 DB `t08_login_sessions`과 `t08_login_audit`의 세션/서명 검증 **성공 여부와 폐기 사실만** 조회해 완료 판정을 기록합니다. **세션 원문, 쿠키값, 토큰 해시, 개인정보는 제출하지 않습니다.**


## 2026-10-20 실제 기기 패스키 로그인 검증 결과

사용자 제공 로그인 화면과 실제 운영 Supabase DB를 대조했습니다.

- 사용한 등록 패스키: `horse` (등록 당시 저장 위치 선택: Google)
- WebAuthn 서명 검증 성공 이벤트: **1건**, 2026-10-20 10:11:44 KST
- 서버 세션: 실제 DB `t08_login_sessions`에 **1개 생성**
- 생성된 세션의 유효기간: 약 12시간
- DB 조회 시점의 세션 상태: **유효**, `revoked=false`
- 동일한 서버 로그에는 서명 검증 실패 `rejected` **2건** 및 사용한 challenge 재사용 `replayed` **2건**이 존재
- 관련 로그의 질문 원문과 세션/토큰/쿠키 원문은 이 문서에 기록하지 않음
- **C29 / C30 서버 실증 완료**
- **C33 실서비스 로그아웃과 동일 세션 재사용 HTTP 401 검증은 아직 대기**: 사용자가 로그아웃 버튼을 클릭하면 서버의 `revoked_at` 및 `logout` 이벤트를 조회하여 확인 예정

**문서 보안 원칙:** 로그인 세션의 해시와 값, 등록용 초대값, 개인키, 비공개 연습 메모 본문은 GitHub 공개 문서에 작성하지 않습니다.
