# 과제 8 — 카드 5 인증·권한 분리 구현 및 확인 보고서

> 상태 (2026-10-20): 코드/모의 요청 검증 및 공개 운영 경로 일부 확인 완료. **owner2 전용 패스키 등록(14:33:42 KST)과 실제 owner2-key 서명 로그인(14:47:29 KST) 성공 확인. 양방향 실계정 접근 거절 증거는 브라우저 로컬에 있어 제출용 실측 기록은 아직 확인 대기.** 미검증 항목을 통과했다고 표시하지 않는다.

**제출 결과물 URL (T08-C01):** https://my-intro-t08.vercel.app/

**제출 소스 URL (T08-C02):** https://github.com/dfdfewqk/my-intro-passkey-t08

둘 다 HTTPS, 새 시크릿 창에서 공개 첫 화면·공개 소스 조회 시 로그인/초대 없이 열려야 한다. 2026-10-20 운영 GET에서 HTML 200, 공개 GitHub 200 확인. 첫 화면 iframe은 1번 과제 원본 `https://dfdfewqk.github.io/my-intro-page/`을 그대로 포함한다. **모든 개인 자료는 평가용으로 만들어 넣은 가상 텍스트**이며 실제 연락처·비밀번호·신분증·개인키를 제출하지 않는다.

## ① 무엇으로 붙였나 — T08-C47 / C48

- **라이브러리 + 직접 구현 혼합:** 브라우저 WebAuthn `navigator.credentials.create/get`, 검증 라이브러리 `@simplewebauthn/server@14.0.3`를 사용했다. 자체 암호 알고리즘을 만드는 대신 검증된 라이브러리의 challenge/서명/RP ID/출처 검증을 활용했다.
- **인증·DB:** Supabase Edge Functions(`t08-login`, `t08-keys`, `t08-owner2`)와 PostgreSQL; 서명·공개키·질문·서버 세션 저장 및 사용자 분리.
- **웹 호스팅:** Vercel의 Node.js API와 공개 HTML/JS. 서버가 `HttpOnly; Secure; SameSite=Strict` 쿠키를 발급해 세션을 유지한다.
- 사이트 계정 `owner`와 `owner2`는 **서로 다른 사이트 사용자**이다. 두 Google 로그인 계정의 원본 개인정보를 가져오거나 동기화하지 않는다.

## ② 왜 그걸 골랐나

패스키 개인키는 기기·패스키 관리자에 남기고 서버에는 공개키와 검증 정보를 보관한다. 서버가 실제 서명을 확인해야 비공개 자료를 조회할 수 있게 구성했다. 같은 PC에서 패스키를 등록할 수 있도록 Google 계정/추가 USB를 필수로 만들지 않았다. **카드 4(한 계정에 2개)**와 **카드 5(다른 계정도 패스키 1개)**를 동시에 만족시키기 위해 최소 3개의 다른 패스키가 필요하다. `horse`, `horse2`는 `owner`에 보존하고 새 `owner2-key`를 별도로 등록하도록 했다.

## ③ 어디를 어떻게 고쳤나 — T08-C49 / C41

| 흐름 | 주요 소스 위치 | 서버 검증/보호 |
|---|---|---|
| 패스키 최초 등록·추가 | `client/enroll.js`, `client/keys.js`, `supabase/functions/t08-register/index.ts`, `supabase/functions/t08-keys/index.ts` | challenge, 서명, 공개키, 세션, 본인 계정 owner_id 검증 |
| 두 번째 사이트 계정 등록 | `client/owner2.js`, `api/owner2.js`, `supabase/functions/t08-owner2/index.ts` | owner 최근 인증 + owner에 기존 패스키 2개 확인 + 신규 패스키 서명 검증 후 owner2만 생성. **기존 키 이동/삭제 없음** |
| 로그인 | `client/login.js`, `api/auth.js`, `supabase/functions/t08-login/index.ts` | 인증서명을 검증하고 **실제 credential_id가 소속된 owner_id**로 서버 세션 생성 |
| 로그아웃 | `client/login.js` → `api/auth.js` → `t08-login` `logout` | 세션의 revoked_at을 변경하고 동일 세션 재검증 거부 |
| 비공개 자료 조회·타 계정 차단 | **`api/private.js`** → `api/auth.js` / `t08-login validate` | 쿠키로 검증된 ownerId만 읽음. `?account=2` 등 다른 계정 명시 시 403 `other_account_forbidden` 반환 |
| 계정번호 위조 무력화 | **`api/private.js`** | 사용자 입력 `?owner_id=2&requestedOwner=2`는 권한이 아니므로 무시. 검증한 ownerId의 자료만 내려줌 |
| 패스키 삭제와 세션 폐기 | `client/keys.js`, `api/keys.js`, `t08-keys`, Postgres `t08_remove_owner_passkey` | 자기 소유 키만 삭제 가능. 마지막 1개 보호. 삭제된 키로 만들어진 기존 세션도 폐기 |
| 실제 권한 요청 검사 | `client/card5.js`, `test/card5-tenants.test.mjs` | 내 자료 건수 전/후, 타 계정 403, URL 계정 ID 위조 시 자기 것 200 출력. 비밀 본문/쿠키는 표시하지 않음 |

**주의:** 두 패스키를 두 계정으로 이동시키는 초기 제안은 카드 4의 패스키 2개 조건을 깨므로 폐기했다. `owner2`에 새로운 패스키를 등록하는 방식으로 변경했다.

## ④ 안 열리는 것을 확인한 기록 — T08-C37~40 / C50

**구별 표기:** **운영** = 공개 실제 서버 HTTP 요청, **모의** = 실데이터 대신 별도 세션/임의 가짜 문서로 검증한 단위 시험, **대기** = 서로 다른 실제 패스키 계정을 만든 뒤 필요한 시험.

| 확인 네 가지 | 통과/허용 요청 | 거절 요청 | 증거와 현재 판정 |
|---|---|---|---|
| 1. 로그인 없이 주소 열기 | `GET /` → HTTP 200 (공개 첫 화면) | `GET /api/private` (무인증) → HTTP 401 `authentication_required` | **운영 확인 완료**. 로그인 후 GET 200/3건은 자동 테스트 성공, 실계정 접속 증거는 다시 수집 가능 |
| 2. 다른 계정 자료 열기 (양방향) | 모의 `owner=1: GET /api/private?account=1` → 200, 임의 문서 3건 / 모의 `owner=2: ...account=2` → 200, 서로 다른 임의 문서 3건 | 모의 owner1 `?account=2` → 403 / 모의 owner2 `?account=1` → 403, `other_account_forbidden` | **양방향 자동 테스트 통과, 두 실제 패스키 계정의 교차 접근 요청 검증 대기**. 각 계정에서 카드 5 검사를 한 번씩 실행 |
| 3. 이미 쓴 질문 재사용 | `POST /api/auth {action:'options'}` → 200; 실제 패스키 정상 서명 검증 이력 존재 | 운영 `POST /api/auth {action:'verify',challengeId:... ,response: 위조된 값}` → 401 `unknown_credential`, **같은 challengeId 재요청** → 409 `challenge_expired_or_replayed` | **운영 확인**. 이 시험은 *위조된 첫 서명*을 사용했으므로, 정상 서명 응답 자체의 반복 제출 증거와 구별 |
| 4. 삭제된 키 로그인 | 삭제 후 남은 horse/horse2의 서버 로그인 검증 성공 이력 및 기존 owner 키 2개 유지 | 삭제한 credential ID가 등록 목록에서 제거돼 `unknown_credential` 401 처리되는 소스/테스트가 존재 | **운영 삭제/재로그인 이력 + 자동 테스트 확인**. 실제 삭제된 패스키로 브라우저 로그인 시도 증거는 별도 보강 가능 |

### T08-C39 자료 건수 보존 기록

자동 테스트의 가상 계정 A: **3건 →** 상대 계정 접근 403 **→ 3건**. 가상 계정 B: **3건 →** 상대 계정 접근 403 **→ 3건**. 이것은 `test/card5-tenants.test.mjs`의 **모의 결과**다. owner2의 실제 패스키 등록은 완료됐으며, 두 계정의 실제 운영 교차 요청과 건수 기록은 추가 확인이 필요하다.

### T08-C40 다른 계정 번호를 적어 요청

**모의**: owner1의 유효한 서버 세션으로 `GET /api/private?owner_id=2&requestedOwner=2` → HTTP 200, `accountId=1`, 자기 자료 3건. 반대로 owner2 세션에서 `?owner_id=1` → HTTP 200, `accountId=2` 자기 자료 3건. 실제 서비스에서는 로그인한 계정의 `ownerId`를 서버 검증 결과에서만 정하고, URL/본문 계정 식별자는 권한으로 인정하지 않는다.

### 실제 계정 검증을 마치면 추가할 증거 (아직 대기)

owner2 패스키는 2026-10-20 14:33:42 KST 등록 완료 → 이제 각 계정에서 `카드 5 실제 접근 검사` 클릭 → 버튼의 요청과 응답을 복사해 이곳에 덧붙임. **계정이 분리되기 전에는 403 테스트를 완료했다고 제출하지 않는다.**

## ⑤ AI와 나 — T08-C53

- **AI에게 맡긴 일:** 기존 코드/DB 제약 분석, WebAuthn 서버 검증·세션 권한 검사, 계정별 자료 분리 구현, HTTP 긍정/거절 쌍 시험, 자동 테스트와 문서 작성.
- **내가 직접 판단한 일:** PC 한 대에서 사용하고 싶다는 조건, 기존 `horse`·`horse2`와 공개 소개 페이지를 유지해야 한다는 조건, 실제 브라우저에서 패스키를 만들고 최종 결과를 확인할지 여부.
- **AI 제안을 따르지 않은 일:** 기존 `horse2`를 두 번째 사이트 계정으로 *이동*하는 안. 그러면 카드 4의 “원래 계정에 패스키 2개”가 깨지므로, 이동하지 않고 세 번째 패스키를 새로 등록하는 방향으로 변경했다.

## ⑥ 아직 못 막은 것 — T08-C51

- **마지막 패스키가 하나뿐일 때 분실 복구:** 마지막 1개 삭제를 막아도 기기 자체를 잃으면 스스로 로그인할 수 없다. 공개 셀프 복구/타인 복구 기능은 만들지 않았다.
- **패스키 관리자 자체의 접근 통제:** OS/Google이 자체 잠금 해제를 생략하거나 기기가 잠금 해제된 상태에서 탈취되면 사이트가 직접 막을 수 없는 위험이 있다. 사이트는 WebAuthn의 사용자 확인(UV)을 필수로 요구하지 않도록 수정한 상태이므로 운영 서비스라면 강화를 검토해야 한다.
- **실제 두 계정 독립 접근 증명 일부 미완료:** owner2-key 패스키 등록과 로그인 성공은 서버 기록으로 확인됐다. 단, owner/owner2 두 방향의 실제 교차 요청·거절 HTTP 응답은 브라우저의 sessionStorage에 남으므로 확인 기록을 복사해 제출 문서에 첨부해야 한다.
- **실제 개인정보 저장 서비스가 아님:** 비공개 데이터는 과제 평가용 가상 기록이며, 상용 보안 인증이나 실제 개인정보 보관에 사용할 수 없다.

## 짧은 확인 방법 — T08-C52

① **어디로 가나요?** https://my-intro-t08.vercel.app/ 의 `카드 5 · 요청과 응답 증거`와 `카드 5 · 두 번째 사이트 계정 준비`.

② **세 단계 안에 무엇을 하나요?** (1) `owner2-key`로 로그인해 카드 5 접근 검사를 실행 (2) 로그아웃 후 `horse` 또는 `horse2`로 로그인해 같은 검사 실행 (3) 양방향 기록 2/2를 확인하고 검사 결과 복사.

③ **무엇이 보이면 통과인가요?** 공개 200, 익명 비공개 401, 자기 자료 200, 다른 계정 자료 403, 위조 URL에도 자기 계정 ID와 자기 자료 200, 거절 전후 내 자료 건수 동일, 유효한 서명·세션 생성 및 삭제된 키 거절.

④ **안 될 때는 무엇이 보이나요?** `authentication_required` 401(로그인 필요), `other_account_forbidden` 403(정상 차단), `recent_login_required` 403(최근 패스키 인증 필요), `challenge_expired_or_consumed` 409(질문 만료/재사용), 인증 서버 503(장애). **403은 의도된 거절이고 503은 오류**다.

## 검증 데이터의 출처

- 실제 운영 무인증 경로 확인(2026-10-20): 결과물 200, GitHub 200, /api/private 401, /api/keys 401, /api/owner2 401.
- 운영 로그인 질문 발급: HTTP 200, 기존 패스키 허용 ID 2개.
- 운영 잘못된 자격증명 검증: HTTP 401 `unknown_credential`, 동일 질문 반복 HTTP 409 `challenge_expired_or_replayed`.
- `npm test` 전체 테스트와 `test/card5-tenants.test.mjs`의 가상 두 계정은 운영에서의 `owner2` 실등록 성공을 대신하지 않는다.

## 2026-10-20 사용자 등록 후 재검사

- 실제 DB: owner=2개(horse, horse2), owner2=1개(owner2-key; 14:33:42 KST). 서로 다른 Credential ID, 각기 다른 owner_id에 저장됨. 기존 owner 패스키 유지.
- 실제 DB 조회 시 owner2의 로그인 세션은 **아직 확인되지 않음**. 새 owner2 패스키의 실제 WebAuthn 로그인과 두 방향의 접근 거절(403)은 시도한 것으로 가정하지 않는다.
- `client/card5.js`는 한 방향 실제 HTTP 요청에서 자기 자료 200, 상대 403/other_account_forbidden, URL 위조에도 내 계정 200, 익명 401, 전후 자료 건수 동일을 모두 검증한 뒤에만 완료 기록을 만든다. 동일 브라우저 탭의 `sessionStorage`에 **상태코드·자료 건수·계정 ID·시간만** 저장한다. 인증 쿠키·패스키 키·비공개 본문은 보관하지 않는다. 다른 브라우저 프로필은 세션 저장이 따로이므로 그 경우는 각 결과를 개별적으로 복사한다.
- 심사 플랫폼에 URL과 설명서를 제출하고 최종 승인을 받는 일은 자동 테스트 통과와는 별개이다.

## 2026-10-20 14:47:29 KST 추가 검증

- **실제 owner2-key 서명 로그인 성공:** public.t08_login_sessions에서 owner_id=2 신규 로그인 세션 1개 생성(14:47:29 KST), 미폐기 유효 세션 1개 확인. 직전 상태(0개)와 구분.
- owner 원래 패스키 horse, horse2 각 1개 그대로 유지; owner2에는 owner2-key 1개만 있음.
- t08_login_audit의 마지막 verified 이벤트 14:47:29 KST, 최신 배포 READY, 운영 오류 목록에서 최근 오류 없음.
- **아직 확인할 증거:** 실제 owner 계정에서 owner2 자료 요청 403, owner2 계정에서 owner 자료 요청 403, 각자 접근 거절 전후 자료 건수 일치, 다른 계정 번호를 넣은 URL의 실제 자기 계정 응답. 서버 DB에는 접근 테스트 로그를 별도 수집하지 않으며 `client/card5.js`가 브라우저 sessionStorage에 계정별 요약을 24시간 기록. 이 기록을 복사해 제출문에 첨부해야 실제 양방향 검증 완료로 판단 가능.
