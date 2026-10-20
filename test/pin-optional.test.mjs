import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const read=path=>fs.readFileSync(new URL('../'+path,import.meta.url),'utf8');
const files={
 initial:read('supabase/functions/t08-register/index.ts'),
 additional:read('supabase/functions/t08-keys/index.ts'),
 profile:read('supabase/functions/t08-profile/index.ts'),
 login:read('supabase/functions/t08-login/index.ts'),
 page:read('index.html')
};
test('PIN not required in initial, additional, or cross-profile WebAuthn registration options',()=>{
 for(const k of ['initial','additional','profile']){
  const src=files[k];
  assert.match(src,/residentKey:'preferred',userVerification:'discouraged'/,k);
  assert.ok(!src.includes("userVerification:'required'"),k);
 }
});
test('PIN optional for all signed registration verifications but physical user presence retained',()=>{
 for(const k of ['initial','additional','profile']){
  const src=files[k];
  assert.ok(src.includes('requireUserPresence:true,requireUserVerification:false'),k);
  assert.ok(src.includes('verifyRegistrationResponse({'),k);
  assert.ok(src.includes('expectedChallenge:'),k);
  assert.ok(src.includes('expectedOrigin:'),k);
  assert.ok(src.includes('expectedRPID:'),k);
  assert.ok(src.includes('.registrationInfo'),k);
 }
});
test('login options and server-side assertion checks do not force PIN or biometric UV',()=>{
 const src=files.login;
 assert.ok(src.includes("rpID:RP_ID, userVerification:'discouraged'"));
 assert.ok(src.includes('requireUserVerification:false'));
 assert.ok(!src.includes('authenticationInfo?.userVerified'));
 assert.ok(src.includes('verifyAuthenticationResponse({'));
 assert.ok(src.includes('if(!result.verified||!result.authenticationInfo)'));
 assert.ok(src.includes('expectedChallenge:issued.challenge'));
 assert.ok(src.includes('expectedOrigin:ORIGIN'));
 assert.ok(src.includes('expectedRPID:RP_ID'));
});
test('replay protection, server sessions, duplicate protection and proof of possession remain',()=>{
 assert.ok(files.login.includes("delete().eq('id',challengeId)"));
 assert.ok(files.login.includes("t08_open_login_session"));
 assert.ok(files.login.includes('counter:Number(keyRow.counter)'));
 assert.ok(files.additional.includes('excludeCredentials:keys.map'));
 assert.ok(files.profile.includes('excludeCredentials:keys.map'));
 assert.ok(files.profile.includes("'t08_finalize_profile_enrollment'"));
});
test('site explains provider PIN policy cannot be overridden',()=>{
 assert.match(files.page,/PIN 입력 필수 아님/);
 assert.match(files.page,/Google·Windows·Bitwarden/);
 assert.match(files.page,/서버는 서명을 검증/);
});
