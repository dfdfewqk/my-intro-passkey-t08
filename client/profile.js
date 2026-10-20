// Separate Google account B passkey via short-lived owner-approved enrollment link.
// No OAuth/google account tokens or passkey private keys enter this app.
const e=id=>document.getElementById(id);
let profileTicket=null,profileChallenge=null,profileAbort=null;
function profileMsg(s){e('profileMessage').textContent=s;}
function profileAudit(s){e('profileEvidence').textContent=s;}
async function profileAPI(action,more={}){
 const r=await fetch('/api/profile',{method:'POST',credentials:'same-origin',
 cache:'no-store',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({action,...more})});
 const d=await r.json().catch(()=>({error:'invalid_response'}));
 return {status:r.status,data:d};
}
function b64decode(input){
 const b=input.replace(/-/g,'+').replace(/_/g,'/');
 return Uint8Array.from(atob(b+'='.repeat((4-b.length%4)%4)),c=>c.charCodeAt(0));
}
function b64encode(buffer){
 let str='';for(const b of new Uint8Array(buffer))str+=String.fromCharCode(b);
 return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function parseNewCredentialOptions(raw){
 if(typeof PublicKeyCredential.parseCreationOptionsFromJSON==='function')
  return PublicKeyCredential.parseCreationOptionsFromJSON(raw);
 return {...raw,challenge:b64decode(raw.challenge),
 user:{...raw.user,id:b64decode(raw.user.id)},
 excludeCredentials:(raw.excludeCredentials||[]).map(c=>({...c,id:b64decode(c.id)}))};
}
function serializeNewCredential(cred){
 if(typeof cred.toJSON==='function')return cred.toJSON();
 const r=cred.response;
 return {id:cred.id,rawId:b64encode(cred.rawId),type:cred.type,
 response:{attestationObject:b64encode(r.attestationObject),clientDataJSON:b64encode(r.clientDataJSON),
 transports:r.getTransports?.()||[]},
 clientExtensionResults:cred.getClientExtensionResults?.()||{}};
}
async function getOwnerLogin(){
 const s=await fetch('/api/auth',{method:'POST',credentials:'same-origin',
 headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'status'})});
 const data=await s.json().catch(()=>({authenticated:false}));
 if(s.ok&&data.authenticated)return true;
 if(typeof window.t08StartLogin!=='function'){profileMsg('로그인 기능이 준비되지 않았습니다. 새로고침하세요.');return false;}
 return await window.t08StartLogin();
}
async function issueLink(){
 const name=e('profileNewName').value.trim();
 if(name.length<2||name.length>48){
  profileMsg('새 패스키 이름은 2~48자로 입력하세요.');return;
 }
 e('profileIssue').disabled=true;
 try{
  profileMsg('계정 A에서 기존 horse 패스키로 로그인하여 소유자 승인 중입니다…');
  if(!await getOwnerLogin()){
   profileMsg('기존 패스키 로그인이 완료되지 않았습니다. 새 프로필에서는 로그인할 필요가 없도록 여기에서 먼저 인증해야 합니다.');
   return;
  }
  const result=await profileAPI('issue',{name});
  if(result.status!==200)throw Error('HTTP '+result.status+' '+(result.data.error||'unknown'));
  const value=location.origin+location.pathname+'#profileEnroll='+result.data.ticket;
  e('profileLink').value=value;
  e('profileLinkBox').hidden=false;
  e('profileCopy').disabled=false;
  profileMsg('5분짜리 일회성 링크가 생성됐습니다. 오른쪽 위 Chrome 프로필 버튼에서 Google 계정 B 프로필을 열고 링크를 붙여넣으세요. A 프로필에서 등록 버튼을 누르면 다시 계정 A 저장소로 연결됩니다.');
  profileAudit('발급 완료 · 이름: '+name+' · 토큰: [가림] · 만료 5분 · 기존 패스키 변경 없음');
  e('googleProfilePanel').scrollIntoView({behavior:'smooth',block:'start'});
 }catch(err){profileMsg('등록 링크 발급 실패: '+err.message);}
 finally{e('profileIssue').disabled=false;}
}
async function copyLink(){
 const link=e('profileLink').value;
 if(!link){profileMsg('먼저 등록 링크를 발급하세요.');return;}
 try{
  await navigator.clipboard.writeText(link);
  profileMsg('링크를 복사했습니다. **다른 Chrome 프로필 B**로 전환해 주소창에 붙여넣으세요. 이 링크는 계정 등록 권한이 있으니 타인에게 공유하지 마세요.');
 }catch{
  e('profileLink').focus();e('profileLink').select();
  profileMsg('자동 복사가 안 됩니다. 링크 입력칸 전체를 복사해 계정 B의 Chrome 프로필에 붙여넣으세요.');
 }
}
function stopOldToken(){
 profileTicket=null;
 profileChallenge=null;
 sessionStorage.removeItem('t08_profile_handoff');
 e('profileReceiver').hidden=true;
 e('profileEnrollBtn').disabled=true;
}
async function openLink(ticket){
 profileTicket=ticket;
 e('profileReceiver').hidden=false;
 e('profileSender').hidden=true;
 e('profileEnrollBtn').disabled=false;
 e('profileReceiverName').textContent='등록 정보 확인 중…';
 e('profileReceiverStatus').textContent='링크 확인 중…';
 const r=await profileAPI('status',{ticket});
 if(r.status!==200){
  e('profileReceiverStatus').textContent='등록 링크가 만료되었거나 유효하지 않습니다. 계정 A에서 새 링크를 발급해 주세요. HTTP '+r.status;
  e('profileEnrollBtn').disabled=true;
  stopOldToken();
  e('profileReceiver').hidden=false;
  return;
 }
 e('profileReceiverName').textContent=r.data.name;
 e('profileReceiverStatus').textContent='이 Chrome 프로필 오른쪽 위 Google 계정이 B인지 확인하세요. 확인 후 새 패스키를 생성하면 같은 사이트 owner 계정에 추가됩니다. 기존 horse는 보존됩니다.';
 profileMsg('계정 B 프로필에서 등록할 준비가 됐습니다. 실제 Chrome 계정을 이 사이트가 자동으로 읽거나 바꾸지는 않습니다.');
 e('profileReceiver').scrollIntoView({behavior:'auto',block:'start'});
}
async function cancelProfileChallenge(){
 if(profileAbort)profileAbort.abort();
 const id=profileChallenge;
 profileChallenge=null;
 if(id&&profileTicket){
  try{await profileAPI('cancel',{ticket:profileTicket,challengeId:id});}catch{}
 }
 e('profileEnrollBtn').disabled=false;
 profileMsg('등록을 취소했습니다. 새 패스키는 서버에 추가되지 않았습니다.');
}
async function registerSecondGoogle(){
 if(!profileTicket)return profileMsg('유효한 등록 링크를 먼저 열어주세요.');
 if(!window.isSecureContext||!navigator.credentials?.create)
  return profileMsg('HTTPS와 WebAuthn 지원 브라우저가 필요합니다.');
 e('profileEnrollBtn').disabled=true;
 try{
  const issued=await profileAPI('options',{ticket:profileTicket});
  if(issued.status!==200)throw Error('등록 질문 HTTP '+issued.status+' '+(issued.data.error||''));
  profileChallenge=issued.data.challengeId;
  profileAudit('별도 Chrome 프로필 B · 등록 challenge 발급 HTTP 200 · 지문 '+issued.data.challengeFingerprint+' · 계정 선택은 Chrome에서 · 링크 토큰 [가림]');
  profileMsg('새 패스키를 만드는 중입니다. Chrome에서 현재 프로필 B의 Google 비밀번호 관리자에 저장하는지 확인하세요.');
  profileAbort=new AbortController();
  const credential=await navigator.credentials.create({
   publicKey:parseNewCredentialOptions(issued.data.options),
   signal:profileAbort.signal
  });
  if(!credential)throw Error('registration_canceled');
  if(!profileChallenge)throw Error('registration_canceled');
  const verify=await profileAPI('verify',{ticket:profileTicket,
    challengeId:profileChallenge,response:serializeNewCredential(credential)});
  profileChallenge=null;
  if(verify.status!==200||!verify.data.passkeyStored)
   throw Error('서버 저장 HTTP '+verify.status+' '+(verify.data.error||''));
  profileAudit('WebAuthn 서명 검증 성공 HTTP 200 · 등록된 패스키 '+verify.data.totalPasskeys+'개 · 링크 1회 사용 완료 · 원문 토큰 [가림]');
  profileMsg('새 패스키 "'+verify.data.displayName+'" 등록 성공! 총 '+verify.data.totalPasskeys+'개. Chrome 계정 B 프로필에서 생성된 자격증명이 같은 사이트 owner 계정에 연결되었습니다. 이제 A 프로필에서 목록을 새로고침해 확인하세요.');
  stopOldToken();
  e('profileReceiver').hidden=false;
  e('profileReceiverStatus').textContent='등록 성공. 이 링크는 재사용할 수 없습니다.';
 }catch(err){
  if(profileChallenge)await cancelProfileChallenge();
  const msg=err?.name==='InvalidStateError'?
   '이미 등록된 horse 패스키가 이 Chrome 프로필에서 선택됐습니다. B 프로필이 별도로 분리되어 있는지, Chrome의 주 Google 계정이 B인지 확인하세요. 기존 패스키는 유지됩니다.':
   ['AbortError','NotAllowedError'].includes(err?.name)?
   '기기에서 등록을 취소했습니다. 같은 링크가 유효한 동안 다시 시도할 수 있습니다.':
   '등록 오류: '+err.message;
  profileMsg(msg);
  if(profileTicket)e('profileEnrollBtn').disabled=false;
 }finally{profileAbort=null;}
}
// Public registration form can start this authorized enrollment flow without
// exposing a fake Google account selector or calling WebAuthn in profile A.
window.t08IssueProfileTicket=issueLink;
async function initializeProfile(){
 e('profileIssue').addEventListener('click',issueLink);
 e('profileCopy').addEventListener('click',copyLink);
 e('profileEnrollBtn').addEventListener('click',registerSecondGoogle);
 e('profileAbortBtn').addEventListener('click',cancelProfileChallenge);
 const incoming=new URLSearchParams(location.hash.slice(1)).get('profileEnroll');
 if(incoming&&/^[0-9a-f]{64}$/.test(incoming)){
  history.replaceState(null,'',location.pathname+location.search);
  sessionStorage.setItem('t08_profile_handoff',incoming);
 }
 const token=sessionStorage.getItem('t08_profile_handoff')||'';
 if(token&&/^[0-9a-f]{64}$/.test(token))await openLink(token);
}
initializeProfile();