// Task 08 Card 3: passwordless authentication, with HttpOnly server session.
const byId=id=>document.getElementById(id);
const button=id=>byId(id);
const state={busy:false,active:null,lastChallenge:null,loginAbort:null,
 sessionMode:'checking',sessionName:'',accountName:'owner'};
const events=[];
let authRevision=0;
let privateRequest=null;
function lockVault(){
 if(privateRequest){privateRequest.abort();privateRequest=null;}
 const vault=byId('vault');vault.replaceChildren();
 const message=document.createElement('p');
 message.className='note';message.textContent='🔒 로그인 후에만 비공개 자료가 표시됩니다.';
 vault.append(message);
}
function report(text){byId('loginMessage').textContent=text;}
function log(label,code,extra=''){
 events.push({time:new Date().toLocaleTimeString('ko-KR'),label,code,extra});
 byId('loginEvidence').textContent=events.map(x=>
   x.time+' | '+x.label+' | HTTP '+x.code+(x.extra?' | '+x.extra:'')).join('\n');
}
function decode(s){
 const v=s.replace(/-/g,'+').replace(/_/g,'/');
 return Uint8Array.from(atob(v+'='.repeat((4-v.length%4)%4)),c=>c.charCodeAt(0));
}
function encode(bytes){
 let t='';for(const b of new Uint8Array(bytes))t+=String.fromCharCode(b);
 return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function call(action,other={}){
 const response=await fetch('/api/auth',{method:'POST',
  credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({action,...other})});
 const data=await response.json().catch(()=>({error:'invalid_server_response'}));
 return {code:response.status,data};
}
function options(raw){
 if(typeof PublicKeyCredential.parseRequestOptionsFromJSON==='function')
  return PublicKeyCredential.parseRequestOptionsFromJSON(raw);
 return {...raw,challenge:decode(raw.challenge),
  allowCredentials:(raw.allowCredentials||[]).map(c=>({...c,id:decode(c.id)}))};
}
function serialize(credential){
 if(typeof credential.toJSON==='function')return credential.toJSON();
 const response=credential.response;
 return {id:credential.id,rawId:encode(credential.rawId),type:credential.type,
  response:{authenticatorData:encode(response.authenticatorData),
   clientDataJSON:encode(response.clientDataJSON),signature:encode(response.signature),
   userHandle:response.userHandle?encode(response.userHandle):null},
  clientExtensionResults:credential.getClientExtensionResults?.()||{}};
}
function renderSessionRibbon(mode=state.sessionMode,name=state.sessionName){
 state.sessionMode=mode;
 state.sessionName=name;
 const panel=byId('sessionRibbon');
 panel.dataset.state=mode;
 const title=byId('sessionRibbonTitle');
 const details=byId('sessionRibbonDetail');
 if(mode==='authenticated'){
  title.textContent='● 로그인됨 · '+(state.accountName||'owner')+' · '+name;
  details.textContent='인증한 패스키: '+name+' · 현재 '+(state.accountName||'owner')+' 자료만 열람 가능';
 }else if(mode==='error'){
  title.textContent='! 로그인 상태 확인 실패';
  details.textContent='서버 연결을 확인하지 못했습니다. 로그인 여부를 확정하지 않습니다.';
 }else if(mode==='checking'){
  title.textContent='로그인 확인 중…';
  details.textContent='비공개 자료실 접근 상태를 확인하고 있습니다.';
 }else{
  title.textContent='○ 로그아웃 · 개인 자료실 잠김';
  details.textContent='공개 소개는 누구나 볼 수 있고, 개인 자료실은 로그인 후에만 열립니다.';
 }
 button('sessionLogin').hidden=mode==='authenticated';
 button('sessionLogout').hidden=mode!=='authenticated';
 button('sessionLogin').disabled=state.busy||mode==='checking';
 button('sessionLogout').disabled=state.busy||mode!=='authenticated';
}
function busy(value){
 state.busy=value;
 renderSessionRibbon();
 for(const id of ['loginPasskey','loginCompare','loginFake'])button(id).disabled=value;
 button('logoutPasskey').disabled=value||button('logoutPasskey').dataset.logged!=='yes';
}
async function issue(){
 const r=await call('options');
 if(r.code!==200)throw Error(r.data.error||'question_unavailable');
 state.active=r.data.challengeId;
 state.lastChallenge=r.data.challengeId;
 log('새 로그인 질문 발급',r.code,'지문 '+r.data.challengeFingerprint);
 return r.data;
}
async function cancelCurrent(){
 const id=state.active;state.active=null;
 if(id)await call('cancel',{challengeId:id});
}
async function loadPrivate(revision){
 const controller=new AbortController();
 privateRequest=controller;
 const r=await fetch('/api/private',{cache:'no-store',credentials:'same-origin',signal:controller.signal});
 if(revision!==authRevision||controller.signal.aborted)return;
 if(!r.ok)throw Error('비공개 자료 요청 HTTP '+r.status);
 const payload=await r.json();
 if(revision!==authRevision||controller.signal.aborted)return;
 if(!payload.private||!Array.isArray(payload.items))throw Error('서버 응답 형식이 올바르지 않습니다');
 const container=byId('vault');
 container.replaceChildren();
 for(const item of payload.items){
  const block=document.createElement('article');
  const h=document.createElement('strong');h.textContent=String(item.title||'연습 메모');
  const p=document.createElement('p');p.textContent=String(item.body||'');
  block.append(h,p);block.style.margin='12px 0';container.append(block);
 }
 log('서버 검증 세션으로 비공개 조회',r.status, '연습 기록 '+payload.items.length+'건');
 return payload.items.length;
}
async function updateStatus(){
 const revision=++authRevision;
 if(privateRequest){privateRequest.abort();privateRequest=null;}
 let status;
 try{status=await call('status');}
 catch(e){
  if(revision===authRevision){
   byId('loginState').textContent='로그인 상태 확인 오류';
   report('로그인 상태 확인 요청이 실패했습니다: '+e.message);
   button('logoutPasskey').dataset.logged='no';
   button('logoutPasskey').disabled=true;
   renderSessionRibbon('error','');
   lockVault();
  }
  return false;
 }
 if(revision!==authRevision)return false;
 if(status.code>=500){
  byId('loginState').textContent='로그인 상태 확인 일시 오류 · 로그아웃으로 판정하지 않음';
  report('인증 서버 확인 오류 HTTP '+status.code+' · 잠시 후 다시 확인하세요.');
  button('logoutPasskey').dataset.logged='no';
  button('logoutPasskey').disabled=true;
  renderSessionRibbon('error','');
  lockVault();
  return false;
 }
 const ok=status.code===200&&status.data.authenticated===true;
 const loginName=ok?String(status.data.passkeyName||'등록된 패스키'):'';
 state.accountName=ok?String(status.data.accountName||'owner'):'owner';
 byId('loginState').textContent=ok?'로그인 중 · '+state.accountName+' · '+loginName+' · 서버 검증 완료':'로그아웃 상태 · 비공개 내용 잠김';
 button('loginPasskey').textContent=ok?'다른 패스키로 다시 로그인':'패스키로 로그인';
 renderSessionRibbon(ok?'authenticated':'loggedOut',loginName);
 button('logoutPasskey').dataset.logged=ok?'yes':'no';
 button('logoutPasskey').disabled=!ok||state.busy;
 if(!ok)lockVault();
 window.dispatchEvent(new CustomEvent('t08-auth-state',{detail:{authenticated:ok}}));
 if(ok){
  try{
   const count=await loadPrivate(revision);
   if(revision===authRevision&&typeof count==='number')
    report('로그인 성공: '+state.accountName+' · '+loginName+' · 서명/세션 확인 · 비공개 자료 '+count+'건 표시');
  }catch(e){
   if(revision===authRevision&&e.name!=='AbortError')
    report('로그인 성공: '+state.accountName+' · '+loginName+' · 다만 비공개 자료 조회 실패: '+e.message);
  }
 }
 return ok;
}
async function login(){
 if(state.busy){
  report('패스키 로그인 확인이 진행 중입니다. 기기 화면을 먼저 완료하세요.');
  return false;
 }
 if(!window.isSecureContext||!navigator.credentials?.get){
  report('HTTPS와 WebAuthn을 지원하는 브라우저에서 실행하세요.');
  return false;
 }
 busy(true);
 try{
  const issued=await issue();
  state.loginAbort=new AbortController();
  report('기기의 패스키 확인 창에서 등록된 패스키를 선택하세요.');
  const credential=await navigator.credentials.get({
   publicKey:options(issued.options),signal:state.loginAbort.signal});
  if(!credential)throw Error('user_canceled');
  const result=await call('verify',{challengeId:issued.challengeId,response:serialize(credential)});
  state.active=null;
  log('실제 WebAuthn 서명 검증',result.code,result.code===200?'성공 · 세션 값 [가림]':result.data.error||'거절');
  if(result.code!==200||!result.data.signatureVerified)throw Error(result.data.error||'signature_invalid');
  byId('sessionProof').textContent='인증: '+String(result.data.passkeyName||'등록된 패스키')+
  ' · 서명 검증 성공 / 방식: 서버 세션 / 보관: HttpOnly·Secure·SameSite=Strict 쿠키 / 세션 값: [가림]';
  report('패스키 로그인 성공! 인증 세션을 확인합니다.');
  const authenticated=await updateStatus();
  if(!authenticated){
    report('서명 확인은 됐지만 서버 세션 또는 쿠키를 확인하지 못했습니다. 로그인 상태 오류를 확인하세요.');
    return false;
  }
  return true;
 }catch(e){
  if(state.active)await cancelCurrent().catch(()=>{});
  const wasCanceled=['NotAllowedError','AbortError'].includes(e.name)||e.message==='user_canceled';
  report(wasCanceled
   ?'패스키 선택이 취소되었거나 기기에 사용할 패스키가 없습니다. Google 저장소에 남은 삭제된 패스키 대신 사이트에 등록된 horse 또는 horse2를 선택하세요.'
   :'패스키 로그인 실패 ('+(e.name||'Error')+'): '+e.message);
  return false;
 }finally{state.loginAbort=null;busy(false);}
}
async function compare(){
 busy(true);
 try{
  const prints=[];
  for(let n=0;n<2;n++){
   const d=await issue();prints.push(d.challengeFingerprint);
   await cancelCurrent();
  }
  report(prints[0]!==prints[1]?'두 로그인 질문의 지문이 서로 다릅니다.':'중복된 질문이 감지됐습니다.');
  log('로그인 질문 2회 비교',prints[0]!==prints[1]?200:500,
   '지문 '+prints.join(' / ')+' · 원본 질문은 공개하지 않음');
 }catch(e){report('질문 비교 실패: '+e.message);}
 finally{await cancelCurrent().catch(()=>{});busy(false);}
}
async function failedAndReplay(){
 busy(true);
 try{
  const d=await issue();
  const invalid={id:'not-registered',rawId:'not-registered',type:'public-key',
   response:{clientDataJSON:'invalid',authenticatorData:'invalid',signature:'invalid'}};
  const bad=await call('verify',{challengeId:d.challengeId,response:invalid});
  log('가짜 서명 제출 거절',bad.code,bad.data.error||'');
  const replay=await call('verify',{challengeId:d.challengeId,response:invalid});
  log('이미 사용한 질문 재제출 거절',replay.code,replay.data.error||'');
  state.active=null;
  report('잘못된 서명: HTTP '+bad.code+' / 질문 재사용: HTTP '+replay.code+
   '. 모두 거절되어야 합니다.');
 }catch(e){report('검증 테스트 오류: '+e.message);}
 finally{await cancelCurrent().catch(()=>{});busy(false);}
}
async function logout(){
 busy(true);
 ++authRevision;
 lockVault();
 try{
  const result=await call('logout');
  const reused=result.data.reuseStatus;
  log('서버 세션 로그아웃',result.code,'세션 값 [가림]');
  if(reused!==undefined)log('동일 세션 값으로 재요청',reused,'폐기 후 재검증 · 세션 값 [가림]');
  byId('sessionProof').textContent='로그아웃 완료 / 세션 값: [가림] / 동일 세션 재요청: HTTP '+(reused??'미확인');
  byId('vault').replaceChildren();
  const p=document.createElement('p');p.textContent='🔒 로그아웃되어 비공개 내용이 내려오지 않습니다.';
  byId('vault').append(p);
  const fresh=await fetch('/api/private',{credentials:'same-origin',cache:'no-store'});
  log('로그아웃 후 비공개 자료 요청',fresh.status,'본문 노출 없음');
  report(result.code===200?'로그아웃 완료 · 기존 서버 세션 폐기 후 동일 값 재사용 결과를 기록했습니다.':
   '로그아웃 서버 응답 HTTP '+result.code);
  await updateStatus();
 }catch(e){
  report('로그아웃 확인 오류: '+e.message);
  renderSessionRibbon('error','');
  lockVault();
 }finally{busy(false);}
}
function start(){
 window.t08StartLogin=login;
 renderSessionRibbon('checking','');
 button('sessionLogin').addEventListener('click',login);
 button('sessionLogout').addEventListener('click',logout);
 button('loginPasskey').addEventListener('click',login);
 button('loginCompare').addEventListener('click',compare);
 button('loginFake').addEventListener('click',failedAndReplay);
 button('logoutPasskey').addEventListener('click',logout);
 window.addEventListener('t08-keys-session-revoked',()=>updateStatus().catch(()=>{}));
 byId('sessionProof').textContent='로그아웃 상태 / 세션 값: [가림]';
 updateStatus().catch(()=>report('인증 서버 상태를 확인하지 못했습니다.'));
}
start();