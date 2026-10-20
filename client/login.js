// Task 08 Card 3: passwordless authentication, with HttpOnly server session.
const byId=id=>document.getElementById(id);
const button=id=>byId(id);
const state={busy:false,active:null,lastChallenge:null,loginAbort:null};
const events=[];
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
function busy(value){
 state.busy=value;
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
async function loadPrivate(){
 const r=await fetch('/api/private',{cache:'no-store',credentials:'same-origin'});
 if(!r.ok)throw Error('비공개 자료 요청 HTTP '+r.status);
 const payload=await r.json();
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
}
async function updateStatus(){
 const status=await call('status');
 const ok=status.code===200&&status.data.authenticated===true;
 byId('loginState').textContent=ok?'로그인 중 · 서버 검증 세션':'로그아웃 상태 · 비공개 내용 잠김';
 button('logoutPasskey').dataset.logged=ok?'yes':'no';
 button('logoutPasskey').disabled=!ok||state.busy;
 window.dispatchEvent(new CustomEvent('t08-auth-state',{detail:{authenticated:ok}}));
 if(ok){try{await loadPrivate();}catch(e){report('세션 확인은 됐지만 자료 조회 오류: '+e.message);}}
 return ok;
}
async function login(){
 if(!window.isSecureContext||!navigator.credentials?.get){
  report('HTTPS와 WebAuthn이 지원되는 브라우저에서 실행하세요.');return;}
 busy(true);
 try{
  const issued=await issue();
  state.loginAbort=new AbortController();
  report('기기의 패스키 확인 창에서 등록한 horse 패스키를 선택하세요.');
  const credential=await navigator.credentials.get({
   publicKey:options(issued.options),signal:state.loginAbort.signal});
  if(!credential)throw Error('user_canceled');
  const result=await call('verify',{challengeId:issued.challengeId,response:serialize(credential)});
  state.active=null;
  log('실제 WebAuthn 서명 검증',result.code,result.code===200?'성공 · 세션 값 [가림]':result.data.error||'거절');
  if(result.code!==200||!result.data.signatureVerified)throw Error(result.data.error||'signature_invalid');
  byId('sessionProof').textContent='인증: 서명 검증 성공 / 방식: 서버 세션 / 보관: HttpOnly·Secure·SameSite=Strict 쿠키 / 세션 값: [가림]';
  report('패스키 로그인 성공! 비공개 자료를 서버에서 가져옵니다.');
  await updateStatus();
 }catch(e){
  if(state.active)await cancelCurrent().catch(()=>{});
  report(['NotAllowedError','AbortError'].includes(e.name)||e.message==='user_canceled'
   ?'로그인을 취소했습니다. 비공개 자료는 열리지 않습니다.':'로그인 실패: '+e.message);
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
 }catch(e){report('로그아웃 확인 오류: '+e.message);}
 finally{busy(false);}
}
function start(){
 button('loginPasskey').addEventListener('click',login);
 button('loginCompare').addEventListener('click',compare);
 button('loginFake').addEventListener('click',failedAndReplay);
 button('logoutPasskey').addEventListener('click',logout);
 window.addEventListener('t08-keys-session-revoked',()=>updateStatus().catch(()=>{}));
 byId('sessionProof').textContent='로그아웃 상태 / 세션 값: [가림]';
 updateStatus().catch(()=>report('인증 서버 상태를 확인하지 못했습니다.'));
}
start();