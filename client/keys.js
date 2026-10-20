// Card 4: second passkey enrollment, safe removal, and server-verified key inventory.
const keyEl=id=>document.getElementById(id);
let pendingId=null,waiter=null,lastRemoved=null,keyAuthorized=false;
let inventoryRevision=0;
let keyOperationBusy=false;
const evidence=[];
const providerLabels={google:'구글 비밀번호 관리자',device:'기기 자체 / Windows Hello',
 phone:'다른 휴대전화 / QR 인증',security_key:'외장 보안 키',unknown:'저장 위치 미확인'};
function sayKeys(t){keyEl('keyManagementMessage').textContent=t;}
function addEvidence(t){evidence.push(new Date().toLocaleTimeString('ko-KR')+' | '+t);
 keyEl('keyManagementEvidence').textContent=evidence.slice(-15).join('\n');}
function fromBase64(s){const t=s.replace(/-/g,'+').replace(/_/g,'/');
 return Uint8Array.from(atob(t+'='.repeat((4-t.length%4)%4)),c=>c.charCodeAt(0));}
function toBase64(buf){let t='';for(const b of new Uint8Array(buf))t+=String.fromCharCode(b);
 return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function keysApi(action,other={}){
 const response=await fetch('/api/keys',{method:'POST',credentials:'same-origin',
 cache:'no-store',headers:{'Content-Type':'application/json'},
 body:JSON.stringify({action,...other})});
 const data=await response.json().catch(()=>({error:'invalid_response'}));
 return {status:response.status,data};
}
function optionsForCreate(o){
 if(PublicKeyCredential.parseCreationOptionsFromJSON)
  return PublicKeyCredential.parseCreationOptionsFromJSON(o);
 return {...o,challenge:fromBase64(o.challenge),
 user:{...o.user,id:fromBase64(o.user.id)},
 excludeCredentials:(o.excludeCredentials||[]).map(c=>({...c,id:fromBase64(c.id)}))};
}
function serializeCreated(c){
 if(typeof c.toJSON==='function')return c.toJSON();
 const r=c.response;
 return {id:c.id,rawId:toBase64(c.rawId),type:c.type,
  response:{attestationObject:toBase64(r.attestationObject),
   clientDataJSON:toBase64(r.clientDataJSON),
   transports:r.getTransports?.()||[]},
  clientExtensionResults:c.getClientExtensionResults?.()||{}};
}
// The form is always editable. Only submitting a new credential requires owner authentication.
function setKeyBusy(yes){
 keyOperationBusy=yes;
 for(const id of ['keyRefresh','keyAdd','keyProbeDeleted']){
  keyEl(id).disabled=yes;
 }
 keyEl('keyCancel').disabled=!yes || !pendingId;
 keyEl('keyUnlock').disabled=yes;
 keyEl('keyEnrollmentFields').disabled=false;
}
function lockManagement(){
 ++inventoryRevision;
 keyAuthorized=false;
 keyEl('keyGate').hidden=false;
 keyEl('keyGateStatus').textContent='현재 로그인하지 않았습니다. 이름과 저장 위치를 미리 고를 수 있으며, 패스키 추가 등록을 누르면 기존 패스키로 본인 확인을 시작합니다.';
 keyEl('keyUnlock').disabled=keyOperationBusy;
 keyEl('keyEnrollmentFields').disabled=false;
 keyEl('keyCountDetailed').textContent='패스키 목록은 기존 패스키로 로그인한 다음 표시됩니다.';
 keyEl('keyListDetailed').replaceChildren();
 const node=document.createElement('p');
 node.className='note';
 node.textContent='패스키 목록은 로그인 후 확인할 수 있습니다. 새 패스키 정보 입력과 등록 시작은 지금도 가능합니다.';
 keyEl('keyListDetailed').append(node);
 keyEl('keyAdd').disabled=keyOperationBusy;
 keyEl('keyRefresh').disabled=keyOperationBusy;
}
async function refreshKeys(){
 const revision=++inventoryRevision;
 let r;
 try{r=await keysApi('list');}
 catch(e){
  if(revision===inventoryRevision)sayKeys('목록 연결 실패: '+e.message+'. 잠시 뒤 새로고침하세요.');
  return false;
 }
 if(revision!==inventoryRevision)return false;
 if(r.status===401){
  lockManagement();
  sayKeys('로그아웃 상태입니다. 바로 위 「기존 패스키로 로그인하고 계속하기」를 누르세요.');
  return false;
 }
 if(r.status!==200){
  sayKeys('목록 확인 오류 HTTP '+r.status+' · '+(r.data.error||'')+'. 로그인 상태를 확인해 주세요.');
  return false;
 }
 const keys=r.data.passkeys||[];
 keyAuthorized=true;
 keyEl('keyGateStatus').textContent='기존 패스키 인증 완료. 새 패스키를 계속 추가할 수 있습니다.';
 keyEl('keyGate').hidden=true;
 keyEl('keyEnrollmentFields').disabled=false;
 keyEl('keyUnlock').disabled=keyOperationBusy;
 const list=keyEl('keyListDetailed');
 list.replaceChildren();
 keyEl('keyAdd').disabled=keyOperationBusy;
 keyEl('keyCountDetailed').textContent='등록된 패스키: '+keys.length+'개';
 if(!keys.length){
  const text=document.createElement('p');
  text.textContent='패스키가 0개라면 이 사이트에 로그인할 방법이 없습니다. 관리자 확인을 거친 별도 복구가 필요합니다. 공개 자가 복구는 허용하지 않습니다.';
  list.append(text);keyEl('keyAdd').disabled=true;
 }else for(const item of keys){
  const card=document.createElement('article');
  card.className='keyItem';
  const top=document.createElement('div');top.className='keyItemHeader';
  const name=document.createElement('strong');name.textContent=item.name;
  const remove=document.createElement('button');remove.type='button';
  remove.className='button secondary';remove.textContent=keys.length<=1?'마지막 패스키 (보호됨)':'이 패스키 삭제';
  remove.disabled=keys.length<=1;
  remove.addEventListener('click',()=>removePasskey(item,keys.length));
  top.append(name,remove);
  const date=document.createElement('p');date.className='note';
  const d=new Date(item.createdAt);
  date.textContent='등록 날짜: '+(Number.isNaN(d.getTime())?String(item.createdAt):
   d.toLocaleString('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}))+
   ' · 저장 위치: '+(providerLabels[item.storageProvider]||'미확인');
  const id=document.createElement('p');id.className='note';id.textContent='자격증명 ID: '+item.id.slice(0,12)+'…';
  card.append(top,date,id);list.append(card);
 }
 keyEl('keyZeroRule').textContent=keys.length===1?
  '현재 마지막 1개만 남아 있어 삭제할 수 없습니다. 먼저 다른 패스키를 등록하세요.':
  '마지막 패스키 삭제는 시스템이 차단합니다. 0개가 되면 로그인 불가이므로 공개 초기화 기능은 제공하지 않습니다.';
 addEvidence('서버 패스키 목록 조회 HTTP 200 / 등록 '+keys.length+'개');
 return true;
}
async function cancelAdd(){
 waiter?.abort();
 const id=pendingId;pendingId=null;
 if(id){const r=await keysApi('cancel',{challengeId:id});
  sayKeys(r.status===200?'패스키 등록 취소: 서버 질문을 삭제했습니다.':'등록 취소 요청을 서버에서 확인하지 못했습니다.');
  addEvidence('두 번째 패스키 등록 취소 HTTP '+r.status);
 }
 setKeyBusy(false);
}
async function ensureEnrollmentSession(){
 // Even after page reload, start button stays enabled; the server decides if session is valid.
 let check=await keysApi('list');
 if(check.status===200){
  keyAuthorized=true;
  return true;
 }
 if(check.status!==401){
  throw Error('로그인 서버 확인 HTTP '+check.status+' ('+(check.data.error||'unknown')+')');
 }
 sayKeys('새 패스키 등록 전 기존 패스키로 본인 확인합니다. 기기 인증 창에서 horse를 선택하세요.');
 const login=window.t08StartLogin;
 if(typeof login!=='function')throw Error('패스키 로그인 모듈을 불러오지 못했습니다. 새로고침 후 다시 시도해 주세요.');
 const ok=await login();
 if(!ok){
  lockManagement();
  sayKeys('기존 패스키 인증이 완료되지 않았습니다. 입력한 새 패스키 이름은 유지됩니다. 기존 horse 패스키로 로그인한 뒤 다시 등록하세요.');
  return false;
 }
 check=await keysApi('list');
 if(check.status!==200){
  lockManagement();
  throw Error('패스키 인증 후 세션 확인 실패 HTTP '+check.status+' ('+(check.data.error||'unknown')+')');
 }
 keyAuthorized=true;
 return true;
}
async function addPasskey(){
 if(keyOperationBusy)return;
 const name=keyEl('additionalKeyName').value.trim();
 const provider=keyEl('additionalKeyProvider').value;
 if(name.length<2||name.length>48){
  sayKeys('새 패스키 이름을 2~48자로 작성하세요. 입력칸은 로그인 전에도 편집할 수 있습니다.');
  keyEl('additionalKeyName').focus();
  return;
 }
 if(!provider){
  sayKeys('패스키를 실제로 저장할 위치를 선택하세요. 기존 구글 관리자와 별개라면 기기 자체/보안 키를 선택할 수 있습니다.');
  keyEl('additionalKeyProvider').focus();
  return;
 }
 if(!window.PublicKeyCredential||!navigator.credentials?.create||!window.isSecureContext){
  sayKeys('HTTPS와 WebAuthn을 지원하는 브라우저가 필요합니다.');
  return;
 }
 setKeyBusy(true);
 try{
  const ready=await ensureEnrollmentSession();
  if(!ready)return;
  sayKeys('로그인 확인 완료. 새로운 패스키 발급 질문을 서버에서 요청 중입니다…');
  let issued=await keysApi('options',{storageProvider:provider});
  if(issued.status===401){
   keyAuthorized=false;
   lockManagement();
   throw Error('로그인 세션이 만료됐습니다. 등록 버튼을 다시 누르면 기존 패스키 인증을 시작합니다.');
  }
  if(issued.status!==200)throw Error('등록 질문 발급 HTTP '+issued.status+' ('+(issued.data.error||'unknown')+')');
  pendingId=issued.data.challengeId;
  keyEl('keyCancel').disabled=false;
  const requested=issued.data.requestedMode||provider;
  const attachment=issued.data.options.authenticatorSelection?.authenticatorAttachment||'브라우저 자동 선택';
  const hints=issued.data.options.hints||[];
  addEvidence('추가 등록 질문 HTTP 200 · 지문 '+issued.data.challengeFingerprint+
   ' · 기존 패스키 제외 '+(issued.data.options.excludeCredentials?.length||0)+'개'+
   ' · 요청 저장 방식 '+requested+' · authenticatorAttachment '+attachment+
   ' · hints '+(hints.join(',')||'없음'));
  const guidance=provider==='phone'
   ?'휴대전화 인증을 안내하는 hybrid 힌트를 요청했습니다. Windows가 USB 보안 키 삽입 창을 띄우면 그 창은 휴대전화 연결이 아닙니다. USB가 없다면 취소하세요. 이 Windows 환경에서 QR이 제공되지 않을 수 있으며, 그 경우 휴대전화 브라우저에서 사이트를 직접 여는 방법을 검토해야 합니다.'
   :provider==='security_key'
   ?'외장 USB/NFC 보안 키 모드를 요청했습니다. 실제 보안 키를 연결하고 Chrome 창에서 보안 키를 선택하세요. 다른 Google 계정은 USB 보안 키가 아닙니다.'
   :provider==='device'
   ?'기기 내장 인증 방식(Windows Hello 등)을 요청했습니다. 구글 관리자가 나타난다면 Windows Hello/다른 인증 방법을 직접 선택해야 할 수 있습니다.'
   :'브라우저의 Google 비밀번호 관리자 선택 화면입니다. 사이트에서는 어떤 Google 계정에 저장할지 직접 지정할 수 없습니다.';
  sayKeys(guidance+' 새 패스키 생성이 완료될 때만 서버에 공개키가 추가됩니다.');
  waiter=new AbortController();
  const credential=await navigator.credentials.create({
   publicKey:optionsForCreate(issued.data.options),signal:waiter.signal
  });
  if(!credential)throw new DOMException('기기 등록 취소','NotAllowedError');
  if(!pendingId)throw new DOMException('사용자 취소','AbortError');
  addEvidence('브라우저가 보고한 인증 장치 유형: '+(credential.authenticatorAttachment||'미확인')+
    ' · 사용자가 선택한 저장 방식: '+provider+' (실제 구글 계정 식별 불가)');
  const result=await keysApi('verify',{
   challengeId:pendingId,response:serializeCreated(credential),name,storageProvider:provider
  });
  pendingId=null;
  addEvidence('추가 패스키 등록 서버 검증 HTTP '+result.status+' / '+(result.data.error||'성공')+' / 개인키 미전송');
  if(result.status!==200||!result.data.passkeyStored){
   throw Error('공개키 저장 실패 HTTP '+result.status+' ('+(result.data.error||'unknown')+')');
  }
  sayKeys('추가 패스키 등록 성공: '+name+' · 현재 '+result.data.totalPasskeys+
   '개. 브라우저 보고 방식: '+(result.data.reportedAttachment||'미확인')+
   '. 기존 horse는 유지됩니다.');
  await refreshKeys();
 }catch(e){
  if(pendingId){
   const id=pendingId;
   pendingId=null;
   try{await keysApi('cancel',{challengeId:id});}catch{}
  }
  const cancelled=['NotAllowedError','AbortError'].includes(e.name);
  if(e.name==='InvalidStateError'){
   addEvidence('기존 패스키 중복 발견 · 브라우저 InvalidStateError · 서버 신규 공개키 저장 없음');
   sayKeys('기존 패스키 중복: Chrome이 이미 horse 자격증명을 가진 저장소를 선택했습니다. 저장 위치 선택만 바꿔서는 다른 패스키가 만들어지지 않습니다. 다른 휴대전화(QR) 방식을 선택하고, 실제로 기존 Google 관리자와 별개인 저장소에서 생성해야 합니다. 기존 horse와 입력 내용은 유지됩니다.');
  }else if(e.name==='NotSupportedError'){
   sayKeys('선택한 인증 장치 방식을 브라우저 또는 기기가 지원하지 않습니다. 실제 사용 가능한 기기 인증 방식으로 바꿔 다시 시도하세요.');
  }else if(cancelled){
   sayKeys('새 패스키 생성이 취소됐습니다. 저장 위치를 다시 확인한 뒤 바로 재시도할 수 있습니다. 입력 내용은 유지됩니다.');
  }else{
   sayKeys('추가 등록 실패 ('+(e.name||'Error')+'): '+e.message+' · 입력 내용은 유지됩니다.');
  }
 }finally{
  waiter=null;
  setKeyBusy(false);
 }
}
async function removePasskey(item,count){
 if(count<=1){sayKeys('마지막 패스키는 삭제할 수 없습니다.');return;}
 const accepted=window.confirm('정말 "'+item.name+'" 패스키를 삭제하시겠습니까?\n\n다른 패스키로 이미 로그인할 수 있음을 확인한 후 삭제하세요. 삭제하면 이 패스키로는 서버 로그인할 수 없습니다. 15분 이내의 새 로그인 필요.');
 if(!accepted)return;
 setKeyBusy(true);
 try{
  const result=await keysApi('remove',{credentialId:item.id});
  addEvidence('패스키 삭제 요청 "'+item.name+'" / HTTP '+result.status+' / '+(result.data.error||'삭제됨'));
  if(result.status!==200||!result.data.removed){
   const msg=result.data.error==='recent_login_required'?'삭제하려면 로그인한 지 15분이 넘지 않아야 합니다. 패스키로 다시 로그인하세요.':
     result.data.error==='last_passkey_protected'?'마지막 패스키는 삭제할 수 없습니다.':
     result.data.error||'삭제 거절';
   sayKeys(msg);return;
  }
  lastRemoved=item.id;
  sessionStorage.setItem('t08_last_deleted_credential',item.id);
  sayKeys('"' +item.name+'" 서버 등록을 삭제했습니다. 삭제된 패스키는 로그인할 수 없습니다.'+
   (result.data.sessionRevoked?' 현재 세션도 폐기되었습니다. 남은 패스키로 다시 로그인하세요.':''));
  if(result.data.sessionRevoked){
   lockManagement();
   window.dispatchEvent(new CustomEvent('t08-keys-session-revoked'));
  }else await refreshKeys();
 }finally{setKeyBusy(false);}
}
async function probeDeleted(){
 const removed=lastRemoved||sessionStorage.getItem('t08_last_deleted_credential');
 if(!removed){sayKeys('먼저 등록된 패스키 하나를 삭제한 후 검사하세요.');return;}
 setKeyBusy(true);
 try{
  const options=await fetch('/api/auth',{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'options'})});
  const body=await options.json();
  if(!options.ok){sayKeys('로그인 질문 생성 실패 HTTP '+options.status);return;}
  const contains=body.options?.allowCredentials?.some(k=>k.id===removed);
  // This is intentionally NOT a real signed assertion. It proves deleted IDs are rejected.
  const result=await fetch('/api/auth',{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({action:'verify',challengeId:body.challengeId,response:{
    id:removed,rawId:removed,type:'public-key',
    response:{authenticatorData:'aW52YWxpZA',clientDataJSON:'aW52YWxpZA',signature:'aW52YWxpZA'}
   }})});
  const data=await result.json().catch(()=>({error:'invalid_response'}));
  addEvidence('삭제된 자격증명 거절 시험 / 선택 목록 포함='+contains+
   ' / HTTP '+result.status+' / '+(data.error||'')+' / 세션·토큰 [가림]');
  sayKeys(!contains&&result.status===401&&data.error==='unknown_credential'?
   '삭제된 패스키 ID가 서버 로그인 목록에서 제외됐고, 제출한 요청도 HTTP 401로 거절됐습니다. 실제 기기 서명 재현은 별도입니다.':
   '삭제 검증 예상값과 다릅니다. 로그인 목록과 서버 기록을 확인해야 합니다.');
 }catch(e){sayKeys('삭제 시험 오류: '+e.message);}
 finally{setKeyBusy(false);}
}
function updateProviderHelp(){
 const mode=keyEl('additionalKeyProvider').value;
 const message=mode==='phone'
  ?'휴대전화 연결은 브라우저에 hybrid 방식으로 요청만 할 수 있습니다. Windows에서 USB 보안 키 삽입 창이 나오면 해당 경로는 휴대전화 QR이 아닙니다. USB를 연결하지 말고 취소하세요. QR 지원 여부는 Windows/브라우저가 결정하며, 웹사이트에서 강제로 열 수 없습니다.'
  :mode==='security_key'
  ?'외장 보안 키: 실제 USB/NFC FIDO2 장치가 있어야 합니다. 서버가 cross-platform과 security-key를 요청하지만 브라우저 선택창은 환경에 따라 다를 수 있습니다.'
  :mode==='device'
  ?'이 PC 장치: Windows Hello 같은 플랫폼 인증기를 우선 요청합니다. Chrome이 Google 비밀번호 관리자를 제안하면 브라우저 창에서 다른 인증 방법을 확인하세요.'
  :mode==='google'
  ?'Google 비밀번호 관리자: 어떤 Google 계정을 사용할지는 사이트가 지정할 수 없습니다. 이미 등록된 horse가 있는 동일 저장소로 다시 연결되면 중복 등록이 거절됩니다.'
  :'저장 위치를 선택하세요. 선택 항목은 등록 요청에 반영되지만, 최종 기기·계정 선택은 브라우저가 결정할 수 있습니다.';
 keyEl('keyProviderHelp').textContent=message;
}
function initKeys(){
 keyEl('additionalKeyProvider').addEventListener('change',updateProviderHelp);
 updateProviderHelp();
 keyEl('keyUnlock').addEventListener('click',async()=>{
  if(keyOperationBusy)return;
  const start=window.t08StartLogin;
  if(typeof start!=='function'){
   sayKeys('로그인 기능을 불러오지 못했습니다. 새로고침 후 다시 시도하세요.');
   return;
  }
  keyEl('keyUnlock').disabled=true;
  keyEl('keyGateStatus').textContent='기기의 패스키 창에서 기존 계정을 선택하세요…';
  try{
   // A bare "login and continue" button checks the session. The blue Add button
   // additionally resumes a new credential registration after this same login.
   const current=await keysApi('list');
   const ok=current.status===200 || (current.status===401 && await start());
   if(!ok){
    sayKeys('기기 패스키 로그인을 완료하지 않았습니다. 기존 horse 패스키를 선택해 주세요.');
    return;
   }
   const valid=await refreshKeys();
   if(valid)sayKeys('로그인 완료. 새 패스키 이름과 저장 위치를 확인한 뒤 「패스키 추가 등록」을 누르세요.');
  }catch(e){sayKeys('로그인 확인 오류: '+e.message);}
  finally{keyEl('keyUnlock').disabled=false;}
 });
 keyEl('keyRefresh').addEventListener('click',refreshKeys);
 keyEl('keyAdd').addEventListener('click',addPasskey);
 keyEl('keyCancel').addEventListener('click',cancelAdd);
 keyEl('keyProbeDeleted').addEventListener('click',probeDeleted);
 window.addEventListener('t08-auth-state',e=>{
  if(e.detail?.authenticated)refreshKeys();
  else lockManagement();
 });
 window.addEventListener('t08-keys-session-revoked',()=>lockManagement());
 window.addEventListener('pageshow',event=>{if(event.persisted)refreshKeys();});
 refreshKeys();
}
initKeys();