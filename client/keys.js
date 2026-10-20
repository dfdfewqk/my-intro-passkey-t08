// Card 4: second passkey enrollment, safe removal, and server-verified key inventory.
const keyEl=id=>document.getElementById(id);
let pendingId=null,waiter=null,lastRemoved=null,keyAuthorized=false;
let inventoryRevision=0;
let keyOperationBusy=false;
const evidence=[];
const providerLabels={google:'구글 비밀번호 관리자',device:'기기 자체 / Windows Hello',
 security_key:'외장 보안 키',unknown:'저장 위치 미확인'};
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
function setKeyBusy(yes){
 keyOperationBusy=yes;
 for(const id of ['keyRefresh','keyAdd','keyCancel','keyProbeDeleted']){
  const control=keyEl(id);if(control)control.disabled=yes;
 }
 keyEl('keyCancel').disabled=!yes;
 keyEl('keyAdd').disabled=yes||!keyAuthorized;
 keyEl('keyUnlock').disabled=yes;
 keyEl('keyEnrollmentFields').disabled=yes||!keyAuthorized;
}
function lockManagement(){
 ++inventoryRevision;
 keyAuthorized=false;
 keyEl('keyGate').hidden=false;
 keyEl('keyGateStatus').textContent='로그아웃 상태입니다. 이곳에서 로그인하면 새 패스키를 이어서 등록할 수 있습니다.';
 keyEl('keyUnlock').disabled=keyOperationBusy;
 keyEl('keyEnrollmentFields').disabled=true;
 keyEl('keyCountDetailed').textContent='로그인 후 패스키 목록을 확인할 수 있습니다.';
 keyEl('keyListDetailed').replaceChildren();
 const node=document.createElement('p');node.className='note';
 node.textContent='로그인 후 두 번째 패스키를 등록할 수 있습니다. 위쪽 로그인 버튼을 먼저 누르세요.';
 keyEl('keyListDetailed').append(node);
 keyEl('keyAdd').disabled=true;
 keyEl('keyRefresh').disabled=false;
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
 keyEl('keyGate').hidden=true;
 keyEl('keyEnrollmentFields').disabled=keyOperationBusy;
 keyEl('keyUnlock').disabled=false;
 const list=keyEl('keyListDetailed');
 list.replaceChildren();
 keyEl('keyAdd').disabled=false;
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
async function addPasskey(){
 if(!window.PublicKeyCredential||!navigator.credentials?.create||!window.isSecureContext){
  sayKeys('HTTPS에서 WebAuthn을 지원하는 브라우저가 필요합니다.');return;
 }
 const name=keyEl('additionalKeyName').value.trim();
 const provider=keyEl('additionalKeyProvider').value;
 if(name.length<2||!provider){sayKeys('패스키의 이름과 실제 저장 위치를 선택하세요.');return;}
 setKeyBusy(true);
 try{
  const issued=await keysApi('options');
  if(issued.status!==200)throw Error(issued.data.error||'등록 질문 발급 실패');
  pendingId=issued.data.challengeId;
  addEvidence('추가 등록 질문 발급 HTTP 200 · 지문 '+issued.data.challengeFingerprint+
   ' · 기존 패스키 제외 '+(issued.data.options.excludeCredentials?.length||0)+'개');
  sayKeys('기기 패스키 등록 창에서 기존 것과 다른 패스키를 생성하세요. 다른 기기나 외장 보안 키도 사용할 수 있습니다.');
  waiter=new AbortController();
  const credential=await navigator.credentials.create({
   publicKey:optionsForCreate(issued.data.options),signal:waiter.signal});
  if(!credential)throw new DOMException('등록 취소','NotAllowedError');
  if(!pendingId)throw Error('registration_canceled');
  const result=await keysApi('verify',{challengeId:pendingId,response:serializeCreated(credential),
   name,storageProvider:provider});
  pendingId=null;
  addEvidence('새 패스키 서버 검증 HTTP '+result.status+' / '+(result.data.error||'저장됨')+
   ' / 개인키 [전송 안 함]');
  if(result.status!==200||!result.data.passkeyStored)throw Error(result.data.error||'등록 실패');
  sayKeys('추가 패스키 등록 성공: '+name+' · 전체 '+result.data.totalPasskeys+
   '개. 기존 패스키도 그대로 유지됩니다.');
  await refreshKeys();
 }catch(e){
  if(pendingId){
   const id=pendingId;pendingId=null;
   try{await keysApi('cancel',{challengeId:id});}catch{}
  }
  sayKeys(['NotAllowedError','AbortError'].includes(e.name)||e.message==='registration_canceled'?
   '추가 등록을 취소했습니다. 새 패스키는 서버에 저장하지 않았습니다.':
   '추가 등록 실패: '+e.message+'. 같은 비밀번호 관리자에 동기화된 기존 자격증명은 별도 패스키로 취급하지 않습니다.');
 }finally{waiter=null;setKeyBusy(false);}
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
function initKeys(){
 keyEl('keyUnlock').addEventListener('click',async()=>{
  const start=window.t08StartLogin;
  if(typeof start!=='function'){
   sayKeys('로그인 기능이 준비되지 않았습니다. 새로고침하고 다시 시도하세요.');return;
  }
  keyEl('keyUnlock').disabled=true;
  keyEl('keyGateStatus').textContent='기기에서 패스키로 인증하는 중입니다…';
  try{
    await start();
    await refreshKeys();
    if(keyAuthorized){
      sayKeys('로그인 성공! 새 이름과 실제 저장 위치를 정하고 「패스키 추가 등록」을 누르세요.');
      keyEl('additionalKeyName').focus();
    }else{
      sayKeys('로그인을 완료하지 못했습니다. 로그인 안내를 확인하고 다시 시도하세요.');
    }
  }catch(e){sayKeys('로그인 오류: '+e.message);}
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