// Card 5: register a THIRD passkey for owner2; never move horse/horse2.
const el=id=>document.getElementById(id);
const output=t=>el('owner2Message').textContent=t;
async function call(action,fields={}){
 const r=await fetch('/api/owner2',{method:'POST',credentials:'same-origin',cache:'no-store',
 headers:{'Content-Type':'application/json'},body:JSON.stringify({action,...fields})});
 return {status:r.status,data:await r.json().catch(()=>({error:'invalid_response'}))};
}
function decode(s){const a=s.replace(/-/g,'+').replace(/_/g,'/');
 return Uint8Array.from(atob(a+'='.repeat((4-a.length%4)%4)),c=>c.charCodeAt(0));}
function encode(b){let s='';for(const c of new Uint8Array(b))s+=String.fromCharCode(c);
 return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function parse(opts){
 if(PublicKeyCredential.parseCreationOptionsFromJSON)return PublicKeyCredential.parseCreationOptionsFromJSON(opts);
 return {...opts,challenge:decode(opts.challenge),user:{...opts.user,id:decode(opts.user.id)}};
}
function serialize(key){
 if(key.toJSON)return key.toJSON();
 return {id:key.id,rawId:encode(key.rawId),type:key.type,
 response:{attestationObject:encode(key.response.attestationObject),
 clientDataJSON:encode(key.response.clientDataJSON),transports:key.response.getTransports?.()||[]},
 clientExtensionResults:key.getClientExtensionResults?.()||{}};
}
async function create(){
 const name=el('owner2PasskeyName').value.trim();
 const button=el('owner2CreateButton');let challengeId;
 if(name.length<2||name.length>48)return output('패스키 이름을 2~48자로 입력하세요.');
 if(!window.isSecureContext||!navigator.credentials?.create)return output('HTTPS·WebAuthn 지원 브라우저가 필요합니다.');
 button.disabled=true;
 try{
  let state=await call('status');
  if(state.status!==200){
   output('먼저 기존 horse 또는 horse2로 owner에 로그인해 주세요.');
   if(!window.t08StartLogin||!await window.t08StartLogin())return;
  }
  let r=await call('options',{name});
  if(r.status===403&&r.data.error==='recent_login_required'){
   output('최근 본인 확인이 필요합니다. 기존 패스키로 다시 로그인하세요.');
   if(!window.t08StartLogin||!await window.t08StartLogin())return;
   r=await call('options',{name});
  }
  if(r.status!==200)throw Error('등록 시작 HTTP '+r.status+' · '+r.data.error);
  challengeId=r.data.challengeId;
  output('새 owner2 전용 패스키를 승인하세요. 기존 horse·horse2는 그대로 유지됩니다.');
  const credential=await navigator.credentials.create({publicKey:parse(r.data.options)});
  if(!credential)throw Error('등록 취소');
  const saved=await call('verify',{challengeId,response:serialize(credential)});
  challengeId=null;
  if(saved.status!==200||!saved.data.passkeyStored)throw Error('등록 실패 HTTP '+saved.status+' · '+saved.data.error);
  output('owner2 등록 성공! 기존 owner에는 horse·horse2가 그대로 있습니다. 로그아웃한 뒤 owner2 패스키로 로그인해 보세요.');
 }catch(e){output('등록 미완료: '+(e.name==='NotAllowedError'?'브라우저 등록 취소':e.message));}
 finally{
  if(challengeId)await call('cancel',{challengeId}).catch(()=>{});
  if(!el('owner2Message').textContent.includes('등록 성공'))button.disabled=false;
 }
}
el('owner2CreateButton').addEventListener('click',create);
