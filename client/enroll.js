// Card 2: navigator.credentials.create() runs in the browser. No private key is sent.
const el=id=>document.getElementById(id);
const LOG_KEY='t08_challenge_log';
let invitation='',active=null,aborter=null;
function say(msg){el('enrollmentMessage').textContent=msg;}
function unb64(s){
 const text=s.replace(/-/g,'+').replace(/_/g,'/');
 const bin=atob(text+'='.repeat((4-text.length%4)%4));
 return Uint8Array.from(bin,c=>c.charCodeAt(0));
}
function b64(buf){
 let str='';
 for(const n of new Uint8Array(buf))str+=String.fromCharCode(n);
 return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function request(action,fields={}){
 const r=await fetch('/api/enroll',{method:'POST',cache:'no-store',
  headers:{'Content-Type':'application/json'},body:JSON.stringify({action,...fields})});
 const data=await r.json().catch(()=>({error:'unexpected_response'}));
 if(!r.ok)throw Error(data.error||String(r.status));
 return data;
}
function setBusy(isBusy){
 el('registerPasskey').disabled=isBusy||!invitation;
 el('compareChallenges').disabled=isBusy||!invitation;
 el('cancelPasskey').disabled=!isBusy;
}
function logFingerprint(data){
 let arr=[];
 try{arr=JSON.parse(sessionStorage.getItem(LOG_KEY)||'[]');}catch{}
 arr.push({time:new Date().toLocaleString('ko-KR'),fingerprint:data.challengeFingerprint});
 arr=arr.slice(-6);
 sessionStorage.setItem(LOG_KEY,JSON.stringify(arr));
 el('challengeHistory').textContent=arr.map((x,i)=>(i+1)+'. '+x.time+' | '+x.fingerprint).join('\n');
}
function convertOptions(raw){
 if(typeof PublicKeyCredential.parseCreationOptionsFromJSON==='function')
   return PublicKeyCredential.parseCreationOptionsFromJSON(raw);
 return {...raw,challenge:unb64(raw.challenge),
  user:{...raw.user,id:unb64(raw.user.id)},
  excludeCredentials:(raw.excludeCredentials||[]).map(c=>({...c,id:unb64(c.id)}))};
}
function serialize(cred){
 if(typeof cred.toJSON==='function')return cred.toJSON();
 const r=cred.response;
 return {id:cred.id,rawId:b64(cred.rawId),type:cred.type,
   response:{attestationObject:b64(r.attestationObject),
    clientDataJSON:b64(r.clientDataJSON),transports:r.getTransports?.()||[]},
   clientExtensionResults:cred.getClientExtensionResults?.()||{},
   authenticatorAttachment:cred.authenticatorAttachment||undefined};
}
async function refreshList(){
 if(!invitation)return;
 try{
  const data=await request('list',{invite:invitation});
  const list=el('passkeyList');list.replaceChildren();
  if(!data.passkeys.length){const li=document.createElement('li');li.textContent='아직 패스키 없음';list.append(li);}
  for(const key of data.passkeys){
   const li=document.createElement('li');
   const span=document.createElement('strong');span.textContent=key.name;
   const desc=document.createElement('p');desc.className='note';
   const providers={google:'구글 비밀번호 관리자',device:'기기 자체',security_key:'보안 키',unknown:'미확인'};
   desc.textContent='저장 위치: '+(providers[key.storageProvider]||'미확인')+' · ID: '+key.id.slice(0,16)+'…';
   const publicPart=document.createElement('pre');publicPart.className='status evidence';
   publicPart.textContent='서버 공개키(COSE/base64url): '+key.publicKey;
   li.append(span,desc,publicPart);list.append(li);
  }
 }catch{say('패스키 목록을 확인하지 못했습니다. 초대 링크의 유효기간을 확인하세요.');}
}
async function issue(){
 const data=await request('options',{invite:invitation});
 active=data.challengeId;
 logFingerprint(data);
 return data;
}
async function cancel(){
 const old=active;
 aborter?.abort();
 active=null;
 if(old){
  try{await request('cancel',{invite:invitation,challengeId:old});
   say('등록 취소: 서버가 대기 중인 질문을 삭제했습니다. 새 패스키는 저장하지 않았습니다.');
  }catch{say('등록을 취소했지만 서버의 질문 삭제 여부는 확인할 수 없습니다.');}
 }
 setBusy(false);
}
async function register(){
 const name=el('passkeyName').value.trim();
 const provider=el('passkeyProvider').value;
 if(name.length<2||!provider){say('패스키 이름과 실제 저장 위치를 입력하세요.');return;}
 if(!isSecureContext||!navigator.credentials?.create||!window.PublicKeyCredential){
  say('HTTPS와 WebAuthn을 지원하는 브라우저가 필요합니다.');return;}
 setBusy(true);
 try{
  const issued=await issue();
  say('기기의 패스키 등록 창에서 확인해 주세요. 취소해도 공개키는 저장되지 않습니다.');
  aborter=new AbortController();
  const cred=await navigator.credentials.create({
   publicKey:convertOptions(issued.options),signal:aborter.signal});
  if(!cred)throw new DOMException('등록 취소','NotAllowedError');
  if(!active)throw Error('canceled');
  const response=serialize(cred),id=active;
  const result=await request('verify',{
    invite:invitation,challengeId:id,name,storageProvider:provider,response});
  active=null;
  el('publicKeyResult').textContent='공개키 (COSE / base64url)\n'+result.passkey.publicKey;
  el('requestResult').textContent=JSON.stringify({
   action:'verify',invite:'[초대 토큰 비공개]',challengeId:'[일회용 식별자]',
   name,storageProvider:provider,
   response:{id:response.id,rawId:response.rawId,type:response.type,
    response:{
     attestationObject:'[base64url '+response.response.attestationObject.length+'자]',
     clientDataJSON:'[base64url '+response.response.clientDataJSON.length+'자]',
     transports:response.response.transports||[]},
    clientExtensionResults:response.clientExtensionResults||{}},
   privateKey:'전송되지 않음'
  },null,2);
  say('등록 성공: 서버에서 서명/출처를 검증하고 공개키만 저장했습니다. 패스키 로그인은 카드 3에서 연결됩니다.');
  await refreshList();
  const status=await request('status');
  el('passkeyCount').textContent='저장된 패스키: '+status.registeredCount+'개';
 }catch(e){
  if(active){
   const id=active;active=null;
   try{await request('cancel',{invite:invitation,challengeId:id});}catch{}
  }
  say(['NotAllowedError','AbortError'].includes(e.name)||e.message==='canceled'
   ?'등록이 취소되었습니다. 서버에는 공개키가 저장되지 않았습니다.'
   :'등록 실패: '+e.message+'. 저장 상태를 확인해 주세요.');
 }finally{aborter=null;setBusy(false);}
}
async function compare(){
 setBusy(true);
 try{
  const fingerprints=[];
  for(let i=0;i<2;i++){
   const d=await issue();fingerprints.push(d.challengeFingerprint);
   const id=active;active=null;
   await request('cancel',{invite:invitation,challengeId:id});
  }
  say(fingerprints[0]!==fingerprints[1]
   ?'서버 질문 2회 발급: 서로 다른 challenge 지문을 확인했습니다. 두 질문 모두 삭제했습니다.'
   :'질문 중복 의심: 등록을 중단하고 점검해 주세요.');
 }catch(e){say('서버 질문 비교 오류: '+e.message);}
 finally{if(active){const id=active;active=null;try{await request('cancel',{invite:invitation,challengeId:id});}catch{}}setBusy(false);}
}
function init(){
 const link=new URLSearchParams(location.hash.slice(1)).get('enroll');
 if(link&&/^[0-9a-f]{64}$/i.test(link)){
  invitation=link.toLowerCase();
  history.replaceState(null,'',location.pathname+location.search);
  sessionStorage.setItem('t08_owner_invitation',invitation);
 }else{invitation=sessionStorage.getItem('t08_owner_invitation')||'';}
 say(invitation?'소유자 전용 링크를 확인했습니다. 이름과 저장 위치를 선택한 후 등록하세요.':
  '공개 소개 페이지입니다. 패스키 등록에는 소유자에게 전달된 전용 초대 링크가 필요합니다.');
 el('registerPasskey').addEventListener('click',register);
 el('cancelPasskey').addEventListener('click',cancel);
 el('compareChallenges').addEventListener('click',compare);
 setBusy(false);
 try{el('challengeHistory').textContent=JSON.parse(sessionStorage.getItem(LOG_KEY)||'[]')
  .map((x,i)=>(i+1)+'. '+x.time+' | '+x.fingerprint).join('\n')||'발급 기록 없음';}catch{}
 request('status').then(s=>{el('passkeyCount').textContent='저장된 패스키: '+s.registeredCount+'개';})
  .catch(()=>{el('passkeyCount').textContent='등록 서버 상태를 확인할 수 없습니다.';});
 refreshList();
}
init();