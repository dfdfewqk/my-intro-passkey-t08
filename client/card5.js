// Card 5: login-aware, automatically runs real HTTP tests after successful login.
// Proof summaries are stored server-side to combine DIFFERENT Chrome/Google profiles.
// No notes, passkey IDs, private keys or cookies are included in evidence.
const by=id=>document.getElementById(id);
const pane=by('card5Evidence'),progress=by('card5Progress');
const btn=by('card5RunChecks'),notice=by('card5CopyMessage');
let checking=false,authSequence=0,latestProof='';
async function ask(url,{method='GET',body}={}){
 const opts={method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}};
 if(body!==undefined){
  opts.headers['Content-Type']='application/json';
  opts.body=JSON.stringify(body);
 }
 const res=await fetch(url,opts);
 const content=await res.json().catch(()=>({error:'response_not_json'}));
 return {http:res.status,content};
}
async function evidenceApi(action,proof){
 return ask('/api/card5-evidence',{method:'POST',
  body:action==='save'?{action,proof}:{action}});
}
function linesFor(records){
 return records.map(x=>'계정 '+x.accountId+' ('+(x.accountId===1?'owner':'owner2')+') '+
  '자기 자료 HTTP '+x.ownHttp+' ('+x.before+'건) → 상대 자료 HTTP '+x.denyHttp+
  ' ('+x.denyError+') → 자기 자료 HTTP '+x.afterHttp+' ('+x.after+'건)'+
  ' · 익명 '+x.anonymousHttp+' · 계정 ID 위조 '+x.spoofHttp+
  ' (반환 accountId '+x.spoofAccount+')');
}
function showProgress(records){
 if(!Array.isArray(records))records=[];
 const good=records.filter(r=>[1,2].includes(r.accountId)&&r.passed===true&&
  r.ownHttp===200&&r.denyHttp===403&&r.afterHttp===200&&r.spoofHttp===200&&
  r.anonymousHttp===401&&r.before===r.after&&r.spoofAccount===r.accountId);
 const a=good.find(r=>r.accountId===1),b=good.find(r=>r.accountId===2);
 const count=Number(!!a)+Number(!!b);
 progress.textContent=count===2?
  '양방향 실계정 HTTP 검사 2/2 완료 · owner↔owner2 접근 거절 403 및 자료 건수 유지 확인':
  '양방향 실계정 HTTP 검사 '+count+'/2 · '+(a?'owner 완료':'owner 검사 필요')+
  ' / '+(b?'owner2 완료':'owner2 검사 필요');
 return good;
}
function hideWhenLoggedOut(message){
 latestProof='';
 progress.textContent='로그인 후 owner 또는 owner2의 실제 HTTP 검사를 진행합니다.';
 pane.textContent=message||'현재 사이트에 로그인하지 않았습니다. 위의 패스키 로그인 버튼을 눌러 주세요.';
}
function one(label,r){
 return label+' → HTTP '+r.http+(r.content.error?' / '+r.content.error:'')+
  (Array.isArray(r.content.items)?' / 자료 '+r.content.items.length+'건':'');
}
async function run(){
 if(checking)return;
 checking=true;btn.disabled=true;
 pane.textContent='로그인 상태를 확인하고 실제 HTTP 접근 검사를 진행 중입니다…';
 try{
  const status=await ask('/api/auth',{method:'POST',body:{action:'status'}});
  if(status.http!==200||!status.content.authenticated||![1,2].includes(status.content.ownerId)){
   if(status.http>=500){
    pane.textContent='로그인 상태 확인 서버 오류 HTTP '+status.http+'. 잠시 뒤 다시 검사하세요.';
   }else hideWhenLoggedOut('사이트 계정 로그인이 필요합니다. 상단 로그인 버튼으로 인증해 주세요.');
   return;
  }
  const mine=status.content.ownerId,other=mine===1?2:1;
  const previous=await ask('/api/private?account='+mine);
  const denied=await ask('/api/private?account='+other);
  const after=await ask('/api/private?account='+mine);
  const spoof=await ask('/api/private?owner_id='+other+'&requestedOwner='+other);
  const anon=await fetch('/api/private',{credentials:'omit',cache:'no-store'});
  const count=Array.isArray(previous.content.items)?previous.content.items.length:null;
  const afterCount=Array.isArray(after.content.items)?after.content.items.length:null;
  const accepted=previous.http===200&&after.http===200&&
   previous.content.accountId===mine&&after.content.accountId===mine&&
   denied.http===403&&denied.content.error==='other_account_forbidden'&&
   !Object.hasOwn(denied.content,'items')&&spoof.http===200&&
   spoof.content.accountId===mine&&Array.isArray(spoof.content.items)&&
   spoof.content.items.length===count&&anon.status===401&&
   count!==null&&afterCount===count;
  const log=[
   '카드 5 실서버 HTTP 검사 · '+new Date().toLocaleString('ko-KR'),
   '로그인: '+status.content.accountName+' / 패스키 '+status.content.passkeyName+
   ' (사이트 계정 ID '+mine+')',
   one('① 비로그인 비공개 주소',{http:anon.status,content:{}}),
   one('② 내 자료 허용 / 차단 이전',previous),
   one('③ 상대 계정 자료 요청',denied),
   one('④ 내 자료 허용 / 차단 이후',after),
   one('⑤ URL에 다른 계정 번호를 적어 요청',spoof),
   'URL 위조 요청에서 실제 반환한 계정: '+(spoof.content.accountId??'미확인'),
   '거절 전후 내 자료 건수: '+(count??'미확인')+' → '+(afterCount??'미확인'),
   accepted?'현재 계정의 실제 서버 접근 검증 통과':'검증 실패: 예상 HTTP 응답과 다릅니다. 제출 전 확인 필요'
  ];
  if(accepted){
   const summary={
    accountId:mine,ownHttp:previous.http,denyHttp:denied.http,denyError:denied.content.error,
    afterHttp:after.http,spoofHttp:spoof.http,spoofAccount:spoof.content.accountId,
    anonymousHttp:anon.status,before:count,after:afterCount,passed:true
   };
   const saved=await evidenceApi('save',summary);
   if(saved.http===200&&saved.content.saved===true){
    const records=showProgress(saved.content.records);
    log.push('--- 두 Chrome 프로필에 공통으로 저장된 계정별 HTTP 검증 요약 ---');
    log.push(...linesFor(records));
    if(records.some(r=>r.accountId===1)&&records.some(r=>r.accountId===2))
     log.push('최종: 실제 두 계정의 HTTP 403 양방향 차단, 자기 자료 200, 건수 보존 확인');
    else log.push('상대 계정 패스키로 로그인하면 자동으로 반대 방향도 검사합니다.');
   }else{
    progress.textContent='현재 계정 HTTP 검사 통과 · 양방향 결과 서버 저장 대기';
    log.push('검사 결과 서버 보관 실패: HTTP '+saved.http+' / '+(saved.content.error||'저장 오류'));
    log.push('현재 기록은 복사할 수 있지만 다른 Chrome 프로필과 자동 합산되지 않습니다.');
   }
  }else{
   progress.textContent='검사 실패 · 서버 응답을 확인하세요.';
  }
  latestProof=log.join('\n');pane.textContent=latestProof;
 }catch(err){pane.textContent='카드 5 검사 실행 오류: '+(err.message||'unknown')+'. 다시 시도해 주세요.';}
 finally{checking=false;btn.disabled=false;}
}
async function initOrRestore(){
 const revision=++authSequence;
 try{
  const response=await ask('/api/auth',{method:'POST',body:{action:'status'}});
  if(revision!==authSequence)return;
  if(response.http===200&&response.content.authenticated===true){
   progress.textContent='인증 확인됨 · 계정 '+response.content.accountName+' · 검사 결과를 확인합니다…';
   await run();
  }else if(response.http>=500){
   pane.textContent='인증 서버 응답 오류 HTTP '+response.http+' · 다시 검사를 눌러 주세요.';
   progress.textContent='인증 상태 확인 오류';
  }else hideWhenLoggedOut();
 }catch(e){
  if(revision!==authSequence)return;
  pane.textContent='인증 상태를 확인할 수 없습니다: '+e.message;
  progress.textContent='상태 확인 실패';
 }
}
btn.addEventListener('click',run);
window.addEventListener('t08-auth-state',event=>{
 if(event.detail?.authenticated){
  initOrRestore();
 }else{
  ++authSequence;
  hideWhenLoggedOut('로그아웃되어 개인 자료가 잠겼습니다. 새로운 패스키로 로그인하면 자동 검사를 실행합니다.');
 }
});
by('card5CopyEvidence').addEventListener('click',async()=>{
 const s=pane.textContent||'';
 if(!s.includes('HTTP')){
  notice.textContent='검사가 끝난 뒤 결과를 복사할 수 있습니다.';
  return;
 }
 try{
  await navigator.clipboard.writeText(s);
  notice.textContent='실제 HTTP 검사 결과를 복사했습니다. 제출문에 붙여넣을 수 있습니다.';
 }catch{notice.textContent='자동 복사할 수 없습니다. 화면에 나온 검사 내용을 직접 복사해 주세요.';}
});
pane.textContent='사이트 로그인 상태 확인 중…';
progress.textContent='인증 상태를 확인하고 있습니다.';
initOrRestore();
