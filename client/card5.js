// Card 5: genuine client HTTP proofs. Only save redacted statuses, account IDs, counts.
const by=id=>document.getElementById(id);
const pane=by('card5Evidence');
const progress=by('card5Progress');
const btn=by('card5RunChecks');
const STORAGE='t08_card5_directional_evidence_v1';
async function ask(url,{method='GET',body}={}){
 const opts={method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}};
 if(body!==undefined){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body);}
 const res=await fetch(url,opts);
 const content=await res.json().catch(()=>({error:'response_not_json'}));
 return {http:res.status,content};
}
function saved(){
 try{
  const raw=JSON.parse(sessionStorage.getItem(STORAGE)||'{}');
  if(!raw||typeof raw!=='object')return {};
  const recent={};
  for(const id of ['1','2']){
   if(raw[id]?.accountId===Number(id)&&raw[id].passed===true&&
      typeof raw[id].timestamp==='number'&&Date.now()-raw[id].timestamp<24*3600*1000)
      recent[id]=raw[id];
  }
  return recent;
 }catch{return {};}
}
function persist(data){try{sessionStorage.setItem(STORAGE,JSON.stringify(data));}catch{}}
function summary(label,result){
 return label+' → HTTP '+result.http+(result.content.error?' / '+result.content.error:'')+
  (Array.isArray(result.content.items)?' / 자료 '+result.content.items.length+'건':'');
}
function evidenceLine(item){
 return '계정 '+item.accountId+' ('+(item.accountId===1?'owner':'owner2')+') '+
  'HTTP '+item.ownHttp+' (내 자료 '+item.before+'건) → 상대 계정 요청 HTTP '+
  item.denyHttp+' ('+item.denyError+') → 내 자료 HTTP '+item.afterHttp+
  ' ('+item.after+'건) · 익명 '+item.anonymousHttp+
  ' · ID 위조 '+item.spoofHttp+' (반환 ownerId '+item.spoofAccount+')';
}
function renderProgress(){
 const all=saved(),done=['1','2'].filter(x=>all[x]).length;
 progress.textContent=done===2?'양방향 실계정 요청 기록 2/2 완료 · 두 계정 모두 실제 HTTP 거절 확인':
  '양방향 실계정 요청 기록 '+done+'/2 · '+(all['1']?'owner 기록 있음':'owner 검사 필요')+
  ' / '+(all['2']?'owner2 기록 있음':'owner2 검사 필요');
 return all;
}
async function run(){
 btn.disabled=true;
 pane.textContent='실제 요청 검사 중… (인증 쿠키와 비공개 본문은 저장하지 않음)';
 try{
  const status=await ask('/api/auth',{method:'POST',body:{action:'status'}});
  if(status.http!==200||!status.content.authenticated||![1,2].includes(status.content.ownerId)){
   pane.textContent='등록된 패스키로 로그인한 뒤 검사를 실행해야 합니다. HTTP '+status.http;return;
  }
  const me=status.content.ownerId,other=me===1?2:1;
  const before=await ask('/api/private?account='+me);
  const cross=await ask('/api/private?account='+other);
  const after=await ask('/api/private?account='+me);
  const spoof=await ask('/api/private?owner_id='+other+'&requestedOwner='+other);
  const anonymous=await fetch('/api/private',{credentials:'omit',cache:'no-store'});
  const beforeCount=Array.isArray(before.content.items)?before.content.items.length:null;
  const afterCount=Array.isArray(after.content.items)?after.content.items.length:null;
  const passed=anonymous.status===401&&before.http===200&&after.http===200&&
   before.content.accountId===me&&after.content.accountId===me&&
   cross.http===403&&cross.content.error==='other_account_forbidden'&&!('items' in cross.content)&&
   spoof.http===200&&spoof.content.accountId===me&&
   Array.isArray(spoof.content.items)&&spoof.content.items.length===beforeCount&&
   beforeCount!==null&&beforeCount===afterCount;
  const lines=[
   '카드 5 실계정 서버 요청 기록 · '+new Date().toLocaleString('ko-KR'),
   '로그인 사이트 계정: '+status.content.accountName+' (ID '+me+') / 패스키 '+status.content.passkeyName,
   summary('① 로그인 없이 자료 요청',{http:anonymous.status,content:{}}),
   summary('② 내 자료 허용 / 거절 이전',before),
   summary('③ 상대 계정 '+other+' 자료 시도',cross),
   summary('④ 내 자료 허용 / 거절 이후',after),
   summary('⑤ 다른 계정 ID '+other+'를 URL에 기입',spoof),
   '다른 계정 ID를 기입한 응답의 실제 accountId: '+(spoof.content.accountId??'미확인'),
   '내 자료 건수: '+(beforeCount??'미확인')+' → '+(afterCount??'미확인'),
   passed?'현재 계정 검사 통과 (서버 실제 HTTP 요청)':'검사 미통과 · 예상 상태/응답 확인 필요'
  ];
  if(passed){
   const record={
    accountId:me,timestamp:Date.now(),passed:true,ownHttp:before.http,
    before:beforeCount,denyHttp:cross.http,denyError:cross.content.error,
    afterHttp:after.http,after:afterCount,spoofHttp:spoof.http,
    spoofAccount:spoof.content.accountId,anonymousHttp:anonymous.status
   };
   const all=saved();all[String(me)]=record;persist(all);
  }
  const result=renderProgress();
  if(result['1']||result['2']){
   lines.push('--- 동일 브라우저 탭에 보관된 계정별 요약 (개인 자료 본문/쿠키 제외) ---');
   for(const id of ['1','2'])if(result[id])lines.push(evidenceLine(result[id]));
   if(result['1']&&result['2'])lines.push('C37/C38 두 방향의 실제 403 및 C39 전후 건수 동일 조건 확인');
   else lines.push('미완료: 상대 사이트 계정으로 로그인해서 검사 버튼을 한 번 더 실행하세요.');
  }
  pane.textContent=lines.join('\n');
 }catch(e){pane.textContent='검사 요청 실패: '+e.message;}
 finally{btn.disabled=false;}
}
renderProgress();
btn.addEventListener('click',run);
by('card5CopyEvidence').addEventListener('click',()=>{
 navigator.clipboard.writeText(pane.textContent).then(()=>{
  by('card5CopyMessage').textContent='현재 실제 HTTP 요청 검사 기록을 복사했습니다.';
 }).catch(()=>by('card5CopyMessage').textContent='복사 실패. 화면의 기록을 직접 복사해 주세요.');
});
