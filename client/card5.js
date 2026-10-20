// Card 5: direct browser HTTP evidence (without revealing private content or cookies).
const by=id=>document.getElementById(id);
const pane=by('card5Evidence');
const btn=by('card5RunChecks');
async function ask(url,{method='GET',body}={}){
 const opts={method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}};
 if(body!==undefined){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body);}
 const res=await fetch(url,opts);
 const content=await res.json().catch(()=>({error:'response_not_json'}));
 return {http:res.status,content};
}
function summary(label,result){
 return label+' → HTTP '+result.http+(result.content.error?' / '+result.content.error:'')+
  (Array.isArray(result.content.items)?' / 자료 '+result.content.items.length+'건':'');
}
async function run(){
 btn.disabled=true;
 pane.textContent='검증 중… (실제 비공개 본문은 기록하지 않음)';
 const lines=['카드 5 실제 HTTP 권한 검사 · '+new Date().toLocaleString('ko-KR')];
 try{
  const status=await ask('/api/auth',{method:'POST',body:{action:'status'}});
  if(status.http!==200||!status.content.authenticated){
   pane.textContent='패스키로 로그인한 뒤 검사를 실행해야 합니다. HTTP '+status.http;return;
  }
  const me=status.content.ownerId,other=me===1?2:1;
  lines.push('현재 사이트 계정: '+status.content.accountName+' (ID '+me+')');
  const before=await ask('/api/private?account='+me);
  const cross=await ask('/api/private?account='+other);
  const after=await ask('/api/private?account='+me);
  const spoof=await ask('/api/private?owner_id='+other+'&requestedOwner='+other);
  const anon=await fetch('/api/private',{credentials:'omit',cache:'no-store'});
  lines.push(summary('① 로그인 없이 요청', {http:anon.status,content:{}}));
  lines.push(summary('① 로그인해서 내 자료',before));
  lines.push(summary('② 다른 계정 account='+other+' 자료 요청',cross));
  lines.push(summary('③ 거절 이후 내 자료',after));
  lines.push(summary('④ URL에 owner_id='+other+'로 변경',spoof));
  lines.push('내 자료 건수: 거절 전 '+(before.content.items?.length??'미확인')+
    '건 → 거절 후 '+(after.content.items?.length??'미확인')+'건');
  const pass=anon.status===401&&before.http===200&&cross.http===403&&after.http===200&&
   spoof.http===200&&spoof.content.accountId===me&&
   before.content.items?.length===after.content.items?.length;
  lines.push(pass?'판정: 현재 계정 방향 검사 통과':'판정: 예상 결과와 다릅니다. 제출 전 확인 필요');
  lines.push('※ 다른 방향은 상대 계정으로 로그인한 뒤 같은 검사를 별도로 실행해야 합니다.');
  pane.textContent=lines.join('\n');
 }catch(e){pane.textContent=lines.join('\n')+'\n검사 실패: '+e.message;}
 finally{btn.disabled=false;}
}
btn.addEventListener('click',run);
by('card5CopyEvidence').addEventListener('click',()=>{
 navigator.clipboard.writeText(pane.textContent).then(()=>{
  by('card5CopyMessage').textContent='현재 화면의 검사 기록을 복사했습니다.';
 }).catch(()=>by('card5CopyMessage').textContent='자동 복사가 안 됩니다. 기록을 직접 복사해 주세요.');
});
