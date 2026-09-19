const $=id=>document.getElementById(id), records=[];
let busy=false;
const labels=['Google 비밀번호 관리자','기기 자체','보안 키','다른 패스키 관리자'];
for(const prefix of ['first','extra']){
 const container=$(prefix+'-fields');
 const nameLabel=document.createElement('label');nameLabel.textContent='패스키 이름';
 const input=document.createElement('input');input.id=prefix+'-name';input.maxLength=60;input.placeholder='예: 내 노트북 / 예비 보안 키';nameLabel.append(input);
 const providerLabel=document.createElement('label');providerLabel.textContent='저장 위치 — 인증창에서 고를 위치';
 const select=document.createElement('select');select.id=prefix+'-provider';
 const empty=document.createElement('option');empty.value='';empty.textContent='저장 위치 선택';select.append(empty);
 for(const value of labels){const option=document.createElement('option');option.value=value;option.textContent=value;select.append(option);}
 providerLabel.append(select);container.append(nameLabel,providerLabel);
}
function message(text,error=false){$('message').textContent=text;$('message').className=error?'error':'';}
async function api(path,method='GET',body){
 const response=await fetch(path,{method,credentials:'same-origin',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined,cache:'no-store'});
 const value=await response.json();
 records.push({time:new Date().toISOString(),request:{method,path,body,authentication:'HttpOnly 쿠키는 기록하지 않음'},response:{status:response.status,body:value}});
 $('record-count').textContent=`현재 탭에서 요청 ${records.length}건 기록`;
 if(!response.ok){const error=new Error(value.message||'요청에 실패했습니다.');error.code=value.error;throw error;}return value;
}
const bytes=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const b64=v=>btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function serialize(c){
 const r=c.response,base={id:c.id,rawId:b64(c.rawId),type:c.type,clientExtensionResults:c.getClientExtensionResults(),authenticatorAttachment:c.authenticatorAttachment};
 base.response={clientDataJSON:b64(r.clientDataJSON)};
 if(r.attestationObject){base.response.attestationObject=b64(r.attestationObject);base.response.transports=r.getTransports?.()||[];}
 else{base.response.authenticatorData=b64(r.authenticatorData);base.response.signature=b64(r.signature);base.response.userHandle=r.userHandle?b64(r.userHandle):null;}
 return base;
}
async function action(fn){if(busy)return;busy=true;document.querySelectorAll('button').forEach(b=>b.disabled=true);try{await fn();}catch(e){
 if(['NotAllowedError','AbortError','InvalidStateError'].includes(e.name)){
  await api('/api/flow/cancel','POST',{}).catch(()=>{});
  message(e.name==='InvalidStateError'?'같은 저장 위치에 패스키가 이미 있습니다. 다른 기기나 보안 키를 골라 주세요.':'인증이 취소되었거나 시간이 지났습니다. 등록 확인 전이라면 서버에 계정·패스키를 저장하지 않습니다.',true);
 }else message(e.message,true);
 }finally{busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false);}}
function clearPrivate(){ $('notes').replaceChildren();$('keys').replaceChildren();$('account-name').textContent='';$('unlocked').hidden=true;$('locked').hidden=false;$('state').textContent='잠겨 있음'; }
async function refresh(){
 try{
  const me=await api('/api/me');const result=await api('/api/private');const keyList=await api('/api/passkeys');
  $('account-name').textContent=me.account.alias;$('state').textContent='패스키로 확인됨';$('locked').hidden=true;$('unlocked').hidden=false;
  $('notes').replaceChildren();for(const note of result.notes){const card=document.createElement('article');card.className='note';const h=document.createElement('h2'),p=document.createElement('p');h.textContent=note.title;p.textContent=note.body;card.append(h,p);$('notes').append(card);}
  $('keys').replaceChildren();for(const key of keyList.passkeys){const card=document.createElement('div');card.className='key';const head=document.createElement('div');head.className='key-head';const title=document.createElement('strong');title.textContent=key.name+(key.current?' · 현재 로그인':'');const button=document.createElement('button');button.textContent='삭제';button.onclick=()=>action(async()=>{if(!confirm('이 패스키를 삭제하면 모든 로그인이 종료됩니다. 남은 패스키를 사용할 수 있는지 확인했나요?'))return;await api('/api/passkeys/'+key.id,'DELETE',{});clearPrivate();message('패스키를 삭제했습니다. 남아 있는 패스키로 로그인해 주세요.');});head.append(title,button);const meta=document.createElement('small');meta.textContent=`${key.provider} · 등록 ${new Date(key.created).toLocaleString('ko-KR')}`;const details=document.createElement('details'),summary=document.createElement('summary'),pre=document.createElement('pre');summary.textContent='서버에 저장된 공개키 보기';pre.textContent=key.public_key;details.append(summary,pre);card.append(head,meta,details);$('keys').append(card);}
 }catch(e){clearPrivate();if(e.code!=='LOGIN_REQUIRED')throw e;}
}
async function register(prefix){
 if(!window.PublicKeyCredential||!window.isSecureContext)throw new Error('HTTPS와 패스키를 지원하는 브라우저가 필요합니다.');
 const payload={name:$(prefix+'-name').value.trim(),provider:$(prefix+'-provider').value,alias:$('alias').value.trim()};
 if(!payload.name||!payload.provider||(prefix==='first'&&!payload.alias))throw new Error('별칭·패스키 이름·저장 위치를 확인해 주세요.');
 const {requestId,options}=await api('/api/register/options','POST',payload);
 const publicKey={...options,challenge:bytes(options.challenge),user:{...options.user,id:bytes(options.user.id)},excludeCredentials:options.excludeCredentials?.map(x=>({...x,id:bytes(x.id)}))};
 message('기기의 패스키 창에서 등록을 완료해 주세요.');
 const credential=await navigator.credentials.create({publicKey});
 await api('/api/register/verify','POST',{requestId,response:serialize(credential)});await refresh();message('패스키 등록을 완료했습니다. 저장 위치가 실제 선택과 일치하는지 확인해 주세요.');
}
$('register').onclick=()=>action(()=>register('first'));
$('add').onclick=()=>action(()=>register('extra'));
$('login').onclick=()=>action(async()=>{
 if(!window.PublicKeyCredential||!window.isSecureContext)throw new Error('HTTPS와 패스키를 지원하는 브라우저가 필요합니다.');
 const {requestId,options}=await api('/api/login/options','POST',{});
 const credential=await navigator.credentials.get({publicKey:{...options,challenge:bytes(options.challenge),allowCredentials:options.allowCredentials?.map(x=>({...x,id:bytes(x.id)}))}});
 await api('/api/login/verify','POST',{requestId,response:serialize(credential)});await refresh();message('패스키로 로그인했습니다.');
});
$('logout').onclick=()=>action(async()=>{await api('/api/logout','POST',{});clearPrivate();message('로그아웃했습니다. 기존 세션으로는 기록을 열 수 없습니다.');});
$('export').onclick=()=>{const blob=new Blob([JSON.stringify({description:'현재 브라우저의 실제 요청·응답. 세션·쿠키 원문 제외. 저장 위치는 사용자가 선택한 값.',records},null,2)],{type:'application/json'});const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='T08-내-확인기록.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
window.addEventListener('pageshow',()=>refresh().catch(e=>message(e.message,true)));
document.addEventListener('visibilitychange',()=>{if(document.hidden)clearPrivate();else refresh().catch(e=>message(e.message,true));});
if(document.modelContext?.registerTool){
 const lifecycle=new AbortController();
 try{Promise.resolve(document.modelContext.registerTool({name:'read_passkey_login_status',description:'현재 로그인 여부를 서버에 확인합니다. 패스키 등록과 본인 확인은 사용자가 직접 합니다.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true},async execute(input){if(!input||Object.keys(input).length)throw new Error('입력값을 받지 않습니다.');try{const result=await api('/api/me');return {loggedIn:true,alias:result.account.alias};}catch(e){if(e.code==='LOGIN_REQUIRED')return {loggedIn:false};throw e;}}},{signal:lifecycle.signal})).catch(()=>{});}catch{}
 window.addEventListener('pagehide',()=>lifecycle.abort(),{once:true});
}
