import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { SITE_ORIGIN } from './config.mjs';
import { Buffer } from 'node:buffer';
const random = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
const digest = async s => Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))).toString('hex');
class Rejection extends Error { constructor(status,code,message){super(message);this.status=status;this.code=code;} }
const reject=(s,c,m)=>{throw new Rejection(s,c,m);};
const valid=(v,n)=>typeof v==='string' && v.trim().length>0 && v.length<=n;
const providers=['Google 비밀번호 관리자','기기 자체','보안 키','다른 패스키 관리자','테스트 인증기'];
export default {
 async fetch(request, env) {
  const url=new URL(request.url), path=url.pathname;
  if(!path.startsWith('/api/')) {
   if(path==='/private') return Response.redirect(new URL('/private/',url),302);
   const response=await env.ASSETS.fetch(new Request(url,request));
   const headers=new Headers(response.headers);
   headers.set('Cache-Control','no-store'); headers.set('X-Content-Type-Options','nosniff');
   headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
   return new Response(response.body,{status:response.status,headers});
  }
  const origin=env.ORIGIN || SITE_ORIGIN, rpID=new URL(origin).hostname;
  const secure=origin.startsWith('https:'), sessionName=secure?'__Host-session':'session', flowName=secure?'__Host-flow':'flow';
  const cookie=Object.fromEntries((request.headers.get('Cookie')||'').split(';').map(x=>x.trim().split('=')).filter(x=>x.length===2));
  const setCookies=[];
  const setCookie=(name,val,seconds)=>setCookies.push(`${name}=${val}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${seconds}${secure?'; Secure':''}`);
  const sql=(q,...p)=>env.DB.prepare(q).bind(...p);
  const get=(q,...p)=>sql(q,...p).first();
  const all=async(q,...p)=>(await sql(q,...p).all()).results;
  const run=(q,...p)=>sql(q,...p).run();
  const reply=(data,status=200)=>{
   const headers=new Headers({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});
   for(const c of setCookies)headers.append('Set-Cookie',c);
   return new Response(JSON.stringify(data),{status,headers});
  };
  const sessionHash=await digest(cookie[sessionName]||'');
  const browserHash=await digest(cookie[flowName]||'');
  const session=()=>get('SELECT * FROM sessions WHERE hash=? AND expires>?',sessionHash,Date.now());
  const requireSession=async(recent=false)=>{
   const s=await session();
   if(!s)reject(401,'LOGIN_REQUIRED','패스키로 로그인해 주세요.');
   if(recent&&Date.now()-s.authenticated>300000)reject(401,'REAUTH_REQUIRED','패스키로 다시 로그인한 뒤 시도해 주세요.');
   return s;
  };
  const begin=async(kind,options,payload)=>{
   const flow=/^[A-Za-z0-9_-]{43}$/.test(cookie[flowName]||'')?cookie[flowName]:random();
   const h=await digest(flow),id=random();
   await env.DB.batch([sql('DELETE FROM challenges WHERE expires<=? OR browser=?',Date.now(),h),sql('INSERT INTO challenges VALUES(?,?,?,?,?,?)',id,h,kind,options.challenge,JSON.stringify(payload),Date.now()+120000)]);
   setCookie(flowName,flow,600); return reply({requestId:id,options});
  };
  const consume=async(data,kind)=>{
   if(!valid(data.requestId,100))reject(400,'BAD_REQUEST','요청 식별자가 필요합니다.');
   // Atomic consume before async signature verification; used/failed/expired attempts cannot be replayed.
   const c=await get('DELETE FROM challenges WHERE id=? AND browser=? AND kind=? RETURNING *',data.requestId,browserHash,kind);
   if(!c||c.expires<=Date.now())reject(400,'CHALLENGE_INVALID','이미 사용했거나 취소·만료된 질문입니다. 다시 시도해 주세요.');
   return {...c,payload:JSON.parse(c.payload)};
  };
  try {
   let data={};
   if(['POST','DELETE'].includes(request.method)){
    if(request.headers.get('Origin')!==origin)reject(403,'ORIGIN_REJECTED','허용되지 않은 요청 출처입니다.');
    if(!request.headers.get('Content-Type')?.startsWith('application/json'))reject(415,'JSON_REQUIRED','JSON 요청이 필요합니다.');
    const reader=request.body?.getReader();let total=0,parts=[];
    if(reader)while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>32768){await reader.cancel();reject(413,'TOO_LARGE','요청이 너무 큽니다.');}parts.push(value);}
    try{data=JSON.parse(Buffer.concat(parts).toString()||'{}');if(!data||Array.isArray(data)||typeof data!=='object')throw 0;}catch{reject(400,'BAD_JSON','요청 형식을 확인해 주세요.');}
   }
   const is=(p,m)=>path===p&&request.method===m;
   if(is('/api/register/options','POST')){
    if(!valid(data.name,60)||!providers.includes(data.provider))reject(400,'BAD_LABEL','패스키 이름과 저장 위치를 선택해 주세요.');
    const s=await session();if(s)await requireSession(true);
    if(!s&&!valid(data.alias,32))reject(400,'BAD_ALIAS','개인정보 대신 연습용 별칭을 입력해 주세요.');
    const owner=s?.owner||random(),alias=s?(await get('SELECT alias FROM accounts WHERE id=?',owner)).alias:data.alias.trim();
    const keys=await all('SELECT id,transports FROM passkeys WHERE owner=?',owner);
    if(keys.length>=10)reject(409,'KEY_LIMIT','패스키는 계정당 10개까지 등록할 수 있습니다.');
    const options=await generateRegistrationOptions({rpName:'YUMI / 나만의 기록',rpID,userID:Buffer.from(owner,'base64url'),userName:`${alias} · ${owner.slice(0,6)}`,userDisplayName:alias,attestationType:'none',supportedAlgorithmIDs:[-7,-257],timeout:120000,authenticatorSelection:{residentKey:'required',userVerification:'required'},excludeCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
    return begin('register',options,{owner,alias,name:data.name.trim(),provider:data.provider,parent:s?.hash||null});
   }
   if(is('/api/register/verify','POST')){
    const c=await consume(data,'register'),p=c.payload;
    if(p.parent){const s=await requireSession(true);if(s.hash!==p.parent||s.owner!==p.owner)reject(403,'WRONG_ACCOUNT','등록을 시작한 계정이 아닙니다.');}
    let v;try{v=await verifyRegistrationResponse({response:data.response,expectedChallenge:c.value,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]});}catch{reject(400,'REGISTRATION_REJECTED','패스키 등록을 확인할 수 없습니다. 처음부터 다시 시도해 주세요.');}
    if(!v.verified)reject(400,'REGISTRATION_REJECTED','등록 확인에 실패했습니다.');
    const k=v.registrationInfo.credential, now=Date.now(),created=new Date().toISOString(),statements=[];
    const keyValues=[k.id,p.owner,Buffer.from(k.publicKey).toString('base64url'),k.counter,p.name,p.provider,JSON.stringify(k.transports||[]),created];
    if(p.parent){
     // Authorization rechecked inside INSERT, after asynchronous verification.
     const result=await run('INSERT INTO passkeys SELECT ?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM sessions WHERE hash=? AND owner=? AND expires>? AND authenticated>?) AND (SELECT COUNT(*) FROM passkeys WHERE owner=?)<10',...keyValues,p.parent,p.owner,now,now-300000,p.owner);
     if(!result.meta.changes)reject(401,'SESSION_ENDED','등록 중 로그인이 종료되었습니다. 다시 시도해 주세요.');
    }else{
     statements.push(sql('INSERT INTO accounts VALUES(?,?,?)',p.owner,p.alias,created),sql('INSERT INTO passkeys VALUES(?,?,?,?,?,?,?,?)',...keyValues));
     for(const [title,body] of [['프로젝트 메모','작은 독서 기록 앱의 화면을 설계합니다.'],['관심 있는 기회','가상의 별빛 연구소 개발 프로젝트를 살펴봅니다.'],['이번 주 회고','질문을 작게 나누니 문제를 확인하기 쉬웠습니다.']])statements.push(sql('INSERT INTO notes VALUES(?,?,?,?)',random(),p.owner,title,`${p.alias}의 가상 기록: ${body}`));
     const raw=random();statements.push(sql('DELETE FROM sessions WHERE hash=?',sessionHash),sql('INSERT INTO sessions VALUES(?,?,?,?,?)',await digest(raw),p.owner,k.id,now+3600000,now));
     await env.DB.batch(statements);setCookie(sessionName,raw,3600);
    }
    return reply({verified:true});
   }
   if(is('/api/login/options','POST'))return begin('login',await generateAuthenticationOptions({rpID,userVerification:'required',timeout:120000}),{});
   if(is('/api/login/verify','POST')){
    const c=await consume(data,'login');
    const k=typeof data.response?.id==='string'?await get('SELECT * FROM passkeys WHERE id=?',data.response.id):null;
    if(!k||data.response.response?.userHandle!==k.owner)reject(401,'LOGIN_REJECTED','등록된 패스키로 확인할 수 없습니다.');
    let v;try{v=await verifyAuthenticationResponse({response:data.response,expectedChallenge:c.value,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true,credential:{id:k.id,publicKey:new Uint8Array(Buffer.from(k.public_key,'base64url')),counter:k.counter,transports:JSON.parse(k.transports)}});}catch{reject(401,'LOGIN_REJECTED','패스키 서명을 확인할 수 없습니다.');}
    if(!v.verified)reject(401,'LOGIN_REJECTED','패스키 서명을 확인할 수 없습니다.');
    const raw=random(),now=Date.now();
    const results=await env.DB.batch([
     sql('INSERT INTO sessions SELECT ?,owner,id,?,? FROM passkeys WHERE id=? AND counter=?',await digest(raw),now+3600000,now,k.id,k.counter),
     sql('UPDATE passkeys SET counter=? WHERE id=? AND counter=?',v.authenticationInfo.newCounter,k.id,k.counter),
     sql('DELETE FROM sessions WHERE hash=? OR expires<=?',sessionHash,now),
    ]);
    if(!results[0].meta.changes)reject(401,'KEY_CHANGED','패스키가 삭제되었거나 상태가 바뀌었습니다.');
    setCookie(sessionName,raw,3600);return reply({verified:true});
   }
   if(is('/api/flow/cancel','POST')){await run('DELETE FROM challenges WHERE browser=?',browserHash);return reply({cancelled:true});}
   if(is('/api/logout','POST')){
    await env.DB.batch([sql('DELETE FROM sessions WHERE hash=?',sessionHash),sql('DELETE FROM challenges WHERE browser=?',browserHash)]);
    setCookie(sessionName,'',0);setCookie(flowName,'',0);return reply({loggedOut:true});
   }
   if(is('/api/me','GET')){const s=await requireSession();return reply({account:await get('SELECT id,alias FROM accounts WHERE id=?',s.owner)});}
   if(path==='/api/private'&&['GET','POST'].includes(request.method)){
    const s=await requireSession();
    // Client-supplied account IDs in URL/body are deliberately ignored.
    return reply({owner:s.owner,fictional:true,notes:await all('SELECT id,title,body FROM notes WHERE owner=?',s.owner)});
   }
   const target=path.match(/^\/api\/accounts\/([^/]+)\/private$/);
   if(target&&request.method==='GET'){
    const s=await requireSession();if(target[1]!==s.owner)reject(403,'OWNER_MISMATCH','다른 계정의 비공개 자료는 열 수 없습니다.');
    return reply({owner:s.owner,notes:await all('SELECT id,title,body FROM notes WHERE owner=?',s.owner)});
   }
   if(is('/api/passkeys','GET')){
    const s=await requireSession();return reply({passkeys:(await all('SELECT id,name,provider,created,public_key FROM passkeys WHERE owner=? ORDER BY created',s.owner)).map(k=>({...k,current:k.id===s.credential}))});
   }
   const removal=path.match(/^\/api\/passkeys\/([A-Za-z0-9_-]+)$/);
   if(removal&&request.method==='DELETE'){
    const s=await requireSession(true),id=removal[1];
    if(!await get('SELECT id FROM passkeys WHERE id=? AND owner=?',id,s.owner))reject(403,'KEY_FORBIDDEN','이 계정의 패스키만 삭제할 수 있습니다.');
    // Both statements run in one serial transaction; last-key deletion is refused atomically.
    const results=await env.DB.batch([
     sql('DELETE FROM sessions WHERE owner=? AND EXISTS(SELECT 1 FROM passkeys WHERE id=? AND owner=?) AND (SELECT COUNT(*) FROM passkeys WHERE owner=?)>1',s.owner,id,s.owner,s.owner),
     sql('DELETE FROM passkeys WHERE id=? AND owner=? AND (SELECT COUNT(*) FROM passkeys WHERE owner=?)>1',id,s.owner,s.owner),
    ]);
    if(!results[1].meta.changes)reject(409,'LAST_PASSKEY','마지막 패스키는 삭제할 수 없습니다. 먼저 다른 패스키를 등록해 주세요.');
    setCookie(sessionName,'',0);return reply({deleted:true,loggedOut:true});
   }
   reject(404,'NOT_FOUND','요청한 기능을 찾을 수 없습니다.');
  }catch(error){
   if(!(error instanceof Rejection))console.error('API failure',error.name);
   return reply({error:error.code||'SERVER_ERROR',message:error instanceof Rejection?error.message:'처리하지 못했습니다. 잠시 뒤 다시 시도해 주세요.'},error.status||500);
  }
 }
};
