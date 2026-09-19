import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createHash, sign } from 'node:crypto';
import { writeFileSync,mkdirSync } from 'node:fs';
import app from '../worker/index.mjs';
import {localEnv} from './local-env.mjs';
const origin='http://localhost:3000', b64=b=>Buffer.from(b).toString('base64url'),sha=b=>createHash('sha256').update(b).digest();
// Test-only CBOR encoding and software authenticator. Production uses SimpleWebAuthn verification.
function cbor(v){
 const h=(m,n)=>n<24?Buffer.from([(m<<5)|n]):n<256?Buffer.from([(m<<5)|24,n]):Buffer.from([(m<<5)|25,n>>8,n&255]);
 if(typeof v==='number')return v>=0?h(0,v):h(1,-1-v);
 if(typeof v==='string'){const b=Buffer.from(v);return Buffer.concat([h(3,b.length),b]);}
 if(Buffer.isBuffer(v))return Buffer.concat([h(2,v.length),v]);
 const a=[...v];return Buffer.concat([h(5,a.length),...a.flatMap(([k,x])=>[cbor(k),cbor(x)])]);
}
function authenticator(){
 const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),j=publicKey.export({format:'jwk'}),id=randomBytes(32);let owner,counter=0;
 const cose=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(j.x,'base64url')],[-3,Buffer.from(j.y,'base64url')]]));
 const client=(kind,challenge,o=origin)=>Buffer.from(JSON.stringify({type:kind,challenge,origin:o,crossOrigin:false}));
 return {id:b64(id),register(options){owner=options.user.id;const count=Buffer.alloc(4),len=Buffer.alloc(2);len.writeUInt16BE(id.length);const auth=Buffer.concat([sha('localhost'),Buffer.from([0x45]),count,Buffer.alloc(16),len,id,cose]);return {id:b64(id),rawId:b64(id),type:'public-key',response:{clientDataJSON:b64(client('webauthn.create',options.challenge)),attestationObject:b64(cbor(new Map([['fmt','none'],['attStmt',new Map()],['authData',auth]]))),transports:['internal']},clientExtensionResults:{}};},login(options,{bad=false,otherOrigin=false,noUV=false}={}){const cd=client('webauthn.get',options.challenge,otherOrigin?'https://evil.example':origin),count=Buffer.alloc(4);count.writeUInt32BE(++counter);const auth=Buffer.concat([sha('localhost'),Buffer.from([noUV?1:5]),count]);const signature=sign('sha256',Buffer.concat([auth,sha(cd)]),privateKey);if(bad)signature[signature.length-1]^=1;return {id:b64(id),rawId:b64(id),type:'public-key',response:{clientDataJSON:b64(cd),authenticatorData:b64(auth),signature:b64(signature),userHandle:owner},clientExtensionResults:{}};}};
}
test('T08 authentication, replay, ownership, cancellation and recovery evidence',async()=>{
 const env=localEnv(origin), evidence=[];
 function browser(name){const jar={};return {name,jar,async request(path,method='GET',body,label=path,expected=200,headers={}){
  const req=new Request(origin+path,{method,headers:{Origin:origin,'Content-Type':'application/json',Cookie:Object.entries(jar).map(([k,v])=>`${k}=${v}`).join('; '),...headers},body:body?JSON.stringify(body):undefined});
  const res=await app.fetch(req,env);const text=await res.text();let value;try{value=JSON.parse(text);}catch{value=text;}
  evidence.push({label,browser:name,request:{method,path,body,cookie:'[REDACTED]'},response:{status:res.status,body:value}});
  for(const c of res.headers.getSetCookie()){const [k,v]=c.split(';')[0].split('=');if(v)jar[k]=v;else delete jar[k];}
  assert.equal(res.status,expected,label+': '+text.slice(0,250));return value;
 }};}
 const a=browser('A'),b=browser('B'),anon=browser('anonymous');const k1=authenticator(),k2=authenticator(),kb=authenticator();
 const beginReg=x=>x.request('/api/register/options','POST',{alias:x.name+' 연습장',name:'테스트 패스키',provider:'테스트 인증기'});
 const r0=await beginReg(a),r1=await beginReg(a);assert.notEqual(r0.options.challenge,r1.options.challenge);
 await a.request('/api/flow/cancel','POST',{},'등록 취소');assert.equal(env.db.prepare('SELECT count(*) n FROM accounts').get().n,0);assert.equal(env.db.prepare('SELECT count(*) n FROM passkeys').get().n,0);
 await a.request('/api/register/verify','POST',{requestId:r1.requestId,response:k1.register(r1.options)},'취소한 등록 거절',400);
 async function register(x,key){const r=await beginReg(x);await x.request('/api/register/verify','POST',{requestId:r.requestId,response:key.register(r.options)},'등록 성공');}
 await register(a,k1);await register(a,k2);await register(b,kb);
 const am=await a.request('/api/me'),bm=await b.request('/api/me');
 const keys=await a.request('/api/passkeys');assert.equal(keys.passkeys.length,2);assert.ok(keys.passkeys.every(k=>k.public_key&&k.created&&k.name));
 const beforeA=await a.request('/api/private'),beforeB=await b.request('/api/private');assert.equal(beforeA.notes.length,3);assert.notDeepEqual(beforeA.notes,beforeB.notes);
 await anon.request('/api/private','GET',undefined,'비로그인 직접 조회 거절',401);
 await a.request(`/api/accounts/${bm.account.id}/private`,'GET',undefined,'A → B 거절',403);
 await b.request(`/api/accounts/${am.account.id}/private`,'GET',undefined,'B → A 거절',403);
 assert.deepEqual(await a.request('/api/private','GET',undefined,'공격 후 A 자료 유지'),beforeA);assert.deepEqual(await b.request('/api/private','GET',undefined,'공격 후 B 자료 유지'),beforeB);
 assert.deepEqual(await a.request('/api/private?accountId='+bm.account.id,'GET',undefined,'URL 계정 위조 → 본인 자료'),beforeA);
 assert.deepEqual(await a.request('/api/private','POST',{accountId:bm.account.id},'본문 계정 위조 → 본인 자료'),beforeA);
 await b.request('/api/passkeys/'+k1.id,'DELETE',{},'타인 패스키 삭제 거절',403);
 await a.request('/api/logout','POST',{},'잘못된 Origin 거절',403,{Origin:'https://evil.example'});
 const oldCookie={...a.jar};await a.request('/api/logout','POST',{},'로그아웃');a.jar.session=oldCookie.session;
 await a.request('/api/private','GET',undefined,'로그아웃 전 쿠키 재사용 거절',401);delete a.jar.session;
 const l0=await a.request('/api/login/options','POST',{}),l1=await a.request('/api/login/options','POST',{});assert.notEqual(l0.options.challenge,l1.options.challenge);
 const loginBody={requestId:l1.requestId,response:k1.login(l1.options)};
 await a.request('/api/login/verify','POST',loginBody,'올바른 서명 성공');await a.request('/api/login/verify','POST',loginBody,'사용한 질문 재사용 거절',400);
 for(const [label,opts] of [['틀린 서명',{bad:true}],['다른 Origin',{otherOrigin:true}],['사용자 확인 없음',{noUV:true}]]){const q=await a.request('/api/login/options','POST',{});await a.request('/api/login/verify','POST',{requestId:q.requestId,response:k1.login(q.options,opts)},label+' 거절',401);}
 const expired=await a.request('/api/login/options','POST',{});env.db.prepare('UPDATE challenges SET expires=0 WHERE id=?').run(expired.requestId);await a.request('/api/login/verify','POST',{requestId:expired.requestId,response:k1.login(expired.options)},'만료한 질문 거절',400);
 await a.request('/api/passkeys/'+k1.id,'DELETE',{},'첫 패스키 삭제');a.jar.session=oldCookie.session;await a.request('/api/private','GET',undefined,'삭제 후 예전 세션 거절',401);delete a.jar.session;
 async function login(x,key,expected=200,label='로그인'){const q=await x.request('/api/login/options','POST',{});return x.request('/api/login/verify','POST',{requestId:q.requestId,response:key.login(q.options)},label,expected);}
 await login(a,k1,401,'삭제한 패스키 로그인 거절');await login(a,k2,200,'남은 패스키 로그인 성공');
 await a.request('/api/passkeys/'+k2.id,'DELETE',{},'마지막 패스키 삭제 방지',409);
 const html=await anon.request('/','GET',undefined,'공개 소개 열기'),privateHTML=await anon.request('/private/','GET',undefined,'잠긴 공간의 공개 껍데기');
 for(const note of beforeA.notes){assert.ok(!html.includes(note.body));assert.ok(!privateHTML.includes(note.body));}
 assert.ok(!/type=["']password/.test(html+privateHTML));
 env.db.prepare('UPDATE sessions SET expires=0').run();await a.request('/api/private','GET',undefined,'세션 만료 거절',401);
 mkdirSync('evidence',{recursive:true});
 // Long public HTML is saved separately; response traces remain easy to review.
 for(const e of evidence)if(typeof e.response.body==='string')e.response.body='[공개 HTML 별도 보관: evidence/public-response.html 및 locked-response.html]';
 writeFileSync('evidence/public-response.html',html);writeFileSync('evidence/locked-response.html',privateHTML);
 writeFileSync('evidence/http-evidence.json',JSON.stringify({environment:'Node 24 + local SQLite adapter; production Worker handler + real SimpleWebAuthn verification; software ES256 test authenticators, not physical device confirmation',recordedAt:new Date().toISOString(),requests:evidence},null,2));
 env.db.close();console.log(`T08 evidence: ${evidence.length} requests passed; no live cookies or private keys recorded.`);
});

