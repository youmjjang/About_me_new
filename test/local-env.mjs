import { DatabaseSync } from 'node:sqlite';
import { readFileSync,readdirSync } from 'node:fs';
export function localEnv(origin='http://localhost:3000'){
 const db=new DatabaseSync(':memory:');db.exec('PRAGMA foreign_keys=ON');
 for(const f of readdirSync('drizzle').filter(f=>f.endsWith('.sql')).sort())db.exec(readFileSync('drizzle/'+f,'utf8'));
 function prepare(q){return {bind(...p){return {async first(){return db.prepare(q).get(...p)||null;},async all(){return {results:db.prepare(q).all(...p)};},async run(){const r=db.prepare(q).run(...p);return {meta:{changes:Number(r.changes)}};}};}};}
 return {db,ORIGIN:origin,DB:{prepare,async batch(items){db.exec('BEGIN');try{const r=[];for(const i of items)r.push(await i.run());db.exec('COMMIT');return r;}catch(e){db.exec('ROLLBACK');throw e;}}},ASSETS:{async fetch(req){const p=new URL(req.url).pathname;const name=p==='/'?'index.html':p==='/private/'?'private/index.html':p.slice(1);if(name.includes('..'))return new Response('',{status:404});try{return new Response(readFileSync('public/'+name),{headers:{'Content-Type':name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':name.endsWith('.svg')?'image/svg+xml':name.endsWith('.png')?'image/png':name.endsWith('.webp')?'image/webp':'text/html; charset=utf-8'}});}catch{return new Response('Not found',{status:404});}}}};
}
