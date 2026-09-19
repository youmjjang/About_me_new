import { build } from 'esbuild';
import { mkdir, cp, writeFile } from 'node:fs/promises';
await mkdir('dist/server',{recursive:true});
await mkdir('dist/.openai',{recursive:true});
await cp('public','dist/client',{recursive:true});
await cp('.openai/hosting.json','dist/.openai/hosting.json');
await cp('drizzle','dist/.openai/drizzle',{recursive:true});
await build({entryPoints:['worker/index.mjs'],outfile:'dist/server/index.js',bundle:true,format:'esm',platform:'browser',target:'es2022',external:['node:*'],define:{'process.env.NODE_ENV':'"production"'}});
await writeFile('dist/server/wrangler.json',JSON.stringify({name:'about-me-new',main:'index.js',compatibility_date:'2026-09-01',compatibility_flags:['nodejs_compat'],assets:{directory:'../client',binding:'ASSETS',run_worker_first:true},d1_databases:[{binding:'DB',database_name:'about-me-new',database_id:'local',migrations_dir:'../../drizzle'}]},null,2));
