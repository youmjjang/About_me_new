import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_PATH||'playwright');
const browser=await chromium.launch({headless:true,channel:'msedge'});
try{
 const page=await browser.newPage({viewport:{width:1366,height:900}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000/');await page.screenshot({path:'evidence/public-page.png'});
 const badImages=await page.locator('img').evaluateAll(images=>images.filter(i=>i.getAttribute('src')&&i.complete&&!i.naturalWidth).map(i=>i.src));
 if(badImages.length)throw new Error('Broken original images: '+badImages.join(','));
 await page.getByRole('link',{name:'패스키로 들어가기',exact:true}).click();
 const cdp=await page.context().newCDPSession(page);await cdp.send('WebAuthn.enable');
 async function device(){return (await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}})).authenticatorId;}
 let auth=await device();
 await page.getByText('처음이라면, 연습용 공간 만들기',{exact:true}).click();await page.locator('#alias').fill('브라우저 검증 A');await page.locator('#first-name').fill('검증용 기기 1');await page.locator('#first-provider').selectOption('기기 자체');await page.locator('#register').click();
 await page.locator('#unlocked:not([hidden])').waitFor();
 await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:auth});auth=await device();
 await page.getByText('두 번째 패스키 추가하기',{exact:true}).click();await page.locator('#extra-name').fill('검증용 기기 2');await page.locator('#extra-provider').selectOption('기기 자체');await page.locator('#add').click();await page.waitForFunction(()=>document.querySelectorAll('.key').length===2);
 await page.screenshot({path:'evidence/two-passkeys.png',fullPage:true});
 page.on('dialog',d=>d.accept());await page.locator('.key').first().getByRole('button',{name:'삭제',exact:true}).click();await page.locator('#locked:not([hidden])').waitFor();await page.locator('#login').click();await page.locator('#unlocked:not([hidden])').waitFor();
 await page.screenshot({path:'evidence/remaining-passkey.png',fullPage:true});
 if(await page.locator('.note').count()!==3||await page.locator('.key').count()!==1)throw new Error('Unexpected private state');
 await page.locator('#logout').click();await page.locator('#locked:not([hidden])').waitFor();
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:'evidence/locked-mobile.png',fullPage:true});
 if(errors.length)throw new Error(errors.join('\n'));
 writeFileSync('evidence/browser-verification.json',JSON.stringify({at:new Date().toISOString(),environment:'Local Cloudflare workerd + D1; Microsoft Edge CDP virtual authenticators. Not physical-device confirmation. UI provider label 기기 자체 denotes emulated device only.',passed:['Original public images load','Register first key via navigator.credentials.create','Add second virtual authenticator','Two-key list screenshot','Delete first key','Login with remaining key via navigator.credentials.get','Three private notes','Logout hides private content','Mobile locked screen','No page JavaScript errors']},null,2));
 console.log('Browser: 10 checks passed (virtual devices).');
}finally{await browser.close();}

