import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { JSDOM } from 'jsdom';

const desktop = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(path.join(desktop, 'ui/index.html'), 'utf8');
const script = readFileSync(path.join(desktop, 'ui/app.js'), 'utf8');
const status = { configured: false, identity: null, host_platform: 'win32', platform: {available: true}, data_dir: 'C:\\SkySeal', orcid_client_id: '' };
const draft = {job_id:'a'.repeat(32), state:'prepared', created_at:'2026-11-10T12:00:00Z', entry_count:1,
  items:[{name:'<img src=x onerror=alert(1)>.txt',size:10,sha256:'a'.repeat(64)}], ots_state:'not_requested'};

async function until(predicate) {
  for (let i=0;i<150;i++) { if(predicate()) return; await new Promise(r=>setTimeout(r,5)); }
  assert.fail('UI did not reach the expected state');
}
async function setup(responder, options={}) {
  const dom = new JSDOM(html, {url:'https://tauri.localhost',runScripts:'outside-only'});
  const {window:w}=dom, calls=[];
  w.HTMLElement.prototype.scrollIntoView=()=>{};
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true;};
  w.HTMLDialogElement.prototype.close=function(){this.open=false;};
  if(!options.noBridge) w.__TAURI__={core:{invoke:async(command,args)=>{
    calls.push({command,...args});
    if(command==='choose_path') return options.paths?.[args.kind] || ['C:\\研究.txt'];
    const {op,params}=args.request;
    const result=await responder?.(op,params);
    return result ?? {ok:true,result:op==='status'?status:op==='tls_status'?{callback_uri:'https://localhost:24731/callback',certificate_path:'local.pem'}:op==='trust_local_certificate'?{trusted:true,certificate_path:'local.pem'}:{}};
  }},event:{listen:async()=>()=>{}}};
  w.eval(script);
  await until(()=>w.document.getElementById('activity').hidden);
  return {dom,w,calls,$:(id)=>w.document.getElementById(id)};
}
const success=(result)=>({ok:true,result});

test('plain browser cannot perform desktop operations or simulate a seal',async()=>{
  const t=await setup(null,{noBridge:true});
  assert.equal(t.$('connection-banner').hidden,false);
  for(const id of ['pick-files','prepare','seal','enroll','verify']) assert.equal(t.$(id).disabled,true);
  t.dom.window.close();
});
test('prepare renders untrusted filenames as text and requires identity before seal',async()=>{
  const t=await setup((op)=>op==='prepare'?success(draft):undefined);
  t.$('pick-files').click(); await until(()=>!t.$('prepare').disabled);
  t.$('prepare').click(); await until(()=>!t.$('review-card').hidden);
  assert.equal(t.$('review-files').querySelector('img'),null);
  assert.match(t.$('review-files').textContent,/<img/);
  assert.equal(t.$('seal').disabled,true);
  assert.deepEqual(Array.from(t.calls.find(c=>c.request?.op==='prepare').request.params.paths),['C:\\研究.txt']);
  t.dom.window.close();
});
test('cancelled native approval is shown as failure, never saved as a successful seal',async()=>{
  const t=await setup((op)=>op==='status'?success({...status,configured:true,identity:{identity_id:'https://orcid.org/0000-0003-3001-7690'}}):op==='prepare'?success(draft):op==='seal'?{ok:false,error:{message:'Approval cancelled'}}:undefined);
  t.$('pick-files').click(); await until(()=>!t.$('prepare').disabled);
  t.$('prepare').click(); await until(()=>!t.$('seal').disabled);
  t.$('seal').click(); await until(()=>!t.$('notice').hidden);
  assert.match(t.$('notice').textContent,/cancelled/);
  assert.equal(t.$('seal-result').hidden,true);
  t.dom.window.close();
});
test('pending verification is distinct from confirmed time and uses a trusted legacy preset',async()=>{
  const t=await setup((op)=>op==='verify'?success({ok:true,signature_valid:true,user_verified:true,time_confirmed:false,candidate_match:null,identity_id:'ORCID',seal_id:'test',profile:'draft'}):undefined,{paths:{evidence:['C:\\evidence.zip']}});
  t.w.document.querySelector('[data-page="verify"]').click();
  t.$('pick-evidence').click(); await until(()=>!t.$('verify').disabled);
  t.$('verify').click(); await until(()=>!t.$('verification-result').hidden);
  assert.match(t.$('verification-result').textContent,/未確定・未確認/);
  const params=t.calls.find(c=>c.request?.op==='verify').request.params;
  assert.equal(params.trusted_rp_id,'proof.excyberlab.net');
  assert.equal(params.trusted_origin,'https://proof.excyberlab.net');
  t.dom.window.close();
});
test('certificate trust is an explicit separate UI action',async()=>{
  const t=await setup();
  t.w.document.querySelector('[data-page="settings"]').click();
  await until(()=>!t.$('trust-certificate').disabled);
  assert.equal(t.calls.some(c=>c.request?.op==='trust_local_certificate'),false);
  t.$('trust-certificate').click(); assert.equal(t.$('certificate-dialog').open,true);
  t.$('cancel-cert').click(); assert.equal(t.calls.some(c=>c.request?.op==='trust_local_certificate'),false);
  t.$('trust-certificate').click(); t.$('confirm-cert').click();
  await until(()=>t.calls.some(c=>c.request?.op==='trust_local_certificate'));
  await until(()=>t.$('activity').hidden);
  assert.equal(t.$('tls-state').textContent,'Windowsに登録済み');
  t.dom.window.close();
});
test('macOS uses Keychain wording and keeps certificate trust explicit',async()=>{
  const macStatus={...status,host_platform:'darwin',platform:{available:true,backend:'macos-keychain'}};
  const t=await setup((op)=>op==='status'?success(macStatus):op==='tls_status'?success({certificate_path:'localhost.pem',trust_scope:'user Keychain / SSL / localhost'}):undefined);
  t.w.document.querySelector('[data-page="settings"]').click();
  await until(()=>t.$('tls-scope').textContent.includes('localhost'));
  assert.match(t.$('native-state').textContent,/macOSキーチェーン/);
  assert.match(t.$('trust-certificate').textContent,/キーチェーン/);
  assert.match(t.$('key-storage-note').textContent,/ログインパスワードと異なる/);
  assert.doesNotMatch(t.$('identity-description').textContent,/Windows|Touch ID/);
  t.$('trust-certificate').click();
  assert.match(t.$('certificate-trust-description').textContent,/現在のユーザー.*localhostのSSL/);
  t.$('cancel-cert').click();
  assert.equal(t.calls.some(c=>c.request?.op==='trust_local_certificate'),false);
  t.dom.window.close();
});
test('cancelled macOS trust authentication is never reported as registered',async()=>{
  const t=await setup((op)=>op==='status'?success({...status,host_platform:'darwin'}):op==='trust_local_certificate'?{ok:false,error:{message:'Keychain authentication cancelled'}}:undefined);
  t.w.document.querySelector('[data-page="settings"]').click();
  await until(()=>!t.$('trust-certificate').disabled);
  t.$('trust-certificate').click(); t.$('confirm-cert').click();
  await until(()=>!t.$('notice').hidden);
  assert.match(t.$('notice-text').textContent,/cancelled/);
  assert.doesNotMatch(t.$('tls-state').textContent,/登録済み/);
  t.dom.window.close();
});
const linuxStatus={...status,host_platform:'linux',configured:true,platform:{available:true,backend:'linux-passphrase-p256'}};
const linuxTls={certificate_path:'localhost.pem',sha256:'ab'.repeat(32),trusted:false,
  trust_scope:'current browser connection / localhost:24731 / this certificate'};
test('Linux uses an application passphrase and explicit scoped browser confirmation',async()=>{
  const t=await setup((op)=>op==='status'?success(linuxStatus):op==='tls_status'?success(linuxTls)
    :op==='trust_local_certificate'?success({...linuxTls,browser_verified:true,browser_confirmation_is_persistent:false}):undefined);
  t.w.document.querySelector('[data-page="settings"]').click();
  await until(()=>!t.$('confirm-cert').disabled);
  assert.match(t.$('native-state').textContent,/Linux.*Pinentry/);
  assert.match(t.$('identity-description').textContent,/SkySeal専用のパスフレーズ/);
  assert.match(t.$('identity-description').textContent,/Pinentryの別ウィンドウ/);
  assert.match(t.$('key-storage-note').textContent,/Linuxのログインパスワードとは別/);
  assert.match(t.$('approval-description').textContent,/SkySeal専用のパスフレーズ/);
  assert.doesNotMatch(t.$('identity-description').textContent,/Windows|Touch ID|キーチェーン/);
  assert.equal(t.$('tls-fingerprint-label').textContent,'証明書 SHA-256');
  assert.equal(t.$('tls-thumbprint').textContent,Array(32).fill('AB').join(':'));
  assert.match(t.$('tls-state').textContent,/ブラウザー接続は未確認/);
  t.$('trust-certificate').click();
  assert.equal(t.$('certificate-dialog').open,true);
  assert.equal(t.$('certificate-dialog-fingerprint').hidden,false);
  assert.match(t.$('certificate-trust-description').textContent,/https:\/\/localhost:24731/);
  assert.match(t.$('certificate-trust-description').textContent,/SHA-256.*一致/);
  assert.match(t.$('certificate-dialog-fingerprint').textContent,/AB:AB/);
  t.$('cancel-cert').click();
  assert.equal(t.calls.some(c=>c.request?.op==='trust_local_certificate'),false);
  t.$('trust-certificate').click(); t.$('confirm-cert').click();
  await until(()=>t.calls.some(c=>c.request?.op==='trust_local_certificate'));
  await until(()=>t.$('activity').hidden);
  const params=t.calls.find(c=>c.request?.op==='trust_local_certificate').request.params;
  assert.equal(params.expected_sha256,linuxTls.sha256);
  assert.equal(t.$('tls-state').textContent,'今回のブラウザー接続を確認済み');
  assert.doesNotMatch(t.$('tls-state').textContent,/登録済み|信頼済み/);
  assert.match(t.$('notice-text').textContent,/今回のHTTPS接続/);
  // A later status refresh does not turn the observation into persistent trust.
  t.w.document.querySelector('[data-page="settings"]').click();
  await until(()=>t.$('tls-state').textContent.includes('ブラウザー接続は未確認'));
  assert.equal(t.$('enroll').disabled,false);
  t.dom.window.close();
});
test('Linux browser confirmation rejects absent fingerprints and false trust claims',async()=>{
  for (const tls of [{...linuxTls,sha256:undefined}, {...linuxTls,sha256:'invalid'}]) {
    const t=await setup((op)=>op==='status'?success(linuxStatus):op==='tls_status'?success(tls):undefined);
    t.w.document.querySelector('[data-page="settings"]').click();
    await until(()=>t.$('activity').hidden);
    t.$('trust-certificate').click();
    assert.equal(t.$('confirm-cert').disabled,true);
    assert.equal(t.calls.some(c=>c.request?.op==='trust_local_certificate'),false);
    t.dom.window.close();
  }
  for (const result of [{...linuxTls,trusted:true}, {...linuxTls,browser_verified:true,sha256:'cd'.repeat(32)}]) {
    const t=await setup((op)=>op==='status'?success(linuxStatus):op==='tls_status'?success(linuxTls)
      :op==='trust_local_certificate'?success(result):undefined);
    t.w.document.querySelector('[data-page="settings"]').click();
    await until(()=>!t.$('confirm-cert').disabled);
    t.$('trust-certificate').click(); t.$('confirm-cert').click();
    await until(()=>!t.$('notice').hidden);
    assert.equal(t.$('notice').classList.contains('error'),true);
    assert.match(t.$('tls-state').textContent,/ブラウザー接続は未確認/);
    assert.doesNotMatch(t.$('tls-state').textContent,/登録済み/);
    t.dom.window.close();
  }
});
test('Mac local user-presence claims are not shown as independently verified',async()=>{
  const t=await setup((op)=>op==='verify'?success({ok:true,signature_valid:true,user_verified:null,user_present:null,time_confirmed:false,
    authentication_assurance:'local_user_presence_not_attested',profile:'skyseal-local-macos-keychain-v0.1-draft'}):undefined,
    {paths:{evidence:['/tmp/evidence.zip']}});
  t.w.document.querySelector('[data-page="verify"]').click();
  t.$('pick-evidence').click(); await until(()=>!t.$('verify').disabled);
  t.$('verify').click(); await until(()=>!t.$('verification-result').hidden);
  assert.match(t.$('verification-result').textContent,/署名が一致/);
  assert.match(t.$('verification-result').textContent,/Macの本人承認.*証拠単独では確認不可/);
  assert.doesNotMatch(t.$('verification-result').textContent,/本人確認を伴う承認確認済み/);
  t.dom.window.close();
});
test('Linux evidence does not attest passphrase entry even when verified on another platform',async()=>{
  const t=await setup((op)=>op==='verify'?success({ok:true,signature_valid:true,user_verified:null,user_present:null,time_confirmed:false,
    authentication_assurance:'local_user_presence_not_attested',approval_method:'linux-passphrase-p256-v0.1',
    profile:'skyseal-local-linux-passphrase-v0.1-draft'}):undefined,{paths:{evidence:['C:\\evidence.zip']}});
  t.w.document.querySelector('[data-page="verify"]').click();
  t.$('pick-evidence').click(); await until(()=>!t.$('verify').disabled);
  t.$('verify').click(); await until(()=>!t.$('verification-result').hidden);
  assert.match(t.$('verification-result').textContent,/署名が一致/);
  assert.match(t.$('verification-result').textContent,/Linuxのパスフレーズ入力.*証拠単独では確認不可/);
  assert.doesNotMatch(t.$('verification-result').textContent,/Macの本人承認|本人確認を伴う承認確認済み/);
  t.dom.window.close();
});
test('an identity created for another platform cannot enable sealing',async()=>{
  const t=await setup((op)=>op==='status'?success({...status,host_platform:'darwin',configured:true,identity:{identity_id:'https://orcid.org/0000-0003-3001-7690',signing_compatible:false}}):op==='prepare'?success(draft):undefined);
  t.$('pick-files').click(); await until(()=>!t.$('prepare').disabled);
  t.$('prepare').click(); await until(()=>!t.$('review-card').hidden);
  assert.equal(t.$('seal').disabled,true);
  assert.match(t.$('seal-disabled-note').textContent,/別のOS用/);
  assert.equal(t.calls.some(c=>c.request?.op==='seal'),false);
  t.dom.window.close();
});
test('UI prepare and history run against real isolated engine processes',async()=>{
  const temporary=mkdtempSync(path.join(tmpdir(),'skyseal-ui-'));
  try {
    const input=path.join(temporary,'研究データ.txt'); writeFileSync(input,'exact original bytes\n');
    const t=await setup((op,params)=>{
      const result=spawnSync(process.env.SKYSEAL_TEST_PYTHON || 'python',['-m','desktop.engine'],{
        cwd:path.dirname(desktop),env:{...process.env,SKYSEAL_DESKTOP_DATA_DIR:path.join(temporary,'data'),PYTHONUTF8:'1'},
        input:JSON.stringify({op,params}),encoding:'utf8',timeout:15000});
      assert.equal(result.status,0,result.stderr); return JSON.parse(result.stdout);
    },{paths:{files:[input]}});
    t.$('pick-files').click(); await until(()=>!t.$('prepare').disabled);
    t.$('prepare').click(); await until(()=>!t.$('review-card').hidden);
    assert.match(t.$('review-files').textContent,/研究データ.txt/);
    assert.equal(t.$('seal').disabled,true);
    t.w.document.querySelector('[data-page="history"]').click();
    await until(()=>t.$('history-list').children.length===1);
    assert.match(t.$('history-list').textContent,/準備済み/);
    t.dom.window.close();
  } finally { rmSync(temporary,{recursive:true,force:true}); }
});
