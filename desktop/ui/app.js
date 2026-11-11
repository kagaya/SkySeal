'use strict';

// This window has no remote content, arbitrary command execution, or browser-mode mocks.
// Every user-supplied string is rendered with textContent.
const $ = (id) => document.getElementById(id);
const state = {page: 'seal', busy: false, status: null, tls: null, paths: [], prepared: null, jobs: [], evidence: '', candidate: ''};
const labels = {seal: '封緘する', history: '履歴', verify: '証拠を検証', settings: '設定'};
const bridge = window.__TAURI__?.core;
const hasBridge = Boolean(bridge?.invoke);

function el(tag, text = '', className = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}
function button(text, handler, className = 'button secondary') {
  const node = el('button', text, className);
  node.addEventListener('click', handler);
  return node;
}
function dateText(value) {
  if (!value) return '日時なし';
  const date = new Date(typeof value === 'number' ? value * 1000 : value);
  return Number.isNaN(date.valueOf()) ? String(value) : new Intl.DateTimeFormat('ja-JP', {dateStyle: 'medium', timeStyle: 'short'}).format(date);
}
function sizeText(bytes) {
  if (!Number.isFinite(Number(bytes))) return '—';
  let value = Number(bytes), index = 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${value.toLocaleString('ja-JP', {maximumFractionDigits: index ? 1 : 0})} ${units[index]}`;
}
function nameOf(path) { return String(path).split(/[\\/]/).filter(Boolean).at(-1) || path; }
function errorMessage(error) { return error?.message || String(error || '処理を完了できませんでした。'); }
function notify(text, isError = false) {
  $('notice-text').textContent = text;
  $('notice').classList.toggle('error', isError);
  $('notice').hidden = false;
}
function syncControls() {
  document.querySelectorAll('button').forEach((node) => {
    if (node.id === 'dismiss-notice' || node.id === 'cancel-cert' || node.classList.contains('nav-button') || node.hasAttribute('data-open-settings') || node.hasAttribute('data-open-seal')) return;
    node.disabled = state.busy || !hasBridge;
  });
  $('verify').disabled = state.busy || !hasBridge || !state.evidence;
  $('prepare').disabled = state.busy || !hasBridge || !state.paths.length;
  $('enroll').disabled = state.busy || !hasBridge || !state.status?.configured || Boolean(state.status?.identity) || !nativeAvailable();
  $('client-id').disabled = state.busy || Boolean(state.status?.identity);
  $('verify-client-id').disabled = state.busy;
  $('save-settings').disabled = state.busy || !hasBridge || Boolean(state.status?.identity);
  $('seal').disabled = state.busy || !hasBridge || !state.status?.identity || state.status.identity.signing_compatible === false || !state.prepared || !canApprove(state.prepared);
  $('seal').textContent = state.prepared?.state === 'sealing' ? '本人承認をやり直す →' : '本人承認して封緘する →';
  $('trust-certificate').disabled = state.busy || !hasBridge || ['windows_required', 'unsupported_platform'].includes(state.status?.platform?.code);
  $('confirm-cert').disabled = state.busy || !hasBridge || (hostPlatform() === 'linux' && !/^[0-9a-f]{64}$/.test(state.tls?.sha256 || ''));
  $('seal-disabled-note').textContent = !state.status?.identity ? '封緘するには、設定画面でORCIDと署名鍵の本人登録を完了してください。'
    : state.status.identity.signing_compatible === false ? 'この本人登録の署名鍵は別のOS用です。この端末からは封緘できません。証拠の検証は利用できます。' : '';
}
function nativeAvailable() {
  const platform = state.status?.platform || {};
  return Boolean(platform.available ?? platform.supported ?? platform.webauthn_available);
}
function hostPlatform() { return state.status?.host_platform || ''; }
function systemName() { return hostPlatform() === 'darwin' ? 'macOS' : hostPlatform() === 'win32' ? 'Windows' : hostPlatform() === 'linux' ? 'Linux' : 'OS'; }
function renderPlatformLabels() {
  const mac = hostPlatform() === 'darwin', windows = hostPlatform() === 'win32', linux = hostPlatform() === 'linux';
  $('trust-certificate').textContent = mac ? '証明書をキーチェーンに登録' : windows ? '証明書をWindowsに登録' : linux ? 'ブラウザーでHTTPSを確認' : '証明書を登録';
  $('approval-description').textContent = mac
    ? 'この保存コピーを対象に、ひまわり画像を取得し、キーチェーンの認証画面で署名を承認します。'
    : windows ? 'この保存コピーを対象に、ひまわり画像を取得し、Windows Helloまたはセキュリティキーで本人承認します。'
      : linux ? 'この保存コピーを対象に、ひまわり画像を取得し、Pinentryの別ウィンドウでSkySeal専用のパスフレーズを入力して署名します。'
      : 'この保存コピーを対象に、ひまわり画像を取得し、このコンピューターの確認画面で本人承認します。';
  $('identity-description').textContent = mac
    ? 'Macのキーチェーンに署名鍵を作り、標準ブラウザでORCIDにサインインします。署名するときはキーチェーンの認証画面で承認します。'
    : windows ? 'Windows HelloまたはFIDO2セキュリティキーを登録し、標準ブラウザでORCIDにサインインします。'
      : linux ? 'SkySeal専用のパスフレーズで暗号化した署名鍵を作り、標準ブラウザーでORCIDにサインインします。パスフレーズはPinentryの別ウィンドウへ入力します。'
      : 'このコンピューターで署名鍵を登録し、標準ブラウザでORCIDにサインインします。';
  $('key-storage-note').textContent = mac
    ? 'キーチェーンのパスワードで承認します。Macのログインパスワードと異なる場合があります。鍵は証拠ZIPに含めません。証拠単独では認証操作の実施を確認できません。'
    : linux ? 'Linuxのログインパスワードとは別の、SkySeal専用のパスフレーズです。署名ごとに入力し、忘れるとその鍵を使えません。秘密鍵は証拠ZIPに含めません。証拠単独では入力操作の実施を確認できません。'
    : '署名鍵はOSまたは認証器が管理します。証拠ファイルのバックアップだけでは、鍵は復元できません。';
  $('certificate-trust-description').textContent = mac
    ? 'このMac専用の証明書を、現在のユーザーのキーチェーンと信頼設定に登録します。適用範囲はlocalhostのSSL通信です。続いてmacOSの認証画面が表示されます。'
    : windows ? 'SkySealが作成したlocalhost用証明書を、Windowsの現在のユーザーの信頼済み証明書ストアに登録します。ORCID認証からこのPCに戻る際に使用します。'
      : linux ? '標準ブラウザーで https://localhost:24731 に接続します。証明書の画面に出るSHA-256が下記と一致することを確かめ、この証明書と接続先だけを許可してください。OS全体の信頼設定は変更しません。'
      : 'SkySealが作成したlocalhost用証明書を、現在のユーザーの信頼設定に登録します。ORCID認証からこのPCに戻る際に使用します。';
  $('certificate-dialog-title').textContent = linux ? 'このPCへのHTTPS接続を確認' : 'このPC専用の証明書を登録';
  $('certificate-trust-note').textContent = linux
    ? 'この結果は今回の接続確認です。ブラウザー・プロファイル・証明書が変わった場合は再確認してください。許可できない設定の場合は、確認を中止できます。'
    : '他のPCと共有する証明書・秘密鍵は使用しません。登録先と識別子は設定画面で確認できます。';
  $('confirm-cert').textContent = linux ? 'ブラウザーを開く' : '登録する';
  $('certificate-dialog-fingerprint').hidden = !linux;
}
async function call(op, params = {}) {
  if (!hasBridge) throw new Error('SkySealデスクトップアプリから開いてください。ブラウザ表示ではPC内の処理を実行できません。');
  const response = await bridge.invoke('backend', {request: {op, params}});
  if (!response || response.ok !== true) throw new Error(response?.error?.message || 'SkySealエンジンから正常な応答がありませんでした。');
  return response.result;
}
async function task(message, work) {
  if (state.busy) return;
  state.busy = true;
  $('activity-text').textContent = message;
  $('activity').hidden = false;
  $('notice').hidden = true;
  syncControls();
  try { return await work(); }
  catch (error) { notify(errorMessage(error), true); }
  finally { state.busy = false; $('activity').hidden = true; syncControls(); }
}
async function pick(kind, suggestedName) {
  if (!hasBridge) throw new Error('ファイル選択はデスクトップアプリで利用できます。');
  return bridge.invoke('choose_path', {kind, suggestedName: suggestedName || null});
}
function showPage(page) {
  state.page = page;
  document.querySelectorAll('.page').forEach((node) => { node.hidden = node.id !== `page-${page}`; });
  document.querySelectorAll('.nav-button').forEach((node) => {
    const active = node.dataset.page === page;
    node.classList.toggle('active', active);
    if (active) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current');
  });
  $('page-label').textContent = labels[page];
  if (page === 'history' && !state.busy && hasBridge) task('履歴を読み込んでいます…', loadHistory);
  if (page === 'settings' && !state.busy && hasBridge) task('設定を確認しています…', async () => { await loadStatus(); await loadTls(); });
}
function renderStatus(status) {
  state.status = status;
  renderPlatformLabels();
  $('client-id').value = status.orcid_client_id || '';
  $('data-dir').textContent = status.data_dir || '保存先を確認できません';
  $('registered-orcid').textContent = status.identity?.identity_id || '未登録';
  $('setup-callout').hidden = Boolean(status.identity);
  $('identity-dot').classList.toggle('ready', Boolean(status.identity));
  const mini = $('identity-mini');
  mini.replaceChildren(document.createTextNode(status.identity ? (status.identity.display_name || '本人登録済み') : '本人登録が必要です'));
  mini.append(el('span', status.identity ? status.identity.identity_id?.replace('https://orcid.org/', '') || 'ローカルの署名鍵を使用' : 'ORCIDと署名鍵を設定'));
  const available = nativeAvailable();
  $('native-state').textContent = available
    ? (hostPlatform() === 'darwin' ? 'macOSキーチェーンの署名を利用できます' : hostPlatform() === 'win32' ? 'Windows WebAuthnを利用できます' : hostPlatform() === 'linux' ? '暗号化したLinux署名鍵とPinentryを利用できます' : 'このコンピューターの署名機能を利用できます')
    : (status.platform?.reason || status.platform?.message || 'デスクトップアプリの実行環境で確認してください');
  $('enroll').textContent = status.identity ? '本人登録済み' : '本人登録を始める ↗';
  syncControls();
}
async function loadStatus() { renderStatus(await call('status')); }
function renderTls(tls) {
  state.tls = tls;
  $('callback-url').textContent = tls.callback_uri || 'https://localhost:24731/callback';
  const digest = tls.sha256 || tls.certificate_sha256;
  const sha256 = /^[0-9a-f]{64}$/i.test(digest || '') ? digest.toUpperCase().match(/.{2}/g).join(':') : null;
  $('tls-fingerprint-label').textContent = sha256 ? '証明書 SHA-256' : '証明書の識別子';
  $('tls-thumbprint').textContent = sha256 || tls.thumbprint || '未生成';
  $('certificate-dialog-fingerprint').textContent = sha256 ? `SHA-256: ${sha256}` : 'SHA-256を読み込めません。設定画面を開き直してください。';
  $('tls-state').textContent = hostPlatform() === 'linux'
    ? tls.browser_verified === true ? '今回のブラウザー接続を確認済み' : '証明書を準備済み（ブラウザー接続は未確認）'
    : tls.trusted === true ? `${systemName()}に登録済み` : tls.exists || tls.certificate_path ? 'PC専用の証明書を準備済み' : '未生成';
  $('tls-scope').textContent = tls.trust_scope || '現在のユーザー';
}
async function loadTls() { renderTls(await call('tls_status')); }
function renderSelection() {
  $('selection').hidden = !state.paths.length;
  $('drop-zone').hidden = Boolean(state.paths.length);
  $('selection-count').textContent = `${state.paths.length} 件を選択`;
  $('selected-paths').replaceChildren();
  state.paths.forEach((path) => {
    const item = el('li');
    item.append(el('span', path));
    const remove = button('×', () => { state.paths = state.paths.filter((p) => p !== path); renderSelection(); }, '');
    remove.setAttribute('aria-label', `${nameOf(path)}を選択から外す`);
    item.append(remove);
    $('selected-paths').append(item);
  });
  syncControls();
}
function addPaths(paths) { state.paths = [...new Set([...state.paths, ...paths])]; renderSelection(); }
function pill(job) {
  let text = '準備済み', cls = 'prepared';
  if (job.time_confirmed || job.ots_state === 'confirmed') { text = '時刻証明確認済み'; cls = 'confirmed'; }
  else if (job.state === 'sealed' || job.state === 'signed' || job.state === 'timestamp_pending' || job.ots_state === 'pending' || job.ots_state === 'pending_or_unverified') { text = '署名済み・時刻証明待ち'; cls = 'pending'; }
  else if (job.state === 'failed' || job.state === 'error') { text = '処理を確認'; cls = 'error'; }
  else if (['signing', 'preparing', 'sealing', 'interrupted'].includes(job.state)) { text = '処理が中断しています'; cls = 'pending'; }
  return el('span', text, `status-pill ${cls}`);
}
function renderPrepared(job) {
  state.prepared = job;
  $('selection-card').hidden = true;
  $('review-card').hidden = false;
  $('seal-result').hidden = true;
  $('review-summary').replaceChildren(pill(job), el('span', `${job.items?.length || 0} ファイル · ${job.entry_count || 0} 個の異なるハッシュ`));
  $('review-files').replaceChildren();
  for (const item of job.items || []) {
    const row = el('tr');
    const hash = el('td', `${String(item.sha256).slice(0, 10)}…${String(item.sha256).slice(-6)}`, 'hash');
    hash.title = item.sha256 || '';
    row.append(el('td', item.name || 'ファイル'), el('td', sizeText(item.size)), hash);
    $('review-files').append(row);
  }
  syncControls();
}
function newSeal() {
  state.paths = []; state.prepared = null;
  $('selection-card').hidden = false;
  $('review-card').hidden = true;
  $('seal-result').hidden = true;
  renderSelection();
}
function addMeta(container, entries) {
  const list = el('dl', '', 'meta');
  for (const [key, value] of entries) { list.append(el('dt', key), el('dd', String(value ?? '—'))); }
  container.append(list);
}
function resultHeading(container, title, subtitle, kind = 'confirmed') {
  const head = el('div', '', 'result-heading');
  head.append(el('span', kind === 'error' ? '!' : '✓', `result-icon ${kind}`));
  const copy = el('div'); copy.append(el('h2', title), el('p', subtitle));
  head.append(copy); container.append(head);
}
async function exportJob(job) {
  await task('証拠を書き出しています…', async () => {
    const paths = await pick('export', `skyseal-${job.job_id}.zip`);
    if (!paths.length) return;
    const result = await call('export', {job_id: job.job_id, destination: paths[0]});
    notify(`証拠を書き出しました：${result.path}`);
  });
}
function sealed(job) { return ['sealed', 'signed', 'timestamp_pending', 'confirmed'].includes(job.state) || !['not_requested', undefined, null].includes(job.ots_state); }
function canApprove(job) { return job.state === 'prepared' || (job.state === 'sealing' && job.recovery_available === true); }
function renderJob(container, job, isResult = false) {
  container.replaceChildren(); container.hidden = false;
  const confirmed = job.time_confirmed || job.ots_state === 'confirmed';
  resultHeading(container, isResult ? '封緘の証拠を保存しました' : '記録の詳細', confirmed ? '時刻証明確認済み（公開ブロック情報で照合）' : sealed(job) ? '時刻証明は確認待ちです。アプリの再起動後も確認を続けられます。' : canApprove(job) ? '保存コピーを再確認し、本人承認すると封緘できます。' : '保存処理が完了していません。新しい保存コピーを作成してください。', confirmed ? 'confirmed' : 'pending');
  addMeta(container, [['記録ID', job.job_id], ['保存日時', dateText(job.created_at)], ['ORCID', job.identity_id || '承認前'], ['異なるハッシュ', job.entry_count], ['状態', pill(job).textContent]]);
  if (job.error) container.append(el('p', job.error?.message || String(job.error), 'verification-warning'));
  const actions = el('div', '', 'button-row right');
  if (canApprove(job)) actions.append(button(job.state === 'sealing' ? '本人承認をやり直す →' : 'この内容を承認する →', () => { showPage('seal'); renderPrepared(job); }));
  else if (!sealed(job)) actions.append(button('新しい保存コピーを作る', () => { newSeal(); showPage('seal'); }));
  if (sealed(job)) {
    actions.append(button('時刻証明を確認', () => task('時刻証明を確認しています…', async () => { const updated = await call('resume', {job_id: job.job_id}); renderJob(container, updated, isResult); await loadHistory(); })));
    actions.append(button('証拠を書き出す ↗', () => exportJob(job), 'button primary'));
  }
  container.append(actions); syncControls();
}
async function loadHistory() {
  const result = await call('list');
  state.jobs = result.jobs || [];
  $('history-count').textContent = `${state.jobs.length} 件の記録`;
  $('history-empty').hidden = Boolean(state.jobs.length);
  $('history-list').replaceChildren();
  for (const job of state.jobs) {
    const row = el('article', '', 'history-row');
    const copy = el('div');
    const itemName = job.items?.[0]?.name;
    const total = job.items?.length || job.entry_count || 0;
    copy.append(el('div', itemName ? `${nameOf(itemName)}${total > 1 ? ` ほか ${total - 1} 件` : ''}` : `${job.entry_count || 0} 個のハッシュ`, 'history-title'));
    copy.append(el('div', `${dateText(job.created_at)} · ${String(job.job_id).slice(0, 13)}`, 'history-subtitle'));
    row.append(el('span', '◇', 'history-file-icon'), copy, pill(job), button('詳細 →', () => task('記録を読み込んでいます…', async () => { const detail = await call('get', {job_id: job.job_id}); renderJob($('job-detail'), detail); $('job-detail').scrollIntoView({behavior: 'smooth', block: 'nearest'}); })));
    $('history-list').append(row);
  }
}
function setEvidence(path) { state.evidence = path || ''; $('evidence-path').textContent = state.evidence || '未選択'; $('evidence-path').classList.toggle('selected', Boolean(path)); $('verification-result').hidden = true; syncControls(); }
function setCandidate(path) { state.candidate = path || ''; $('candidate-path').textContent = state.candidate || '証拠だけを検証します'; $('candidate-path').classList.toggle('selected', Boolean(path)); $('clear-candidate').hidden = !path; $('verification-result').hidden = true; }
function checkRow(container, label, text, cls = '') { const row = el('div', '', 'check-row'); row.append(el('span', label), el('strong', text, cls)); container.append(row); }
function renderVerification(result) {
  const container = $('verification-result'); container.replaceChildren(); container.hidden = false;
  const valid = result.ok === true;
  resultHeading(container, valid ? '証拠の整合性を確認しました' : '検証を完了できませんでした', result.time_confirmed ? '時刻証明確認済み（公開ブロック情報で照合）' : '時刻証明の確認状況を、署名の検証結果と分けて表示しています。', valid ? 'confirmed' : 'error');
  const checks = el('div', '', 'check-list');
  checkRow(checks, '内容と証拠の整合性', valid ? '確認済み' : '未確認', valid ? '' : 'error');
  checkRow(checks, '承認署名', result.signature_valid ? '署名が一致' : '未確認', result.signature_valid ? '' : 'pending');
  if (result.authentication_assurance === 'local_user_presence_not_attested') {
    const linux = result.approval_method === 'linux-passphrase-p256-v0.1' || result.profile === 'skyseal-local-linux-passphrase-v0.1-draft';
    checkRow(checks, linux ? 'Linuxのパスフレーズ入力' : 'Macの本人承認', '署名時に要求・証拠単独では確認不可', 'pending');
  } else {
    checkRow(checks, '本人確認を伴う承認', result.user_verified ? '確認済み' : '未確認', result.user_verified ? '' : 'pending');
  }
  checkRow(checks, '独立した時刻証明', result.time_confirmed ? '公開ブロック情報で照合済み' : '未確定・未確認', result.time_confirmed ? '' : 'pending');
  if (result.candidate_match !== null && result.candidate_match !== undefined) checkRow(checks, '選択ファイルのハッシュ', result.candidate_match ? '封緘した集合に含まれます' : '含まれていません', result.candidate_match ? '' : 'error');
  container.append(checks);
  addMeta(container, [['ORCID', result.identity_id], ['封緘ID', result.seal_id], ['証拠形式', result.profile]]);
  for (const warning of result.warnings || []) container.append(el('p', warning, 'verification-warning'));
  const details = el('details'); details.append(el('summary', '検証結果の詳細', 'text-button'));
  details.append(el('pre', JSON.stringify(result, null, 2), 'verification-details'));
  container.append(details);
}

for (const node of document.querySelectorAll('[data-page]')) node.addEventListener('click', () => showPage(node.dataset.page));
for (const node of document.querySelectorAll('[data-open-settings]')) node.addEventListener('click', () => showPage('settings'));
for (const node of document.querySelectorAll('[data-open-seal]')) node.addEventListener('click', () => showPage('seal'));
$('dismiss-notice').addEventListener('click', () => { $('notice').hidden = true; });
$('pick-files').addEventListener('click', (event) => { event.stopPropagation(); task('ファイルを選択してください…', async () => addPaths(await pick('files'))); });
$('pick-folder').addEventListener('click', (event) => { event.stopPropagation(); task('フォルダーを選択してください…', async () => addPaths(await pick('folder'))); });
$('drop-zone').addEventListener('click', () => $('pick-files').click());
$('drop-zone').addEventListener('keydown', (event) => { if (event.target === $('drop-zone') && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); $('pick-files').click(); } });
$('clear-selection').addEventListener('click', () => { state.paths = []; renderSelection(); });
$('prepare').addEventListener('click', () => task('対象をPC内に保存し、ハッシュを計算しています…', async () => renderPrepared(await call('prepare', {paths: state.paths}))));
$('new-seal').addEventListener('click', newSeal);
$('seal').addEventListener('click', () => task(hostPlatform() === 'linux' ? 'ひまわり画像を取得し、署名を待っています。PinentryにSkySeal専用のパスフレーズを入力してください…' : `ひまわり画像を取得し、本人承認を待っています。${systemName()}の確認画面で操作してください…`, async () => {
  const job = await call('seal', {job_id: state.prepared.job_id});
  state.prepared = job; $('review-card').hidden = true; renderJob($('seal-result'), job, true);
}));
$('refresh-history').addEventListener('click', () => task('履歴を読み込んでいます…', loadHistory));
$('resume-all').addEventListener('click', () => task('未完了の時刻証明を確認しています…', async () => { await call('resume'); await loadHistory(); notify('時刻証明の確認処理を終了しました。各記録の状態をご確認ください。'); }));
$('pick-evidence').addEventListener('click', () => task('証拠を選択してください…', async () => { const paths = await pick('evidence'); if (paths.length) setEvidence(paths[0]); }));
$('pick-evidence-folder').addEventListener('click', () => task('証拠フォルダーを選択してください…', async () => { const paths = await pick('evidence_folder'); if (paths.length) setEvidence(paths[0]); }));
$('pick-candidate').addEventListener('click', () => task('比較するファイルを選択してください…', async () => { const paths = await pick('candidate'); if (paths.length) setCandidate(paths[0]); }));
$('clear-candidate').addEventListener('click', () => setCandidate(''));
$('verify').addEventListener('click', () => task('署名と証拠を検証しています…', async () => {
  $('verification-result').hidden = true;
  try { renderVerification(await call('verify', {path: state.evidence, trusted_rp_id: 'proof.excyberlab.net', trusted_origin: 'https://proof.excyberlab.net', ...($('verify-client-id').value.trim() ? {trusted_client_id: $('verify-client-id').value.trim()} : {}), ...(state.candidate ? {candidate: state.candidate} : {})})); }
  catch (error) { const box = $('verification-result'); box.replaceChildren(); box.hidden = false; resultHeading(box, '証拠を確認できませんでした', errorMessage(error), 'error'); throw error; }
}));
$('save-settings').addEventListener('click', () => task('設定を保存しています…', async () => { renderStatus(await call('configure', {orcid_client_id: $('client-id').value.trim()})); notify('設定を保存しました。'); }));
$('trust-certificate').addEventListener('click', () => $('certificate-dialog').showModal());
$('cancel-cert').addEventListener('click', () => $('certificate-dialog').close());
$('confirm-cert').addEventListener('click', () => { $('certificate-dialog').close(); task(hostPlatform() === 'linux' ? '標準ブラウザーでlocalhostの証明書を確認してください。今回のHTTPS接続が確認できるまで待っています…' : `このPC専用の証明書を${systemName()}に登録しています。OSの認証画面が出た場合は内容を確認してください…`, async () => {
  const linux = hostPlatform() === 'linux';
  const fingerprint = state.tls?.sha256;
  if (linux && !/^[0-9a-f]{64}$/.test(fingerprint || '')) throw new Error('証明書のSHA-256を読み込めません。設定画面を開き直してください。');
  const tls = await call('trust_local_certificate', linux ? {expected_sha256: fingerprint} : {});
  if (linux ? tls.browser_verified !== true || tls.sha256 !== fingerprint : tls.trusted !== true) throw new Error('証明書の接続確認・信頼登録を確認できませんでした。');
  renderTls(tls); notify(linux ? 'このブラウザーからの今回のHTTPS接続を確認しました。ブラウザーを変更した場合は、もう一度確認してください。' : 'このPC専用の認証用証明書を登録しました。');
}); });
$('enroll').addEventListener('click', () => task(hostPlatform() === 'linux' ? 'PinentryでSkySeal専用のパスフレーズを設定し、標準ブラウザーでORCIDにサインインしてください…' : `${systemName()}の確認画面と標準ブラウザで本人登録を進めてください。認証の完了を待っています…`, async () => { renderStatus(await call('identity_enroll')); notify('ORCIDと署名鍵の本人登録が完了しました。'); }));

async function initialize() {
  if (!hasBridge) {
    $('connection-banner').textContent = '画面プレビューです。封緘・本人登録・ファイル操作には、SkySealデスクトップアプリを起動してください。';
    $('connection-banner').hidden = false;
    renderStatus({configured: false, platform: {reason: 'デスクトップアプリで確認してください'}, data_dir: 'デスクトップアプリで確認できます'});
    syncControls(); return;
  }
  // Tauri's native drag event supplies local paths; browser File objects do not.
  const events = window.__TAURI__?.event;
  if (events?.listen) {
    await events.listen('tauri://drag-enter', () => $('drop-zone').classList.add('dragging'));
    await events.listen('tauri://drag-leave', () => $('drop-zone').classList.remove('dragging'));
    await events.listen('tauri://drag-drop', (event) => {
      $('drop-zone').classList.remove('dragging');
      if (state.busy || state.page !== 'seal' || state.prepared) return;
      addPaths(event.payload.paths || []);
    });
  }
  await task('ローカルの状態を確認しています…', loadStatus);
}
initialize().catch((error) => { notify(errorMessage(error), true); syncControls(); });
