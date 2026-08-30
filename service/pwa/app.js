"use strict";

const state = {
  me: null,
  sealId: null,
  bearer: null,
  recoveryCode: null,
  pending: [],
};

const element = (id) => document.getElementById(id);
const show = (id, visible = true) => element(id).classList.toggle("hidden", !visible);
const setResult = (value) => {
  element("result").textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
};

function base64urlToBytes(value) {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function bytesToHex(value) {
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function requestJSON(url, options = {}) {
  const response = await fetch(url, {credentials: "same-origin", ...options});
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.message || `HTTP ${response.status}`);
    error.data = data;
    throw error;
  }
  return data;
}

function csrfHeaders(extra = {}) {
  return {"X-SkySeal-CSRF": state.me.csrf_token, ...extra};
}

async function loadIdentity() {
  state.me = await requestJSON("/api/v1/me");
  show("orcid-login", !state.me.authenticated);
  show("mock-login", !state.me.authenticated && state.me.mock_orcid_available);
  show("logout", state.me.authenticated);
  show("register-passkey", state.me.authenticated && state.me.can_register_initial_passkey);
  if (!state.me.authenticated) {
    element("identity-state").textContent = "ORCID認証が必要です。";
    show("genesis-panel", false);
    show("pending-card", false);
    return;
  }
  element("identity-state").textContent = `${state.me.display_name} — ${state.me.orcid} — ${state.me.identity_status}`;
  if (state.me.identity_status === "pending_activation" || state.me.identity_status === "active") {
    const compact = state.me.orcid.split("/").at(-1);
    element("genesis-download").href = `/api/v1/identity/${compact}/genesis`;
    show("genesis-panel", state.me.identity_status === "pending_activation");
    show("activate-identity", state.me.can_activate_identity);
  } else {
    show("genesis-panel", false);
  }
  await loadPending();
}

function selectPendingSeal(seal) {
  state.sealId = seal.seal_id;
  state.bearer = null;
  element("seal-id").textContent = state.sealId;
  element("confirmation-code").textContent = "承認開始後に表示";
  show("approval-card");
  element("approval-card").scrollIntoView({behavior: "smooth", block: "start"});
}

async function loadPending() {
  const response = await requestJSON("/api/v1/seals/pending");
  state.pending = response.seals;
  const list = element("pending-list");
  list.replaceChildren();
  for (const seal of state.pending) {
    const item = document.createElement("div");
    item.className = "pending-item";
    const description = document.createElement("p");
    const created = new Date(seal.created_at * 1000).toLocaleString();
    description.textContent = `${created}・${seal.entry_count}件のハッシュ`;
    const button = document.createElement("button");
    button.className = "secondary";
    button.textContent = "確認して承認";
    button.addEventListener("click", () => selectPendingSeal(seal));
    item.append(description, button);
    list.append(item);
  }
  show("pending-card", state.pending.length > 0);
}

function parseApprovalFragment() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const seal = fragment.get("seal");
  const token = fragment.get("token");
  if (seal && token) {
    sessionStorage.setItem("skyseal.seal", seal);
    sessionStorage.setItem("skyseal.bearer", token);
    history.replaceState(null, "", "/");
  }
  state.sealId = seal || sessionStorage.getItem("skyseal.seal");
  state.bearer = token || sessionStorage.getItem("skyseal.bearer");
  if (state.sealId && state.bearer) {
    element("seal-id").textContent = state.sealId;
    show("approval-card");
  }
}

async function recoveryCommitment() {
  const recovery = crypto.getRandomValues(new Uint8Array(32));
  const prefix = new TextEncoder().encode("SkySeal Recovery Code v1\0");
  const joined = new Uint8Array(prefix.length + recovery.length);
  joined.set(prefix);
  joined.set(recovery, prefix.length);
  const digest = await crypto.subtle.digest("SHA-256", joined);
  state.recoveryCode = bytesToBase64url(recovery).match(/.{1,8}/g).join("-");
  return `sha256:${bytesToHex(digest)}`;
}

async function registerPasskey() {
  if (!window.PublicKeyCredential) throw new Error("このブラウザはWebAuthnに対応していません。");
  const button = element("register-passkey");
  button.disabled = true;
  try {
    const options = await requestJSON("/api/v1/webauthn/registration/options", {
      method: "POST",
      headers: csrfHeaders(),
    });
    const publicKey = options.publicKey;
    publicKey.challenge = base64urlToBytes(publicKey.challenge);
    publicKey.user.id = base64urlToBytes(publicKey.user.id);
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((item) => ({
      ...item,
      id: base64urlToBytes(item.id),
    }));
    const credential = await navigator.credentials.create({publicKey});
    const commitment = await recoveryCommitment();
    const response = credential.response;
    const transports = typeof response.getTransports === "function" ? response.getTransports() : [];
    const result = await requestJSON("/api/v1/webauthn/registration/complete", {
      method: "POST",
      headers: csrfHeaders({"Content-Type": "application/json"}),
      body: JSON.stringify({
        registration_id: options.registration_id,
        credential: {
          id: bytesToBase64url(credential.rawId),
          raw_id: bytesToBase64url(credential.rawId),
          type: credential.type,
          response: {
            client_data_json: bytesToBase64url(response.clientDataJSON),
            attestation_object: bytesToBase64url(response.attestationObject),
          },
          transports,
          recovery_code_commitment: commitment,
        },
      }),
    });
    element("recovery-code").textContent = state.recoveryCode;
    show("recovery-card");
    setResult(result);
    await loadIdentity();
  } finally {
    button.disabled = false;
  }
}

async function approveSeal() {
  if (!state.me?.authenticated) throw new Error("先にORCIDで認証してください。");
  if (!state.sealId) throw new Error("承認対象が選択されていません。");
  const button = element("approve-seal");
  button.disabled = true;
  let completed = false;
  try {
    const authorization = state.bearer ? {Authorization: `Bearer ${state.bearer}`} : {};
    const options = await requestJSON(`/api/v1/seals/${state.sealId}/webauthn/options`, {
      method: "POST",
      headers: csrfHeaders(authorization),
    });
    element("confirmation-code").textContent = options.confirmation_code;
    if (options.development_unsealed_identity_bypass) {
      element("approval-warning").textContent = "開発用設定：本人登録が未完了のIDで承認しています。公開用途には使用できません。";
      show("approval-warning");
    }
    const publicKey = options.publicKey;
    publicKey.challenge = base64urlToBytes(publicKey.challenge);
    publicKey.allowCredentials = publicKey.allowCredentials.map((item) => ({
      ...item,
      id: base64urlToBytes(item.id),
    }));
    const credential = await navigator.credentials.get({publicKey});
    const response = credential.response;
    const result = await requestJSON(`/api/v1/seals/${state.sealId}/webauthn/assertion`, {
      method: "POST",
      headers: csrfHeaders({...authorization, "Content-Type": "application/json"}),
      body: JSON.stringify({
        raw_id: bytesToBase64url(credential.rawId),
        type: credential.type,
        response: {
          client_data_json: bytesToBase64url(response.clientDataJSON),
          authenticator_data: bytesToBase64url(response.authenticatorData),
          signature: bytesToBase64url(response.signature),
          user_handle: response.userHandle ? bytesToBase64url(response.userHandle) : null,
        },
      }),
    });
    sessionStorage.removeItem("skyseal.seal");
    sessionStorage.removeItem("skyseal.bearer");
    setResult(result);
    completed = true;
    show("approval-card", false);
    await loadPending();
  } finally {
    button.disabled = completed;
  }
}

async function activateIdentity() {
  if (!state.me?.authenticated) throw new Error("先にORCIDで認証してください。");
  if (!window.PublicKeyCredential) throw new Error("このブラウザはWebAuthnに対応していません。");
  const button = element("activate-identity");
  button.disabled = true;
  try {
    const options = await requestJSON("/api/v1/identity/activation/options", {
      method: "POST",
      headers: csrfHeaders(),
    });
    const publicKey = options.publicKey;
    publicKey.challenge = base64urlToBytes(publicKey.challenge);
    publicKey.allowCredentials = publicKey.allowCredentials.map((item) => ({
      ...item,
      id: base64urlToBytes(item.id),
    }));
    const credential = await navigator.credentials.get({publicKey});
    const response = credential.response;
    const result = await requestJSON("/api/v1/identity/activation/assertion", {
      method: "POST",
      headers: csrfHeaders({"Content-Type": "application/json"}),
      body: JSON.stringify({
        raw_id: bytesToBase64url(credential.rawId),
        type: credential.type,
        response: {
          client_data_json: bytesToBase64url(response.clientDataJSON),
          authenticator_data: bytesToBase64url(response.authenticatorData),
          signature: bytesToBase64url(response.signature),
          user_handle: response.userHandle ? bytesToBase64url(response.userHandle) : null,
        },
      }),
    });
    setResult(result);
    await loadIdentity();
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  await requestJSON("/api/v1/logout", {method: "POST", headers: csrfHeaders()});
  state.me = null;
  await loadIdentity();
}

function reportError(error) {
  console.error(error.name || "Error");
  setResult({ok: false, error: error.name || "Error", message: error.message});
}

element("register-passkey").addEventListener("click", () => registerPasskey().catch(reportError));
element("activate-identity").addEventListener("click", () => activateIdentity().catch(reportError));
element("approve-seal").addEventListener("click", () => approveSeal().catch(reportError));
element("logout").addEventListener("click", () => logout().catch(reportError));
element("copy-recovery").addEventListener("click", async () => {
  if (state.recoveryCode) await navigator.clipboard.writeText(state.recoveryCode);
});

parseApprovalFragment();
loadIdentity().catch(reportError);
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
