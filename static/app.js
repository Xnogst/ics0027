"use strict";
// All cryptography happens here. The master password and encryption key never leave the browser.
const ITER = 600000;                                   // must equal KDF_ITER in app.py
const enc = new TextEncoder(), dec = new TextDecoder();
const $ = id => document.getElementById(id);
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
let encKey = null, csrf = null, editId = null, idleTimer = null;
const note = t => { $("msg").textContent = t; };

async function api(method, url, body) {
  const headers = {"Content-Type": "application/json"};
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const r = await fetch(url, {method, headers, credentials: "same-origin",
                              body: body ? JSON.stringify(body) : undefined});
  if (r.status === 401 && url !== "/api/login") lock("Session expired. Log in again.");
  return r;
}

// master password --PBKDF2--> master key --HKDF--> (auth key for server) + (AES key, never sent)
async function derive(password, saltB64, iter) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const master = await crypto.subtle.deriveBits(
    {name: "PBKDF2", hash: "SHA-256", salt: unb64(saltB64), iterations: iter}, base, 256);
  const hk = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
  const p = info => ({name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode(info)});
  const authKey = b64(await crypto.subtle.deriveBits(p("auth"), hk, 256));
  const key = await crypto.subtle.deriveKey(p("vault-enc"), hk, {name: "AES-GCM", length: 256},
                                            false, ["encrypt", "decrypt"]);   // non-extractable
  return {authKey, key};
}

async function seal(item) {
  const iv = crypto.getRandomValues(new Uint8Array(12));            // fresh IV every time
  const ct = await crypto.subtle.encrypt({name: "AES-GCM", iv}, encKey, enc.encode(JSON.stringify(item)));
  return {iv: b64(iv), ciphertext: b64(ct)};
}
async function open(row) {
  const pt = await crypto.subtle.decrypt({name: "AES-GCM", iv: unb64(row.iv)}, encKey, unb64(row.ciphertext));
  return JSON.parse(dec.decode(pt));                                // throws if tampered (GCM tag)
}

function genPw(n = 20) {
  const cs = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
  const lim = Math.floor(2 ** 32 / cs.length) * cs.length;           // rejection sampling, no bias
  let out = "";
  while (out.length < n) { const [x] = crypto.getRandomValues(new Uint32Array(1)); if (x < lim) out += cs[x % cs.length]; }
  return out;
}

function show(loggedIn) { $("auth").hidden = loggedIn; $("vault").hidden = !loggedIn; }
function lock(msg) {
  encKey = null; csrf = null; editId = null; clearTimeout(idleTimer);
  $("list").replaceChildren(); show(false); note(msg || "");
}
function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => { await api("POST", "/api/logout"); lock("Locked after 15 minutes idle."); }, 15 * 60 * 1000);
}
["click", "keydown"].forEach(ev => document.addEventListener(ev, () => { if (encKey) resetIdle(); }));

function render(row, item) {                                        // textContent only: no XSS sink
  const li = document.createElement("li");
  const title = document.createElement("strong"); title.textContent = item.site;
  const meta = document.createElement("div"); meta.textContent = item.user || "";
  const pw = document.createElement("span"); pw.textContent = "••••••••";
  const btn = (label, fn) => { const b = document.createElement("button"); b.textContent = label; b.onclick = fn; return b; };
  li.append(title, meta, pw,
    btn("Show", () => { pw.textContent = pw.textContent === "••••••••" ? item.pw : "••••••••"; }),
    btn("Copy", () => navigator.clipboard.writeText(item.pw)),
    btn("Edit", () => { $("site").value = item.site; $("eu").value = item.user; $("ep").value = item.pw;
                        $("notes").value = item.notes || ""; editId = row.id; }),
    btn("Delete", async () => { await api("DELETE", `/api/credentials/${row.id}`); load(); }));
  return li;
}

async function load() {
  const rows = await (await api("GET", "/api/credentials")).json();
  const ul = $("list"); ul.replaceChildren();
  for (const row of rows) {
    let item;
    try { item = await open(row); } catch { item = {site: "(could not decrypt)", user: "", pw: ""}; }
    ul.appendChild(render(row, item));
  }
}

$("regBtn").onclick = async () => {
  const u = $("user").value.trim(), p = $("pw").value;
  if (p.length < 12) return note("Master password must be 12+ characters. It cannot be recovered if lost.");
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const {authKey} = await derive(p, salt, ITER);
  const r = await api("POST", "/api/register", {username: u, salt, auth_key: authKey});
  note(r.ok ? "Account created. Now log in." : "Registration failed (invalid input or name unavailable).");
};

$("authForm").onsubmit = async e => {
  e.preventDefault();
  const u = $("user").value.trim(), p = $("pw").value;
  const pre = await api("POST", "/api/prelogin", {username: u});
  if (!pre.ok) return note("Invalid credentials or try again later.");
  const {salt, iter} = await pre.json();
  const {authKey, key} = await derive(p, salt, iter);
  const r = await api("POST", "/api/login", {username: u, auth_key: authKey});
  if (!r.ok) return note("Invalid credentials or try again later.");
  csrf = (await r.json()).csrf; encKey = key; $("pw").value = "";
  note(""); show(true); await load(); resetIdle();
};

$("entryForm").onsubmit = async e => {
  e.preventDefault();
  const item = {site: $("site").value, user: $("eu").value, pw: $("ep").value, notes: $("notes").value};
  const blob = await seal(item);
  const r = editId ? await api("PUT", `/api/credentials/${editId}`, blob) : await api("POST", "/api/credentials", blob);
  if (!r.ok) return note("Save failed.");
  editId = null; e.target.reset(); note(""); load();
};
$("genBtn").onclick = () => { $("ep").value = genPw(); };
$("logoutBtn").onclick = async () => { await api("POST", "/api/logout"); lock("Logged out."); };
