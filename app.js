import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js";
import {
  getAuth,
  onAuthStateChanged,
  signInAnonymously,
  signOut
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js";
import {
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  getFirestore,
  limit,
  onSnapshot,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  where,
  writeBatch
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyBYSoz9F_pAgznjUjWmPIPqL_jdCk1CFVY",
  authDomain: "rede-b5f80.firebaseapp.com",
  projectId: "rede-b5f80",
  storageBucket: "rede-b5f80.firebasestorage.app",
  messagingSenderId: "855256737101",
  appId: "1:855256737101:web:c5295b8fdf2970f40a8304"
};

const DAY_MS = 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 250000;

let app = null;
let auth = null;
let db = null;

const state = {
  currentUser: null,
  privateKey: null,
  activePartner: null,
  unsubscribeMessages: null,
  unsubscribeConversations: null,
  privacyTimer: null,
  conversationKeys: new Map()
};

const gateScreen = document.getElementById("gateScreen");
const chatScreen = document.getElementById("chatScreen");
const registerForm = document.getElementById("registerForm");
const unlockForm = document.getElementById("unlockForm");
const gateMessage = document.getElementById("gateMessage");
const unlockName = document.getElementById("unlockName");
const currentUserName = document.getElementById("currentUserName");
const userSearch = document.getElementById("userSearch");
const searchResults = document.getElementById("searchResults");
const conversationList = document.getElementById("conversationList");
const activeChatName = document.getElementById("activeChatName");
const emptyState = document.getElementById("emptyState");
const messagesSection = document.getElementById("messagesSection");
const messageList = document.getElementById("messageList");
const privacyOverlay = document.getElementById("privacyOverlay");
const backToHomeButton = document.getElementById("backToHomeButton");

function showMessage(message, isError = false) {
  gateMessage.textContent = message;
  gateMessage.style.color = isError ? "#ff8a8a" : "#cfcfcf";
}

function explainFirebaseError(error, fallbackMessage) {
  const errorCode = error?.code || "";

  if (errorCode === "auth/operation-not-allowed") {
    return "Ative Authentication > Sign-in method > Anonymous no Firebase.";
  }

  if (errorCode === "auth/api-key-not-valid.-please-pass-a-valid-api-key.") {
    return "A apiKey do Firebase esta invalida ou incompleta.";
  }

  if (errorCode === "auth/network-request-failed") {
    return "Falha de rede ao falar com o Firebase.";
  }

  if (errorCode === "permission-denied" || errorCode === "firestore/permission-denied") {
    return "As regras do Firestore ainda nao permitem esta operacao.";
  }

  if (errorCode) {
    return `${fallbackMessage} (${errorCode})`;
  }

  return fallbackMessage;
}

function isFirebaseConfigured() {
  return Boolean(firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.appId);
}

function ensureFirebase() {
  if (!isFirebaseConfigured()) return false;
  if (!app) {
    app = initializeApp(firebaseConfig);
    auth = getAuth(app);
    db = getFirestore(app);
  }
  return true;
}

function directoryRef(userId) {
  return doc(db, "directory", userId);
}

function secretRef(userId) {
  return doc(db, "users", userId, "private", "secret");
}

function contactRef(ownerId, partnerId) {
  return doc(db, "users", ownerId, "contacts", partnerId);
}

function messagesCollection(ownerId, partnerId) {
  return collection(db, "users", ownerId, "contacts", partnerId, "messages");
}

function makeConversationId(a, b) {
  return [a, b].sort().join("__");
}

function makeAvatarMarkup(name) {
  const initial = escapeHtml((name || "?").trim().charAt(0).toUpperCase() || "?");
  return `<div class="avatar-badge" aria-hidden="true">${initial}</div>`;
}

async function hashPassword(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToBase64(hash);
}

function bytesToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function derivePasswordKey(password, saltBase64) {
  const passwordMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(saltBase64),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    passwordMaterial,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function generateUserKeys() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey: bytesToBase64(publicKey),
    privateKey: bytesToBase64(privateKey)
  };
}

async function protectPrivateKey(privateKeyBase64, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePasswordKey(password, bytesToBase64(salt));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(privateKeyBase64)
  );

  return {
    encryptedPrivateKey: bytesToBase64(encrypted),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv)
  };
}

async function restorePrivateKey(secretData, password) {
  const key = await derivePasswordKey(password, secretData.salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(secretData.iv) },
    key,
    base64ToBytes(secretData.encryptedPrivateKey)
  );

  return crypto.subtle.importKey(
    "pkcs8",
    base64ToBytes(new TextDecoder().decode(decrypted)),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}

async function importPublicKey(publicKeyBase64) {
  return crypto.subtle.importKey(
    "spki",
    base64ToBytes(publicKeyBase64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

async function createConversationKey() {
  return crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportConversationKey(key) {
  return bytesToBase64(await crypto.subtle.exportKey("raw", key));
}

async function importConversationKey(rawBase64) {
  return crypto.subtle.importKey(
    "raw",
    base64ToBytes(rawBase64),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptConversationKeyForUser(key, publicKeyBase64) {
  const rawKey = base64ToBytes(await exportConversationKey(key));
  const publicKey = await importPublicKey(publicKeyBase64);
  const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKey);
  return bytesToBase64(encrypted);
}

async function decryptConversationKey(encryptedKeyBase64) {
  if (!state.privateKey) {
    throw new Error("Private key not unlocked.");
  }

  const decrypted = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    state.privateKey,
    base64ToBytes(encryptedKeyBase64)
  );

  return importConversationKey(bytesToBase64(decrypted));
}

async function encryptMessageText(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text)
  );

  return {
    ciphertext: bytesToBase64(encrypted),
    iv: bytesToBase64(iv)
  };
}

async function decryptMessageText(ciphertextBase64, ivBase64, key) {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(ivBase64) },
    key,
    base64ToBytes(ciphertextBase64)
  );

  return new TextDecoder().decode(decrypted);
}

async function loadKnownUser() {
  if (!ensureFirebase()) {
    registerForm.classList.remove("hidden");
    unlockForm.classList.add("hidden");
    return;
  }

  const userId = auth.currentUser?.uid;
  if (!userId) return;

  try {
    const [profileSnap, secretSnap] = await Promise.all([
      getDoc(directoryRef(userId)),
      getDoc(secretRef(userId))
    ]);

    if (!profileSnap.exists() || !secretSnap.exists()) {
      registerForm.classList.remove("hidden");
      unlockForm.classList.add("hidden");
      showMessage("Crie seu perfil para ativar o cofre criptografado.");
      return;
    }

    unlockName.textContent = `Ola, ${profileSnap.data().displayName}`;
    registerForm.classList.add("hidden");
    unlockForm.classList.remove("hidden");
    showMessage("Seu perfil foi encontrado neste aparelho.");
  } catch (error) {
    showMessage("Nao consegui carregar o perfil salvo neste aparelho.", true);
  }
}

async function registerUser(event) {
  event.preventDefault();
  if (!ensureFirebase()) {
    showMessage("Preencha o firebaseConfig em app.js antes de usar.", true);
    return;
  }

  const displayName = document.getElementById("registerName").value.trim();
  const password = document.getElementById("registerPassword").value.trim();
  if (!displayName || !password) {
    showMessage("Preencha nome e senha.", true);
    return;
  }

  try {
    const userId = auth.currentUser.uid;
    const passwordHash = await hashPassword(password);
    const keyMaterial = await generateUserKeys();
    const protectedPrivateKey = await protectPrivateKey(keyMaterial.privateKey, password);
    const privateKey = await restorePrivateKey(
      { ...protectedPrivateKey, encryptedPrivateKey: protectedPrivateKey.encryptedPrivateKey },
      password
    );

    await setDoc(directoryRef(userId), {
      displayName,
      lowerDisplayName: displayName.toLowerCase(),
      publicKey: keyMaterial.publicKey,
      createdAt: serverTimestamp(),
      lastSeenAt: serverTimestamp()
    });

    await setDoc(secretRef(userId), {
      encryptedPrivateKey: protectedPrivateKey.encryptedPrivateKey,
      salt: protectedPrivateKey.salt,
      iv: protectedPrivateKey.iv,
      passwordHash,
      updatedAt: serverTimestamp()
    });

    state.currentUser = {
      id: userId,
      displayName,
      lowerDisplayName: displayName.toLowerCase(),
      publicKey: keyMaterial.publicKey
    };
    state.privateKey = privateKey;
    openApp();
  } catch (error) {
    showMessage("Nao consegui criar seu acesso criptografado agora.", true);
  }
}

async function unlockUser(event) {
  event.preventDefault();
  if (!ensureFirebase()) {
    showMessage("Preencha o firebaseConfig em app.js antes de usar.", true);
    return;
  }

  const userId = auth.currentUser?.uid;
  const password = document.getElementById("unlockPassword").value.trim();
  if (!userId || !password) {
    showMessage("Digite sua senha.", true);
    return;
  }

  try {
    const [profileSnap, secretSnap] = await Promise.all([
      getDoc(directoryRef(userId)),
      getDoc(secretRef(userId))
    ]);

    if (!profileSnap.exists() || !secretSnap.exists()) {
      showMessage("Perfil nao encontrado neste aparelho.", true);
      return;
    }

    const passwordHash = await hashPassword(password);
    if (passwordHash !== secretSnap.data().passwordHash) {
      showMessage("Senha incorreta.", true);
      return;
    }

    const privateKey = await restorePrivateKey(secretSnap.data(), password);
    await setDoc(directoryRef(userId), { lastSeenAt: serverTimestamp() }, { merge: true });

    state.currentUser = { id: userId, ...profileSnap.data() };
    state.privateKey = privateKey;
    openApp();
  } catch (error) {
    showMessage("Nao consegui validar sua senha.", true);
  }
}

async function resetDevice() {
  if (!ensureFirebase()) {
    registerForm.classList.remove("hidden");
    unlockForm.classList.add("hidden");
    showMessage("Preencha o Firebase antes de continuar.", true);
    return;
  }

  state.currentUser = null;
  state.privateKey = null;
  state.activePartner = null;
  state.conversationKeys.clear();
  unlockForm.reset();
  registerForm.reset();
  registerForm.classList.remove("hidden");
  unlockForm.classList.add("hidden");
  if (state.unsubscribeMessages) state.unsubscribeMessages();
  if (state.unsubscribeConversations) state.unsubscribeConversations();
  await signOut(auth);
  await signInAnonymously(auth);
  showMessage("Este aparelho foi desvinculado.");
}

function openApp() {
  gateScreen.classList.add("hidden");
  chatScreen.classList.remove("hidden");
  currentUserName.textContent = state.currentUser.displayName;
  showHome();
  userSearch.value = "";
  userSearch.focus();
  wireConversationStream();
  cleanupExpiredMessages();
}

function showHome() {
  state.activePartner = null;
  emptyState.classList.remove("hidden");
  messagesSection.classList.add("hidden");
  activeChatName.textContent = "Selecione alguem";
}

function lockApp() {
  if (state.unsubscribeMessages) state.unsubscribeMessages();
  if (state.unsubscribeConversations) state.unsubscribeConversations();
  state.unsubscribeMessages = null;
  state.unsubscribeConversations = null;
  state.activePartner = null;
  state.privateKey = null;
  state.conversationKeys.clear();
  gateScreen.classList.remove("hidden");
  chatScreen.classList.add("hidden");
  messageList.innerHTML = "";
  conversationList.innerHTML = "";
  searchResults.innerHTML = "";
  emptyState.classList.remove("hidden");
  messagesSection.classList.add("hidden");
  unlockForm.classList.remove("hidden");
  registerForm.classList.add("hidden");
  document.getElementById("unlockPassword").value = "";
  unlockName.textContent = `Ola, ${state.currentUser.displayName}`;
}

async function searchUsers(term) {
  if (!ensureFirebase()) return;
  if (!term.trim()) {
    searchResults.innerHTML = "";
    return;
  }

  const lower = term.trim().toLowerCase();
  const q = query(
    collection(db, "directory"),
    where("lowerDisplayName", ">=", lower),
    where("lowerDisplayName", "<=", `${lower}\uf8ff`),
    limit(12)
  );

  const snapshot = await getDocs(q);
  const users = snapshot.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .filter((item) => item.id !== state.currentUser.id);

  searchResults.innerHTML = users.length
    ? users.map((user) => `
      <button class="search-result" data-open-user="${user.id}" type="button">
        <div class="badge-main">
          ${makeAvatarMarkup(user.displayName)}
          <div class="person-meta">
            <span class="person-name">${escapeHtml(user.displayName)}</span>
            <span class="person-hint">Abrir conversa privada</span>
          </div>
        </div>
        <span class="muted-tag">Cript.</span>
      </button>
    `).join("")
    : `<div class="search-result"><div class="badge-main">${makeAvatarMarkup("Ninguem")}<div class="person-meta"><span class="person-name">Ninguem encontrado</span><span class="person-hint">Tente outro nome</span></div></div></div>`;
}

function wireConversationStream() {
  if (!ensureFirebase()) return;
  if (state.unsubscribeConversations) state.unsubscribeConversations();

  const q = query(
    collection(db, "users", state.currentUser.id, "contacts"),
    orderBy("updatedAt", "desc")
  );

  state.unsubscribeConversations = onSnapshot(q, async (snapshot) => {
    const conversations = snapshot.docs.map((item) => ({ id: item.id, ...item.data() }));
    const userIds = [...new Set(conversations.map((conversation) => conversation.partnerId))];
    const userMap = {};

    await Promise.all(userIds.map(async (id) => {
      const snap = await getDoc(directoryRef(id));
      if (snap.exists()) userMap[id] = snap.data();
    }));

    renderConversationList(conversations, userMap);
  });
}

function renderConversationList(conversations, userMap) {
  conversationList.innerHTML = conversations.length
    ? conversations.map((conversation) => {
      const partner = userMap[conversation.partnerId];
      const activeClass = conversation.partnerId === state.activePartner?.id ? "active" : "";
      return `
        <button class="conversation-badge ${activeClass}" data-open-user="${conversation.partnerId}" type="button">
          <div class="badge-main">
            ${makeAvatarMarkup(partner?.displayName || "Pessoa")}
            <div class="person-meta">
              <span class="person-name">${escapeHtml(partner?.displayName || "Pessoa")}</span>
              <span class="conversation-preview">${escapeHtml(conversation.lastMessageLabel || "Mensagem criptografada")}</span>
            </div>
          </div>
          <span class="muted-tag">24h</span>
        </button>
      `;
    }).join("")
    : `<div class="conversation-badge"><div class="badge-main">${makeAvatarMarkup("Noite")}<div class="person-meta"><span class="person-name">Sem conversas ainda</span><span class="conversation-preview">Use a pesquisa para comecar</span></div></div></div>`;
}

async function getConversationKey(partnerId) {
  if (state.conversationKeys.has(partnerId)) {
    return state.conversationKeys.get(partnerId);
  }

  const contactSnap = await getDoc(contactRef(state.currentUser.id, partnerId));
  if (!contactSnap.exists()) return null;

  const encryptedConversationKey = contactSnap.data().encryptedConversationKey;
  if (!encryptedConversationKey) return null;

  const key = await decryptConversationKey(encryptedConversationKey);
  state.conversationKeys.set(partnerId, key);
  return key;
}

async function ensureConversationForPartner(partner) {
  const existingKey = await getConversationKey(partner.id);
  if (existingKey) return existingKey;

  const partnerSnap = await getDoc(directoryRef(partner.id));
  if (!partnerSnap.exists()) {
    throw new Error("Partner profile not found.");
  }

  const conversationKey = await createConversationKey();
  const [ownEncryptedKey, partnerEncryptedKey] = await Promise.all([
    encryptConversationKeyForUser(conversationKey, state.currentUser.publicKey),
    encryptConversationKeyForUser(conversationKey, partnerSnap.data().publicKey)
  ]);

  const nowFields = {
    conversationId: makeConversationId(state.currentUser.id, partner.id),
    participantIds: [state.currentUser.id, partner.id],
    lastMessageLabel: "Cofre criptografado ativo",
    updatedAt: serverTimestamp()
  };

  const batch = writeBatch(db);
  batch.set(contactRef(state.currentUser.id, partner.id), {
    ...nowFields,
    ownerId: state.currentUser.id,
    partnerId: partner.id,
    encryptedConversationKey: ownEncryptedKey
  }, { merge: true });
  batch.set(contactRef(partner.id, state.currentUser.id), {
    ...nowFields,
    ownerId: partner.id,
    partnerId: state.currentUser.id,
    encryptedConversationKey: partnerEncryptedKey
  }, { merge: true });
  await batch.commit();

  state.conversationKeys.set(partner.id, conversationKey);
  return conversationKey;
}

async function openConversationWithUser(userId) {
  if (!ensureFirebase()) return;
  const userSnap = await getDoc(directoryRef(userId));
  if (!userSnap.exists()) return;

  const partner = { id: userId, ...userSnap.data() };
  state.activePartner = partner;
  activeChatName.textContent = partner.displayName;
  emptyState.classList.add("hidden");
  messagesSection.classList.remove("hidden");
  searchResults.innerHTML = "";

  try {
    await getConversationKey(partner.id);
  } catch (error) {
    showMessage("Nao consegui abrir a chave criptografada desta conversa.", true);
  }

  wireMessages(partner.id);
}

function wireMessages(partnerId) {
  if (!ensureFirebase()) return;
  if (state.unsubscribeMessages) state.unsubscribeMessages();

  const q = query(messagesCollection(state.currentUser.id, partnerId), orderBy("createdAt", "asc"));

  state.unsubscribeMessages = onSnapshot(q, async (snapshot) => {
    const now = Date.now();
    const key = await getConversationKey(partnerId).catch(() => null);
    const messages = [];

    for (const item of snapshot.docs) {
      const data = item.data();
      const expiresAtMs = data.expiresAt?.toMillis?.() || 0;
      if (expiresAtMs && expiresAtMs <= now) {
        await deleteDoc(item.ref);
        continue;
      }

      let text = "Mensagem criptografada indisponivel.";
      if (key && data.ciphertext && data.iv) {
        try {
          text = await decryptMessageText(data.ciphertext, data.iv, key);
        } catch (error) {
          text = "Nao foi possivel descriptografar.";
        }
      }

      messages.push({ id: item.id, ...data, text });
    }

    renderMessages(messages);
  });
}

function renderMessages(messages) {
  messageList.innerHTML = messages.length
    ? messages.map((message) => {
      const own = message.senderId === state.currentUser.id;
      const createdAt = message.createdAt?.toDate?.() || new Date();
      const expiresAt = message.expiresAt?.toDate?.() || new Date(Date.now() + DAY_MS);
      const author = own ? state.currentUser.displayName : state.activePartner?.displayName || "Pessoa";
      return `
        <article class="message-item ${own ? "own" : ""}">
          <div class="message-meta">
            <span class="message-author">${escapeHtml(author)}</span>
            <span class="message-time">${formatHour(createdAt)} - some ${formatRelativeExpiry(expiresAt)}</span>
          </div>
          <div class="message-text">${escapeHtml(message.text)}</div>
        </article>
      `;
    }).join("")
    : `<div class="empty-state"><div><p class="empty-title">Sem mensagens por enquanto</p><p class="empty-copy">Tudo o que for enviado aqui vira texto cifrado e desaparece em 24 horas.</p></div></div>`;

  messageList.scrollTop = messageList.scrollHeight;
}

async function sendMessage(event) {
  event.preventDefault();
  if (!ensureFirebase()) {
    showMessage("Preencha o Firebase antes de enviar mensagens.", true);
    return;
  }

  const input = document.getElementById("messageInput");
  const text = input.value.trim();
  if (!text || !state.activePartner) return;

  try {
    const conversationKey = await ensureConversationForPartner(state.activePartner);
    const encryptedMessage = await encryptMessageText(text, conversationKey);
    const expiresAt = new Date(Date.now() + DAY_MS);
    const conversationId = makeConversationId(state.currentUser.id, state.activePartner.id);
    const batch = writeBatch(db);
    const ownContact = contactRef(state.currentUser.id, state.activePartner.id);
    const partnerContact = contactRef(state.activePartner.id, state.currentUser.id);

    batch.set(ownContact, {
      ownerId: state.currentUser.id,
      partnerId: state.activePartner.id,
      participantIds: [state.currentUser.id, state.activePartner.id],
      conversationId,
      lastMessageLabel: "Mensagem criptografada",
      updatedAt: serverTimestamp()
    }, { merge: true });

    batch.set(partnerContact, {
      ownerId: state.activePartner.id,
      partnerId: state.currentUser.id,
      participantIds: [state.currentUser.id, state.activePartner.id],
      conversationId,
      lastMessageLabel: "Nova mensagem criptografada",
      updatedAt: serverTimestamp()
    }, { merge: true });

    await batch.commit();

    const payload = {
      senderId: state.currentUser.id,
      recipientId: state.activePartner.id,
      conversationId,
      ciphertext: encryptedMessage.ciphertext,
      iv: encryptedMessage.iv,
      createdAt: serverTimestamp(),
      expiresAt
    };

    await Promise.all([
      addDoc(messagesCollection(state.currentUser.id, state.activePartner.id), payload),
      addDoc(messagesCollection(state.activePartner.id, state.currentUser.id), payload)
    ]);

    input.value = "";
  } catch (error) {
    showMessage("Nao consegui enviar a mensagem criptografada.", true);
  }
}

async function cleanupExpiredMessages() {
  if (!ensureFirebase() || !state.currentUser) return;
  const q = query(collection(db, "users", state.currentUser.id, "contacts"), limit(30));
  const snapshot = await getDocs(q);
  const now = Date.now();

  await Promise.all(snapshot.docs.map(async (contact) => {
    const messagesSnapshot = await getDocs(messagesCollection(state.currentUser.id, contact.id));
    await Promise.all(messagesSnapshot.docs.map(async (message) => {
      const expiresAtMs = message.data().expiresAt?.toMillis?.() || 0;
      if (expiresAtMs && expiresAtMs <= now) {
        await deleteDoc(message.ref);
      }
    }));
  }));
}

function formatHour(date) {
  return new Intl.DateTimeFormat("pt-BR", {
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function formatRelativeExpiry(date) {
  const diff = Math.max(0, date.getTime() - Date.now());
  const hours = Math.ceil(diff / (1000 * 60 * 60));
  return `em ${hours}h`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function showPrivacyOverlay(temporary = true) {
  privacyOverlay.classList.remove("hidden");
  if (state.privacyTimer) clearTimeout(state.privacyTimer);
  if (temporary) {
    state.privacyTimer = window.setTimeout(() => {
      privacyOverlay.classList.add("hidden");
    }, 2200);
  }
}

function hidePrivacyOverlay() {
  privacyOverlay.classList.add("hidden");
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    showPrivacyOverlay(false);
  } else {
    hidePrivacyOverlay();
  }
});

window.addEventListener("beforeprint", () => showPrivacyOverlay(false));
window.addEventListener("afterprint", hidePrivacyOverlay);

document.addEventListener("keydown", (event) => {
  if (event.key === "PrintScreen") {
    showPrivacyOverlay();
  }
  if (event.key === "Escape") {
    hidePrivacyOverlay();
  }
});

privacyOverlay.addEventListener("click", hidePrivacyOverlay);

document.addEventListener("click", async (event) => {
  const openButton = event.target.closest("[data-open-user]");
  if (!openButton) return;
  await openConversationWithUser(openButton.dataset.openUser);
});

registerForm.addEventListener("submit", registerUser);
unlockForm.addEventListener("submit", unlockUser);
document.getElementById("resetDeviceButton").addEventListener("click", () => {
  resetDevice().catch(() => showMessage("Nao consegui trocar o aparelho agora.", true));
});
document.getElementById("lockButton").addEventListener("click", lockApp);
document.getElementById("messageForm").addEventListener("submit", sendMessage);
backToHomeButton.addEventListener("click", showHome);
userSearch.addEventListener("input", (event) => searchUsers(event.target.value));

async function bootstrap() {
  if (!ensureFirebase()) {
    showMessage("Preencha o firebaseConfig em app.js para conectar o app ao Firebase.");
    registerForm.classList.remove("hidden");
    return;
  }

  await signInAnonymously(auth);
  onAuthStateChanged(auth, async () => {
    await loadKnownUser();
  });
}

if (!isFirebaseConfigured()) {
  showMessage("Preencha o firebaseConfig em app.js para conectar o app ao Firebase.");
  registerForm.classList.remove("hidden");
} else {
  bootstrap().catch((error) => {
    console.error("Firebase bootstrap error:", error);
    showMessage(explainFirebaseError(error, "Nao consegui iniciar o Firebase agora."), true);
    registerForm.classList.remove("hidden");
  });
}

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}
