import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js";
import {
  createUserWithEmailAndPassword,
  deleteUser,
  getAuth,
  inMemoryPersistence,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  setPersistence,
  signOut
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js";
import {
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
  runTransaction,
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
const USER_CODE_LENGTH = 5;
const MAX_USER_CODE_ATTEMPTS = 20;

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
  conversationKeys: new Map(),
  pendingMessages: new Map(),
  currentMessages: [],
  longPressTimer: null,
  activeMessageActionId: null
};

const gateScreen = document.getElementById("gateScreen");
const chatScreen = document.getElementById("chatScreen");
const authForm = document.getElementById("authForm");
const gateMessage = document.getElementById("gateMessage");
const deviceHint = document.getElementById("deviceHint");
const authName = document.getElementById("authName");
const authPassword = document.getElementById("authPassword");
const currentUserName = document.getElementById("currentUserName");
const currentUserCode = document.getElementById("currentUserCode");
const userSearch = document.getElementById("userSearch");
const searchResults = document.getElementById("searchResults");
const conversationList = document.getElementById("conversationList");
const activeChatName = document.getElementById("activeChatName");
const activeChatAvatar = document.getElementById("activeChatAvatar");
const emptyState = document.getElementById("emptyState");
const messagesSection = document.getElementById("messagesSection");
const messageList = document.getElementById("messageList");
const privacyOverlay = document.getElementById("privacyOverlay");
const messageForm = document.getElementById("messageForm");
const messageInput = document.getElementById("messageInput");

function showMessage(message, isError = false) {
  gateMessage.textContent = message;
  gateMessage.style.color = isError ? "#ff8a8a" : "#cfcfcf";
}

function explainFirebaseError(error, fallbackMessage) {
  const errorCode = error?.code || "";

  if (errorCode === "auth/operation-not-allowed") {
    return "Ative Authentication > Sign-in method > Email/Password no Firebase.";
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

  if (errorCode === "auth/invalid-credential" || errorCode === "auth/wrong-password") {
    return "Nome ou senha incorretos.";
  }

  if (errorCode === "auth/email-already-in-use") {
    return "Esse nome ja esta em uso. Escolha outro.";
  }

  if (errorCode === "auth/user-not-found") {
    return "Essa conta ainda nao existe.";
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

function usernameRef(lowerDisplayName) {
  return doc(db, "usernames", lowerDisplayName);
}

function userCodeRef(userCode) {
  return doc(db, "userCodes", userCode);
}

function contactRef(ownerId, partnerId) {
  return doc(db, "users", ownerId, "contacts", partnerId);
}

function messagesCollection(ownerId, partnerId) {
  return collection(db, "users", ownerId, "contacts", partnerId, "messages");
}

function messageRef(ownerId, partnerId, messageId) {
  return doc(db, "users", ownerId, "contacts", partnerId, "messages", messageId);
}

function makeConversationId(a, b) {
  return [a, b].sort().join("__");
}

function makeMessageId() {
  return `msg-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function makeAuthEmail(lowerDisplayName) {
  const normalized = lowerDisplayName
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, ".");

  const safeName = normalized.replace(/^\.+|\.+$/g, "") || "usuario";
  return `${safeName}.${bytesToHex(new TextEncoder().encode(lowerDisplayName)).slice(0, 12)}@redeprivada.app`;
}

function generateUserCode() {
  const min = 10 ** (USER_CODE_LENGTH - 1);
  const max = (10 ** USER_CODE_LENGTH) - 1;
  return String(Math.floor(Math.random() * (max - min + 1)) + min);
}

async function ensureUserCode(userId, profileData) {
  if (profileData?.userCode) {
    return profileData.userCode;
  }

  const displayName = profileData?.displayName || "";
  const lowerDisplayName = profileData?.lowerDisplayName || displayName.toLowerCase();

  for (let attempt = 0; attempt < MAX_USER_CODE_ATTEMPTS; attempt += 1) {
    const userCode = generateUserCode();

    try {
      await runTransaction(db, async (transaction) => {
        const [profileSnap, reservedUserCode] = await Promise.all([
          transaction.get(directoryRef(userId)),
          transaction.get(userCodeRef(userCode))
        ]);

        if (!profileSnap.exists()) {
          throw new Error("PROFILE_NOT_FOUND");
        }

        const currentProfile = profileSnap.data();
        if (currentProfile.userCode) {
          throw new Error(`USER_CODE_READY:${currentProfile.userCode}`);
        }

        if (reservedUserCode.exists()) {
          throw new Error("USER_CODE_ALREADY_EXISTS");
        }

        transaction.set(directoryRef(userId), {
          userCode
        }, { merge: true });

        transaction.set(userCodeRef(userCode), {
          userId,
          displayName: currentProfile.displayName || displayName,
          lowerDisplayName: currentProfile.lowerDisplayName || lowerDisplayName,
          userCode,
          createdAt: serverTimestamp()
        });
      });

      return userCode;
    } catch (error) {
      if (error?.message === "USER_CODE_ALREADY_EXISTS") {
        continue;
      }

      if (error?.message?.startsWith("USER_CODE_READY:")) {
        return error.message.split(":")[1];
      }

      throw error;
    }
  }

  throw new Error("USER_CODE_GENERATION_FAILED");
}

function makeAvatarMarkup(name) {
  const initial = escapeHtml((name || "?").trim().charAt(0).toUpperCase() || "?");
  return `<div class="avatar-badge" aria-hidden="true">${initial}</div>`;
}

function getAvatarInitial(name) {
  return (name || "?").trim().charAt(0).toUpperCase() || "?";
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

function bytesToHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
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
    return;
  }

  authForm.reset();
  deviceHint.textContent = "";
  showMessage("Digite nome e senha para entrar ou criar sua conta.");
}

async function createUser(userId, displayName, password) {
  const lowerDisplayName = displayName.toLowerCase();
  const passwordHash = await hashPassword(password);
  const keyMaterial = await generateUserKeys();
  const protectedPrivateKey = await protectPrivateKey(keyMaterial.privateKey, password);
  const privateKey = await restorePrivateKey(
    { ...protectedPrivateKey, encryptedPrivateKey: protectedPrivateKey.encryptedPrivateKey },
    password
  );
  let userCode = "";

  for (let attempt = 0; attempt < MAX_USER_CODE_ATTEMPTS; attempt += 1) {
    userCode = generateUserCode();

    try {
      await runTransaction(db, async (transaction) => {
        const [reservedUsername, reservedUserCode] = await Promise.all([
          transaction.get(usernameRef(lowerDisplayName)),
          transaction.get(userCodeRef(userCode))
        ]);

        if (reservedUsername.exists()) {
          throw new Error("USERNAME_ALREADY_EXISTS");
        }

        if (reservedUserCode.exists()) {
          throw new Error("USER_CODE_ALREADY_EXISTS");
        }

        transaction.set(directoryRef(userId), {
          displayName,
          lowerDisplayName,
          userCode,
          publicKey: keyMaterial.publicKey,
          createdAt: serverTimestamp(),
          lastSeenAt: serverTimestamp()
        });

        transaction.set(secretRef(userId), {
          encryptedPrivateKey: protectedPrivateKey.encryptedPrivateKey,
          salt: protectedPrivateKey.salt,
          iv: protectedPrivateKey.iv,
          passwordHash,
          updatedAt: serverTimestamp()
        });

        transaction.set(usernameRef(lowerDisplayName), {
          userId,
          displayName,
          lowerDisplayName,
          createdAt: serverTimestamp()
        });

        transaction.set(userCodeRef(userCode), {
          userId,
          displayName,
          lowerDisplayName,
          userCode,
          createdAt: serverTimestamp()
        });
      });

      break;
    } catch (error) {
      if (error?.message === "USER_CODE_ALREADY_EXISTS") {
        continue;
      }

      throw error;
    }
  }

  if (!userCode) {
    throw new Error("USER_CODE_GENERATION_FAILED");
  }

  state.currentUser = {
    id: userId,
    displayName,
    lowerDisplayName,
    userCode,
    publicKey: keyMaterial.publicKey
  };
  state.privateKey = privateKey;
}

async function unlockExistingUser(userId, profileSnap, secretSnap, displayName, password) {
  const profileData = profileSnap.data();

  const passwordHash = await hashPassword(password);
  if (passwordHash !== secretSnap.data().passwordHash) {
    throw new Error("INVALID_PASSWORD");
  }

  const privateKey = await restorePrivateKey(secretSnap.data(), password);
  await setDoc(directoryRef(userId), { lastSeenAt: serverTimestamp() }, { merge: true });

  const userCode = await ensureUserCode(userId, profileData);
  state.currentUser = { id: userId, ...profileData, userCode };
  state.privateKey = privateKey;
}

async function handleAuth(event) {
  event.preventDefault();
  if (!ensureFirebase()) {
    showMessage("Preencha o firebaseConfig em app.js antes de usar.", true);
    return;
  }

  const displayName = authName.value.trim();
  const password = authPassword.value.trim();
  if (!displayName || !password) {
    showMessage("Preencha nome e senha.", true);
    return;
  }

  try {
    const lowerDisplayName = displayName.toLowerCase();
    const authEmail = makeAuthEmail(lowerDisplayName);
    const reservedUsernameSnap = await getDoc(usernameRef(lowerDisplayName));
    let authUser = null;

    if (reservedUsernameSnap.exists()) {
      try {
        const signInCredential = await signInWithEmailAndPassword(auth, authEmail, password);
        authUser = signInCredential.user;
      } catch (error) {
        if (error?.code === "auth/wrong-password" || error?.code === "auth/invalid-credential") {
          throw new Error("INVALID_PASSWORD");
        }

        throw error;
      }
    } else {
      try {
        const createCredential = await createUserWithEmailAndPassword(auth, authEmail, password);
        authUser = createCredential.user;
        await createUser(authUser.uid, displayName, password);
      } catch (createError) {
        if (createError?.code === "auth/email-already-in-use") {
          throw new Error("USERNAME_ALREADY_EXISTS");
        }

        if (auth.currentUser) {
          await deleteUser(auth.currentUser).catch(() => {});
        }

        throw createError;
      }
    }

    if (!authUser) {
      if (reservedUsernameSnap.exists()) {
        throw new Error("INVALID_PASSWORD");
      }

      throw new Error("PROFILE_NOT_FOUND");
    }

    if (!state.currentUser) {
      const userId = authUser?.uid;
      const [profileSnap, secretSnap] = await Promise.all([
        getDoc(directoryRef(userId)),
        getDoc(secretRef(userId))
      ]);

      if (!profileSnap.exists() || !secretSnap.exists()) {
        throw new Error("PROFILE_NOT_FOUND");
      }

      await unlockExistingUser(userId, profileSnap, secretSnap, displayName, password);
    }

    authPassword.value = "";
    deviceHint.textContent = state.currentUser.userCode ? `Seu ID: ${state.currentUser.userCode}` : "";
    openApp();
  } catch (error) {
    if (error?.message === "USERNAME_ALREADY_EXISTS") {
      showMessage("Esse nome ja esta em uso. Escolha outro.", true);
      return;
    }

    if (error?.message === "USER_CODE_GENERATION_FAILED") {
      showMessage("Nao consegui gerar um ID unico agora. Tente novamente.", true);
      return;
    }

    if (error?.message === "INVALID_PASSWORD") {
      showMessage("Senha incorreta.", true);
      return;
    }

    if (error?.message === "PROFILE_NOT_FOUND") {
      showMessage("Nao consegui encontrar essa conta agora.", true);
      return;
    }

    console.error("Auth error:", error);
    showMessage(explainFirebaseError(error, "Nao consegui entrar agora."), true);
  }
}

function openApp() {
  gateScreen.classList.add("hidden");
  chatScreen.classList.remove("hidden");
  currentUserName.textContent = state.currentUser.displayName;
  currentUserCode.textContent = state.currentUser.userCode ? `ID ${state.currentUser.userCode}` : "Carregando ID...";
  window.history.replaceState({ screen: "home" }, "");
  showHome();
  userSearch.value = "";
  userSearch.focus();
  wireConversationStream();
  cleanupExpiredMessages();
  syncCurrentUserCode().catch(() => {
    currentUserCode.textContent = state.currentUser.userCode ? `ID ${state.currentUser.userCode}` : "";
  });
}

async function syncCurrentUserCode() {
  if (!state.currentUser?.id) return;

  const userCode = await ensureUserCode(state.currentUser.id, state.currentUser);
  state.currentUser.userCode = userCode;
  currentUserCode.textContent = userCode ? `ID ${userCode}` : "";
}

function showHome() {
  state.activePartner = null;
  state.currentMessages = [];
  state.activeMessageActionId = null;
  emptyState.classList.remove("hidden");
  messagesSection.classList.add("hidden");
  activeChatName.textContent = "Selecione alguem";
  activeChatAvatar.textContent = "?";
}

function lockApp() {
  if (state.unsubscribeMessages) state.unsubscribeMessages();
  if (state.unsubscribeConversations) state.unsubscribeConversations();
  state.unsubscribeMessages = null;
  state.unsubscribeConversations = null;
  state.activePartner = null;
  state.privateKey = null;
  state.conversationKeys.clear();
  state.currentMessages = [];
  state.activeMessageActionId = null;
  gateScreen.classList.remove("hidden");
  chatScreen.classList.add("hidden");
  messageList.innerHTML = "";
  conversationList.innerHTML = "";
  searchResults.innerHTML = "";
  emptyState.classList.remove("hidden");
  messagesSection.classList.add("hidden");
  authName.value = "";
  authPassword.value = "";
  deviceHint.textContent = "";
  showMessage("Digite nome e senha para entrar ou criar sua conta.");
  signOut(auth).catch(() => {});
}

async function searchUsers(term) {
  if (!ensureFirebase()) return;
  const normalizedTerm = term.replace(/\D/g, "").slice(0, USER_CODE_LENGTH);
  userSearch.value = normalizedTerm;

  if (!normalizedTerm) {
    searchResults.innerHTML = "";
    return;
  }

  if (normalizedTerm.length < USER_CODE_LENGTH) {
    searchResults.innerHTML = `<div class="search-result"><div class="badge-main">${makeAvatarMarkup("#")}<div class="person-meta"><span class="person-name">Digite os 5 numeros do ID</span><span class="person-hint">A busca funciona so pelo ID completo</span></div></div></div>`;
    return;
  }

  const userCodeSnap = await getDoc(userCodeRef(normalizedTerm));
  if (!userCodeSnap.exists()) {
    searchResults.innerHTML = `<div class="search-result"><div class="badge-main">${makeAvatarMarkup("N")}<div class="person-meta"><span class="person-name">ID nao encontrado</span><span class="person-hint">Confira os 5 numeros e tente novamente</span></div></div></div>`;
    return;
  }

  const user = userCodeSnap.data();
  if (user.userId === state.currentUser.id) {
    searchResults.innerHTML = `<div class="search-result"><div class="badge-main">${makeAvatarMarkup("Y")}<div class="person-meta"><span class="person-name">Esse ID e o seu</span><span class="person-hint">Use o ID de outra pessoa para abrir conversa</span></div></div></div>`;
    return;
  }

  searchResults.innerHTML = `
      <button class="search-result" data-open-user="${user.userId}" type="button">
        <div class="badge-main">
          ${makeAvatarMarkup(user.displayName)}
          <div class="person-meta">
            <span class="person-name">${escapeHtml(user.displayName)}</span>
            <span class="person-hint">ID ${escapeHtml(user.userCode || normalizedTerm)}</span>
          </div>
        </div>
        <span class="muted-tag">Cript.</span>
      </button>
    `;
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
  state.currentMessages = [];
  state.activeMessageActionId = null;
  activeChatName.textContent = partner.displayName;
  activeChatAvatar.textContent = getAvatarInitial(partner.displayName);
  emptyState.classList.add("hidden");
  messagesSection.classList.remove("hidden");
  searchResults.innerHTML = "";
  const historyState = window.history.state;
  if (!historyState || historyState.screen !== "chat" || historyState.partnerId !== partner.id) {
    window.history.pushState({ screen: "chat", partnerId: partner.id }, "");
  }

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

    state.currentMessages = messages;
    renderMessages(messages);
  });
}

function renderMessages(messages) {
  const pendingMessages = state.activePartner
    ? state.pendingMessages.get(state.activePartner.id) || []
    : [];
  const allMessages = [...messages, ...pendingMessages]
    .sort((first, second) => {
      const firstTime = first.createdAt?.toDate?.()?.getTime?.() || first.createdAt?.getTime?.() || 0;
      const secondTime = second.createdAt?.toDate?.()?.getTime?.() || second.createdAt?.getTime?.() || 0;
      return firstTime - secondTime;
    });

  messageList.innerHTML = allMessages.length
    ? allMessages.map((message) => {
      const own = message.senderId === state.currentUser.id;
      const createdAt = message.createdAt?.toDate?.() || new Date();
      const expiresAt = message.expiresAt?.toDate?.() || new Date(Date.now() + DAY_MS);
      const author = own ? state.currentUser.displayName : state.activePartner?.displayName || "Pessoa";
      const canEdit = own && !String(message.id).startsWith("pending-");
      const editedNote = message.wasEdited ? "dei uma ajeitadinha, prometo que ficou melhor" : "";
      const showActions = state.activeMessageActionId === message.id ? "show-actions" : "";
      return `
        <article class="message-item ${own ? "own" : ""} ${showActions}" data-message-id="${escapeHtml(message.id)}">
          <div class="message-meta">
            <span class="message-author">${escapeHtml(author)}</span>
            <span class="message-time">${formatHour(createdAt)} - some ${formatRelativeExpiry(expiresAt)}</span>
          </div>
          ${canEdit ? `<button type="button" class="message-menu-button" aria-label="Editar mensagem" data-edit-message="${escapeHtml(message.id)}">...</button>` : ""}
          <div class="message-text">${escapeHtml(message.text)}</div>
          ${editedNote ? `<div class="message-edited-note">${escapeHtml(editedNote)}</div>` : ""}
        </article>
      `;
    }).join("")
    : `<div class="empty-state"><div><p class="empty-title">Sem mensagens por enquanto</p><p class="empty-copy">Tudo o que for enviado aqui vira texto cifrado e desaparece em 24 horas.</p></div></div>`;

  messageList.scrollTop = messageList.scrollHeight;
}

function addPendingMessage(partnerId, text) {
  const pendingMessage = {
    id: `pending-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    senderId: state.currentUser.id,
    recipientId: partnerId,
    text,
    wasEdited: false,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + DAY_MS)
  };
  const existingMessages = state.pendingMessages.get(partnerId) || [];
  state.pendingMessages.set(partnerId, [...existingMessages, pendingMessage]);
  return pendingMessage.id;
}

function removePendingMessage(partnerId, pendingId) {
  const existingMessages = state.pendingMessages.get(partnerId) || [];
  const nextMessages = existingMessages.filter((message) => message.id !== pendingId);

  if (nextMessages.length) {
    state.pendingMessages.set(partnerId, nextMessages);
    return;
  }

  state.pendingMessages.delete(partnerId);
}

function findMessageById(messageId) {
  return state.currentMessages.find((message) => message.id === messageId) || null;
}

function setActiveMessageAction(messageId = null) {
  state.activeMessageActionId = messageId;
  renderMessages(state.currentMessages);
}

function clearLongPressTimer() {
  if (!state.longPressTimer) return;
  clearTimeout(state.longPressTimer);
  state.longPressTimer = null;
}

async function openEditMessagePrompt(messageId) {
  const message = findMessageById(messageId);
  if (!message || message.senderId !== state.currentUser.id || !state.activePartner) return;

  const nextText = window.prompt("Editar mensagem", message.text);
  state.activeMessageActionId = null;
  if (nextText === null) return;

  const trimmedText = nextText.trim();
  if (!trimmedText || trimmedText === message.text) return;

  try {
    const conversationKey = await getConversationKey(state.activePartner.id);
    if (!conversationKey) {
      showMessage("Nao consegui abrir a chave desta conversa para editar.", true);
      return;
    }

    const encryptedMessage = await encryptMessageText(trimmedText, conversationKey);
    const updatePayload = {
      ciphertext: encryptedMessage.ciphertext,
      iv: encryptedMessage.iv,
      wasEdited: true,
      editedAt: serverTimestamp()
    };

    await Promise.all([
      setDoc(messageRef(state.currentUser.id, state.activePartner.id, messageId), updatePayload, { merge: true }),
      setDoc(messageRef(state.activePartner.id, state.currentUser.id, messageId), updatePayload, { merge: true })
    ]);
  } catch (error) {
    showMessage("Nao consegui retocar essa mensagem agora.", true);
  }
}

async function sendMessage(event) {
  event.preventDefault();
  if (!ensureFirebase()) {
    showMessage("Preencha o Firebase antes de enviar mensagens.", true);
    return;
  }

  const text = messageInput.value.trim();
  const partner = state.activePartner;
  if (!text || !partner) return;

  messageInput.value = "";
  const pendingId = addPendingMessage(partner.id, text);
  renderMessages(state.currentMessages);

  try {
    const conversationKey = await ensureConversationForPartner(partner);
    const encryptedMessage = await encryptMessageText(text, conversationKey);
    const expiresAt = new Date(Date.now() + DAY_MS);
    const conversationId = makeConversationId(state.currentUser.id, partner.id);
    const messageId = makeMessageId();
    const batch = writeBatch(db);
    const ownContact = contactRef(state.currentUser.id, partner.id);
    const partnerContact = contactRef(partner.id, state.currentUser.id);

    batch.set(ownContact, {
      ownerId: state.currentUser.id,
      partnerId: partner.id,
      participantIds: [state.currentUser.id, partner.id],
      conversationId,
      lastMessageLabel: "Mensagem criptografada",
      updatedAt: serverTimestamp()
    }, { merge: true });

    batch.set(partnerContact, {
      ownerId: partner.id,
      partnerId: state.currentUser.id,
      participantIds: [state.currentUser.id, partner.id],
      conversationId,
      lastMessageLabel: "Nova mensagem criptografada",
      updatedAt: serverTimestamp()
    }, { merge: true });

    await batch.commit();

    const payload = {
      id: messageId,
      senderId: state.currentUser.id,
      recipientId: partner.id,
      conversationId,
      ciphertext: encryptedMessage.ciphertext,
      iv: encryptedMessage.iv,
      wasEdited: false,
      createdAt: serverTimestamp(),
      expiresAt
    };

    await Promise.all([
      setDoc(messageRef(state.currentUser.id, partner.id, messageId), payload),
      setDoc(messageRef(partner.id, state.currentUser.id, messageId), payload)
    ]);
    removePendingMessage(partner.id, pendingId);
    if (state.activePartner?.id === partner.id) {
      renderMessages(state.currentMessages);
    }
  } catch (error) {
    removePendingMessage(partner.id, pendingId);
    if (state.activePartner?.id === partner.id) {
      messageInput.value = text;
      renderMessages(state.currentMessages);
    }
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

function handlePrivacyRiskStart() {
  showPrivacyOverlay(false);
}

function handlePrivacyRiskEnd() {
  if (document.visibilityState === "visible" && document.hasFocus()) {
    hidePrivacyOverlay();
  }
}

function isPrintScreenEvent(event) {
  const key = String(event.key || "").toLowerCase();
  const code = String(event.code || "").toLowerCase();

  return key === "printscreen"
    || key === "printscr"
    || key === "sysrq"
    || code === "printscreen"
    || code === "sysrq";
}

function isDesktopKeyboardSend(event) {
  if (event.key !== "Enter" || event.shiftKey || event.isComposing) {
    return false;
  }

  return window.matchMedia("(hover: hover) and (pointer: fine)").matches;
}

function lockViewportPosition() {
  document.documentElement.scrollTop = 0;
  document.body.scrollTop = 0;
  window.scrollTo(0, 0);
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    handlePrivacyRiskStart();
  } else {
    handlePrivacyRiskEnd();
  }
});

window.addEventListener("beforeprint", handlePrivacyRiskStart);
window.addEventListener("afterprint", handlePrivacyRiskEnd);
window.addEventListener("blur", handlePrivacyRiskStart);
window.addEventListener("focus", handlePrivacyRiskEnd);
window.addEventListener("pagehide", handlePrivacyRiskStart);
window.addEventListener("pageshow", lockViewportPosition);
window.addEventListener("resize", lockViewportPosition);
document.addEventListener("freeze", handlePrivacyRiskStart);

document.addEventListener("keydown", (event) => {
  if (isPrintScreenEvent(event)) {
    handlePrivacyRiskStart();
  }

  if (event.key === "Escape") {
    hidePrivacyOverlay();
  }
}, true);

document.addEventListener("keyup", (event) => {
  if (isPrintScreenEvent(event)) {
    handlePrivacyRiskStart();
  }
}, true);

privacyOverlay.addEventListener("click", hidePrivacyOverlay);

document.addEventListener("click", async (event) => {
  const editButton = event.target.closest("[data-edit-message]");
  if (editButton) {
    await openEditMessagePrompt(editButton.dataset.editMessage);
    return;
  }

  if (!event.target.closest(".message-item")) {
    setActiveMessageAction(null);
  }

  const openButton = event.target.closest("[data-open-user]");
  if (!openButton) return;
  await openConversationWithUser(openButton.dataset.openUser);
});

messageList.addEventListener("pointerdown", (event) => {
  const messageElement = event.target.closest(".message-item.own[data-message-id]");
  if (!messageElement || window.matchMedia("(hover: hover) and (pointer: fine)").matches) return;

  clearLongPressTimer();
  state.longPressTimer = window.setTimeout(() => {
    setActiveMessageAction(messageElement.dataset.messageId);
  }, 520);
});

messageList.addEventListener("pointerup", clearLongPressTimer);
messageList.addEventListener("pointercancel", clearLongPressTimer);
messageList.addEventListener("pointerleave", clearLongPressTimer);

authForm.addEventListener("submit", handleAuth);
document.getElementById("lockButton").addEventListener("click", lockApp);
messageForm.addEventListener("submit", sendMessage);
messageInput.addEventListener("keydown", (event) => {
  if (!isDesktopKeyboardSend(event)) return;

  event.preventDefault();
  messageForm.requestSubmit();
});
userSearch.addEventListener("input", (event) => searchUsers(event.target.value));
window.addEventListener("popstate", (event) => {
  if (event.state?.screen === "chat" && event.state?.partnerId) {
    openConversationWithUser(event.state.partnerId).catch(() => {});
    return;
  }

  showHome();
});

async function bootstrap() {
  if (!ensureFirebase()) {
    showMessage("Preencha o firebaseConfig em app.js para conectar o app ao Firebase.");
    return;
  }

  await setPersistence(auth, inMemoryPersistence);
  onAuthStateChanged(auth, async () => {
    await loadKnownUser();
  });
}

if (!isFirebaseConfigured()) {
  showMessage("Preencha o firebaseConfig em app.js para conectar o app ao Firebase.");
} else {
  if ("scrollRestoration" in history) {
    history.scrollRestoration = "manual";
  }
  lockViewportPosition();
  bootstrap().catch((error) => {
    console.error("Firebase bootstrap error:", error);
    showMessage(explainFirebaseError(error, "Nao consegui iniciar o Firebase agora."), true);
  });
}

if ("serviceWorker" in navigator || "caches" in window) {
  window.addEventListener("load", async () => {
    lockViewportPosition();

    try {
      if ("serviceWorker" in navigator) {
        const registrations = await navigator.serviceWorker.getRegistrations();
        await Promise.all(registrations.map((registration) => registration.unregister()));
      }

      if ("caches" in window) {
        const cacheKeys = await caches.keys();
        await Promise.all(cacheKeys.map((cacheKey) => caches.delete(cacheKey)));
      }
    } catch (error) {
      console.warn("Nao consegui limpar os caches locais do navegador.", error);
    }
  });
}
