/*
Identity flow (priority):
1) Authenticated user ID
2) Server session ID
3) Stored ID
4) Deterministic fallback hash
5) Server-issued ID

Optional runtime config:
window.ACCESS_GATE_CONFIG = {
  authUserId: "optional-auth-user-id",
  authUserIdGlobal: "ACCESS_GATE_AUTH_USER_ID",
  adminToken: "optional-admin-token",
  adminTokenGlobal: "ACCESS_GATE_ADMIN_TOKEN",
  sessionEndpoint: "https://example.com/access/session",
  issueEndpoint: "https://example.com/access/issue",
  blockEndpoint: "https://example.com/access/check",
  adminCheckEndpoint: "https://example.com/access/is-admin",
  blockUserEndpoint: "https://example.com/access/block",
  unblockUserEndpoint: "https://example.com/access/unblock",
  deterministicSalt: "my-radio-io.v1",
  adminTokenHeader: "x-access-gate-token",
  storageKey: "accessgate.identity.v1"
};
*/
function base64UrlFromBytes(bytes) {
  if (!bytes || bytes.length === 0) return "";
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }

  const b64 = (typeof btoa === "function")
    ? btoa(binary)
    : Buffer.from(binary, "binary").toString("base64");

  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function getStorage() {
  if (typeof globalThis !== "undefined" && globalThis.localStorage) {
    return globalThis.localStorage;
  }
  // Worker / non-localStorage fallback: in-memory
  if (!globalThis.__ACCESS_GATE_MEMSTORE__) {
    globalThis.__ACCESS_GATE_MEMSTORE__ = new Map();
  }
  const store = globalThis.__ACCESS_GATE_MEMSTORE__;
  return {
    getItem(k) { return store.get(k) ?? null; },
    setItem(k, v) { store.set(k, String(v)); }
  };
}

const AccessGate = {
  config: Object.assign(
    {
      authUserId: "",
      authUserIdGlobal: "ACCESS_GATE_AUTH_USER_ID",
      adminToken: "",
      adminTokenGlobal: "ACCESS_GATE_ADMIN_TOKEN",
      sessionEndpoint: "/access/session",
      issueEndpoint: "/access/issue",
      blockEndpoint: "/access/check",
      adminCheckEndpoint: "/access/is-admin",
      blockUserEndpoint: "/access/block",
      unblockUserEndpoint: "/access/unblock",
      deterministicSalt: "my-radio-io.v1",
      adminTokenHeader: "x-access-gate-token",
      storageKey: "accessgate.identity.v1"
    },
    typeof globalThis !== "undefined" && globalThis.ACCESS_GATE_CONFIG
      ? globalThis.ACCESS_GATE_CONFIG
      : {}
  ),

  check() {
    const hasFetch = typeof fetch === "function";
    return hasFetch; // Worker or browser; storage is abstracted
  },

  _getStoredId() {
    try {
      return getStorage().getItem(this.config.storageKey);
    } catch {
      return null;
    }
  },

  _setStoredId(id) {
    try {
      getStorage().setItem(this.config.storageKey, id);
    } catch (e) {
      console.warn("AccessGate: could not persist identity:", e);
    }
  },

  _setUserToken(id) {
    if (!this._isValidId(id)) return;
    try {
      if (typeof globalThis !== "undefined") {
        globalThis.ACCESS_GATE_USER_TOKEN = id;
      }
      getStorage().setItem("ACCESS_GATE_USER_TOKEN", id);
    } catch (e) {
      console.warn("AccessGate: could not persist user token:", e);
    }
  },

  _getUserToken() {
    if (typeof globalThis !== "undefined" && globalThis.ACCESS_GATE_USER_TOKEN) {
      return globalThis.ACCESS_GATE_USER_TOKEN;
    }
    try {
      const stored = getStorage().getItem("ACCESS_GATE_USER_TOKEN");
      if (this._isValidId(stored)) return stored;
    } catch {}
    try {
      const stored = getStorage().getItem(this.config.storageKey);
      if (this._isValidId(stored)) return stored;
    } catch {}
    return null;
  },

  _isValidId(value) {
    return typeof value === "string" && value.trim().length >= 8 && value.trim().length <= 128;
  },

  _globalAuthUserId() {
    const fromConfig = this.config.authUserId;
    if (this._isValidId(fromConfig)) return String(fromConfig).trim();
    const globalKey = this.config.authUserIdGlobal;
    if (!globalKey || typeof globalThis === "undefined") return null;
    const value = globalThis[globalKey];
    return this._isValidId(value) ? String(value).trim() : null;
  },

  _globalAdminToken() {
    const fromConfig = this.config.adminToken;
    if (this._isValidId(fromConfig)) return String(fromConfig).trim();
    const globalKey = this.config.adminTokenGlobal;
    if (!globalKey || typeof globalThis === "undefined") return null;
    const value = globalThis[globalKey];
    return this._isValidId(value) ? String(value).trim() : null;
  },

  async _hashText(text) {
    const bytes = new TextEncoder().encode(String(text));
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },

  async _deterministicFallbackId() {
    const hasNavigator = typeof navigator !== "undefined";
    const seed = [
      this.config.deterministicSalt || "my-radio-io.v1",
      hasNavigator ? navigator.userAgent || "" : "",
      hasNavigator ? navigator.language || "" : "",
      hasNavigator ? navigator.platform || "" : "",
      hasNavigator ? String(navigator.hardwareConcurrency || "") : "",
      hasNavigator ? String(navigator.maxTouchPoints || 0) : "",
      String(new Date().getTimezoneOffset())
    ].join("|");
    const digest = await this._hashText(seed);
    return "det_" + digest.slice(0, 48);
  },

  async requestIssuedId() {
    const existing = this._getStoredId();
    const payload = existing ? { existingId: existing } : {};
    const wasmHeaders =
      typeof globalThis !== "undefined" &&
      globalThis.AuthWasm &&
      typeof globalThis.AuthWasm.authHeaders === "function"
        ? await globalThis.AuthWasm.authHeaders()
        : {};
    const response = await fetch(this.config.issueEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...wasmHeaders },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error("Issue request failed with status " + response.status);
    }

    const result = await response.json();
    const candidate = result.id || result.uuid || result.userId;
    if (!this._isValidId(candidate)) {
      throw new Error("Server did not return a valid identity.");
    }

    this._setStoredId(candidate);
    return candidate;
  },

  async requestSessionId() {
    const wasmHeaders =
      typeof globalThis !== "undefined" &&
      globalThis.AuthWasm &&
      typeof globalThis.AuthWasm.authHeaders === "function"
        ? await globalThis.AuthWasm.authHeaders()
        : {};
    const response = await fetch(this.config.sessionEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...wasmHeaders },
      body: "{}"
    });
    if (!response.ok) {
      throw new Error("Session request failed with status " + response.status);
    }
    const result = await response.json();
    const candidate = result.id || result.uuid;
    if (!this._isValidId(candidate)) {
      throw new Error("Session endpoint did not return a valid identity.");
    }
    return candidate;
  },

  async getOrCreateIdentity() {
    const authId = this._globalAuthUserId();
    if (this._isValidId(authId)) {
      const id = `auth:${authId}`;
      this._setStoredId(id);
      return id;
    }

    const cached = this._getStoredId();
    if (this._isValidId(cached)) return cached;

    try {
      const sessionId = await this.requestSessionId();
      if (this._isValidId(sessionId)) {
        this._setStoredId(sessionId);
        return sessionId;
      }
    } catch {}

    try {
      const detId = await this._deterministicFallbackId();
      if (this._isValidId(detId)) {
        this._setStoredId(detId);
        return detId;
      }
    } catch {}

    return this.requestIssuedId();
  },

  async isBlocked(id) {
    const wasmHeaders =
      typeof globalThis !== "undefined" &&
      globalThis.AuthWasm &&
      typeof globalThis.AuthWasm.authHeaders === "function"
        ? await globalThis.AuthWasm.authHeaders()
        : {};
    let response;
    try {
      response = await fetch(this.config.blockEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...wasmHeaders },
        body: JSON.stringify({ id, uuid: id })
      });
    } catch (error) {
      console.warn("AccessGate: block check endpoint unavailable, defaulting to not blocked.", error);
      return false;
    }

    if (response.status === 404 || response.status === 405) {
      console.warn("AccessGate: block check endpoint missing, defaulting to not blocked.");
      return false;
    }

    if (!response.ok) {
      throw new Error("Block check failed with status " + response.status);
    }

    const result = await response.json();
    return !!result.blocked;
  },

  async _otpAuthHeaders(seedId = null) {
    const fallback =
      typeof globalThis !== "undefined" &&
      globalThis.OTPWasm &&
      typeof globalThis.OTPWasm.authHeaders === "function"
        ? await globalThis.OTPWasm.authHeaders()
        : {};
    try {
      const id = seedId && this._isValidId(seedId) ? seedId : this._getUserToken();
      if (!this._isValidId(id)) return fallback;
      const key = await this.generate2auth(2048, id);
      return Object.assign({}, fallback, { "x-otp-wasm": key });
    } catch {
      return fallback;
    }
  },

  async blockUser(id, reason, adminToken) {
    const wasmHeaders =
      typeof globalThis !== "undefined" &&
      globalThis.AuthWasm &&
      typeof globalThis.AuthWasm.authHeaders === "function"
        ? await globalThis.AuthWasm.authHeaders()
        : {};
    const otpWasmHeaders = await this._otpAuthHeaders();
    const token = adminToken || "";
    const response = await fetch(this.config.blockUserEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [this.config.adminTokenHeader]: token,
        "ACCESS_GATE_ADMIN_TOKEN": token,
        ...wasmHeaders,
        ...otpWasmHeaders
      },
      body: JSON.stringify({ id, uuid: id, reason: reason || "manual" })
    });
    if (!response.ok) {
      throw new Error("Block user failed with status " + response.status);
    }
    return response.json();
  },

  async isAdmin(adminToken) {
    const token = (adminToken || "").trim();
    if (!this._isValidId(token)) {
      return false;
    }
    const wasmHeaders =
      typeof globalThis !== "undefined" &&
      globalThis.AuthWasm &&
      typeof globalThis.AuthWasm.authHeaders === "function"
        ? await globalThis.AuthWasm.authHeaders()
        : {};
    const otpWasmHeaders = await this._otpAuthHeaders();
    const response = await fetch(this.config.adminCheckEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [this.config.adminTokenHeader]: token,
        ...wasmHeaders,
        ...otpWasmHeaders
      },
      body: "{}"
    });
    if (!response.ok) {
      return false;
    }
    const result = await response.json();
    return !!(result && result.isAdmin);
  },

  async "2auth"(adminToken) {
    const id = adminToken || this._getUserToken();
    return this.isAdmin(id);
  },

  async generate2auth(length = 2048, seed = null) {
    const target = Number.isFinite(length) && length > 0 ? Math.floor(length) : 2048;
    const id = seed && this._isValidId(seed) ? seed : this._getUserToken();
    if (!this._isValidId(id)) {
      throw new Error("Valid AccessGate ID required");
    }
    const encoder = new TextEncoder();
    const parts = [];
    let counter = 0;
    while (parts.join("").length < target) {
      const material = `${id}|${counter}`;
      const hashBuffer = await crypto.subtle.digest("SHA-512", encoder.encode(material));
      parts.push(base64UrlFromBytes(new Uint8Array(hashBuffer)));
      counter += 1;
    }
    return parts.join("").slice(0, target);
  }
};

export default AccessGate;
export { AccessGate };
