// Firefox Accounts auth-server client, OAuth/bearer edition.
//
// Every device endpoint is authenticated with the OAuth access token
// (`Authorization: Bearer ...`). When a call comes back 401 (errno 110), the
// client refreshes the access token once via the injected `onRefresh` callback
// and retries -- so a long-lived session survives access-token expiry.

const DEFAULT_API = "https://api.accounts.firefox.com/v1";
export const COMMAND_SEND_TAB = "https://identity.mozilla.com/cmd/open-uri";

export class FxAError extends Error {
  constructor(body, status) {
    super(body?.message || `FxA request failed with HTTP ${status}`);
    this.name = "FxAError";
    this.status = status;
    this.errno = body?.errno;
    this.body = body;
  }
}

export class FxAClient {
  /**
   * @param refreshToken the OAuth *refresh* token -- FxA's device endpoints
   *        authenticate a device by its refresh token, not the access token.
   */
  constructor(refreshToken, { apiServer = DEFAULT_API } = {}) {
    this.apiServer = apiServer.replace(/\/$/, "");
    this.refreshToken = refreshToken;
  }

  async request(method, path, { body = null } = {}) {
    const headers = { Authorization: `Bearer ${this.refreshToken}` };
    let payload = null;
    if (body !== null) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }

    const res = await fetch(this.apiServer + path, { method, headers, body: payload });
    const text = await res.text();
    let json = {};
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = { message: text };
      }
    }

    if (!res.ok) throw new FxAError(json, res.status);
    return json;
  }

  // --- devices and commands -------------------------------------------------

  registerDevice({ id, name, type = "desktop", availableCommands }) {
    const body = { name, type };
    if (id) body.id = id;
    if (availableCommands) body.availableCommands = availableCommands;
    return this.request("POST", "/account/device", { body });
  }

  destroyDevice(id) {
    return this.request("POST", "/account/device/destroy", { body: { id } });
  }

  listDevices() {
    return this.request("GET", "/account/devices");
  }

  invokeCommand({ target, command, payload, ttl }) {
    const body = { target, command, payload };
    if (ttl) body.ttl = ttl;
    return this.request("POST", "/account/devices/invoke_command", { body });
  }

  /** Pending commands addressed to this device, with index > `index`. */
  fetchCommands(index = 0, limit = 100) {
    const q = `?index=${encodeURIComponent(index)}&limit=${encodeURIComponent(limit)}`;
    return this.request("GET", `/account/device/commands${q}`);
  }
}

/** Human-readable hints for the FxA error numbers this client can hit. */
export function explainError(err) {
  if (!(err instanceof FxAError)) return err.message;
  const hints = {
    107: "The request was rejected by the server's schema.",
    108: "Missing request parameter.",
    110: "The credential is invalid or expired; try `login` again.",
    114: "Too many requests -- wait a few minutes and try again.",
    177: "Unknown device id.",
    181: "This access token lacks the scope this endpoint needs.",
  };
  const hint = hints[err.errno];
  const base = hint ? `${err.message} (errno ${err.errno}) -- ${hint}` : `${err.message} (errno ${err.errno})`;

  // FxA reports credential problems on device endpoints as a 107 whose
  // `validation` is the literal string "authorization".
  if (err.body?.validation === "authorization") {
    return `${base} [the credential was not accepted -- device endpoints require the refresh token]`;
  }
  const keys = validationKeys(err);
  return keys.length ? `${base} [rejected field(s): ${keys.join(", ")}]` : base;
}

/** The offending payload keys FxA reports on a validation error, if any. */
export function validationKeys(err) {
  const v = err?.body?.validation;
  if (!v || typeof v === "string") return [];
  const keys = Array.isArray(v.keys) ? v.keys.filter((k) => k !== "") : [];
  return keys;
}
