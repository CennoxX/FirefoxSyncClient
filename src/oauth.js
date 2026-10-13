// Firefox Accounts OAuth 2.0 client with PKCE and scoped keys.
//
// This replaces the retired password-login ("onepw") API, which Mozilla now
// blocks at their CDN edge. The user signs in through the browser -- so 2FA,
// email confirmation and sign-in unblocking are all handled by Firefox's own
// pages -- and pastes back the redirect that carries the authorization code.
//
// Requesting the `oldsync` scope with a `keys_jwk` makes the token endpoint
// return `keys_jwe`: the account's sync key, encrypted to our ephemeral key.
// That yields the same 64-byte key bundle the old /account/keys path produced,
// without the server ever seeing kB.

import { b64urlDecode, b64urlEncode, dec, randomBytes, utf8 } from "./util.js";
import { sha256 } from "./crypto.js";
import { decryptCompactJwe } from "./jwe.js";

// Firefox for Android. Chosen because it is a trusted client whose registered
// redirect is a real HTTPS page -- so the authorization code lands in the
// browser's address bar where it can be copied, unlike Desktop's WebChannel.
export const CLIENT_ID = "a2270f727f45f648";
export const REDIRECT_URI = `https://accounts.firefox.com/oauth/success/${CLIENT_ID}`;

export const SCOPE_OLDSYNC = "https://identity.mozilla.com/apps/oldsync";
export const SCOPES = [SCOPE_OLDSYNC, "profile"];

export const CONTENT_SERVER = "https://accounts.firefox.com";
export const OAUTH_SERVER = "https://oauth.accounts.firefox.com/v1";
export const PROFILE_SERVER = "https://profile.accounts.firefox.com/v1";

const subtle = crypto.subtle;

function b64url(bytes) {
  return b64urlEncode(bytes);
}

/**
 * Builds everything needed to start an authorization: the URL to open plus the
 * secrets required to complete the exchange afterwards.
 */
export async function createAuthRequest({ scopes = SCOPES } = {}) {
  const codeVerifier = b64url(randomBytes(32));
  const codeChallenge = b64url(await sha256(utf8(codeVerifier)));
  const state = b64url(randomBytes(16));

  // Ephemeral P-256 key: its public half rides along as keys_jwk, and the
  // token endpoint encrypts the scoped key to it.
  const keyPair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const pubJwk = await subtle.exportKey("jwk", keyPair.publicKey);
  const keysJwkPublic = { kty: "EC", crv: "P-256", x: pubJwk.x, y: pubJwk.y };
  const keysJwkPrivate = await subtle.exportKey("jwk", keyPair.privateKey);

  const keysJwkParam = b64url(utf8(JSON.stringify(keysJwkPublic)));

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: scopes.join(" "),
    state,
    access_type: "offline", // ask for a refresh token
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    keys_jwk: keysJwkParam,
  });

  return {
    url: `${CONTENT_SERVER}/authorization?${params.toString()}`,
    state,
    codeVerifier,
    keysJwkPrivate,
  };
}

/** Pulls `code` (and `state`, if present) out of whatever the user pasted. */
export function parseRedirect(input) {
  const text = input.trim();
  try {
    const url = new URL(text);
    return { code: url.searchParams.get("code"), state: url.searchParams.get("state") };
  } catch {
    // Not a URL -- maybe they pasted just the code, or a bare query string.
    const qs = new URLSearchParams(text.replace(/^\?/, ""));
    if (qs.has("code")) return { code: qs.get("code"), state: qs.get("state") };
    return { code: text, state: null };
  }
}

async function tokenRequest(body) {
  const res = await fetch(`${OAUTH_SERVER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = json.message || json.error || `HTTP ${res.status}`;
    const err = new Error(`Token request failed: ${msg}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

/** Exchanges an authorization code for tokens (and keys_jwe). */
export async function exchangeCode({ code, codeVerifier }) {
  return await tokenRequest({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    code_verifier: codeVerifier,
  });
}

/**
 * Decrypts the `keys_jwe` from a token response and returns the 64-byte sync
 * key bundle for the oldsync scope (32 bytes AES + 32 bytes HMAC).
 */
export async function extractSyncKey(tokenResponse, keysJwkPrivate) {
  if (!tokenResponse.keys_jwe) {
    throw new Error(
      "The token response had no keys_jwe. The sign-in must grant the sync-data scope; " +
        "make sure you approved it in the browser.",
    );
  }
  const plaintext = await decryptCompactJwe(tokenResponse.keys_jwe, keysJwkPrivate);
  const bundle = JSON.parse(dec.decode(plaintext));
  const scoped = bundle[SCOPE_OLDSYNC];
  if (!scoped?.k) throw new Error("keys_jwe did not contain an oldsync key");
  const key = b64urlDecode(scoped.k);
  if (key.length !== 64) throw new Error(`oldsync key has unexpected length ${key.length}`);
  return { syncKey: key, kid: scoped.kid };
}

/** Fetches the account profile (email, uid) with a bearer access token. */
export async function fetchProfile(accessToken) {
  const res = await fetch(`${PROFILE_SERVER}/profile`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return {};
  return await res.json().catch(() => ({}));
}
