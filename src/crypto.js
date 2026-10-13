// Crypto primitives for the send-tab path, built on WebCrypto only.
//
// Two layers live here:
//   1. Sync 1.5 record encryption (AES-256-CBC + HMAC-SHA256 over the *base64*
//      ciphertext) -- used for the device `availableCommands` bundles.
//   2. WebPush aes128gcm (RFC 8188 + RFC 8291) -- used for send-tab payloads.
//
// The account's 64-byte sync key ("oldsync" scope) is obtained via OAuth scoped
// keys (see src/oauth.js), so no password-based key derivation lives here.

import { b64ToBytes, bytesToB64, bytesToHex, concat, dec, u32be, utf8, randomBytes } from "./util.js";

const subtle = crypto.subtle;

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

export async function hmacSha256(keyBytes, data) {
  const key = await subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return new Uint8Array(await subtle.sign("HMAC", key, data));
}

/** HKDF-SHA256. A null salt is treated as 32 zero bytes (RFC 5869 §2.2). */
export async function hkdf(ikm, salt, info, length) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt ?? new Uint8Array(32),
      info: info ?? new Uint8Array(0),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// 1. Sync 1.5 record encryption
// ---------------------------------------------------------------------------

async function aesCbc(mode, keyBytes, iv, data) {
  const key = await subtle.importKey("raw", keyBytes, "AES-CBC", false, [mode]);
  const fn = mode === "encrypt" ? subtle.encrypt : subtle.decrypt;
  return new Uint8Array(await fn.call(subtle, { name: "AES-CBC", iv }, key, data));
}

/**
 * Encrypts a string into a Sync record `{ciphertext, IV, hmac}`.
 * Sync quirk: the HMAC covers the *base64 text* of the ciphertext (not the raw
 * bytes) and is hex-encoded.
 */
export async function syncEncrypt(keyBundle, plaintext) {
  const iv = randomBytes(16);
  const ct = await aesCbc("encrypt", keyBundle.subarray(0, 32), iv, utf8(plaintext));
  const ciphertext = bytesToB64(ct);
  const hmac = bytesToHex(await hmacSha256(keyBundle.subarray(32, 64), utf8(ciphertext)));
  return { ciphertext, IV: bytesToB64(iv), hmac };
}

export async function syncDecrypt(keyBundle, record) {
  const { ciphertext, IV, hmac } = record;
  if (!ciphertext || !IV || !hmac) throw new Error("malformed Sync record");
  const expected = await hmacSha256(keyBundle.subarray(32, 64), utf8(ciphertext));
  if (bytesToHex(expected) !== hmac.toLowerCase()) {
    throw new Error("Sync record HMAC mismatch (wrong key, or the record was tampered with)");
  }
  const pt = await aesCbc("decrypt", keyBundle.subarray(0, 32), b64ToBytes(IV), b64ToBytes(ciphertext));
  return dec.decode(pt);
}

// ---------------------------------------------------------------------------
// 2. WebPush aes128gcm (send-tab payloads)
// ---------------------------------------------------------------------------

const P256 = { name: "ECDH", namedCurve: "P-256" };

export async function generateEceKeyPair() {
  const pair = await subtle.generateKey(P256, true, ["deriveBits"]);
  const publicKey = new Uint8Array(await subtle.exportKey("raw", pair.publicKey)); // 65 bytes
  const privateJwk = await subtle.exportKey("jwk", pair.privateKey);
  return { publicKey, privateJwk, authSecret: randomBytes(16) };
}

async function importPublic(raw) {
  return await subtle.importKey("raw", raw, P256, false, []);
}

async function importPrivate(jwk) {
  return await subtle.importKey("jwk", { ...jwk, key_ops: ["deriveBits"] }, P256, false, [
    "deriveBits",
  ]);
}

/**
 * PRK shared by both directions (RFC 8291 §3.3). `receiverPublic` is always the
 * *recipient's* key, regardless of who is deriving.
 */
async function derivePrk(privateKey, otherPublicKey, receiverPublic, senderPublic, authSecret) {
  const shared = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: otherPublicKey }, privateKey, 256),
  );
  const info = concat(utf8("WebPush: info"), new Uint8Array([0]), receiverPublic, senderPublic);
  return await hkdf(shared, authSecret, info, 32);
}

async function deriveContentKeys(prk, salt) {
  const cek = await hkdf(prk, salt, utf8("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(prk, salt, utf8("Content-Encoding: nonce\0"), 12);
  return { cek, nonce };
}

function recordNonce(baseNonce, seq) {
  const nonce = baseNonce.slice();
  const view = new DataView(nonce.buffer);
  view.setUint32(8, view.getUint32(8, false) ^ seq, false);
  return nonce;
}

/**
 * Encrypts `plaintext` for a recipient identified by their raw P-256 public key
 * and 16-byte auth secret. Returns the full aes128gcm body (header + records).
 */
export async function eceEncrypt(plaintext, receiverPublicRaw, authSecret, recordSize = 4096) {
  const ephemeral = await subtle.generateKey(P256, true, ["deriveBits"]);
  const senderPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
  const receiverKey = await importPublic(receiverPublicRaw);

  const prk = await derivePrk(ephemeral.privateKey, receiverKey, receiverPublicRaw, senderPublic, authSecret);

  const salt = randomBytes(16);
  const { cek, nonce } = await deriveContentKeys(prk, salt);
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);

  const chunkSize = recordSize - 17; // 16-byte tag + 1-byte delimiter
  const chunks = [];
  for (let i = 0; i < Math.max(1, Math.ceil(plaintext.length / chunkSize)); i++) {
    chunks.push(plaintext.subarray(i * chunkSize, (i + 1) * chunkSize));
  }

  const records = [];
  for (let i = 0; i < chunks.length; i++) {
    const isLast = i === chunks.length - 1;
    const padded = concat(chunks[i], new Uint8Array([isLast ? 2 : 1]));
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: recordNonce(nonce, i), tagLength: 128 },
      key,
      padded,
    );
    records.push(new Uint8Array(ct));
  }

  const header = concat(salt, u32be(recordSize), new Uint8Array([senderPublic.length]), senderPublic);
  return concat(header, ...records);
}

/** Decrypts an aes128gcm body addressed to our own key pair. */
export async function eceDecrypt(payload, privateJwk, ourPublicRaw, authSecret) {
  if (payload.length < 21) throw new Error("aes128gcm payload too short");
  const salt = payload.subarray(0, 16);
  const recordSize = new DataView(payload.buffer, payload.byteOffset).getUint32(16, false);
  const idLen = payload[20];
  const senderPublic = payload.subarray(21, 21 + idLen);
  const body = payload.subarray(21 + idLen);
  if (idLen !== 65) throw new Error(`unexpected key id length ${idLen}`);
  if (recordSize < 18) throw new Error(`invalid record size ${recordSize}`);

  const privateKey = await importPrivate(privateJwk);
  const senderKey = await importPublic(senderPublic);
  const prk = await derivePrk(privateKey, senderKey, ourPublicRaw, senderPublic, authSecret);
  const { cek, nonce } = await deriveContentKeys(prk, salt);
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);

  const parts = [];
  for (let i = 0, off = 0; off < body.length; i++, off += recordSize) {
    const record = body.subarray(off, Math.min(off + recordSize, body.length));
    const pt = new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv: recordNonce(nonce, i), tagLength: 128 }, key, record),
    );
    let end = pt.length - 1;
    while (end >= 0 && pt[end] === 0) end--;
    if (end < 0) throw new Error("aes128gcm record has no padding delimiter");
    parts.push(pt.subarray(0, end));
  }
  return concat(...parts);
}
