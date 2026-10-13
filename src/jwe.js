// Compact JWE decryption for the one shape FxA returns in `keys_jwe`:
// alg = ECDH-ES (direct), enc = A256GCM. This unwraps the scoped sync key.
//
// Key agreement follows RFC 7518 §4.6: ECDH gives Z (the P-256 X coordinate),
// then the NIST SP 800-56A Concat KDF with SHA-256 derives the content key.

import { b64urlDecode, b64urlEncode, concat, dec, u32be, utf8 } from "./util.js";
import { sha256 } from "./crypto.js";

const subtle = crypto.subtle;
const P256 = { name: "ECDH", namedCurve: "P-256" };

function lengthPrefixed(bytes) {
  return concat(u32be(bytes.length), bytes);
}

/**
 * Concat KDF (single round, valid because keydatalen (256) == SHA-256 length).
 * @param z shared secret (P-256 X coordinate, 32 bytes)
 */
async function concatKdf(z, algorithmId, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
  const input = concat(
    u32be(1),
    z,
    lengthPrefixed(utf8(algorithmId)),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    u32be(256), // keydatalen in bits
  );
  return (await sha256(input)).subarray(0, 32);
}

async function importEcPublic(jwk) {
  return await subtle.importKey("jwk", { ...jwk, key_ops: [] }, P256, false, []);
}

async function importEcPrivate(jwk) {
  return await subtle.importKey("jwk", { ...jwk, key_ops: ["deriveBits"] }, P256, false, [
    "deriveBits",
  ]);
}

/**
 * Derives the A256GCM content key from an ephemeral public key (`epk`) and our
 * private key. Shared by both decrypt and the test-only encrypt path.
 */
async function deriveContentKey(privateKey, epkJwk, enc, apu, apv) {
  const epk = await importEcPublic(epkJwk);
  const z = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: epk }, privateKey, 256));
  const raw = await concatKdf(z, enc, apu, apv);
  return raw;
}

/** Decrypts a compact JWE (ECDH-ES / A256GCM) using our private JWK. */
export async function decryptCompactJwe(compact, privateJwk) {
  const parts = compact.split(".");
  if (parts.length !== 5) throw new Error("not a compact JWE (need 5 segments)");
  const [headerB64, encryptedKey, ivB64, ciphertextB64, tagB64] = parts;

  const header = JSON.parse(dec.decode(b64urlDecode(headerB64)));
  if (header.alg !== "ECDH-ES") throw new Error(`unsupported JWE alg "${header.alg}"`);
  if (header.enc !== "A256GCM") throw new Error(`unsupported JWE enc "${header.enc}"`);
  if (encryptedKey) throw new Error("ECDH-ES direct mode must have an empty encrypted key");
  if (!header.epk) throw new Error("JWE header is missing the ephemeral public key (epk)");

  const apu = header.apu ? b64urlDecode(header.apu) : new Uint8Array(0);
  const apv = header.apv ? b64urlDecode(header.apv) : new Uint8Array(0);

  const privateKey = await importEcPrivate(privateJwk);
  const cek = await deriveContentKey(privateKey, header.epk, header.enc, apu, apv);
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);

  const ciphertext = b64urlDecode(ciphertextB64);
  const tag = b64urlDecode(tagB64);
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv: b64urlDecode(ivB64), additionalData: utf8(headerB64), tagLength: 128 },
    key,
    concat(ciphertext, tag),
  );
  return new Uint8Array(plaintext);
}

/**
 * Encrypts a compact JWE the way FxA does. Used only by the self-test to verify
 * the decrypt path against a known round-trip; the client never calls it.
 */
export async function encryptCompactJwe(plaintext, recipientPublicJwk) {
  const ephemeral = await subtle.generateKey(P256, true, ["deriveBits"]);
  const epkJwk = await subtle.exportKey("jwk", ephemeral.publicKey);
  const epk = { kty: "EC", crv: "P-256", x: epkJwk.x, y: epkJwk.y };
  const header = { alg: "ECDH-ES", enc: "A256GCM", epk };
  const headerB64 = b64urlEncode(utf8(JSON.stringify(header)));

  const recipient = await importEcPublic(recipientPublicJwk);
  const z = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: recipient }, ephemeral.privateKey, 256),
  );
  const cek = await concatKdf(z, "A256GCM");
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const out = new Uint8Array(
    await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: utf8(headerB64), tagLength: 128 },
      key,
      plaintext,
    ),
  );
  const ciphertext = out.subarray(0, out.length - 16);
  const tag = out.subarray(out.length - 16);
  return [headerB64, "", b64urlEncode(iv), b64urlEncode(ciphertext), b64urlEncode(tag)].join(".");
}
