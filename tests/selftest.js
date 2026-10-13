// Offline self-test for every crypto layer the send-tab path relies on, plus
// the OAuth helpers. No network, no account needed.
//
//   deno task test

import {
  eceDecrypt,
  eceEncrypt,
  generateEceKeyPair,
  hkdf,
  syncDecrypt,
  syncEncrypt,
} from "../src/crypto.js";
import { decryptCompactJwe, encryptCompactJwe } from "../src/jwe.js";
import {
  buildAvailableCommands,
  createSendTabKeys,
  decryptIncomingTab,
  encryptTabFor,
} from "../src/sendtab.js";
import { createAuthRequest, parseRedirect } from "../src/oauth.js";
import { COMMAND_SEND_TAB } from "../src/fxa.js";
import { b64urlEncode, bytesToHex, dec, hexToBytes, randomBytes, utf8 } from "../src/util.js";

let failures = 0;
let count = 0;

function check(name, ok, detail = "") {
  count++;
  if (ok) console.log(`  ok   ${name}`);
  else {
    failures++;
    console.log(`  FAIL ${name}${detail ? `\n         ${detail}` : ""}`);
  }
}

async function section(name, fn) {
  console.log(`\n${name}`);
  try {
    await fn();
  } catch (err) {
    failures++;
    console.log(`  FAIL ${name} threw: ${err.stack}`);
  }
}

// ---------------------------------------------------------------------------

await section("HKDF (RFC 5869 case 1)", async () => {
  const okm = await hkdf(
    new Uint8Array(22).fill(0x0b),
    hexToBytes("000102030405060708090a0b0c"),
    hexToBytes("f0f1f2f3f4f5f6f7f8f9"),
    42,
  );
  check(
    "known answer",
    bytesToHex(okm) ===
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    `got ${bytesToHex(okm)}`,
  );
  const a = await hkdf(utf8("ikm"), null, utf8("info"), 32);
  const b = await hkdf(utf8("ikm"), new Uint8Array(32), utf8("info"), 32);
  check("null salt == zero salt", bytesToHex(a) === bytesToHex(b));
});

await section("JWE (ECDH-ES / A256GCM) -- unwraps the scoped sync key", async () => {
  // Recipient key pair, exactly as createAuthRequest produces (keys_jwk).
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const pubJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const recipientPublic = { kty: "EC", crv: "P-256", x: pubJwk.x, y: pubJwk.y };

  // Server-side: a keys_jwe carrying a 64-byte oldsync key.
  const syncKey = randomBytes(64);
  const payload = {
    "https://identity.mozilla.com/apps/oldsync": {
      kid: "1234567890123-abc",
      k: b64urlEncode(syncKey),
      kty: "oct",
    },
  };
  const jwe = await encryptCompactJwe(utf8(JSON.stringify(payload)), recipientPublic);
  check("compact JWE has 5 segments", jwe.split(".").length === 5);

  const plaintext = await decryptCompactJwe(jwe, privJwk);
  const recovered = JSON.parse(dec.decode(plaintext));
  check(
    "round-trips the oldsync key",
    recovered["https://identity.mozilla.com/apps/oldsync"].k === b64urlEncode(syncKey),
  );

  // A different recipient key must fail (AES-GCM tag check).
  const other = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const otherPriv = await crypto.subtle.exportKey("jwk", other.privateKey);
  let rejected = false;
  try {
    await decryptCompactJwe(jwe, otherPriv);
  } catch {
    rejected = true;
  }
  check("wrong recipient key rejected", rejected);
});

await section("Sync 1.5 record encryption", async () => {
  const keyBundle = randomBytes(64); // 32 AES + 32 HMAC, as the oldsync key is
  const plaintext = JSON.stringify({ hello: "wörld", n: 42 });
  const record = await syncEncrypt(keyBundle, plaintext);
  check("record has ciphertext/IV/hmac", Boolean(record.ciphertext && record.IV && record.hmac));
  check("round-trip", (await syncDecrypt(keyBundle, record)) === plaintext);

  let rejected = false;
  try {
    await syncDecrypt(keyBundle, { ...record, hmac: "00".repeat(32) });
  } catch {
    rejected = true;
  }
  check("bad HMAC rejected", rejected);
});

await section("WebPush aes128gcm (ECE)", async () => {
  const keys = await generateEceKeyPair();
  const message = utf8("a short tab payload");
  const body = await eceEncrypt(message, keys.publicKey, keys.authSecret);
  check("header carries the 65-byte sender key", body[20] === 65);
  check("round-trip (single record)", dec.decode(await eceDecrypt(body, keys.privateJwk, keys.publicKey, keys.authSecret)) === dec.decode(message));

  const big = utf8("x".repeat(200));
  const multi = await eceEncrypt(big, keys.publicKey, keys.authSecret, 50);
  check("round-trip (multi record)", dec.decode(await eceDecrypt(multi, keys.privateJwk, keys.publicKey, keys.authSecret)) === dec.decode(big));

  const other = await generateEceKeyPair();
  let rejected = false;
  try {
    await eceDecrypt(body, other.privateJwk, other.publicKey, other.authSecret);
  } catch {
    rejected = true;
  }
  check("wrong recipient key rejected", rejected);
});

await section("send-tab end to end", async () => {
  const syncKey = randomBytes(64); // shared oldsync key across the account
  const receiverKeys = await createSendTabKeys();
  const availableCommands = await buildAvailableCommands(syncKey, receiverKeys);
  check("advertises the open-uri command", Boolean(availableCommands[COMMAND_SEND_TAB]));

  const device = { id: "abc123", name: "Other PC", availableCommands };
  const payload = await encryptTabFor(syncKey, device, {
    url: "https://example.org/article",
    title: "An article",
  });
  const tabs = await decryptIncomingTab(receiverKeys, payload);
  check("one tab received", tabs.length === 1);
  check("url survived", tabs[0]?.url === "https://example.org/article");
  check("title survived", tabs[0]?.title === "An article");

  let rejected = false;
  try {
    await encryptTabFor(syncKey, { id: "x", name: "Old client", availableCommands: {} }, {
      url: "https://example.org/",
    });
  } catch {
    rejected = true;
  }
  check("device without send-tab support rejected", rejected);
});

await section("OAuth helpers", async () => {
  const auth = await createAuthRequest();
  const url = new URL(auth.url);
  check("authorization endpoint", url.host === "accounts.firefox.com" && url.pathname === "/authorization");
  check("uses PKCE S256", url.searchParams.get("code_challenge_method") === "S256");
  check("requests offline access", url.searchParams.get("access_type") === "offline");
  check("carries keys_jwk", Boolean(url.searchParams.get("keys_jwk")));
  check("scope includes oldsync", (url.searchParams.get("scope") || "").includes("apps/oldsync"));
  check("state echoed into the URL", url.searchParams.get("state") === auth.state);
  check("keeps the private key for JWE", Boolean(auth.keysJwkPrivate?.d));

  // Redirect parsing accepts a full URL, a bare query, or just the code.
  const full = parseRedirect("https://accounts.firefox.com/oauth/success/x?code=THECODE&state=ST");
  check("parses code from full URL", full.code === "THECODE" && full.state === "ST");
  check("parses bare query", parseRedirect("?code=abc&state=z").code === "abc");
  check("parses a lone code", parseRedirect("justacode").code === "justacode");
});

console.log(`\n${count - failures}/${count} checks passed`);
if (failures > 0) Deno.exit(1);
