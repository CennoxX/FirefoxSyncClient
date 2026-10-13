// The send-tab command layer.
//
// How Firefox does it (FxAccountsCommands.sys.mjs):
//   * Every device generates a P-256 key pair + 16-byte auth secret.
//   * {publicKey, authSecret} is encrypted with the account's oldsync key and
//     published as `availableCommands["https://identity.mozilla.com/cmd/open-uri"]`.
//   * A sender reads that bundle, decrypts it with the same account key, then
//     encrypts the tab payload to the recipient's public key using WebPush
//     aes128gcm, and POSTs it to /account/devices/invoke_command.
//
// One quirk to match exactly: Firefox passes an already-serialised JSON *string*
// into the Sync record encrypter, which stringifies again -- so the plaintext is
// double-encoded JSON. We reproduce that on write and tolerate both on read.

import { COMMAND_SEND_TAB } from "./fxa.js";
import {
  eceDecrypt,
  eceEncrypt,
  generateEceKeyPair,
  syncDecrypt,
  syncEncrypt,
} from "./crypto.js";
import { b64urlDecode, b64urlEncode, bytesToHex, dec, randomBytes, utf8 } from "./util.js";

/** Creates the key material this client publishes so others can send it tabs. */
export async function createSendTabKeys() {
  const { publicKey, privateJwk, authSecret } = await generateEceKeyPair();
  return {
    publicKey: b64urlEncode(publicKey),
    authSecret: b64urlEncode(authSecret),
    privateJwk,
  };
}

/** Builds the encrypted `availableCommands` value advertising our keys. */
export async function buildAvailableCommands(syncKeyBundle, sendTabKeys) {
  const inner = JSON.stringify({
    publicKey: sendTabKeys.publicKey,
    authSecret: sendTabKeys.authSecret,
  });
  // Double-encoded, matching Firefox's CryptoWrapper round-trip.
  const record = await syncEncrypt(syncKeyBundle, JSON.stringify(inner));
  return { [COMMAND_SEND_TAB]: JSON.stringify(record) };
}

/** Decrypts another device's advertised send-tab keys. */
export async function readDeviceKeys(syncKeyBundle, bundleString) {
  const record = JSON.parse(bundleString);
  const plaintext = await syncDecrypt(syncKeyBundle, record);
  let value = JSON.parse(plaintext);
  if (typeof value === "string") value = JSON.parse(value); // undo the double encoding
  if (!value?.publicKey || !value?.authSecret) {
    throw new Error("device key bundle is missing publicKey/authSecret");
  }
  return {
    publicKey: b64urlDecode(value.publicKey),
    authSecret: b64urlDecode(value.authSecret),
  };
}

/** Encrypts a tab for `device`, returning the command payload to POST. */
export async function encryptTabFor(syncKeyBundle, device, { url, title = "" }) {
  const bundle = device.availableCommands?.[COMMAND_SEND_TAB];
  if (!bundle) {
    throw new Error(
      `Device "${device.name}" does not advertise send-tab support ` +
        "(it may be an old client, or signed out).",
    );
  }
  const { publicKey, authSecret } = await readDeviceKeys(syncKeyBundle, bundle);

  const tab = {
    entries: [{ title, url }],
    flowID: bytesToHex(randomBytes(16)),
    streamID: bytesToHex(randomBytes(16)),
  };
  const encrypted = await eceEncrypt(utf8(JSON.stringify(tab)), publicKey, authSecret);
  return { encrypted: b64urlEncode(encrypted) };
}

/** Decrypts an incoming open-uri command payload. */
export async function decryptIncomingTab(sendTabKeys, payload) {
  if (!payload?.encrypted) throw new Error("command payload has no `encrypted` field");
  const plaintext = await eceDecrypt(
    b64urlDecode(payload.encrypted),
    sendTabKeys.privateJwk,
    b64urlDecode(sendTabKeys.publicKey),
    b64urlDecode(sendTabKeys.authSecret),
  );
  const data = JSON.parse(dec.decode(plaintext));
  const entries = Array.isArray(data.entries) ? data.entries : [];
  return entries.map((e) => ({ url: e.url, title: e.title || "" }));
}

export { COMMAND_SEND_TAB };
