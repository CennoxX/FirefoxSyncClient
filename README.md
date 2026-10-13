# Firefox Sync Client

A minimal Firefox tab-sharing client in plain JavaScript on Deno. It signs in to a
Firefox Account through the browser, registers itself as a **device** on that account,
and can **send a tab to any other signed-in machine** — where it appears in Firefox
exactly as if you had used "Send Tab to Device". It can also receive tabs sent to it.

Focused scope: sending and receiving tabs between your devices. It does not read or write
other Sync data (bookmarks, history, passwords, …). No dependencies; all crypto is
WebCrypto.

## Quick start

```sh
deno run -A main.js login                    # sign in via the browser, register this machine
deno run -A main.js devices                  # list every device on the account
deno run -A main.js send 2 https://deno.com  # send a tab to device #2
deno run -A main.js receive --watch --open   # listen for tabs sent to this machine
```

`-A` grants all permissions; the explicit set is
`--allow-net --allow-read --allow-write --allow-env --allow-run` (net for the API, run
for opening the browser, read/write for the credential file). `deno task test` runs an
offline self-test of every crypto layer (27 checks).

## Signing in

Mozilla **retired the direct password-login API** — `POST /account/login` now returns a
bodiless `406` from their CDN edge before it ever reaches the auth server (sibling
endpoints from the same client still work, and `curl` gets the same 406, so it is
server-side and route-specific, not a client bug). The supported replacement is OAuth,
so this client uses the browser sign-in flow:

1. `login` prints an `accounts.firefox.com/authorization?...` URL and opens it.
2. You sign in in your browser. **Two-step auth, email confirmation, and sign-in
   unblocking all happen there**, on Firefox's own pages.
3. You land on a "Sign-in successful" page whose address contains `?code=...`. Copy the
   full address from the address bar and paste it back into the terminal.
4. The client exchanges the code for tokens and the encrypted sync key, then registers
   this machine as a device.

This is how the client "adds itself" to the account. (Firefox's "Connect another device"
QR pairing is a different mechanism — a TLS 1.3 tunnel over a WebSocket — and is out of
scope here.) Use `--no-browser` to print the URL instead of launching a browser.

## How sending a tab works

Modern Firefox does **not** push sent tabs through the Sync storage server. It uses
**Firefox Accounts device commands**, and this client implements the same protocol, so
it interoperates with real Firefox installs in both directions.

1. **Get the sync key.** The OAuth token request asks for the
   `https://identity.mozilla.com/apps/oldsync` scope and sends an ephemeral public key
   (`keys_jwk`). The token response includes `keys_jwe` — the account's 64-byte sync key
   (32 AES + 32 HMAC), encrypted to that ephemeral key (JWE, ECDH-ES + A256GCM). The
   server never sees it in the clear, and the root key kB never leaves Firefox at all.
2. **Publish a mailbox.** This client generates a P-256 key pair and a 16-byte auth
   secret, encrypts `{publicKey, authSecret}` under the sync key as a Sync 1.5 record,
   and registers it as `availableCommands["https://identity.mozilla.com/cmd/open-uri"]`.
   That is how other devices learn where to send this one tabs.
3. **Send.** Read the *target's* published bundle, decrypt it with the sync key, then
   encrypt `{entries:[{title,url}]}` to the target's public key using WebPush
   **aes128gcm** (RFC 8188 / RFC 8291), and `POST /account/devices/invoke_command`.
4. **Receive.** `GET /account/device/commands?index=N` returns queued commands, decrypted
   with this client's private key.

Every device/command call is authenticated with the OAuth **refresh** token
(`Authorization: Bearer <refresh_token>`) — not the access token. In FxA's model a
device *is* a refresh token, so those endpoints expect it; presenting the access token
there fails with a `107 "authorization"` error. The refresh token is long-lived, so
there is nothing to refresh during normal use. The server only ever sees ciphertext, so
it cannot read a sent tab.

## Commands

| Command | What it does |
| --- | --- |
| `login` | Browser OAuth sign-in, then registers this machine as a device. |
| `register` | Re-register this device using saved credentials (retry after a failed login, no browser needed). |
| `rename <new name>` | Rename this device as it appears on the account. |
| `status` | Shows the account, device registration, and whether the session is still valid. |
| `devices` | Lists all devices, marks which can receive tabs, shows last-active times. |
| `send <device> <url> [title]` | Encrypts and delivers a tab. `<device>` is a list number, an id prefix, or part of the name. Title is fetched from the page if omitted. |
| `receive [--watch] [--open]` | Polls for tabs sent to this client, decrypts and prints them. `--open` launches them in your browser. |
| `clear` | Discards tabs queued for this device without showing them. |
| `logout` | Removes the device and deletes local credentials. |

Flags: `--name`, `--title`, `--interval <seconds>`, `--open`, `--watch`, `--no-browser`.

## Files

```
main.js            CLI: argument parsing and the commands
src/oauth.js       OAuth PKCE + scoped-keys sign-in
src/jwe.js         Compact JWE (ECDH-ES / A256GCM) to unwrap the sync key
src/crypto.js      Sync 1.5 records + WebPush aes128gcm
src/fxa.js         Bearer-authenticated device/command client
src/sendtab.js     Device key bundles, tab encryption/decryption
src/state.js       Credential persistence
src/prompt.js      Terminal prompts
tests/selftest.js  Offline crypto + OAuth self-test
```

## Security notes

- `data/session.json` holds your **OAuth refresh token and the sync key** (the refresh
  token is the credential the device endpoints trust). Anyone who reads it can act as
  your device and decrypt sent tabs. It is chmod 600 on POSIX; on Windows it inherits
  directory ACLs, so keep it off shared drives. `.gitignore` excludes `data/`.
- No password is ever seen or stored — authentication happens entirely in your browser.
- `logout` deletes local credentials and removes the device. To fully revoke the refresh
  token, also remove the device under Firefox Settings → your account → Connected
  services. Set `FXSYNC_HOME` to store state elsewhere.

## Verified vs. untested

Verified offline by `deno task test`: HKDF against RFC 5869; JWE (ECDH-ES / A256GCM)
round-trip with wrong-key rejection — the exact `keys_jwe` shape FxA returns; Sync 1.5
record round-trip with HMAC rejection; aes128gcm across single and multiple records with
wrong-key rejection; a full send-tab round-trip; and the OAuth request builder (PKCE,
`keys_jwk`, scope, redirect parsing).

Verified end to end against a real Firefox Account: browser OAuth sign-in, sync-key
decryption from `keys_jwe`, device registration, listing all devices on the account,
and **sending a tab that a real Firefox desktop received and opened**. This also confirms
the WebPush aes128gcm payload and the encrypted `availableCommands` bundle are
byte-compatible with Firefox's own Send Tab.

Also observed against the live servers: the password-login route is edge-blocked while
sibling routes work (which is why OAuth is used); and device/command endpoints reject the
access token but accept the refresh token.

Two details handled defensively, worth knowing:

- Firefox double-JSON-encodes the plaintext inside device key bundles (a quirk of its
  `CryptoWrapper` round-trip). This client reproduces that on write and accepts both
  forms on read.
- The optional `ttl` field on `invoke_command`; if a deployment rejects it, `send`
  retries without it automatically.
