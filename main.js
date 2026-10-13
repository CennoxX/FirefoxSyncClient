#!/usr/bin/env -S deno run --allow-net --allow-read --allow-write --allow-env --allow-run
//
// A minimal Firefox Sync client. Signs in to a Firefox Account through the
// browser (OAuth), registers as a device, and sends tabs to -- or receives
// them from -- your other signed-in machines.

import { COMMAND_SEND_TAB, FxAClient, FxAError, explainError, validationKeys } from "./src/fxa.js";
import { bytesToHex, hexToBytes } from "./src/util.js";
import { clearState, loadState, requireState, saveState, statePathString } from "./src/state.js";
import {
  buildAvailableCommands,
  createSendTabKeys,
  decryptIncomingTab,
  encryptTabFor,
} from "./src/sendtab.js";
import { ask } from "./src/prompt.js";
import {
  createAuthRequest,
  exchangeCode,
  extractSyncKey,
  fetchProfile,
  parseRedirect,
} from "./src/oauth.js";

const USAGE = `
Firefox Sync Client (Deno)

  deno run -A main.js <command> [options]

Account
  login [--name <name>] [--no-browser]
      Sign in with your Firefox Account (opens a browser).
        --name         name this device on the account (default: this PC's hostname)
        --no-browser   print the sign-in URL instead of opening a browser
  logout
      Sign out: remove this device and delete local credentials.
  status
      Show the current account, device, and whether the session is valid.

This device
  register [--name <name>]
      Re-register this device / retry after a failed login (no browser needed).
        --name         name this device (default: keep current, else hostname)
  rename <new name>
      Rename this device as it appears on your account and other devices.

Devices & tabs
  devices
      List every device connected to the account, numbered for use below.
  send <device> <url> [title] [--title <text>]
      Send a tab to another device.
        <device>       a list number, a device id prefix, or part of the name
        title          tab title (positional); or use --title. Default: page title
  receive [--watch] [--open] [--interval <seconds>]
      Fetch tabs other devices sent to this one.
        --watch        keep polling instead of checking once
        --open         open received tabs in your default browser
        --interval     seconds between polls when --watch is set (default 15)
  clear
      Discard all tabs queued for this device without showing or opening them.

  help
      Show this text.
`.trim();

// ---------------------------------------------------------------------------
// argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  const valued = new Set(["name", "title", "interval"]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const [key, inline] = arg.slice(2).split(/=(.*)/s);
      if (valued.has(key)) {
        flags[key] = inline !== undefined ? inline : argv[++i];
      } else {
        flags[key] = inline !== undefined ? inline !== "false" : true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function defaultDeviceName() {
  const host = Deno.env.get("COMPUTERNAME") || Deno.env.get("HOSTNAME") || "unknown-host";
  return `${host} (Deno Sync Client)`;
}

function syncKeyOf(state) {
  if (!state.syncKey) {
    throw new Error("Local state has no sync key. Run `login` again to re-fetch it.");
  }
  return hexToBytes(state.syncKey);
}

function shortId(id) {
  return id.slice(0, 8);
}

function formatTime(ms) {
  if (!ms) return "unknown";
  const delta = Date.now() - ms;
  const mins = Math.round(delta / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function canReceiveTabs(device) {
  return Boolean(device.availableCommands?.[COMMAND_SEND_TAB]);
}

function pickDevice(devices, selector) {
  const asIndex = Number(selector);
  if (Number.isInteger(asIndex) && asIndex >= 1 && asIndex <= devices.length) {
    return devices[asIndex - 1];
  }
  const byId = devices.filter((d) => d.id.startsWith(selector.toLowerCase()));
  if (byId.length === 1) return byId[0];

  const needle = selector.toLowerCase();
  const byName = devices.filter((d) => (d.name || "").toLowerCase().includes(needle));
  if (byName.length === 1) return byName[0];
  if (byName.length > 1) {
    throw new Error(`"${selector}" matches several devices: ${byName.map((d) => d.name).join(", ")}`);
  }
  throw new Error(`No device matches "${selector}". Run \`devices\` to see the list.`);
}

function validateUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`"${raw}" is not a valid URL (include the scheme, e.g. https://...)`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Only http/https URLs can be sent, got "${url.protocol}"`);
  }
  return url.toString();
}

async function fetchTitle(url) {
  try {
    const res = await fetch(url, { headers: { Accept: "text/html" }, signal: AbortSignal.timeout(4000) });
    const html = await res.text();
    const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    if (match) return match[1].replace(/\s+/g, " ").trim().slice(0, 255);
  } catch {
    // Title is cosmetic -- fall through.
  }
  return new URL(url).hostname;
}

function openInBrowser(url) {
  // On Windows, `cmd /c start` treats `&` as a command separator and truncates
  // URLs with query strings. rundll32 takes the URL as one literal argument.
  const spec = Deno.build.os === "windows"
    ? { cmd: "rundll32", args: ["url.dll,FileProtocolHandler", url] }
    : Deno.build.os === "darwin"
    ? { cmd: "open", args: [url] }
    : { cmd: "xdg-open", args: [url] };
  try {
    new Deno.Command(spec.cmd, { args: spec.args, stdout: "null", stderr: "null" }).spawn();
    return true;
  } catch (err) {
    console.error(`  (could not open browser: ${err.message})`);
    return false;
  }
}

/**
 * Builds an FxAClient for the device/command endpoints. These authenticate a
 * device by its OAuth *refresh* token (a device is a refresh token in FxA's
 * model), so that -- not the access token -- is the operative credential.
 */
function makeClient(state) {
  if (!state.refreshToken) {
    throw new Error(
      "This session has no refresh token, which the device/send-tab endpoints require. " +
        "Run `login` again and approve access so an offline (refresh) token is granted.",
    );
  }
  return new FxAClient(state.refreshToken);
}

/**
 * Registers or refreshes this client's device record.
 *
 * Registration is done in two steps -- basic device first, then the send-tab
 * command -- because some deployments reject `availableCommands` at creation
 * time. If attaching the command still fails, the device is left registered
 * (it can send tabs; it just cannot receive them) and the exact rejected field
 * is reported so the cause is visible rather than fatal.
 */
async function ensureDevice(client, state, { name } = {}) {
  const syncKey = syncKeyOf(state);
  if (!state.sendTabKeys) {
    state.sendTabKeys = await createSendTabKeys();
    state.deviceId = null; // keys changed, so the published bundle must change too
  }
  const deviceName = name || state.deviceName || defaultDeviceName();
  const availableCommands = await buildAvailableCommands(syncKey, state.sendTabKeys);

  // Step 1: basic device (create or update). A 107 here is a name/type problem.
  const base = { id: state.deviceId || undefined, name: deviceName, type: "desktop" };
  let device;
  try {
    device = await client.registerDevice(base);
  } catch (err) {
    if (err instanceof FxAError && err.errno === 107) {
      const keys = validationKeys(err);
      throw new Error(
        `Device registration was rejected on field(s): ${keys.join(", ") || "unknown"}. ` +
          "This is the basic device record (name/type), before any send-tab data.",
      );
    }
    throw err;
  }
  state.deviceId = device.id;
  state.deviceName = device.name;
  await saveState(state);

  // Step 2: attach the send-tab command so other devices can reach this one.
  try {
    device = await client.registerDevice({ id: device.id, name: deviceName, type: "desktop", availableCommands });
    state.canReceive = true;
  } catch (err) {
    if (err instanceof FxAError && err.errno === 107) {
      state.canReceive = false;
      const keys = validationKeys(err);
      console.error(
        `\nWarning: the server rejected the send-tab command on field(s): ${keys.join(", ") || "availableCommands"}.`,
      );
      console.error("This device is registered and can SEND tabs, but other devices cannot send");
      console.error("tabs to it until this is resolved. Sending from here still works.\n");
    } else {
      throw err;
    }
  }
  await saveState(state);
  return device;
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

async function cmdLogin({ flags }) {
  const auth = await createAuthRequest();

  console.log("To sign in, open this URL in your browser and approve access:\n");
  console.log(`  ${auth.url}\n`);
  if (!flags["no-browser"]) {
    if (openInBrowser(auth.url)) console.log("(opened in your default browser)\n");
  }
  console.log(
    "After signing in you land on a Firefox 'Sign-in successful' page. Copy that page's\n" +
      "full address from the browser's address bar (it contains ?code=...) and paste it here.\n",
  );

  const pasted = ask("Paste the redirect URL (or just the code):");
  const { code, state: returnedState } = parseRedirect(pasted);
  if (!code) throw new Error("Could not find an authorization code in what you pasted.");
  if (returnedState && returnedState !== auth.state) {
    throw new Error("State mismatch -- the pasted redirect does not match this login attempt.");
  }

  const token = await exchangeCode({ code, codeVerifier: auth.codeVerifier });
  const { syncKey } = await extractSyncKey(token, auth.keysJwkPrivate);
  const profile = await fetchProfile(token.access_token);

  const state = {
    email: profile.email || "(unknown)",
    uid: profile.uid || null,
    accessToken: token.access_token,
    refreshToken: token.refresh_token || null,
    syncKey: bytesToHex(syncKey),
    deviceName: flags.name || defaultDeviceName(),
    deviceId: null,
    sendTabKeys: null,
    commandIndex: 0,
    createdAt: new Date().toISOString(),
  };

  // Persist credentials BEFORE registering the device, so a registration
  // hiccup never forces the user through the browser sign-in again.
  await saveState(state);
  console.log(`\nSigned in as ${state.email}`);
  console.log(`Credentials stored in ${statePathString()} -- keep this file private.`);
  if (!state.refreshToken) {
    console.log("\nNote: no refresh token was granted, so this session ends when the access token");
    console.log("expires (you will need to `login` again). This can happen if offline access was");
    console.log("not approved.");
  }

  const client = makeClient(state);
  try {
    const device = await ensureDevice(client, state, { name: state.deviceName });
    console.log(`Registered device "${device.name}" (${shortId(device.id)})`);
    console.log(`\nNext: \`devices\` to list your machines, then \`send <device> <url>\`.`);
  } catch (err) {
    console.error(`\nSign-in worked, but device registration failed:\n  ${explainError(err)}`);
    console.error("You are still signed in. Retry registration (no browser needed) with:");
    console.error("  deno run -A main.js register");
    Deno.exit(1);
  }
}

async function cmdRegister({ flags }) {
  const state = await requireState();
  const client = makeClient(state);
  const device = await ensureDevice(client, state, { name: flags.name });
  console.log(`Registered device "${device.name}" (${shortId(device.id)})`);
  if (state.canReceive === false) {
    console.log("(send-tab receive is not active on this device -- see the warning above)");
  }
}

async function cmdRename({ flags, positional }) {
  const newName = [...positional, flags.name].filter(Boolean).join(" ").trim();
  if (!newName) throw new Error("Usage: rename <new name>");
  const state = await requireState();
  const client = makeClient(state);
  const device = await ensureDevice(client, state, { name: newName });
  console.log(`Renamed this device to "${device.name}".`);
}

async function cmdStatus() {
  const state = await loadState();
  if (!state?.accessToken) {
    console.log("Not signed in. Run:  deno run -A main.js login");
    return;
  }
  console.log(`Account:   ${state.email}${state.uid ? ` (${state.uid})` : ""}`);
  console.log(`Device:    ${state.deviceName || "-"}${state.deviceId ? ` (${shortId(state.deviceId)})` : " (not registered)"}`);
  console.log(`State:     ${statePathString()}`);
  console.log(`Signed in: ${state.createdAt || "unknown"}`);
  const client = makeClient(state);
  try {
    const { devices } = { devices: await client.listDevices() };
    console.log(`Session:   ok (${devices.length} device(s) visible)`);
  } catch (err) {
    console.log(`Session:   invalid -- ${explainError(err)}`);
  }
}

async function listDevices(client) {
  const devices = await client.listDevices();
  devices.sort((a, b) => (a.isCurrentDevice ? -1 : b.isCurrentDevice ? 1 : 0));
  return devices;
}

async function cmdDevices() {
  const state = await requireState();
  const client = makeClient(state);
  const devices = await listDevices(client);

  if (devices.length === 0) {
    console.log("No devices found on this account.");
    return;
  }
  console.log(`${devices.length} device(s) on ${state.email}:\n`);
  devices.forEach((d, i) => {
    const tags = [
      d.type || "unknown",
      d.isCurrentDevice ? "this client" : null,
      canReceiveTabs(d) ? "can receive tabs" : "no send-tab support",
    ].filter(Boolean);
    console.log(`  ${String(i + 1).padStart(2)}. ${d.name}`);
    console.log(`      id ${shortId(d.id)}  ${tags.join("  |  ")}`);
    console.log(`      last active ${formatTime(d.lastAccessTime)}`);
  });
  console.log(`\nSend a tab with:  deno run -A main.js send <number|name> <url>`);
}

async function cmdSend({ flags, positional }) {
  const [selector, rawUrl, ...titleParts] = positional;
  if (!selector || !rawUrl) throw new Error("Usage: send <device> <url> [title]");
  const url = validateUrl(rawUrl);

  const state = await requireState();
  const client = makeClient(state);
  const devices = await listDevices(client);
  const target = pickDevice(devices, selector);
  if (target.isCurrentDevice) {
    console.log("Note: the target is this client itself; run `receive` to read it back.");
  }

  const title = flags.title || titleParts.join(" ") || (await fetchTitle(url));
  const payload = await encryptTabFor(syncKeyOf(state), target, { url, title });
  const command = { target: target.id, command: COMMAND_SEND_TAB, payload };
  try {
    await client.invokeCommand({ ...command, ttl: 60 * 60 * 24 });
  } catch (err) {
    // `ttl` is optional; if this deployment's schema rejects it, send without.
    if (err instanceof FxAError && err.errno === 107) {
      await client.invokeCommand(command);
    } else {
      throw err;
    }
  }

  console.log(`Sent to ${target.name}:`);
  console.log(`  ${title}`);
  console.log(`  ${url}`);
  if (!target.isCurrentDevice) {
    console.log("\nIt appears on that machine as a Firefox notification (or in its tab list).");
  }
}

async function pollOnce(client, state, { open }) {
  const res = await client.fetchCommands(state.commandIndex ?? 0);
  const messages = res.messages || [];
  let received = 0;

  for (const message of messages) {
    // The `index` query parameter is inclusive, so the cursor must point one
    // past the last message seen, or that message is returned again next time.
    if (typeof message.index === "number") {
      state.commandIndex = Math.max(state.commandIndex ?? 0, message.index + 1);
    }
    const data = message.data || {};
    if (data.command !== COMMAND_SEND_TAB) continue;
    try {
      const tabs = await decryptIncomingTab(state.sendTabKeys, data.payload);
      const sender = data.sender?.name || "another device";
      for (const tab of tabs) {
        received++;
        console.log(`\nFrom ${sender}:`);
        console.log(`  ${tab.title || "(no title)"}`);
        console.log(`  ${tab.url}`);
        if (open && tab.url) {
          try {
            openInBrowser(validateUrl(tab.url));
          } catch (err) {
            console.error(`  (not opening: ${err.message})`);
          }
        }
      }
    } catch (err) {
      console.error(`  Could not decrypt a command from the server: ${err.message}`);
    }
  }

  await saveState(state);
  return received;
}

async function cmdReceive({ flags }) {
  const state = await requireState();
  const client = makeClient(state);
  if (!state.sendTabKeys || !state.deviceId) {
    console.log("This client is not registered as a device yet; registering now...");
    await ensureDevice(client, state);
  }

  const total = await pollOnce(client, state, { open: Boolean(flags.open) });
  if (!flags.watch) {
    if (total === 0) console.log("No new tabs.");
    return;
  }

  const interval = Math.max(5, Number(flags.interval) || 15) * 1000;
  console.log(`${total === 0 ? "No new tabs. " : ""}Watching for incoming tabs (Ctrl-C to stop)...`);
  while (true) {
    await new Promise((r) => setTimeout(r, interval));
    try {
      await pollOnce(client, state, { open: Boolean(flags.open) });
    } catch (err) {
      console.error(`Poll failed: ${explainError(err)}`);
    }
  }
}

async function cmdClear() {
  const state = await requireState();
  const client = makeClient(state);
  if (!state.deviceId) {
    console.log("This device isn't registered, so there is nothing queued for it.");
    return;
  }

  // Drain the queue: fetch pages and advance our index past them, discarding
  // the contents. Loops until a page comes back empty (or the index stops
  // moving, as a safety net against an unexpected server response).
  let cleared = 0;
  while (true) {
    const start = state.commandIndex ?? 0;
    const res = await client.fetchCommands(start);
    const messages = res.messages || [];
    for (const message of messages) {
      if (typeof message.index === "number") {
        state.commandIndex = Math.max(state.commandIndex ?? 0, message.index + 1);
      }
      if (message.data?.command === COMMAND_SEND_TAB) cleared++;
    }
    if (messages.length === 0) break;
    if ((state.commandIndex ?? 0) <= start) break; // no progress -- stop
  }
  await saveState(state);
  console.log(
    cleared === 0
      ? "No pending tabs to clear."
      : `Cleared ${cleared} pending tab(s); they will not be shown on the next receive.`,
  );
}

async function cmdLogout() {
  const state = await loadState();
  if (!state?.accessToken) {
    console.log("Not signed in.");
    return;
  }
  const client = makeClient(state);
  if (state.deviceId) {
    try {
      await client.destroyDevice(state.deviceId);
      console.log("Device removed from the account.");
    } catch (err) {
      console.error(`Could not remove the device: ${explainError(err)}`);
    }
  }
  await clearState();
  console.log("Local credentials deleted.");
  console.log("To fully revoke access, also remove this device under");
  console.log("  Firefox Settings -> your account -> Connected devices/services.");
}

// ---------------------------------------------------------------------------

const COMMANDS = {
  login: cmdLogin,
  register: cmdRegister,
  rename: cmdRename,
  status: cmdStatus,
  devices: cmdDevices,
  send: cmdSend,
  receive: cmdReceive,
  clear: cmdClear,
  logout: cmdLogout,
  help: () => console.log(USAGE),
};

async function main() {
  const { flags, positional } = parseArgs(Deno.args);
  const name = positional.shift() || "help";
  const command = COMMANDS[name];
  if (!command) {
    console.error(`Unknown command "${name}".\n`);
    console.log(USAGE);
    Deno.exit(2);
  }
  try {
    await command({ flags, positional });
  } catch (err) {
    console.error(`\nError: ${err instanceof FxAError ? explainError(err) : err.message}`);
    Deno.exit(1);
  }
}

if (import.meta.main) {
  await main();
}
