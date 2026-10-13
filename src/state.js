// Persistent client state. Contains long-lived secrets: the FxA session token
// and the account's derived sync key. Treat the file like a password store.

const DEFAULT_DIR = new URL("../data/", import.meta.url);

function stateDir() {
  const override = Deno.env.get("FXSYNC_HOME");
  return override ? (override.endsWith("/") || override.endsWith("\\") ? override : override + "/") : DEFAULT_DIR;
}

function statePath() {
  const dir = stateDir();
  return typeof dir === "string" ? dir + "session.json" : new URL("session.json", dir);
}

export async function loadState() {
  try {
    const text = await Deno.readTextFile(statePath());
    return JSON.parse(text);
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) return null;
    throw err;
  }
}

export async function saveState(state) {
  const dir = stateDir();
  await Deno.mkdir(dir, { recursive: true });
  const path = statePath();
  await Deno.writeTextFile(path, JSON.stringify(state, null, 2));
  // Best effort on POSIX; a no-op on Windows, where ACL inheritance applies.
  if (Deno.build.os !== "windows") {
    try {
      await Deno.chmod(path, 0o600);
    } catch {
      // not fatal
    }
  }
  return path;
}

export async function clearState() {
  try {
    await Deno.remove(statePath());
    return true;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) return false;
    throw err;
  }
}

export function statePathString() {
  const p = statePath();
  return typeof p === "string" ? p : decodeURIComponent(p.pathname.replace(/^\/([A-Za-z]:)/, "$1"));
}

export async function requireState() {
  const state = await loadState();
  if (!state?.accessToken) {
    throw new Error("Not signed in. Run:  deno run -A main.js login");
  }
  return state;
}
