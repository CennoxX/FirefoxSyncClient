// Terminal input helpers.

import { dec, enc } from "./util.js";

export function ask(message, { required = true } = {}) {
  while (true) {
    const value = globalThis.prompt(message);
    if (value === null) Deno.exit(130);
    const trimmed = value.trim();
    if (trimmed || !required) return trimmed;
  }
}

/** Reads a line without echoing it. Falls back to a visible prompt if not a TTY. */
export async function askHidden(message) {
  if (!Deno.stdin.isTerminal()) return ask(message);

  await Deno.stdout.write(enc.encode(message + " "));
  Deno.stdin.setRaw(true);
  const bytes = [];
  const buf = new Uint8Array(1);
  try {
    while (true) {
      const n = await Deno.stdin.read(buf);
      if (n === null) break;
      const c = buf[0];
      if (c === 13 || c === 10) break; // Enter
      if (c === 3) {
        // Ctrl-C
        Deno.stdin.setRaw(false);
        console.log();
        Deno.exit(130);
      }
      if (c === 127 || c === 8) {
        bytes.pop();
        continue;
      }
      bytes.push(c);
    }
  } finally {
    Deno.stdin.setRaw(false);
  }
  console.log();
  return dec.decode(new Uint8Array(bytes));
}
