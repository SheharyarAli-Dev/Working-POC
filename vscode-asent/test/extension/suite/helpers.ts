import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import type { AsentApi } from "../../../src/extension";

export const FOLDER = process.env.ASENT_TEST_FOLDER!;
export const STUB = process.env.ASENT_TEST_STUB!;
/** The bare command name runTest.ts gives the stub on PATH (unique, so an asent installed on the machine cannot answer). */
export const STUB_NAME = process.env.ASENT_TEST_STUB_NAME!;
const LOG = process.env.ASENT_STUB_LOG!;
const CONTROL = process.env.ASENT_STUB_CONTROL!;
export const ID = "asent-fyp.asent-vscode";

export interface Call { argv: string[]; cwd: string }

export function calls(): Call[] {
  if (!fs.existsSync(LOG)) return [];
  return fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

export function callsOf(command: string): Call[] {
  return calls().filter((c) => c.argv[0] === command);
}

/** A fake asent that runTest.ts put in the workspace folder (first on PATH) ran: it writes HIJACKED. */
export function hijacked(): boolean {
  return fs.existsSync(path.join(FOLDER, "HIJACKED"));
}

export function stub(control: { gate?: string; mode?: string }): void {
  fs.writeFileSync(CONTROL, JSON.stringify(control));
}

export async function api(): Promise<AsentApi> {
  const extension = vscode.extensions.getExtension<AsentApi>(ID);
  assert.ok(extension, `${ID} is not installed in the test instance`);
  return extension.isActive ? extension.exports : extension.activate();
}

export async function until(what: string, test: () => boolean | Promise<boolean>, ms = 10000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await test()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.fail(`timed out waiting for: ${what}`);
}

/**
 * Replaces vscode.env.openExternal with a recorder, so a test never opens a real browser tab.
 * VS Code leaves vscode.env writable only while extension tests run (it is frozen otherwise), and the
 * extension under test gets the same `vscode` API object as these test files.
 */
export function stubOpenExternal(): { opened: string[]; restore(): void } {
  const env = vscode.env as { openExternal: typeof vscode.env.openExternal };
  const original = env.openExternal;
  const opened: string[] = [];
  const recorder = async (target: vscode.Uri) => {
    opened.push(target.toString(true));
    return true;
  };
  env.openExternal = recorder;
  assert.strictEqual(vscode.env.openExternal, recorder, "vscode.env.openExternal could not be stubbed");
  return { opened, restore: () => { env.openExternal = original; } };
}

/** URLs that reached the operating system's opener anyway (the PATH shims of runTest.ts log them). */
export function urlsThatReachedTheOs(): string[] {
  const log = process.env.ASENT_TEST_OPEN_LOG;
  if (!log || !fs.existsSync(log)) return [];
  return fs.readFileSync(log, "utf8").split("\n").filter(Boolean);
}
