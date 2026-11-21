import * as assert from "assert";
import * as fs from "fs";
import * as vscode from "vscode";
import type { AsentApi } from "../../../src/extension";

export const FOLDER = process.env.ASENT_TEST_FOLDER!;
export const STUB = process.env.ASENT_TEST_STUB!;
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
