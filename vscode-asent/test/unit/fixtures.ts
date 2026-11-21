// Reads the real `asent` outputs in test/fixtures (see test/fixtures/README.md).
import * as fs from "fs";
import * as path from "path";

export const FIXTURES = path.join(__dirname, "..", "..", "..", "test", "fixtures");

export function fixturePath(...parts: string[]): string {
  return path.join(FIXTURES, ...parts);
}

export function fixtureText(...parts: string[]): string {
  return fs.readFileSync(fixturePath(...parts), "utf8");
}

export function fixtureJson(...parts: string[]): any {
  return JSON.parse(fixtureText(...parts));
}

export function hasFixture(...parts: string[]): boolean {
  return fs.existsSync(fixturePath(...parts));
}
