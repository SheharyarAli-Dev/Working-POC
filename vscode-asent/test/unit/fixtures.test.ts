// The committed fixtures carry the generator's neutral placeholders, not the paths of the machine
// that wrote them (scripts/make_fixtures.py: neutral()).
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { FIXTURES, fixtureJson } from "./fixtures";

const files = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true })
  .flatMap((e) => (e.isDirectory() ? files(path.join(dir, e.name)) : e.name.endsWith(".json") ? [path.join(dir, e.name)] : []));

describe("fixtures carry neutral paths", () => {
  const all = files(FIXTURES);

  it("there are fixtures to check", () => {
    assert.ok(all.length >= 7, all.join(", "));
  });

  it("no home folder, checkout, scenario temp folder or random temp suffix", () => {
    for (const file of all) {
      const text = fs.readFileSync(file, "utf8");
      assert.doesNotMatch(text, /\/home\/(?!user\b)[^/"]+/, `${file}: a home folder other than /home/user`);
      assert.doesNotMatch(text, /Working-POC|asent-fixture-|pytest-of-|\/Users\/|C:\\\\Users/, file);
      assert.doesNotMatch(text, /\/tmp\/[A-Za-z][\w.-]*-[a-z0-9_]{8}(?=[/"])/, `${file}: a tempfile.mkdtemp folder`);
    }
  });

  it("the placeholders are the documented ones", () => {
    assert.strictEqual(fixtureJson("reports", "accept.json").repository, "/workspace/project");
    assert.strictEqual(fixtureJson("init", "init.json").asent_dir, "/workspace/project/.asent");
    assert.strictEqual(fixtureJson("doctor", "doctor.json").assets, "/opt/asent");
    assert.match(fixtureJson("reports", "accept.json").assurance.run.candidate_workspace, /^\/tmp\/asent-gate-run\/runtime\/workspaces\//);
  });
});
