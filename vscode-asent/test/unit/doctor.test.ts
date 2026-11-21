// src/doctor.ts: what the user is told when asent or Docker is missing, from real `asent doctor --json`.
import * as assert from "assert";
import { readDoctor, doctorLines, notFoundLines, dockerMissing, DoctorError, INSTALL_LINES } from "../../src/doctor";
import { fixtureJson } from "./fixtures";

describe("doctor output", () => {
  it("not ready (Docker not installed): every required check that is not ok, with asent's own fix line", () => {
    const raw = fixtureJson("doctor", "doctor.json");
    const doctor = readDoctor(raw);
    assert.strictEqual(doctor.ready, false);
    assert.deepStrictEqual(doctor.problems.map((p) => p.id),
      ["docker", "docker-daemon", "image:asent-sandbox:local", "image:asent-satra-runner:local", "dashboard-ui"]);
    const docker = doctor.problems.find((p) => p.id === "docker")!;
    assert.strictEqual(docker.fix, "Install Docker: https://docs.docker.com/get-docker/");
    assert.strictEqual(docker.required, true);
    assert.strictEqual(doctor.problems.find((p) => p.id === "dashboard-ui")!.required, false);
    assert.ok(dockerMissing(doctor));
  });

  it("the lines shown copy label, detail and fix exactly, required ones first", () => {
    const raw = fixtureJson("doctor", "doctor.json");
    const lines = doctorLines(readDoctor(raw));
    assert.strictEqual(lines[0], "ASENT doctor: not ready (4 required checks need attention). Nothing was changed; run the fixes yourself.");
    const fixes = lines.filter((l) => l.trim().startsWith("fix: "));
    for (const check of raw.checks.filter((c: any) => c.status !== "ok")) {
      assert.ok(fixes.includes(`    fix: ${check.fix}`), check.id);
    }
    assert.ok(lines.indexOf("  MISSING  Docker: " + raw.checks.find((c: any) => c.id === "docker").detail) <
      lines.findIndex((l) => l.includes("Dashboard UI")));
  });

  it("ready: says so, lists nothing, Docker is not missing", () => {
    const raw = fixtureJson("doctor", "doctor.json");
    raw.ready = true;
    raw.checks = raw.checks.filter((c: any) => c.status === "ok");
    const doctor = readDoctor(raw);
    assert.deepStrictEqual(doctor.problems, []);
    assert.strictEqual(dockerMissing(doctor), false);
    assert.deepStrictEqual(doctorLines(doctor), ["ASENT doctor: ready. Everything `asent gate` needs is here."]);
  });

  it("anything else is refused (fail closed, no guessing)", () => {
    for (const bad of [null, [], "x", { schema: "asent.gate.v1" }, { schema: "asent.doctor.v1", ready: "yes", checks: [] },
      { schema: "asent.doctor.v1", ready: false, checks: "none" }]) {
      assert.throws(() => readDoctor(bad), DoctorError, JSON.stringify(bad));
    }
  });

  it("asent not found: names the path and the install commands of README §4.0", () => {
    const lines = notFoundLines("/opt/bin/asent");
    assert.match(lines[0], /asent was not found: "\/opt\/bin\/asent"/);
    for (const install of INSTALL_LINES) assert.ok(lines.includes("  " + install));
    assert.ok(INSTALL_LINES.includes("pipx install git+https://github.com/SheharyarAli-Dev/Working-POC"));
    assert.ok(lines.some((l) => l.includes("asent.path")));
  });
});
