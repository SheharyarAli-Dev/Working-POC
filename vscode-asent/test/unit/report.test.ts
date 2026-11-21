// src/report.ts on real `asent gate --json` reports (test/fixtures/reports), and on broken input.
import * as assert from "assert";
import { parseReport, fromJson, ReportError, GateReport } from "../../src/report";
import { fixtureJson, fixtureText, hasFixture } from "./fixtures";

const card = (report: GateReport, key: string) => {
  const found = report.modules.find((m) => m.key === key);
  assert.ok(found, `no ${key} card`);
  return found;
};

describe("parseReport on real gate reports", () => {
  it("ACCEPT: decision, commits, config digest, CAVR pass and disabled modules never shown as passed", () => {
    const raw = fixtureJson("reports", "accept.json");
    const report = parseReport(fixtureText("reports", "accept.json"));
    assert.strictEqual(report.decision, "ACCEPT");
    assert.strictEqual(report.exitCode, 0);
    assert.deepStrictEqual(report.base, { ref: raw.base.ref, sha: raw.base.sha });
    assert.deepStrictEqual(report.head, { ref: raw.head.ref, sha: raw.head.sha });
    assert.strictEqual(report.configDigest, raw.config.digest);
    assert.match(report.configDigest ?? "", /^[0-9a-f]{64}$/);
    assert.deepStrictEqual(report.modules.map((m) => [m.key, m.title]), [["CAVR", "CAVR"], ["SATRA", "SATRA-RV"], ["SABLE", "SABLE"]]);
    const cavr = card(report, "CAVR");
    assert.strictEqual(cavr.result, "pass");
    assert.strictEqual(cavr.status, "VERIFIED");
    assert.strictEqual(cavr.reason, raw.modules.CAVR.reason);
    for (const key of ["SATRA", "SABLE"]) {
      assert.strictEqual(card(report, key).result, "not assessed (disabled by base config)");
      assert.strictEqual(card(report, key).assessed, false);
    }
    assert.strictEqual(report.findings.length, 0, "an ACCEPT has nothing for the Problems tab");
  });

  it("ACCEPT: CAVR key evidence names the verified package with its real SHA-256", () => {
    const report = parseReport(fixtureText("reports", "accept.json"));
    const evidence = card(report, "CAVR").evidence.join("\n");
    assert.match(evidence, /requirements\.txt: VERIFIED ALL_CHECKS_PASSED/);
    assert.match(evidence, /pypdf==6\.19\.0: VERIFIED, sha256 7e5d6e730e7d/);
  });

  it("CAVR BLOCK: the denylist rule is the evidence, and requirements.txt goes to the Problems tab without a line", () => {
    const report = parseReport(fixtureText("reports", "cavr-block.json"));
    assert.strictEqual(report.decision, "BLOCK");
    assert.strictEqual(report.exitCode, 1);
    assert.deepStrictEqual(report.reasons, ["CAVR: REJECTED"]);
    const cavr = card(report, "CAVR");
    assert.strictEqual(cavr.result, "block");
    assert.strictEqual(cavr.status, "REJECTED");
    assert.match(cavr.evidence.join("\n"), /requirements\.txt: BLOCK DENYLIST: reqeusts is on the project denylist/);
    assert.deepStrictEqual(report.findings, [{
      module: "CAVR", file: "requirements.txt", line: null, severity: "error",
      message: "CAVR BLOCK DENYLIST: reqeusts is on the project denylist: typosquat of requests",
    }]);
  });

  it("REVIEW: config changed in head is shown, although CAVR itself passes", () => {
    const report = parseReport(fixtureText("reports", "review.json"));
    assert.strictEqual(report.decision, "REVIEW");
    assert.strictEqual(report.exitCode, 2);
    assert.strictEqual(report.configChangedInHead, true);
    assert.deepStrictEqual(report.reasons, ["ASENT configuration changed in this change; requires maintainer review"]);
    assert.strictEqual(card(report, "CAVR").result, "pass");
    assert.strictEqual(report.findings.length, 0);
  });

  it("SABLE BLOCK: obligation, successor and the unexpected resource are the key evidence; no Problems entry without a line", () => {
    const report = parseReport(fixtureText("reports", "sable-block.json"));
    assert.strictEqual(report.decision, "BLOCK");
    const sable = card(report, "SABLE");
    assert.strictEqual(sable.result, "block");
    assert.strictEqual(sable.status, "REGRESSED");
    const evidence = sable.evidence.join("\n");
    assert.match(evidence, /invoice-data: REGRESSED: Missing, widened or misbound role-to-asset authorization/);
    assert.match(evidence, /successor module\.storage\.aws_s3_bucket\.active_invoices/);
    assert.match(evidence, /unexpected resource \$\{module\.storage\.aws_s3_bucket\.archive_invoices\.arn\}\/\*/);
    assert.strictEqual(report.findings.length, 0);
  });

  const satra = hasFixture("reports", "satra-block.json") ? it : it.skip;
  satra("SATRA BLOCK: REJECT with the failing trusted tests as evidence " +
    (hasFixture("reports", "satra-block.json") ? "" : "(SKIPPED: test/fixtures/reports/satra-block.json needs Docker; " +
      "run the manual workflow 'VS Code extension fixtures' and commit its satra-block.json)"), () => {
    const report = parseReport(fixtureText("reports", "satra-block.json"));
    assert.strictEqual(report.decision, "BLOCK");
    assert.strictEqual(report.exitCode, 1);
    const row = card(report, "SATRA");
    assert.strictEqual(row.title, "SATRA-RV");
    assert.strictEqual(row.result, "block");
    assert.strictEqual(row.status, "REJECT");
    const evidence = row.evidence.join("\n");
    assert.match(evidence, /APPLICATION_REGRESSION: failing test test_other_user_denied/);
    assert.match(evidence, /trusted_candidate: \d+ passed, [1-9]\d* failed/);
  });
});

describe("parseReport refuses anything that is not an ASENT gate report", () => {
  const accept = () => fixtureJson("reports", "accept.json");

  it("not JSON", () => {
    assert.throws(() => parseReport("{broken"), (e: unknown) => e instanceof ReportError && /not valid JSON/.test(e.message));
  });

  it("JSON that is not an object", () => {
    for (const text of ["[]", "null", "42", '"ACCEPT"']) {
      assert.throws(() => parseReport(text), ReportError, text);
    }
  });

  it("another schema (e.g. the doctor's output)", () => {
    assert.throws(() => parseReport(fixtureText("doctor", "doctor.json")), /expected schema asent\.gate\.v1/);
  });

  it("an unknown decision is never mapped to one of the three", () => {
    for (const decision of ["PASS", "accept", "", null]) {
      assert.throws(() => fromJson({ ...accept(), decision }), /unknown decision/);
    }
  });

  it("a missing module row", () => {
    const raw = accept();
    delete raw.modules.SATRA;
    assert.throws(() => fromJson(raw), /SATRA is missing/);
  });

  it("missing base/head objects", () => {
    assert.throws(() => fromJson({ ...accept(), base: null }), /base/);
  });

  it("odd field types become null instead of guesses, and nothing crashes", () => {
    const raw = accept();
    raw.config.digest = 12;
    raw.modules.CAVR.reason = { not: "text" };
    raw.assurance = "not an object";
    raw.reasons = "one string";
    const report = fromJson(raw);
    assert.strictEqual(report.configDigest, null);
    assert.strictEqual(card(report, "CAVR").reason, null);
    assert.deepStrictEqual(card(report, "CAVR").evidence, []);
    assert.deepStrictEqual(report.reasons, []);
  });
});

describe("Problems entries from CAVR package call sites", () => {
  // Derived input, not a fixture: the real ACCEPT report with ONLY the package's status changed to a
  // rejection, because no recorded real run rejects a package that the project calls. It checks that
  // the call sites the report lists (file + line) become the locations.
  it("a rejected package is reported at each call site the report lists", () => {
    const raw = fixtureJson("reports", "accept.json");
    const record = raw.assurance.evidence.find((e: any) => e.evidence_id === raw.modules.CAVR.evidence_id);
    const entry = record.details.pipeline[0];
    Object.assign(entry, { status: "BLOCK", mapped: "REJECTED", rule: "ADVISORY", reason: "derived for this test" });
    Object.assign(entry.packages[0], { status: "BLOCK", mapped: "REJECTED", rule: "ADVISORY", reason: "derived for this test" });
    const findings = fromJson(raw).findings;
    assert.deepStrictEqual(findings.map((f) => [f.file, f.line, f.severity]), [
      ["requirements.txt", null, "error"],
      ["app/pdf_adapter.py", 7, "error"],
      ["app/pdf_adapter.py", 8, "error"],
    ]);
    assert.strictEqual(findings[1].message, "CAVR BLOCK ADVISORY: pypdf==6.19.0 is called here (pypdf.apply_configuration): derived for this test");
  });

  it("UNRESOLVED is a warning, not an error", () => {
    const raw = fixtureJson("reports", "cavr-block.json");
    const record = raw.assurance.evidence.find((e: any) => e.evidence_id === raw.modules.CAVR.evidence_id);
    Object.assign(record.details.pipeline[0], { status: "UNRESOLVED", mapped: "UNRESOLVED" });
    assert.strictEqual(fromJson(raw).findings[0].severity, "warning");
  });

  it("entries with no usable file, or a line that is not a positive integer, are left out or file-level", () => {
    const raw = fixtureJson("reports", "accept.json");
    const record = raw.assurance.evidence.find((e: any) => e.evidence_id === raw.modules.CAVR.evidence_id);
    const entry = record.details.pipeline[0];
    Object.assign(entry, { mapped: "REJECTED", file: 7 });
    Object.assign(entry.packages[0], { mapped: "REJECTED" });
    entry.packages[0].contract.call_sites = [{ file: "a.py", line: 0 }, { file: "", line: 3 }, { file: "b.py", line: 2.5 }];
    assert.deepStrictEqual(fromJson(raw).findings.map((f) => [f.file, f.line]), [["a.py", null], ["b.py", null]]);
  });
});
