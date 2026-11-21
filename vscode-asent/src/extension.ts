// ASENT for VS Code: runs the installed `asent` CLI (always --json, always an argument array) and
// shows what it printed: a report panel, a status bar item and Problems entries. It decides nothing
// itself, stores nothing, and sends nothing anywhere; the only address it opens is the local
// dashboard URL that `asent dashboard --json` printed.
import * as vscode from "vscode";
import * as fs from "fs";
import * as os from "os";
import { runAsent, startDashboard, AsentNotFound, AsentOutputError, AsentCancelled, Dashboard, RunResult } from "./cli";
import { gateArgs, reportArgs, initArgs, doctorArgs, dashboardArgs, reportFile } from "./args";
import { fromJson, GateReport, ReportError, Decision } from "./report";
import { readDoctor, doctorLines, notFoundLines, dockerMissing, DoctorError } from "./doctor";
import { locate } from "./diagnostics";
import { ReportPanel } from "./panel";

const LOCAL_DASHBOARD = /^http:\/\/127\.0\.0\.1:\d{1,5}\/$/;
const GATE_TIMEOUT_MS = 30 * 60 * 1000;
const SHORT_TIMEOUT_MS = 60 * 1000;
const NOT_RUN_FOR = new Set(["not assessed (disabled by base config)", "not applicable"]);

/** Read-only view for the extension test; it exposes nothing the user could not already see. */
export interface AsentApi {
  state(): {
    statusText: string; decision: Decision | null; gateRunning: boolean; dashboardRunning: boolean;
    dashboardPid: number | undefined; panelHtml: string | undefined;
  };
}

let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let problems: vscode.DiagnosticCollection;
let panel: ReportPanel;
let last: { folder: string; report: GateReport } | null = null;
let gateRunning = false;
let dashboard: { process: Dashboard; url: string } | null = null;
let dashboardStarting = false;

export function activate(context: vscode.ExtensionContext): AsentApi {
  output = vscode.window.createOutputChannel("ASENT");
  problems = vscode.languages.createDiagnosticCollection("asent");
  panel = new ReportPanel();
  status = vscode.window.createStatusBarItem("asent.status", vscode.StatusBarAlignment.Left, 100);
  status.name = "ASENT gate";
  status.command = "asent.showReport";
  setStatus(null);
  status.show();
  context.subscriptions.push(output, problems, status, { dispose: () => panel.dispose() }, { dispose: stopDashboard },
    vscode.commands.registerCommand("asent.init", () => guarded(initProject)),
    vscode.commands.registerCommand("asent.gate", () => guarded(runGate)),
    vscode.commands.registerCommand("asent.showReport", () => guarded(showReport)),
    vscode.commands.registerCommand("asent.doctor", () => guarded(doctor)),
    vscode.commands.registerCommand("asent.dashboard", () => guarded(openDashboard)),
    vscode.commands.registerCommand("asent.stopDashboard", () => guarded(stopDashboardCommand)));

  const folder = currentFolder();
  if (folder) {
    const watcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(folder, "asent-report.json"));
    let timer: NodeJS.Timeout | undefined;
    const reload = () => {
      clearTimeout(timer);
      timer = setTimeout(() => { if (!gateRunning) void loadReport(folder.uri.fsPath, false); }, 300);
    };
    watcher.onDidCreate(reload);
    watcher.onDidChange(reload);
    watcher.onDidDelete(() => { if (last?.folder === folder.uri.fsPath) clearReport(); });
    context.subscriptions.push(watcher);
    if (fs.existsSync(reportFile(folder.uri.fsPath))) void loadReport(folder.uri.fsPath, false);
  }

  return {
    state: () => ({ statusText: status.text, decision: last?.report.decision ?? null, gateRunning,
      dashboardRunning: dashboard !== null, dashboardPid: dashboard?.process.process.pid, panelHtml: panel.visibleHtml }),
  };
}

export function deactivate(): void {
  stopDashboard();
}

// --- helpers ---------------------------------------------------------------------------------

function currentFolder(): vscode.WorkspaceFolder | undefined {
  const active = vscode.window.activeTextEditor?.document.uri;
  return (active && vscode.workspace.getWorkspaceFolder(active)) || vscode.workspace.workspaceFolders?.[0];
}

function asentPath(folder?: vscode.WorkspaceFolder): string {
  // In an untrusted folder VS Code ignores the workspace's value (restrictedConfigurations).
  return vscode.workspace.getConfiguration("asent", folder?.uri).get<string>("path", "asent").trim() || "asent";
}

async function guarded(command: () => Promise<void>): Promise<void> {
  try {
    await command();
  } catch (e) {
    reportError(e);
  }
}

function needFolder(): vscode.WorkspaceFolder | undefined {
  const folder = currentFolder();
  if (!folder) void vscode.window.showWarningMessage("ASENT: open a folder (a git repository) first.");
  return folder;
}

/** Init, Run gate and Dashboard run asent on this folder's code: only in a trusted folder. */
function needTrust(title: string): boolean {
  if (vscode.workspace.isTrusted) return true;
  void vscode.window.showWarningMessage(
    `ASENT: "${title}" is disabled because this folder is not trusted: it runs asent on the folder's code. ` +
    `Trust the folder to use it. "ASENT: Show report" still works.`, "Manage Workspace Trust")
    .then((choice) => { if (choice) void vscode.commands.executeCommand("workbench.trust.manage"); });
  return false;
}

function show(lines: string[]): void {
  output.appendLine(`--- ${new Date().toISOString()}`);
  for (const line of lines) output.appendLine(line);
}

function reportError(e: unknown): void {
  if (e instanceof AsentNotFound) {
    const lines = notFoundLines(e.asentPath);
    show(e.code === "ENOENT" ? lines : [e.message, ...lines.slice(1)]);
    void vscode.window.showErrorMessage(`ASENT: ${e.message}. Install asent, or set asent.path.`, "Show details", "Open settings")
      .then((choice) => {
        if (choice === "Show details") output.show(true);
        if (choice === "Open settings") void vscode.commands.executeCommand("workbench.action.openSettings", "asent.path");
      });
  } else if (e instanceof AsentCancelled) {
    void vscode.window.showWarningMessage(`ASENT: ${e.message}.`);
  } else if (e instanceof AsentOutputError) {
    show([e.message]);
    void vscode.window.showErrorMessage(`ASENT: ${e.message.split("\n")[0]}`, "Show details", "Run Doctor")
      .then((choice) => {
        if (choice === "Show details") output.show(true);
        if (choice === "Run Doctor") void vscode.commands.executeCommand("asent.doctor");
      });
  } else {
    const message = e instanceof Error ? e.message : String(e);
    show([message]);
    void vscode.window.showErrorMessage(`ASENT: ${message}`);
  }
}

function errorOf(result: RunResult): string | null {
  const json = result.json as Record<string, unknown> | null;
  return json && typeof json === "object" && typeof json.error === "string" ? json.error : null;
}

// --- report: status bar, Problems, panel -------------------------------------------------------

function setStatus(report: GateReport | null, running = false): void {
  status.backgroundColor = undefined;
  if (running) {
    status.text = "$(sync~spin) ASENT: gate running";
    status.tooltip = "asent gate is running";
    return;
  }
  if (!report) {
    status.text = "$(shield) ASENT";
    status.tooltip = "No ASENT gate report in this folder yet. Click to open the panel.";
    return;
  }
  status.text = `$(shield) ASENT: ${report.decision}`;
  status.tooltip = `ASENT gate ${report.decision}: base ${report.base.ref ?? "?"} -> head ${report.head.ref ?? "?"}` +
    `${report.generatedAt ? ` (${report.generatedAt})` : ""}. Click to open the report.`;
  if (report.decision === "BLOCK") status.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  if (report.decision === "REVIEW") status.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
}

function useReport(folder: string, report: GateReport): void {
  last = { folder, report };
  setStatus(report);
  problems.clear();
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of locate(report.findings, folder, report.repository)) {
    const line = Math.max(0, f.line);
    const d = new vscode.Diagnostic(new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER), f.message,
      f.severity === "error" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning);
    d.source = f.source;
    byFile.set(f.file, [...(byFile.get(f.file) ?? []), d]);
  }
  for (const [file, list] of byFile) problems.set(vscode.Uri.file(file), list);
  panel.refresh(report);
}

function clearReport(): void {
  last = null;
  setStatus(null);
  problems.clear();
  panel.refresh(null, "asent-report.json was removed from this folder.");
}

/** `asent report --json --file=<folder>/asent-report.json`; returns the error text when there is no usable report. */
async function loadReport(folder: string, loud: boolean): Promise<string | null> {
  let result: RunResult;
  try {
    result = await runAsent(asentPath(vscode.workspace.getWorkspaceFolder(vscode.Uri.file(folder))), reportArgs(reportFile(folder)),
      { cwd: folder, timeoutMs: SHORT_TIMEOUT_MS });
  } catch (e) {
    if (loud) throw e;
    show([`Reading the report failed: ${e instanceof Error ? e.message : String(e)}`]);
    return e instanceof Error ? e.message : String(e);
  }
  const error = errorOf(result);
  if (error) {
    if (last?.folder === folder) clearReport();
    return error;
  }
  try {
    useReport(folder, fromJson(result.json));
    return null;
  } catch (e) {
    if (!(e instanceof ReportError)) throw e;
    return e.message;
  }
}

// --- commands ----------------------------------------------------------------------------------

async function showReport(): Promise<void> {
  const folder = needFolder();
  if (!folder) return;
  const error = await loadReport(folder.uri.fsPath, true);
  if (error) {
    panel.show(null, `${error}\n`);
    return;
  }
  panel.show(last!.report);
}

async function runGate(): Promise<void> {
  if (gateRunning) {
    void vscode.window.showInformationMessage("ASENT: a gate run is already in progress.");
    return;
  }
  const folder = needFolder();
  if (!folder || !needTrust("Run gate on this branch")) return;
  const base = vscode.workspace.getConfiguration("asent", folder.uri).get<string>("baseBranch", "");
  const cwd = folder.uri.fsPath;
  gateRunning = true;
  setStatus(null, true);
  let report: GateReport;
  try {
    const result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "ASENT: running asent gate", cancellable: true },
      (_progress, token) => {
        const controller = new AbortController();
        token.onCancellationRequested(() => controller.abort());
        return runAsent(asentPath(folder), gateArgs(cwd, base), { cwd, timeoutMs: GATE_TIMEOUT_MS, signal: controller.signal });
      });
    report = fromJson(result.json);
  } catch (e) {
    setStatus(last?.report ?? null);
    throw e;
  } finally {
    gateRunning = false;
  }
  useReport(cwd, report);
  panel.show(report);
  const text = `ASENT gate: ${report.decision}` + (report.reasons.length ? ` (${report.reasons[0]})` : "");
  const notify = report.decision === "ACCEPT" ? vscode.window.showInformationMessage
    : report.decision === "REVIEW" ? vscode.window.showWarningMessage : vscode.window.showErrorMessage;
  void notify(text);
  await warnIfDockerMissing(report, folder);
}

/** SATRA needs Docker; when the report says Docker was not there for an enabled SATRA, show doctor's fixes. */
async function warnIfDockerMissing(report: GateReport, folder: vscode.WorkspaceFolder): Promise<void> {
  const satra = report.modules.find((m) => m.key === "SATRA");
  const engine = report.tools.docker === true || report.tools.podman === true;
  if (engine || !satra || NOT_RUN_FOR.has(satra.result ?? "")) return;
  const result = await runAsent(asentPath(folder), doctorArgs(), { cwd: os.homedir(), timeoutMs: SHORT_TIMEOUT_MS });
  const doc = readDoctor(result.json);
  if (!dockerMissing(doc)) return;
  show(doctorLines(doc));
  void vscode.window.showWarningMessage(
    "ASENT: Docker is not available, so SATRA could not run the trusted tests in its sandbox (SATRA is INCONCLUSIVE, the gate REVIEW).",
    "Show doctor's fixes").then((choice) => { if (choice) output.show(true); });
}

async function doctor(): Promise<void> {
  const folder = currentFolder();
  // doctor checks this machine, not the folder: it runs in the home directory.
  const result = await runAsent(asentPath(folder), doctorArgs(), { cwd: os.homedir(), timeoutMs: SHORT_TIMEOUT_MS });
  let doc;
  try {
    doc = readDoctor(result.json);
  } catch (e) {
    if (e instanceof DoctorError) throw new Error(`${e.message}: ${errorOf(result) ?? "unexpected output"}`);
    throw e;
  }
  show(doctorLines(doc));
  output.show(true);
  if (doc.ready) void vscode.window.showInformationMessage("ASENT doctor: ready. Everything `asent gate` needs is here.");
  else void vscode.window.showWarningMessage(doctorLines(doc)[0] + " The fix lines are in the ASENT output.");
}

async function initProject(): Promise<void> {
  const folder = needFolder();
  if (!folder || !needTrust("Init project")) return;
  const result = await runAsent(asentPath(folder), initArgs(folder.uri.fsPath), { cwd: folder.uri.fsPath, timeoutMs: SHORT_TIMEOUT_MS });
  const error = errorOf(result);
  if (error) {
    void vscode.window.showErrorMessage(`ASENT init: ${error}`);
    return;
  }
  const json = result.json as { files?: unknown; not_copied?: unknown };
  const files = Array.isArray(json.files) ? json.files.map(String) : [];
  const notCopied = Array.isArray(json.not_copied) ? json.not_copied.map(String) : [];
  show(["asent init wrote:", ...files.map((f) => "  " + f),
    ...(notCopied.length ? ["Not approved (not an exact pin): " + notCopied.join(", ")] : [])]);
  void vscode.window.showInformationMessage(`ASENT: starter written (${files.join(", ")}). Review every file in .asent/, then remove ` +
    `"_starter" from .asent/config.json; until then every gate decision is REVIEW.`);
}

async function openDashboard(): Promise<void> {
  if (dashboard || dashboardStarting) {
    const url = dashboard?.url;
    void vscode.window.showInformationMessage(`ASENT: the dashboard is already running${url ? ` at ${url}` : " (starting)"}.`, ...(url ? ["Open"] : []))
      .then((choice) => { if (choice && url) void openLocal(url); });
    return;
  }
  const folder = needFolder();
  if (!folder || !needTrust("Open web dashboard")) return;
  dashboardStarting = true;
  let started: Dashboard;
  try {
    started = await startDashboard(asentPath(folder), dashboardArgs(), { cwd: folder.uri.fsPath });
  } finally {
    dashboardStarting = false;
  }
  const url = (started.info as { url?: unknown }).url;
  if (typeof url !== "string" || !LOCAL_DASHBOARD.test(url)) {
    started.stop();
    throw new Error(`asent dashboard printed an address that is not http://127.0.0.1:PORT/: ${JSON.stringify(url)}`);
  }
  dashboard = { process: started, url };
  started.process.once("exit", (code) => {
    if (dashboard?.process === started) dashboard = null;
    show([`asent dashboard stopped (exit ${code ?? "signal"}).`]);
  });
  show([`asent dashboard running at ${url} (this machine only). It stops when this VS Code window closes.`]);
  await openLocal(url);
}

async function openLocal(url: string): Promise<void> {
  if (LOCAL_DASHBOARD.test(url)) await vscode.env.openExternal(vscode.Uri.parse(url));
}

function stopDashboard(): void {
  dashboard?.process.stop();
  dashboard = null;
}

/** "ASENT: Stop dashboard": stops only the process this window started. Allowed in untrusted folders: it runs nothing. */
async function stopDashboardCommand(): Promise<void> {
  if (dashboardStarting) {
    void vscode.window.showInformationMessage("ASENT: the dashboard is still starting; stop it once it is running.");
    return;
  }
  if (!dashboard) {
    void vscode.window.showInformationMessage("ASENT: the dashboard is not running.");
    return;
  }
  const url = dashboard.url;
  stopDashboard();
  show([`asent dashboard at ${url} stopped on request.`]);
  void vscode.window.showInformationMessage(`ASENT: dashboard at ${url} stopped.`);
}
