// Starts the installed `asent` CLI and reads the one JSON document it prints with --json.
//
// Always child_process.spawn(executable, argumentArray, { shell: false }): no shell parses anything,
// so no value from a setting, a path or a report can become a command. No vscode import, so the
// unit tests run it in plain Node against test/stub/asent.
import { spawn, ChildProcess, SpawnOptions } from "child_process";
import * as fs from "fs";
import * as path from "path";

const MAX_OUTPUT = 64 * 1024 * 1024; // a gate report with full evidence is well under 1 MB
const STDERR_TAIL = 2000;

export interface RunOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface RunResult {
  exitCode: number | null;
  json: unknown;
  stderr: string;
}

/**
 * The executable could not be started (ENOENT: not found; EACCES: not executable; NOT_ABSOLUTE: asent.path
 * is a relative path, which would depend on the working directory).
 */
export class AsentNotFound extends Error {
  constructor(public readonly asentPath: string, public readonly code: string) {
    super(code === "ENOENT"
      ? `asent was not found: "${asentPath}" (setting asent.path)`
      : code === "NOT_ABSOLUTE"
        ? `asent.path must be a command name on PATH or an absolute path, not "${asentPath}"`
        : `asent could not be started: "${asentPath}" (${code}; setting asent.path)`);
  }
}

export interface ResolveOptions {
  platform?: NodeJS.Platform; // default process.platform
  env?: NodeJS.ProcessEnv; // where PATH is read (default process.env)
  excluded?: string[]; // the workspace folders: PATH entries equal to or inside one are skipped
  isExecutable?: (file: string) => boolean;
  realpath?: (p: string) => string; // throws when the path does not exist
}

function defaultIsExecutable(platform: NodeJS.Platform) {
  return (file: string): boolean => {
    try {
      if (!fs.statSync(file).isFile()) return false;
      if (platform !== "win32") fs.accessSync(file, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  };
}

/**
 * The absolute path of the asent to start. An absolute asent.path is used as it is. A bare name is looked up
 * here, on PATH, instead of by spawn: on Windows spawn searches the child's working directory before PATH, so a
 * repository's own asent.exe would run. Empty, "." and other relative PATH entries are skipped (they mean the
 * working directory), and so is every entry that is, or after realpath lies in, a workspace folder; a found
 * file whose realpath lies in a workspace folder is skipped too. A relative path with a separator is refused.
 */
export function resolveAsent(configured: string, options: ResolveOptions = {}): string {
  const platform = options.platform ?? process.platform;
  const win = platform === "win32";
  const p = win ? path.win32 : path.posix;
  const env = options.env ?? process.env;
  const isExecutable = options.isExecutable ?? defaultIsExecutable(platform);
  const realpath = options.realpath ?? ((x: string) => fs.realpathSync.native(x));
  const real = (x: string): string | null => {
    try {
      return realpath(x);
    } catch {
      return null;
    }
  };
  if (p.isAbsolute(configured)) return configured;
  if (configured.includes("/") || (win && (configured.includes("\\") || configured.includes(":")))) {
    throw new AsentNotFound(configured, "NOT_ABSOLUTE");
  }
  const inside = (root: string, target: string) => {
    const rel = p.relative(root, target);
    return rel === "" || (rel !== ".." && !rel.startsWith(".." + p.sep) && !p.isAbsolute(rel));
  };
  const roots = (options.excluded ?? []).flatMap((r) => [p.resolve(r), real(r)]).filter((r): r is string => r !== null);
  const inWorkspace = (x: string) => roots.some((r) => inside(r, x));
  const key = win ? Object.keys(env).find((k) => k.toUpperCase() === "PATH") : "PATH";
  const entries = ((key && env[key]) || "").split(win ? ";" : ":");
  const names = win && !p.extname(configured) ? [configured + ".com", configured + ".exe"] : [configured];
  for (const raw of entries) {
    const entry = win ? raw.replace(/^"(.*)"$/, "$1") : raw;
    if (!entry || !p.isAbsolute(entry) || inWorkspace(entry)) continue;
    const realEntry = real(entry);
    if (realEntry === null || inWorkspace(realEntry)) continue;
    for (const name of names) {
      const file = p.join(entry, name);
      if (!isExecutable(file)) continue;
      const realFile = real(file);
      if (realFile !== null && !inWorkspace(realFile)) return file;
    }
  }
  throw new AsentNotFound(configured, "ENOENT");
}

/** asent ran but did not print one JSON document on stdout (e.g. a crash with a Python traceback). */
export class AsentOutputError extends Error {
  constructor(public readonly command: string, public readonly exitCode: number | null, public readonly stderr: string) {
    super(`asent ${command} printed no JSON (exit ${exitCode ?? "none"})` + (stderr.trim() ? `: ${stderr.trim()}` : ""));
  }
}

export class AsentCancelled extends Error {
  constructor(public readonly reason: "cancelled" | "timed out") {
    super(`asent was stopped: ${reason}`);
  }
}

function checkArgs(args: string[]): void {
  for (const a of args) if (typeof a !== "string" || a.includes("\0")) throw new Error("asent argument contains a NUL byte");
}

function spawnAsent(asentPath: string, args: string[], cwd: string, env?: NodeJS.ProcessEnv): ChildProcess {
  const options: SpawnOptions = { cwd, env: env ?? process.env, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] };
  return spawn(asentPath, args, options);
}

const tail = (s: string) => (s.length > STDERR_TAIL ? "…" + s.slice(-STDERR_TAIL) : s);

export function runAsent(asentPath: string, args: string[], options: RunOptions): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    checkArgs(args);
    if (options.signal?.aborted) return reject(new AsentCancelled("cancelled"));
    const child = spawnAsent(asentPath, args, options.cwd, options.env);
    const out: Buffer[] = [];
    let outSize = 0;
    let err = "";
    let stopped: AsentCancelled | null = null;
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      fn();
    };
    const stop = (reason: "cancelled" | "timed out") => {
      stopped = new AsentCancelled(reason);
      child.kill("SIGTERM");
      setTimeout(() => child.exitCode === null && child.kill("SIGKILL"), 3000).unref();
    };
    const onAbort = () => stop("cancelled");
    options.signal?.addEventListener("abort", onAbort);
    const timer = options.timeoutMs ? setTimeout(() => stop("timed out"), options.timeoutMs) : undefined;

    child.stdout!.on("data", (chunk: Buffer) => {
      outSize += chunk.length;
      if (outSize > MAX_OUTPUT) stop("cancelled");
      else out.push(chunk);
    });
    child.stderr!.on("data", (chunk: Buffer) => { err = tail(err + chunk.toString("utf8")); });
    child.on("error", (e: NodeJS.ErrnoException) => {
      finish(() => reject(e.code === "ENOENT" || e.code === "EACCES" || e.code === "ENOTDIR"
        ? new AsentNotFound(asentPath, e.code) : e));
    });
    child.on("close", (code) => {
      finish(() => {
        if (stopped) return reject(stopped);
        const text = Buffer.concat(out).toString("utf8").trim();
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch {
          return reject(new AsentOutputError(args[0] ?? "", code, err));
        }
        resolve({ exitCode: code, json, stderr: err });
      });
    });
  });
}

export interface Dashboard {
  info: unknown; // the one line `asent dashboard --json` prints before serving
  process: ChildProcess;
  stop(): void;
}

/** Starts `asent dashboard --json`, waits for its first stdout line, and leaves it serving. */
export function startDashboard(asentPath: string, args: string[], options: RunOptions): Promise<Dashboard> {
  return new Promise((resolve, reject) => {
    checkArgs(args);
    const child = spawnAsent(asentPath, args, options.cwd, options.env);
    let buffered = "";
    let err = "";
    let settled = false;
    const stop = () => {
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        setTimeout(() => child.exitCode === null && child.kill("SIGKILL"), 3000).unref();
      }
    };
    const timer = setTimeout(() => fail(new AsentCancelled("timed out")), options.timeoutMs ?? 30000);
    function fail(e: Error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stop();
      reject(e);
    }
    // Success is one JSON line printed before serving (cli.dashboard_command: json.dumps(info)). An error
    // ({"error": ...}, e.g. port in use) is an indented multi-line document, after which asent exits.
    const parse = (text: string): unknown => {
      try {
        return JSON.parse(text);
      } catch {
        return undefined;
      }
    };
    const handle = (doc: unknown) => {
      if (typeof doc === "object" && doc !== null && "error" in doc) {
        return fail(new Error(String((doc as { error: unknown }).error)));
      }
      settled = true;
      clearTimeout(timer);
      resolve({ info: doc, process: child, stop });
    };
    child.stdout!.on("data", (chunk: Buffer) => {
      if (settled) return; // after the first line the server's output is not read
      buffered += chunk.toString("utf8");
      const newline = buffered.indexOf("\n");
      const doc = newline < 0 ? undefined : parse(buffered.slice(0, newline)) ?? parse(buffered.trim());
      if (doc !== undefined) handle(doc);
    });
    child.stderr!.on("data", (chunk: Buffer) => { err = tail(err + chunk.toString("utf8")); });
    child.on("error", (e: NodeJS.ErrnoException) => fail(e.code === "ENOENT" || e.code === "EACCES" || e.code === "ENOTDIR"
      ? new AsentNotFound(asentPath, e.code) : e));
    child.on("close", (code) => {
      if (settled) return;
      const doc = parse(buffered.trim());
      if (typeof doc === "object" && doc !== null && "error" in doc) return handle(doc);
      fail(new AsentOutputError("dashboard", code, err));
    });
  });
}
