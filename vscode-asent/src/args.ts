// The argument lists the extension gives `asent`. Each value is one array element in `--name=value`
// form, so a value that starts with "-" can never be read as another option, and no shell ever sees it.
import * as path from "path";

export const REPORT_NAME = "asent-report.json";

export function reportFile(folder: string): string {
  return path.join(folder, REPORT_NAME);
}

// `asent gate` with no --repository gates the repository containing the working directory (head HEAD).
// --output-dir puts asent-report.json in the workspace folder, where `report` and the watcher look.
// An empty base is left out: asent then picks the repository's default branch itself.
export function gateArgs(folder: string, base: string): string[] {
  const args = ["gate", "--json", `--output-dir=${folder}`];
  const trimmed = base.trim();
  return trimmed ? [...args, `--base=${trimmed}`] : args;
}

export function reportArgs(file: string): string[] {
  return ["report", "--json", `--file=${file}`];
}

export function initArgs(folder: string): string[] {
  return ["init", "--json", `--repository=${folder}`];
}

export function doctorArgs(): string[] {
  return ["doctor", "--json"];
}

export function dashboardArgs(): string[] {
  return ["dashboard", "--json"];
}
