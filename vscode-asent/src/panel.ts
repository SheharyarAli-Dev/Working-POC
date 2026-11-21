// The one ASENT report panel (a webview). It shows HTML from html.ts and nothing else: no scripts,
// no command links, no local files, no messages to or from the page.
import * as vscode from "vscode";
import * as crypto from "crypto";
import { renderPanel } from "./html";
import { GateReport } from "./report";

export class ReportPanel {
  private panel: vscode.WebviewPanel | undefined;
  private html: string | undefined;

  show(report: GateReport | null, message?: string): void {
    if (!this.panel) {
      this.panel = vscode.window.createWebviewPanel("asent.report", "ASENT report", vscode.ViewColumn.Active, {
        enableScripts: false,
        enableCommandUris: false,
        enableForms: false,
        localResourceRoots: [],
      });
      this.panel.onDidDispose(() => { this.panel = undefined; this.html = undefined; });
    } else {
      this.panel.reveal(undefined, true);
    }
    this.render(report, message);
  }

  /** Re-render if the panel is open (a new report arrived); never opens it. */
  refresh(report: GateReport | null, message?: string): void {
    if (this.panel) this.render(report, message);
  }

  get visibleHtml(): string | undefined {
    return this.html;
  }

  dispose(): void {
    this.panel?.dispose();
  }

  private render(report: GateReport | null, message?: string): void {
    const nonce = crypto.randomBytes(16).toString("base64");
    this.html = renderPanel(report, { nonce, message });
    this.panel!.webview.html = this.html;
  }
}
