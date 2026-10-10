# Tool disclosure

| Tool | Use | Notes |
|---|---|---|
| Antigravity IDE agent | Wrote and ran the SATRA code, tests and docs in this repository | Model: Claude (selected in the IDE as "Claude Sonnet 5.5 (Low)") |
| Ollama 0.40.2 (Windows) | Local model server used by SATRA at runtime for optional test proposals | Model `qwen2.5-coder:1.5b`, digest `d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668` |
| Docker Desktop 29.8.2 | Disposable sandbox containers for running candidate code | Used from WSL2 |

## What each produced

- Antigravity produced all code and docs; the owner reviews and defends each file (see `ai-usage-log.md`).
- Ollama produces only candidate pytest proposals. Its output is never an authority: a deterministic validator and deterministic execution decide.

## Privacy and risk notes

- Ollama runs on the owner's machine; no source code is sent to a hosted model. SATRA calls it only from the backend process, never from inside the sandbox.
- Before any model call the context is redacted (secrets, tokens, emails, environment values) and size-limited.
- Ollama is bound to `0.0.0.0` on Windows so WSL can reach it; this exposes the port to the local network. Restrict it with the Windows firewall or bind it to the WSL gateway address if the machine is on an untrusted network.
- The model is small (1.5B parameters) and may produce weak or wrong tests; the validator exists to reject them.
- `GITHUB_TOKEN` is optional, read from the environment and never logged.
