"""C1 pip wrapper: run the CAVR pipeline before pip, and only let pip install what was verified.

    python -m backend.cavr.pip_shim install pypdf==6.19.0              decide only
    python -m backend.cavr.pip_shim install pypdf==6.19.0 --install    decide, then install if VERIFIED

What the wrapper does, in order:

1. Takes its own options out of the arguments (`split_arguments`). The rest is the pip command.
2. Reads the project policy and calls `pipeline.verify_request` with the pip command.
3. Prints the verdict and its evidence.
4. Without `--install` it stops here. Exit code 0 on VERIFIED, 1 REJECTED, 2 UNRESOLVED, 3 BLOCK.
5. With `--install`, and only when the verdict is VERIFIED, it writes a requirements file that
   lists every file of the verified tree as `name==version --hash=sha256:<digest>` and runs

       python -m pip install <PIP_INSTALL_OPTIONS> -r <that file>

   The exit code is then 0 when pip succeeds and 4 when it does not.

Why pip cannot install something else than what was verified:

- The arguments the user typed are never passed to pip. They are only read by the capture.
  pip gets a fixed option list and the generated file, so `--index-url`, `--no-binary`, `-e`
  and the like cannot reach it (the capture already makes such a request UNRESOLVED).
- `--require-hashes` makes pip refuse any file whose SHA-256 is not the one in the generated
  file, and that digest is the one the pipeline computed from the bytes it analysed. pip
  downloads the file again, but a different file cannot pass.
- `--no-deps` stops pip from resolving dependencies on its own: the generated file already
  holds the whole verified tree, and nothing outside it is installed.
- `--only-binary :all:` keeps pip from building an sdist (which would run its setup code).

The wrapper's own options (anywhere before a `--`):

    --install             install after a VERIFIED verdict (default: decide only)
    --cavr-project DIR    the project being changed (default: the current directory)
    --cavr-policy FILE    the project policy (default: $CAVR_POLICY, else DIR/cavr-policy.json)
    --cavr-python PATH    the interpreter whose pip installs (default: the one running this)
    --cavr-json           print the whole verdict as JSON instead of the summary

A policy file that is missing is not replaced by another one: the verdict is UNRESOLVED.
Only `pip install` is handled. Any other pip command is UNRESOLVED and is not passed on.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from packaging.version import InvalidVersion, Version

from backend.cavr.pipeline import verify_request
from backend.cavr.requirement_gate import load_json_file
from backend.cavr.storage import CavrStorage

POLICY_FILE_NAME = "cavr-policy.json"
POLICY_ENVIRONMENT_VARIABLE = "CAVR_POLICY"
PYPI_INDEX = "https://pypi.org/simple/"

# Everything pip is told, apart from the generated file. `--isolated` makes pip ignore PIP_*
# environment variables and the user's pip configuration, so they cannot add an index or an option.
PIP_INSTALL_OPTIONS = ("--isolated", "--disable-pip-version-check", "--no-input", "--index-url", PYPI_INDEX,
                       "--require-hashes", "--no-deps", "--only-binary", ":all:")

EXIT_CODES = {"VERIFIED": 0, "REJECTED": 1, "UNRESOLVED": 2, "BLOCK": 3}
EXIT_USAGE = 2
EXIT_INSTALL_FAILED = 4

FLAG_OPTIONS = {"--install": "install", "--cavr-json": "json"}
VALUE_OPTIONS = {"--cavr-project": "project", "--cavr-policy": "policy", "--cavr-python": "python"}
CANONICAL_NAME = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")
SHA256 = re.compile(r"[0-9a-f]{64}")


def main(argv=None, *, pip_runner=None, out=None, store=None, **verify_options) -> int:
    """Run the wrapper and return its exit code.

    `argv` is the arguments after the program name (default: `sys.argv[1:]`). The keyword
    arguments are for tests: `pip_runner(command) -> return code` replaces the real pip, `out`
    replaces stdout, `store` replaces the default `CavrStorage`, and anything else is passed
    to `verify_request` (`transport`, `quarantine_dir`, `advisory_cache_dir`, ...).
    """
    out = out or sys.stdout
    options, pip_arguments, problem = split_arguments(sys.argv[1:] if argv is None else argv)
    if problem:
        print(f"cavr pip wrapper: {problem}\nnothing was verified and nothing was installed", file=out)
        return EXIT_USAGE

    project = Path(options["project"]) if options["project"] else Path.cwd()
    policy_path = options["policy"] or os.environ.get(POLICY_ENVIRONMENT_VARIABLE) or project / POLICY_FILE_NAME
    try:
        verdict = verify_request(["pip", *pip_arguments], project, load_json_file(Path(policy_path)),
                                 store if store is not None else _default_store(), **verify_options)
    except Exception as exc:  # the pipeline returns verdicts and should not raise; if it does, that is "unknown"
        verdict = {"status": "UNRESOLVED", "stage": "internal", "rule": "INTERNAL_ERROR",
                   "reason": f"the pipeline failed: {type(exc).__name__}: {exc}", "packages": []}

    install = _install(verdict, options, pip_runner or subprocess.call)
    code = EXIT_CODES.get(verdict.get("status"), EXIT_CODES["UNRESOLVED"])
    if options["install"] and code == 0 and install["returncode"] != 0:
        code = EXIT_INSTALL_FAILED
    if options["json"]:
        print(json.dumps({"verdict": verdict, "install": install, "exit_code": code}, indent=2, default=str), file=out)
    else:
        print(render(verdict, install), file=out)
    return code


def split_arguments(argv):
    """Separate the wrapper's options from the pip command.

    Returns (options, pip arguments, problem). `problem` is None or a sentence; when it is
    set nothing may be verified or installed. Everything from a `--` on belongs to pip.
    """
    options = {"install": False, "json": False, "project": None, "policy": None, "python": None}
    if not isinstance(argv, (list, tuple)) or not all(isinstance(token, str) for token in argv):
        return options, [], "the arguments must be a list of strings"
    rest = []
    position = 0
    while position < len(argv):
        token = argv[position]
        position += 1
        if token == "--":
            rest += argv[position - 1:]
            break
        name, equals, value = token.partition("=")
        if name in FLAG_OPTIONS:
            if equals:
                return options, [], f"{name} takes no value"
            options[FLAG_OPTIONS[name]] = True
        elif name in VALUE_OPTIONS:
            if not equals:
                if position >= len(argv):
                    return options, [], f"{name} needs a value"
                value = argv[position]
                position += 1
            if not value:
                return options, [], f"{name} needs a value"
            options[VALUE_OPTIONS[name]] = value
        elif token.startswith("--cavr-"):
            return options, [], f"unknown option {name}"
        else:
            rest.append(token)
    return options, rest, None


def install_plan(verdict):
    """The requirements-file lines for a VERIFIED verdict: one `name==version --hash=sha256:...` per file.

    Returns (lines, None), or (None, why) when the verdict is anything but a fully verified
    tree. The values are checked again here, because each line is read by pip: a name, version
    or digest that is not exactly one could otherwise add an option or a second requirement.
    """
    if not isinstance(verdict, dict) or verdict.get("status") != "VERIFIED":
        return None, "the verdict is not VERIFIED"
    pins = {}
    try:
        for package in verdict["packages"]:
            label = f"{package['package']}=={package['version']}"
            if package["status"] != "VERIFIED":
                return None, f"{label} is not VERIFIED"
            tree = package["evidence"]["tree"]
            if (tree["result"], tree["rule"]) != ("OK", "TREE_BUILT"):
                return None, f"the dependency tree was not built for {label}"
            for node in tree["nodes"]:
                name, version, sha256 = node["name"], node["version"], node["sha256"]
                if not isinstance(name, str) or not CANONICAL_NAME.fullmatch(name):
                    return None, f"{name!r} is not a package name"
                if not _is_exact_version(version):
                    return None, f"{version!r} is not a version"
                if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
                    return None, f"{sha256!r} is not a SHA-256"
                if pins.setdefault(name, (version, sha256)) != (version, sha256):
                    return None, f"two different files for {name} were verified; pip can install only one"
    except (KeyError, TypeError, AttributeError) as exc:
        return None, f"the verdict's evidence is incomplete: {type(exc).__name__}: {exc}"
    if not pins:
        return None, "the verdict has no verified package to install"
    return [f"{name}=={version} --hash=sha256:{sha256}" for name, (version, sha256) in sorted(pins.items())], None


def render(verdict: dict, install: dict) -> str:
    """The verdict and its evidence as text."""
    request = verdict.get("request") or {}
    gate = verdict.get("gate") or {}
    lines = [f"CAVR verdict: {verdict.get('status')}",
             f"  stage: {verdict.get('stage')}   rule: {verdict.get('rule')}",
             f"  reason: {verdict.get('reason')}",
             f"  request: {' '.join(str(token) for token in request.get('command') or [])}",
             f"  fast_gate_ms: {verdict.get('fast_gate_ms')}   cache_hit: {verdict.get('cache_hit')}   "
             f"escalated: {verdict.get('escalated')}"]
    if verdict.get("escalation"):
        lines.append(f"  escalation: {verdict['escalation']}")
    for key in ("unsupported", "errors"):
        lines += [f"  not captured ({item.get('reason')}): {item.get('raw')}" for item in request.get(key) or []]
    if gate:
        lines.append(f"  gate: {gate.get('result')} ({gate.get('rule')})   policy version: {verdict.get('policy_version')}")
    for package in verdict.get("packages") or []:
        lines += _render_package(package)
    lines.append("install: " + install["summary"])
    lines += ["  " + line for line in install["lines"] or []]
    if install["command"]:
        lines.append("  command: " + " ".join(install["command"]))
    return "\n".join(lines)


# --- internals ---------------------------------------------------------------

def _default_store():
    """The shared CAVR database, or None (no cache, no log) when it cannot be opened."""
    try:
        return CavrStorage()
    except Exception:
        return None


def _is_exact_version(version) -> bool:
    """True for a version written exactly as `packaging` writes it (`6.19.0`, not ` 6.19.0` or `>=6`)."""
    try:
        return isinstance(version, str) and str(Version(version)) == version
    except InvalidVersion:
        return False


def _install(verdict: dict, options: dict, pip_runner) -> dict:
    """Run pip when it was asked for and the verdict allows it. Always returns the same keys."""
    result = {"requested": options["install"], "performed": False, "returncode": None, "lines": None, "command": None,
              "summary": "not requested; nothing was installed (run again with --install after a VERIFIED verdict)"}
    if not options["install"]:
        return result
    lines, problem = install_plan(verdict)
    if problem:
        result["summary"] = f"refused; {problem}; nothing was installed"
        return result
    result["lines"] = lines
    with tempfile.TemporaryDirectory(prefix="cavr-install-") as directory:
        requirements = Path(directory) / "verified-requirements.txt"
        requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
        command = [options["python"] or sys.executable, "-m", "pip", "install", *PIP_INSTALL_OPTIONS, "-r", str(requirements)]
        result["command"] = command
        try:
            result["returncode"] = pip_runner(command)
        except OSError as exc:
            result["summary"] = f"pip could not be started: {type(exc).__name__}: {exc}; nothing was installed"
            return result
    result["performed"] = True
    result["summary"] = f"pip exited with {result['returncode']}"
    return result


def _render_package(package: dict) -> list[str]:
    evidence = package.get("evidence") or {}
    artifact, tree, contract = (evidence.get(key) or {} for key in ("artifact", "tree", "contract"))
    reachability, cache = evidence.get("reachability") or {}, package.get("cache") or {}
    lines = [f"package {package.get('package')}=={package.get('version')}: {package.get('status')} "
             f"({package.get('stage')} / {package.get('rule')})",
             f"  reason: {package.get('reason')}"]
    if artifact:
        lines += [f"  artifact: {artifact.get('filename')} {artifact.get('rule')}",
                  f"    sha256 {artifact.get('sha256')}", f"    registry {artifact.get('registry_sha256')}"]
    if tree:
        lines.append(f"  tree: {tree.get('rule')}, {len(tree.get('nodes') or [])} file(s), subtree digest {tree.get('subtree_digest')}")
        lines += [f"    {node.get('name')}=={node.get('version')} sha256 {node.get('sha256')}" for node in tree.get("nodes") or []]
    if contract:
        lines.append(f"  contract: {contract.get('rule')}, {len(contract.get('call_sites') or [])} call site(s), "
                     f"digest {contract.get('digest')}")
    for advisory in evidence.get("advisories") or []:
        ids = ", ".join(str(match.get("id")) for match in advisory.get("affected") or [])
        lines.append(f"  advisories: {advisory.get('name')} {advisory.get('version')} {advisory.get('rule')}" + (f" ({ids})" if ids else ""))
    for scan in evidence.get("scan") or []:
        lines.append(f"  scan: {scan.get('package')} {scan.get('rule')} ({scan.get('python_files')} Python files)")
    for sink in reachability.get("sinks") or []:
        lines.append(f"  sink: {sink.get('file')}:{sink.get('line')} {sink.get('sink')} {sink.get('verdict')}")
    lines.append(f"  cache: {cache.get('lookup')}" + (", stored" if cache.get("stored") else ""))
    return lines


if __name__ == "__main__":
    sys.exit(main())
