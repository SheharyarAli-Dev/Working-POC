"""`asent doctor`: what this machine has and lacks for `asent gate`, each with a plain fix.

It only looks. The only commands it runs are `git --version`, `docker info` and
`docker image inspect`; it never builds or pulls images, starts containers, calls sudo or writes a
file. Fixes are printed for the person to run (tests/test_cli_doctor.py checks this).

Required (exit 1 when any is not ok): Python >= 3.12, the packaged resources, git, Docker installed,
the Docker daemon reachable, and the two images the official gate workflow builds
(`asent-sandbox:local`, `asent-satra-runner:local`). Optional: the bundled dashboard UI.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import sys

from backend.config import ASSETS, DATA, INSTALLED, ROOT, VERSION

MIN_PYTHON = (3, 12)
TIMEOUT = 15
# image -> (Dockerfile, build context), both relative to ASSETS; the same commands as scripts/satra_build_sandbox.sh
IMAGES = {
    "asent-sandbox:local": ("docker/sandbox.Dockerfile", "."),
    "asent-satra-runner:local": ("docker/satra-runner.Dockerfile", "docker"),
}
RESOURCES = ("docker/sandbox.Dockerfile", "docker/satra-runner.Dockerfile", "docker/satra-runner.requirements.txt",
             "docker/asent-seccomp.json", "docker/asent-sandbox/Dockerfile", "requirements.lock.txt")
POLICIES = ("cavr/project_policy.json", "cavr/osv_snapshot.json", "sable/sable_config.json", "satra/trusted/policy.json")
NO_DOCKER_MEANS = ("Without it SATRA cannot run the project's tests in its sandbox, so an enabled SATRA is "
                   "INCONCLUSIVE and the gate decides REVIEW (CAVR and SABLE gate checks do not need Docker).")


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)


def build_command(image):
    dockerfile, context = IMAGES[image]
    context_path = ASSETS if context == "." else ASSETS / context
    # Text for the person to run; doctor itself never runs it.
    return f"docker build -t {image} -f {shlex.quote(str(ASSETS / dockerfile))} {shlex.quote(str(context_path))}"


def ui_bundled():
    return (ASSETS / "frontend" / "dist" / "index.html").is_file()


def _check(id, label, status, detail, fix=None, required=True):
    return {"id": id, "label": label, "status": status, "required": required, "detail": detail,
            "fix": None if status == "ok" else fix}


def _probe(run, argv):
    try:
        done = run(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    text = (done.stdout or "").strip() if done.returncode == 0 else (done.stderr or done.stdout or "").strip()
    return done.returncode == 0, " ".join(text.split())[-300:]


def run_checks(which=shutil.which, run=_run, version_info=None, assets=None):
    assets = ASSETS if assets is None else assets
    version = tuple(version_info or sys.version_info)[:3]
    checks = []
    shown = ".".join(str(part) for part in version)
    checks.append(_check("python", "Python", "ok" if version[:2] >= MIN_PYTHON else "missing",
                         f"Python {shown} ({sys.executable})",
                         "Install Python 3.12 or newer and reinstall ASENT with it, e.g. "
                         "`pipx install --python python3.12 git+https://github.com/SheharyarAli-Dev/Working-POC`."))

    package = ROOT / "backend"
    missing = [name for name in RESOURCES if not (assets / name).is_file()]
    missing += [f"backend/{name}" for name in POLICIES if not (package / name).is_file()]
    if not any((package / "threat_repo" / "seed").glob("*.json")):
        missing.append("backend/threat_repo/seed/*.json")
    checks.append(_check("resources", "ASENT files (Dockerfiles, seccomp profile, lockfile, default policies)",
                         "missing" if missing else "ok",
                         ("Missing: " + ", ".join(missing)) if missing else
                         f"ASENT {VERSION} at {package} ({'installed package' if INSTALLED else 'source checkout'})",
                         "This install is incomplete; reinstall ASENT (`pipx reinstall asent`, or "
                         "`pip install --force-reinstall` of the same wheel)."))

    if which("git"):
        ok, text = _probe(run, ["git", "--version"])
        checks.append(_check("git", "git", "ok" if ok else "missing", text if ok else f"git did not run: {text}",
                             "Reinstall git (https://git-scm.com/downloads)."))
    else:
        checks.append(_check("git", "git", "missing", "git is not on PATH; `asent gate` reads both commits with git.",
                             "Install git (https://git-scm.com/downloads) and make sure it is on PATH."))

    daemon = False
    if which("docker"):
        checks.append(_check("docker", "Docker", "ok", f"docker at {which('docker')}"))
        daemon, text = _probe(run, ["docker", "info", "--format", "{{.ServerVersion}}"])
        checks.append(_check("docker-daemon", "Docker daemon", "ok" if daemon else "missing",
                             f"Docker server {text}" if daemon else f"Docker is installed but its daemon is not reachable: {text}. "
                             + NO_DOCKER_MEANS,
                             "Start Docker (Docker Desktop, or `sudo systemctl start docker` on Linux) and make sure "
                             "your user may use it (`docker info` must work without sudo)."))
    else:
        checks.append(_check("docker", "Docker", "missing", "Docker is not installed (no `docker` on PATH). " + NO_DOCKER_MEANS,
                             "Install Docker: https://docs.docker.com/get-docker/"))
        checks.append(_check("docker-daemon", "Docker daemon", "skipped", "not checked: Docker is not installed",
                             "Install Docker first."))

    for image in IMAGES:
        label = f"Docker image {image}"
        if not daemon:
            checks.append(_check("image:" + image, label, "skipped", "not checked: the Docker daemon is not reachable",
                                 "When Docker works, build it: " + build_command(image)))
            continue
        ok, text = _probe(run, ["docker", "image", "inspect", "--format", "{{.Id}}", image])
        checks.append(_check("image:" + image, label, "ok" if ok else "missing",
                             f"present ({text[:19]})" if ok else f"{image} is not built on this machine.",
                             build_command(image)))

    bundled = ui_bundled()
    checks.append(_check("dashboard-ui", "Dashboard UI", "ok" if bundled else "warning",
                         "bundled" if bundled else
                         ("This install has no dashboard UI (an install from git cannot include it)" if INSTALLED else
                          "frontend/dist is not built in this checkout")
                         + ", so `asent dashboard` serves the API only.",
                         "Install the wheel built by CI (artifact `asent-wheel`), which includes the UI; in a checkout run "
                         "`npm ci --prefix frontend && npm run build --prefix frontend`.", required=False))

    ready = all(c["status"] == "ok" for c in checks if c["required"])
    return {"schema": "asent.doctor.v1", "version": VERSION, "ready": ready, "assets": str(assets),
            "data_dir": str(DATA), "checks": checks}


MARK = {"ok": "ok", "missing": "MISSING", "warning": "warning", "skipped": "skipped"}


def render(result) -> str:
    lines = [f"ASENT doctor (asent {result['version']})", ""]
    for c in result["checks"]:
        lines.append(f"  {MARK[c['status']]:<8} {c['label']}: {c['detail']}")
        if c["fix"]:
            lines.append(f"  {'':<8} fix: {c['fix']}")
    bad = [c for c in result["checks"] if c["required"] and c["status"] != "ok"]
    lines += ["", "Ready: everything `asent gate` needs is here." if result["ready"] else
              f"Not ready: {len(bad)} required check(s) need attention (see fix: lines above). "
              "doctor changed nothing; run the fixes yourself."]
    return "\n".join(lines) + "\n"
