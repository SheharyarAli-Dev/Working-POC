"""Check a built ASENT wheel before it is uploaded (CI: .github/workflows/package.yml).

    python scripts/ci/check_wheel.py dist/asent-X-py3-none-any.whl [--require-ui]

Fails (exit 1, listing what is wrong) when a required asset, default policy or the `asent` entry point
is missing, when anything other than `backend/` and the dist-info is in the wheel, or, with
--require-ui, when the dashboard build is not bundled. The full file-by-file comparison with the
source tree is tests/test_cli_packaging.py.
"""
import sys
import zipfile

REQUIRED = [
    "backend/cli.py", "backend/config.py",
    "backend/_data/docker/sandbox.Dockerfile", "backend/_data/docker/satra-runner.Dockerfile",
    "backend/_data/docker/satra-runner.requirements.txt", "backend/_data/docker/asent-seccomp.json",
    "backend/_data/docker/asent-sandbox/Dockerfile", "backend/_data/requirements.lock.txt",
    "backend/_data/scenarios/catalog.json", "backend/_data/demo_project/InvoiceHub/pytest.ini",
    "backend/cavr/project_policy.json", "backend/cavr/osv_snapshot.json", "backend/sable/sable_config.json",
    "backend/satra/trusted/policy.json",
]
UI = "backend/_data/frontend/dist/index.html"


def problems(path, require_ui=False):
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        entry_points = next((z.read(n).decode() for n in names if n.endswith(".dist-info/entry_points.txt")), "")
    found = [f"missing {name}" for name in REQUIRED if name not in names]
    if not any(n.startswith("backend/threat_repo/seed/") and n.endswith(".json") for n in names):
        found.append("missing backend/threat_repo/seed/*.json")
    if "asent = backend.cli:entry" not in entry_points:
        found.append("no `asent = backend.cli:entry` console script")
    found += [f"unexpected {n}" for n in sorted(names) if not (n.startswith("backend/") or ".dist-info/" in n)]
    found += [f"unexpected {n}" for n in sorted(names) if "__pycache__" in n or n.endswith(".pyc")]
    if require_ui and UI not in names:
        found.append(f"missing {UI} (build the frontend before the wheel)")
    return found


def main(argv):
    args = [a for a in argv if a != "--require-ui"]
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    found = problems(args[0], "--require-ui" in argv)
    for line in found:
        print(line, file=sys.stderr)
    print(f"{args[0]}: {'FAILED' if found else 'ok'}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
