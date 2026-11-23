"""The CAVR sandbox image `asent-cavr-sandbox:local` and its identity check (PR 3 of docs/cavr-m2-plan.md, Q6). Fail closed.

The image is CAVR's own (SATRA's is `asent-sandbox:local`). It is built only by `build()` (shell wrapper
`docker/cavr-sandbox/build.sh`), which

  1. runs `docker build` with the label `org.asent.cavr.recipe-sha256` = SHA-256 of `docker/cavr-sandbox/Dockerfile`,
  2. reads the new image's ID with `docker image inspect`,
  3. writes {image, image_id, recipe_sha256, base, built_at} to `record_path()` (`DATA/cavr/sandbox-image.json`).

`image_identity()` runs before every sandbox run. It is ok only when the image exists, its ID equals the recorded
one, and its label equals the SHA-256 of the Dockerfile in this checkout. Every other case is not ok, with a rule:

    ENGINE_UNAVAILABLE   no docker binary, the daemon cannot be reached, or inspect timed out
    IMAGE_MISSING        the engine answers but has no image of that name
    IMAGE_NOT_RECORDED   no build record, or one that cannot be read (built some other way, or never built)
    IMAGE_ID_MISMATCH    the image's ID is not the recorded one (rebuilt or re-tagged outside build())
    IMAGE_STALE          the image's recipe label is not the SHA-256 of the current Dockerfile
    SECCOMP_MISSING      the CAVR seccomp profile is missing or not a JSON object
    ENGINE_ERROR         anything else inspect said

The sandbox then runs the image by its checked ID, never by tag, so the tag cannot be moved between check and run.
`docker build` is not reproducible (apt packages change), so the expected ID is the one recorded at build time,
not a constant in the source.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from backend.config import ASSETS, DATA

IMAGE = "asent-cavr-sandbox:local"
DIRECTORY = ASSETS / "docker" / "cavr-sandbox"
DOCKERFILE = DIRECTORY / "Dockerfile"
SECCOMP_PROFILE = DIRECTORY / "cavr-seccomp.json"
SHARED_SECCOMP_PROFILE = ASSETS / "docker" / "asent-seccomp.json"
RECIPE_LABEL = "org.asent.cavr.recipe-sha256"
ENGINE = "docker"
INSPECT_SECONDS = 15
BUILD_SECONDS = 900
RUN = None  # tests replace it; None means subprocess.run, looked up at call time. Never called with a shell.


def record_path() -> Path:
    return Path(DATA) / "cavr" / "sandbox-image.json"


def sha256_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def base_image(dockerfile=None) -> str | None:
    """The `FROM` reference of the Dockerfile, or None when there is none."""
    text = Path(dockerfile or DOCKERFILE).read_text(encoding="utf-8")
    match = re.search(r"^FROM\s+(\S+)", text, re.MULTILINE)
    return match.group(1) if match else None


def image_identity(image: str = IMAGE, record=None) -> dict:
    """{ok, rule, reason, image, image_id, recipe_sha256, seccomp_sha256}. Never raises."""
    try:
        return _identity(image, Path(record) if record is not None else record_path())
    except Exception as exc:  # an unexpected fault is "unknown", never "ok"
        return _id(False, "ENGINE_ERROR", f"image check failed: {type(exc).__name__}: {exc}", image)


def _identity(image, record) -> dict:
    try:
        profile = json.loads(SECCOMP_PROFILE.read_text(encoding="utf-8"))
        if not isinstance(profile, dict):
            raise ValueError("not a JSON object")
        seccomp = sha256_file(SECCOMP_PROFILE)
    except (OSError, ValueError) as exc:
        return _id(False, "SECCOMP_MISSING", f"CAVR seccomp profile {SECCOMP_PROFILE} is unusable: {exc}", image)
    found = inspect(image)
    if not found["ok"]:
        return _id(False, found["rule"], found["reason"], image, seccomp=seccomp)
    image_id, labels = found["image_id"], found["labels"]
    try:
        recorded = json.loads(record.read_text(encoding="utf-8"))
        if not isinstance(recorded, dict) or not isinstance(recorded.get("image_id"), str):
            raise ValueError("no image_id")
    except (OSError, ValueError) as exc:
        return _id(False, "IMAGE_NOT_RECORDED", f"{image} exists but has no build record at {record} ({exc}); "
                   f"build it with docker/cavr-sandbox/build.sh", image, image_id=image_id, seccomp=seccomp)
    if recorded["image_id"] != image_id:
        return _id(False, "IMAGE_ID_MISMATCH", f"{image} has ID {image_id}; the build record expects "
                   f"{recorded['image_id']}", image, image_id=image_id, seccomp=seccomp)
    recipe = sha256_file(DOCKERFILE)
    if labels.get(RECIPE_LABEL) != recipe:
        return _id(False, "IMAGE_STALE", f"{image} was built from a Dockerfile with SHA-256 {labels.get(RECIPE_LABEL)}; "
                   f"the current one is {recipe}; rebuild it", image, image_id=image_id, seccomp=seccomp)
    return _id(True, "IMAGE_OK", f"{image} is {image_id}, built from the current Dockerfile", image,
               image_id=image_id, recipe=recipe, seccomp=seccomp)


def inspect(image: str = IMAGE) -> dict:
    """{ok, rule, reason, image_id, labels} from `docker image inspect`."""
    try:
        done = _run([ENGINE, "image", "inspect", "--format", "{{json .Id}} {{json .Config.Labels}}", image],
                   capture_output=True, text=True, timeout=INSPECT_SECONDS)
    except FileNotFoundError:
        return _inspected("ENGINE_UNAVAILABLE", f"no `{ENGINE}` binary on PATH")
    except subprocess.TimeoutExpired:
        return _inspected("ENGINE_UNAVAILABLE", f"`{ENGINE} image inspect` did not answer within {INSPECT_SECONDS} s")
    except OSError as exc:
        return _inspected("ENGINE_UNAVAILABLE", f"cannot start `{ENGINE}`: {exc}")
    if done.returncode != 0:
        said = (done.stderr or done.stdout or "").strip()
        if "no such image" in said.lower():
            return _inspected("IMAGE_MISSING", f"{image} is not built; build it with docker/cavr-sandbox/build.sh")
        if "cannot connect" in said.lower() or "daemon" in said.lower() or "permission denied" in said.lower():
            return _inspected("ENGINE_UNAVAILABLE", f"the {ENGINE} engine cannot be reached: {said[:300]}")
        return _inspected("ENGINE_ERROR", f"`{ENGINE} image inspect` failed ({done.returncode}): {said[:300]}")
    try:
        id_part, labels_part = done.stdout.strip().split(" ", 1)
        image_id, labels = json.loads(id_part), json.loads(labels_part) or {}
        if not (isinstance(image_id, str) and image_id.startswith("sha256:") and isinstance(labels, dict)):
            raise ValueError(done.stdout[:200])
    except ValueError as exc:
        return _inspected("ENGINE_ERROR", f"unreadable inspect output: {exc}")
    return {"ok": True, "rule": "IMAGE_FOUND", "reason": f"{image} is {image_id}", "image_id": image_id, "labels": labels}


def build(image: str = IMAGE, record=None, emit=print) -> dict:
    """Build the image, then record its ID. {ok, rule, reason, image_id, record}. Never raises."""
    record = Path(record) if record is not None else record_path()
    try:
        recipe = sha256_file(DOCKERFILE)
        cmd = [ENGINE, "build", "--label", f"{RECIPE_LABEL}={recipe}", "-t", image, "-f", str(DOCKERFILE), str(DIRECTORY)]
        emit(" ".join(cmd))
        done = _run(cmd, timeout=BUILD_SECONDS)
        if done.returncode != 0:
            return {"ok": False, "rule": "BUILD_FAILED", "reason": f"docker build exited {done.returncode}", "image_id": None}
        found = inspect(image)
        if not found["ok"]:
            return {"ok": False, "rule": found["rule"], "reason": found["reason"], "image_id": None}
        if found["labels"].get(RECIPE_LABEL) != recipe:
            return {"ok": False, "rule": "BUILD_FAILED", "reason": "the built image does not carry the recipe label",
                    "image_id": found["image_id"]}
        record.parent.mkdir(parents=True, exist_ok=True)
        entry = {"image": image, "image_id": found["image_id"], "recipe_sha256": recipe, "base": base_image(),
                 "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        record.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        return {"ok": True, "rule": "BUILT", "reason": f"{image} is {found['image_id']}", "image_id": found["image_id"],
                "record": str(record)}
    except FileNotFoundError:
        return {"ok": False, "rule": "ENGINE_UNAVAILABLE", "reason": f"no `{ENGINE}` binary on PATH", "image_id": None}
    except Exception as exc:
        return {"ok": False, "rule": "BUILD_FAILED", "reason": f"{type(exc).__name__}: {exc}", "image_id": None}


def _run(cmd, **kwargs):
    return (RUN or subprocess.run)(cmd, **kwargs)


def _inspected(rule, reason) -> dict:
    return {"ok": False, "rule": rule, "reason": reason, "image_id": None, "labels": {}}


def _id(ok, rule, reason, image, image_id=None, recipe=None, seccomp=None) -> dict:
    return {"ok": ok, "rule": rule, "reason": reason, "image": image, "image_id": image_id, "recipe_sha256": recipe,
            "seccomp_sha256": seccomp}


def main(argv) -> int:
    if argv[:1] == ["build"]:
        result = build()
    elif argv[:1] == ["check"]:
        result = image_identity()
    else:
        print("usage: python -m backend.cavr.sandbox_image build|check", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
