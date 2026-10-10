import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
import uuid
from pathlib import Path

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
FORGE_URL_PATTERN = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
STATUS_WORDS = {"A": "added", "D": "deleted", "M": "modified", "R": "renamed", "T": "modified", "C": "copied"}
RECORD_SPLIT = "\x1e"
FIELD_SPLIT = "\x1f"


class IngestError(Exception):
    pass


def require_sha(candidate_text):
    if not isinstance(candidate_text, str) or not SHA_PATTERN.match(candidate_text):
        raise IngestError("malformed sha: expected 40 lowercase hex characters")
    return candidate_text


def slug_of(url_text):
    hit = FORGE_URL_PATTERN.match(url_text or "")
    if hit:
        return hit.group(1) + "/" + hit.group(2)
    return None


def require_allowed_url(url_text, allowlist):
    slug = slug_of(url_text)
    if slug is not None:
        if slug in allowlist:
            return slug
        raise IngestError("repository %s is not in the allowlist" % slug)
    if isinstance(url_text, str) and os.path.isabs(url_text) and url_text in allowlist:
        return "local/" + Path(url_text).name
    raise IngestError("unsupported or non-allowlisted repository url")


def git_environment():
    cleaned = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    cleaned["GIT_TERMINAL_PROMPT"] = "0"
    cleaned["LC_ALL"] = "C.UTF-8"
    return cleaned


def run_git(repo_dir, *arguments, feed=None, tolerate=False):
    outcome = subprocess.run(
        ["git", "-C", str(repo_dir), *arguments],
        input=feed,
        capture_output=True,
        env=git_environment(),
        timeout=120,
    )
    if outcome.returncode != 0 and not tolerate:
        raise IngestError("git %s failed: %s" % (arguments[0], outcome.stderr.decode("utf-8", "replace").strip()))
    return outcome.stdout.decode("utf-8", "replace")


def repo_path_for(settings, slug):
    return settings.workspace / "repos" / slug.replace("/", "__")


def ensure_repository(settings):
    slug = require_allowed_url(settings.target_url, settings.allowlist)
    source = settings.target_source
    if not isinstance(source, str) or source.startswith("-"):
        raise IngestError("refusing option-like clone source")
    destination = repo_path_for(settings, slug)
    if (destination / ".git").exists():
        run_git(destination, "fetch", "--quiet", "--all", "--tags", "--prune")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    outcome = subprocess.run(
        ["git", "clone", "--quiet", "--", source, str(destination)],
        capture_output=True,
        env=git_environment(),
        timeout=300,
    )
    if outcome.returncode != 0:
        raise IngestError("clone failed: " + outcome.stderr.decode("utf-8", "replace").strip())
    return destination


def tip_names(repo_dir):
    table = {}
    listing = run_git(repo_dir, "for-each-ref", "--format=%(objectname) %(refname:short)", "refs/remotes", "refs/heads")
    for row in listing.splitlines():
        digest, _, label = row.partition(" ")
        if label.endswith("/HEAD"):
            continue
        table.setdefault(digest, []).append(label)
    return table


def list_recent_commits(repo_dir, limit=20):
    limit = max(1, min(int(limit), 200))
    layout = FIELD_SPLIT.join(["%H", "%P", "%an", "%aI", "%s"]) + RECORD_SPLIT
    raw = run_git(repo_dir, "log", "--branches", "--remotes", "-n", str(limit), "--format=" + layout)
    tips = tip_names(repo_dir)
    rows = []
    for chunk in raw.split(RECORD_SPLIT):
        chunk = chunk.strip("\n")
        if not chunk:
            continue
        digest, parents, author, stamp, subject = chunk.split(FIELD_SPLIT)
        rows.append({
            "sha": digest,
            "parents": parents.split(),
            "author": author,
            "date": stamp,
            "message": subject,
            "refs": tips.get(digest, []),
        })
    return rows


def fetch_forge_commits(settings, limit=20):
    slug = slug_of(settings.target_url)
    if slug is None or slug not in settings.allowlist:
        return {"available": False, "reason": "target url is not an allowlisted forge repository", "commits": []}
    endpoint = "https://api.github.com/repos/%s/commits?per_page=%d" % (slug, max(1, min(int(limit), 100)))
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "satra-rv"}
    if settings.forge_token:
        headers["Authorization"] = "Bearer " + settings.forge_token
    try:
        with urllib.request.urlopen(urllib.request.Request(endpoint, headers=headers), timeout=10) as handle:
            payload = json.loads(handle.read().decode("utf-8"))
    except urllib.error.HTTPError as problem:
        if problem.code in (403, 429):
            return {"available": False, "reason": "forge rate limit reached", "reset": problem.headers.get("X-RateLimit-Reset"), "commits": []}
        return {"available": False, "reason": "forge returned HTTP %d" % problem.code, "commits": []}
    except (OSError, ValueError) as problem:
        return {"available": False, "reason": "forge unreachable: %s" % problem, "commits": []}
    rows = [{"sha": item["sha"], "author": item["commit"]["author"]["name"], "date": item["commit"]["author"]["date"], "message": item["commit"]["message"].splitlines()[0]} for item in payload]
    return {"available": True, "commits": rows}


def require_ref(repo_dir, ref_text):
    if not isinstance(ref_text, str) or not ref_text or ref_text.startswith("-") or any(ch in ref_text for ch in "\x00\n\r"):
        raise IngestError("refusing malformed or option-like ref")
    found = run_git(repo_dir, "rev-parse", "--verify", "--quiet", ref_text + "^{commit}", tolerate=True).strip()
    if not SHA_PATTERN.match(found):
        raise IngestError("unknown ref: %s" % ref_text)
    return found


def resolve_commit(repo_dir, sha):
    if isinstance(sha, str) and 4 <= len(sha) < 40 and re.match(r"^[0-9a-fA-F]+$", sha):
        found = run_git(repo_dir, "rev-parse", "--verify", "--quiet", sha + "^{commit}", tolerate=True).strip()
        if SHA_PATTERN.match(found):
            sha = found
    require_sha(sha)
    kind = run_git(repo_dir, "cat-file", "-t", sha, tolerate=True).strip()
    if kind != "commit":
        raise IngestError("commit %s is not present in the repository" % sha)
    layout = FIELD_SPLIT.join(["%H", "%P", "%an", "%ae", "%aI", "%B"])
    raw = run_git(repo_dir, "show", "-s", "--format=" + layout, sha)
    digest, parents, author, email, stamp, body = raw.split(FIELD_SPLIT, 5)
    return {"sha": digest, "parents": parents.split(), "author": author, "email": email, "date": stamp, "message": body.strip()}


def empty_tree_hash(repo_dir):
    return run_git(repo_dir, "hash-object", "-t", "tree", "--stdin", feed=b"").strip()


def resolve_base(repo_dir, commit):
    parents = commit["parents"]
    if not parents:
        return {"base": empty_tree_hash(repo_dir), "kind": "root", "merge": False}
    return {"base": parents[0], "kind": "merge-first-parent" if len(parents) > 1 else "first-parent", "merge": len(parents) > 1}


def parse_name_status(raw):
    tokens = raw.split("\x00")
    cursor = 0
    entries = []
    while cursor < len(tokens) and tokens[cursor]:
        marker = tokens[cursor]
        code = marker[0]
        if code in "RC":
            entries.append({"code": code, "old": tokens[cursor + 1], "new": tokens[cursor + 2]})
            cursor += 3
        else:
            entries.append({"code": code, "old": tokens[cursor + 1], "new": tokens[cursor + 1]})
            cursor += 2
    return entries


def parse_numstat(raw):
    tokens = raw.split("\x00")
    cursor = 0
    table = {}
    while cursor < len(tokens) and tokens[cursor]:
        plus, minus, rest = tokens[cursor].split("\t", 2)
        if rest == "":
            old, new = tokens[cursor + 1], tokens[cursor + 2]
            cursor += 3
        else:
            new = rest
            cursor += 1
        binary = plus == "-"
        table[new] = {"additions": 0 if binary else int(plus), "deletions": 0 if binary else int(minus), "binary": binary}
    return table


def build_change_set(repo_dir, commit):
    base_info = resolve_base(repo_dir, commit)
    base, cand = base_info["base"], commit["sha"]
    entries = parse_name_status(run_git(repo_dir, "diff", "-M", "-z", "--name-status", base, cand))
    counts = parse_numstat(run_git(repo_dir, "diff", "-M", "-z", "--numstat", base, cand))
    rows = []
    for entry in entries:
        code = entry["code"]
        stats = counts.get(entry["new"], {"additions": 0, "deletions": 0, "binary": False})
        scope = [entry["old"], entry["new"]] if code in "RC" else [entry["new"]]
        text = ""
        if not stats["binary"]:
            text = run_git(repo_dir, "diff", "-M", "--no-color", "--no-ext-diff", base, cand, "--", *scope)
        rows.append({
            "status": STATUS_WORDS.get(code, "modified"),
            "path": entry["new"],
            "old_path": entry["old"] if code in "RC" else None,
            "additions": stats["additions"],
            "deletions": stats["deletions"],
            "binary": stats["binary"],
            "diff": text,
        })
    return {
        "sha": cand,
        "base": base,
        "base_kind": base_info["kind"],
        "merge": base_info["merge"],
        "parents": commit["parents"],
        "author": commit["author"],
        "date": commit["date"],
        "message": commit["message"],
        "files": rows,
    }


def ingest_commit(repo_dir, sha):
    return build_change_set(repo_dir, resolve_commit(repo_dir, sha))


def prepare_run_dirs(settings, repo_dir, change_set):
    run_id = uuid.uuid4().hex[:12]
    root = settings.workspace / "runs" / run_id
    baseline_dir, candidate_dir = root / "baseline", root / "candidate"
    root.mkdir(parents=True)
    run_git(repo_dir, "worktree", "add", "--detach", "--quiet", str(candidate_dir), change_set["sha"])
    if change_set["base_kind"] == "root":
        baseline_dir.mkdir()
    else:
        run_git(repo_dir, "worktree", "add", "--detach", "--quiet", str(baseline_dir), change_set["base"])
    return {"run_id": run_id, "root": root, "baseline": baseline_dir, "candidate": candidate_dir, "repo": repo_dir, "root_commit": change_set["base_kind"] == "root"}


def release_run_dirs(handle):
    for key in ("candidate", "baseline"):
        target = handle[key]
        if key == "baseline" and handle["root_commit"]:
            shutil.rmtree(target, ignore_errors=True)
            continue
        run_git(handle["repo"], "worktree", "remove", "--force", str(target), tolerate=True)
        shutil.rmtree(target, ignore_errors=True)
    run_git(handle["repo"], "worktree", "prune", tolerate=True)
