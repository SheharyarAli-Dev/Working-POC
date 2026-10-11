import pytest
from backend.satra import ingest
from test_satra_gitkit import git_do, make_settings, record, start_repo


@pytest.fixture
def repo(tmp_path):
    return start_repo(tmp_path)


def test_modified_file(repo):
    first = record(repo, {"a.py": "x = 1\n"}, message="one")
    second = record(repo, {"a.py": "x = 2\n"}, message="two")
    change = ingest.ingest_commit(repo, second)
    assert change["base"] == first
    assert change["base_kind"] == "first-parent"
    assert [(f["status"], f["path"], f["additions"], f["deletions"]) for f in change["files"]] == [("modified", "a.py", 1, 1)]
    assert "-x = 1" in change["files"][0]["diff"] and "+x = 2" in change["files"][0]["diff"]


def test_added_and_deleted(repo):
    record(repo, {"old.py": "alpha = 1\n"}, message="one")
    second = record(repo, {"new.py": "completely different body\nwith other words\n"}, remove=["old.py"], message="two")
    change = ingest.ingest_commit(repo, second)
    found = {f["path"]: f["status"] for f in change["files"]}
    assert found == {"new.py": "added", "old.py": "deleted"}


def test_rename_records_both_paths(repo):
    body = "".join("line %d\n" % n for n in range(40))
    record(repo, {"before.py": body}, message="one")
    git_do(repo, "mv", "before.py", "after.py")
    git_do(repo, "commit", "-q", "-m", "rename")
    sha = git_do(repo, "rev-parse", "HEAD")
    change = ingest.ingest_commit(repo, sha)
    assert len(change["files"]) == 1
    row = change["files"][0]
    assert (row["status"], row["old_path"], row["path"]) == ("renamed", "before.py", "after.py")


def test_binary_is_recorded_without_diff(repo):
    record(repo, {"a.py": "x = 1\n"}, message="one")
    second = record(repo, {"blob.bin": bytes(range(256)) * 4}, message="two")
    row = ingest.ingest_commit(repo, second)["files"][0]
    assert row["binary"] is True and row["diff"] == ""


def test_root_commit_uses_empty_tree(repo):
    first = record(repo, {"a.py": "x = 1\n"}, message="root")
    change = ingest.ingest_commit(repo, first)
    assert change["base_kind"] == "root"
    assert change["base"] == ingest.empty_tree_hash(repo)
    assert change["files"][0]["status"] == "added"


def test_merge_commit_uses_first_parent(repo):
    record(repo, {"a.py": "x = 1\n"}, message="one")
    git_do(repo, "checkout", "-q", "-b", "side")
    side = record(repo, {"side.py": "y = 1\n"}, message="side")
    git_do(repo, "checkout", "-q", "main")
    mainline = record(repo, {"main.py": "z = 1\n"}, message="main work")
    git_do(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    merged = git_do(repo, "rev-parse", "HEAD")
    change = ingest.ingest_commit(repo, merged)
    assert change["merge"] is True
    assert change["base"] == mainline
    assert change["base_kind"] == "merge-first-parent"
    assert [f["path"] for f in change["files"]] == ["side.py"]
    assert side in change["parents"]


@pytest.mark.parametrize("bad", ["", "abc", "G" * 40, "A" * 40, "--upload-pack=x", "a" * 39, "a" * 41, "-" + "a" * 39])
def test_hostile_sha_rejected(repo, bad):
    record(repo, {"a.py": "x\n"}, message="one")
    with pytest.raises(ingest.IngestError):
        ingest.ingest_commit(repo, bad)


def test_absent_sha_rejected(repo):
    record(repo, {"a.py": "x\n"}, message="one")
    with pytest.raises(ingest.IngestError):
        ingest.ingest_commit(repo, "0" * 40)


@pytest.mark.parametrize("bad", ["--output=/tmp/x", "-n", "", "no-such-branch", "main\nother"])
def test_hostile_ref_rejected(repo, bad):
    record(repo, {"a.py": "x\n"}, message="one")
    with pytest.raises(ingest.IngestError):
        ingest.require_ref(repo, bad)


def test_valid_ref_resolves(repo):
    sha = record(repo, {"a.py": "x\n"}, message="one")
    assert ingest.require_ref(repo, "main") == sha


def test_wrong_repository_url_rejected():
    allow = ("SheharyarAli-Dev/Threat-Repository",)
    assert ingest.require_allowed_url("https://github.com/SheharyarAli-Dev/Threat-Repository.git", allow)
    for url in ("https://github.com/evil/Threat-Repository", "https://example.com/SheharyarAli-Dev/Threat-Repository", "-oProxy=x", "/tmp/anything", "file:///etc"):
        with pytest.raises(ingest.IngestError):
            ingest.require_allowed_url(url, allow)


def test_ensure_repository_refuses_non_allowlisted(tmp_path, repo):
    settings = make_settings(tmp_path / "ws", repo)
    object.__setattr__(settings, "allowlist", ())
    with pytest.raises(ingest.IngestError):
        ingest.ensure_repository(settings)


def test_clone_list_and_worktrees(tmp_path, repo):
    first = record(repo, {"a.py": "x = 1\n"}, message="one")
    second = record(repo, {"a.py": "x = 2\n"}, message="two")
    settings = make_settings(tmp_path / "ws", repo)
    cloned = ingest.ensure_repository(settings)
    rows = ingest.list_recent_commits(cloned, 5)
    assert [r["sha"] for r in rows] == [second, first]
    change = ingest.ingest_commit(cloned, second)
    handle = ingest.prepare_run_dirs(settings, cloned, change)
    assert (handle["baseline"] / "a.py").read_text() == "x = 1\n"
    assert (handle["candidate"] / "a.py").read_text() == "x = 2\n"
    ingest.release_run_dirs(handle)
    assert not handle["candidate"].exists() and not handle["baseline"].exists()
    assert handle["root"].exists()


def test_worktree_for_root_commit_has_empty_baseline(tmp_path, repo):
    first = record(repo, {"a.py": "x = 1\n"}, message="root")
    settings = make_settings(tmp_path / "ws", repo)
    cloned = ingest.ensure_repository(settings)
    handle = ingest.prepare_run_dirs(settings, cloned, ingest.ingest_commit(cloned, first))
    assert list(handle["baseline"].iterdir()) == []
    ingest.release_run_dirs(handle)
