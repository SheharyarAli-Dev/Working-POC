"""C3 transitive tree and subtree digest (plan step 6). Offline: tmp-built wheels served by FakeIndex."""
import json

import pytest

from backend.cavr import dep_tree
from backend.cavr.dep_tree import build_tree
from backend.cavr.pypi_client import TransportError, registry_url
from test_cavr_support import PYPDF_SHA256, REPO, FakeIndex, build_wheel, sha256_file

LINUX = {"sys_platform": "linux", "python_version": "3.12", "python_full_version": "3.12.0"}


def outcome(tree):
    return tree["result"], tree["rule"]


def lock(*pins, **sha256):
    """A project lockfile: `lock("mid==1.0", "leaf==2.0", leaf="<sha256>")`."""
    packages = []
    for pin in pins:
        name, version = pin.split("==")
        packages.append({"name": name, "version": version, "ecosystem": "PyPI", **({"sha256": sha256[name]} if name in sha256 else {})})
    return {"lock_version": 1, "packages": packages, "edges": []}


class World:
    """tmp-built wheels plus the index that serves them."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.index = FakeIndex()
        self.wheels = {}
        self.builds = 0

    def add(self, name, version, requires=(), **wheel_args):
        self.builds += 1
        wheel = build_wheel(self.tmp_path / f"build{self.builds}", name, version, requires=requires, **wheel_args)
        self.wheels[name] = wheel
        self.index.add(name, version, wheel)
        return wheel

    def tree(self, name, version, lockfile, **args):
        args.setdefault("environment", LINUX)
        return build_tree(name, version, lockfile, self.tmp_path / "quarantine", transport=self.index, **args)

    def fetched(self):
        return sorted(url.rsplit("/", 1)[-1] for url in self.index.downloads())


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def three_levels(world, leaf_source="VALUE = 1\n"):
    world.add("app", "1.0", requires=["mid>=1,<2"])
    world.add("mid", "1.5", requires=["leaf"])
    world.add("leaf", "2.0", files={"leaf/__init__.py": leaf_source})
    return lock("app==1.0", "mid==1.5", "leaf==2.0")


# --- a 3-level tree -------------------------------------------------------------------------

def test_three_level_tree(world):
    tree = world.tree("app", "1.0", three_levels(world))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert [(node["name"], node["version"]) for node in tree["nodes"]] == [("app", "1.0"), ("leaf", "2.0"), ("mid", "1.5")]
    assert tree["edges"] == [
        {"parent": "app==1.0", "child": "mid==1.5", "requirement": "mid>=1,<2"},
        {"parent": "mid==1.5", "child": "leaf==2.0", "requirement": "leaf"},
    ]
    assert tree["root"] == {"name": "app", "version": "1.0"}
    assert tree["problems"] == [] and tree["excluded"] == []
    assert len(tree["subtree_digest"]) == 64


def test_every_node_is_downloaded_and_hashed(world):
    tree = world.tree("app", "1.0", three_levels(world))
    assert world.fetched() == ["app-1.0-py3-none-any.whl", "leaf-2.0-py3-none-any.whl", "mid-1.5-py3-none-any.whl"]
    for node in tree["nodes"]:
        assert node["sha256"] == sha256_file(world.wheels[node["name"]]) == sha256_file(node["path"])
        assert node["artifact"]["rule"] == "HASH_MATCH" and node["metadata"]["rule"] == "METADATA_READ"
    assert tree["nodes"][0]["import_names"] == ["app"]


def test_subtree_digest_is_stable_and_edge_order_does_not_depend_on_requires_dist_order(tmp_path):
    def run(directory, order):
        world = World(directory)
        world.add("app", "1.0", requires=order)
        world.add("left", "1.0")
        world.add("right", "1.0")
        return world.tree("app", "1.0", lock("left==1.0", "right==1.0"))

    first, again = run(tmp_path / "a", ["left", "right"]), run(tmp_path / "b", ["left", "right"])
    assert outcome(first) == ("OK", "TREE_BUILT")
    assert first["subtree_digest"] == again["subtree_digest"]
    # A different Requires-Dist order is a different root wheel, so compare the edges and the leaves only.
    swapped = run(tmp_path / "c", ["right", "left"])
    assert [edge["child"] for edge in swapped["edges"]] == [edge["child"] for edge in first["edges"]]
    assert [node["name"] for node in swapped["nodes"]] == ["app", "left", "right"]


def test_subtree_digest_changes_when_a_leafs_bytes_change(tmp_path):
    def run(directory, leaf_source):
        world = World(directory)
        lockfile = three_levels(world, leaf_source)
        return world.tree("app", "1.0", lockfile)

    clean, changed = run(tmp_path / "a", "VALUE = 1\n"), run(tmp_path / "b", "VALUE = 1\nimport os\n")
    by_name = lambda tree: {node["name"]: node["sha256"] for node in tree["nodes"]}
    assert by_name(clean)["app"] == by_name(changed)["app"]
    assert by_name(clean)["mid"] == by_name(changed)["mid"]
    assert by_name(clean)["leaf"] != by_name(changed)["leaf"]
    assert clean["subtree_digest"] != changed["subtree_digest"]


def test_subtree_digest_covers_the_edges_not_only_the_nodes(world, monkeypatch):
    world.add("app", "1.0", requires=["b", "c"])
    world.add("b", "1.0")
    world.add("c", "1.0")
    tree = world.tree("app", "1.0", lock("b==1.0", "c==1.0"))
    nodes = [[node["name"], node["version"], node["sha256"]] for node in tree["nodes"]]
    edges = [["app", "1.0", "b", "1.0"], ["app", "1.0", "c", "1.0"]]
    assert tree["subtree_digest"] == dep_tree.subtree_digest(["app", "1.0"], nodes, edges)
    assert tree["subtree_digest"] != dep_tree.subtree_digest(["app", "1.0"], nodes, [["app", "1.0", "b", "1.0"], ["b", "1.0", "c", "1.0"]])
    assert tree["subtree_digest"] != dep_tree.subtree_digest(["b", "1.0"], nodes, edges)
    assert tree["subtree_digest"] == dep_tree.subtree_digest(["app", "1.0"], list(reversed(nodes)), list(reversed(edges)))


def test_root_without_dependencies_needs_no_lockfile(world):
    world.add("solo", "1.0")
    tree = world.tree("solo", "1.0", None)
    assert outcome(tree) == ("OK", "TREE_BUILT") and len(tree["nodes"]) == 1 and tree["edges"] == []


# --- cycles ---------------------------------------------------------------------------------------

def test_dependency_cycle_terminates(world):
    world.add("a", "1.0", requires=["b"])
    world.add("b", "1.0", requires=["c"])
    world.add("c", "1.0", requires=["a", "c"])
    tree = world.tree("a", "1.0", lock("a==1.0", "b==1.0", "c==1.0"))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert [node["name"] for node in tree["nodes"]] == ["a", "b", "c"]
    assert [(edge["parent"], edge["child"]) for edge in tree["edges"]] == [
        ("a==1.0", "b==1.0"), ("b==1.0", "c==1.0"), ("c==1.0", "a==1.0"), ("c==1.0", "c==1.0")]
    assert len(world.fetched()) == 3  # each node once


def test_cycle_digest_is_the_same_from_two_runs(tmp_path):
    def run(directory):
        world = World(directory)
        world.add("a", "1.0", requires=["b"])
        world.add("b", "1.0", requires=["a"])
        return world.tree("a", "1.0", lock("a==1.0", "b==1.0"))

    assert run(tmp_path / "x")["subtree_digest"] == run(tmp_path / "y")["subtree_digest"]


# --- markers and extras ------------------------------------------------------------------------------

def test_marker_excluded_dependency_is_not_followed_and_needs_no_pin(world):
    world.add("app", "1.0", requires=['win-only==1.0; sys_platform == "win32"', "leaf"])
    world.add("leaf", "1.0")
    tree = world.tree("app", "1.0", lock("leaf==1.0"))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert [node["name"] for node in tree["nodes"]] == ["app", "leaf"]
    assert tree["excluded"] == [{"parent": "app==1.0", "requirement": 'win-only==1.0; sys_platform == "win32"',
                                 "marker": 'sys_platform == "win32"'}]
    assert not any("win" in url for url in world.index.calls)


def test_the_same_dependency_is_followed_when_its_marker_holds(world):
    world.add("app", "1.0", requires=['win-only==1.0; sys_platform == "win32"'])
    tree = world.tree("app", "1.0", lock(), environment={**LINUX, "sys_platform": "win32"})
    assert outcome(tree) == ("UNRESOLVED", "CHILD_NOT_PINNED")


def test_extras_are_off_for_the_root(world):
    world.add("app", "1.0", requires=['speedup==1.0; extra == "fast"'])
    tree = world.tree("app", "1.0", None)
    assert outcome(tree) == ("OK", "TREE_BUILT") and len(tree["nodes"]) == 1
    assert tree["excluded"][0]["marker"] == 'extra == "fast"'


def test_extra_asked_for_by_a_parent_turns_on_the_childs_extra_dependencies(world):
    world.add("app", "1.0", requires=["mid[fast]"])
    world.add("mid", "1.0", requires=['speedup; extra == "fast"', 'docs-tool; extra == "docs"'])
    world.add("speedup", "1.0")
    tree = world.tree("app", "1.0", lock("mid==1.0", "speedup==1.0"))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert [node["name"] for node in tree["nodes"]] == ["app", "mid", "speedup"]
    assert [entry["requirement"] for entry in tree["excluded"]] == ['docs-tool; extra == "docs"']
    assert tree["nodes"][1]["extras"] == ["fast"]


def test_extra_that_arrives_after_the_node_was_first_seen_is_still_applied(world):
    # "mid" is reached first without extras (through "a"), then with [fast] (through "b").
    world.add("app", "1.0", requires=["a", "b"])
    world.add("a", "1.0", requires=["mid"])
    world.add("b", "1.0", requires=["mid[fast]"])
    world.add("mid", "1.0", requires=['speedup; extra == "fast"'])
    world.add("speedup", "1.0")
    tree = world.tree("app", "1.0", lock("a==1.0", "b==1.0", "mid==1.0", "speedup==1.0"))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert "speedup" in [node["name"] for node in tree["nodes"]]
    assert len(world.fetched()) == 5


def test_real_pypdf_wheel_has_no_dependencies_on_this_interpreter(tmp_path):
    index = FakeIndex()
    index.add_pypdf()
    lockfile = json.loads((REPO / "demo_project/InvoiceHub/dependencies.lock.json").read_text())
    tree = build_tree("pypdf", "6.19.0", lockfile, tmp_path / "quarantine", transport=index)
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert [(node["name"], node["version"], node["sha256"]) for node in tree["nodes"]] == [("pypdf", "6.19.0", PYPDF_SHA256)]
    assert tree["nodes"][0]["lockfile_sha256"] == PYPDF_SHA256
    assert len(tree["excluded"]) == 23  # typing_extensions (python < 3.11) and 22 extra-gated lines


def test_real_pypdf_wheel_on_python_3_10_needs_typing_extensions_pinned(tmp_path):
    index = FakeIndex()
    index.add_pypdf()
    old_python = {"python_version": "3.10", "python_full_version": "3.10.0"}
    tree = build_tree("pypdf", "6.19.0", lock("pypdf==6.19.0"), tmp_path / "quarantine", transport=index, environment=old_python)
    assert outcome(tree) == ("UNRESOLVED", "CHILD_NOT_PINNED")
    assert "typing-extensions" in tree["reason"]


# --- children that cannot be pinned exactly -> UNRESOLVED ----------------------------------------------

def test_child_missing_from_the_lockfile_is_unresolved(world):
    world.add("app", "1.0", requires=["leaf>=1"])
    world.add("leaf", "1.0")
    tree = world.tree("app", "1.0", lock("app==1.0"))
    assert outcome(tree) == ("UNRESOLVED", "CHILD_NOT_PINNED")
    assert tree["subtree_digest"] is None
    assert tree["problems"][0]["node"] == "app==1.0" and tree["problems"][0]["requirement"] == "leaf>=1"
    assert world.fetched() == ["app-1.0-py3-none-any.whl"]


def test_child_without_any_lockfile_is_unresolved(world):
    world.add("app", "1.0", requires=["leaf==1.0"])
    world.add("leaf", "1.0")
    # Even an exact `==` in Requires-Dist is not a project pin: the plan pins children from the lockfile.
    assert outcome(world.tree("app", "1.0", None)) == ("UNRESOLVED", "CHILD_NOT_PINNED")


def test_lockfile_version_outside_the_childs_specifier_is_unresolved(world):
    world.add("app", "1.0", requires=["leaf>=2"])
    world.add("leaf", "1.0")
    tree = world.tree("app", "1.0", lock("leaf==1.0"))
    assert outcome(tree) == ("UNRESOLVED", "CHILD_PIN_CONFLICT")
    assert world.fetched() == ["app-1.0-py3-none-any.whl"]


def test_two_lockfile_versions_that_both_fit_are_unresolved(world):
    world.add("app", "1.0", requires=["leaf"])
    tree = world.tree("app", "1.0", lock("leaf==1.0", "leaf==2.0"))
    assert outcome(tree) == ("UNRESOLVED", "CHILD_NOT_PINNED")
    assert "more than one" in tree["reason"]


def test_two_lockfile_versions_of_which_one_fits_is_pinned(world):
    world.add("app", "1.0", requires=["leaf<2"])
    world.add("leaf", "1.0")
    tree = world.tree("app", "1.0", lock("leaf==1.0", "leaf==2.0"))
    assert outcome(tree) == ("OK", "TREE_BUILT") and tree["edges"][0]["child"] == "leaf==1.0"


def test_lockfile_names_are_matched_canonically_and_other_ecosystems_are_ignored(world):
    world.add("app", "1.0", requires=["Left_Pad", "npm-thing"])
    world.add("left-pad", "1.0")
    lockfile = lock("left.PAD==1.0")
    lockfile["packages"].append({"name": "npm-thing", "version": "1.0", "ecosystem": "npm"})
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("UNRESOLVED", "CHILD_NOT_PINNED")
    assert [problem["requirement"] for problem in tree["problems"]] == ["npm-thing"]
    assert "left-pad" in [node["name"] for node in tree["nodes"]]


@pytest.mark.parametrize("lockfile", [[], {"packages": "x"}, {"packages": [{"name": "leaf"}]},
                                      {"packages": [{"name": "leaf", "version": "?", "ecosystem": "PyPI"}]}])
def test_invalid_lockfile_is_unresolved_before_any_download(world, lockfile):
    world.add("app", "1.0")
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("UNRESOLVED", "LOCKFILE_INVALID")
    assert world.index.calls == []


# --- every node goes through the hash check ---------------------------------------------------------------

def tamper(world, name, version):
    response = json.loads(world.index.routes[registry_url(name, version)])
    url = response["urls"][0]["url"]
    data = bytearray(world.index.routes[url])
    data[-1] ^= 0x01
    world.index.routes[url] = bytes(data)


def test_tampered_leaf_rejects_the_whole_tree(world):
    lockfile = three_levels(world)
    tamper(world, "leaf", "2.0")
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("REJECTED", "HASH_MISMATCH")
    assert tree["subtree_digest"] is None
    assert tree["problems"] == [{"node": "leaf==2.0", "stage": "artifact", "result": "REJECTED", "rule": "HASH_MISMATCH",
                                 "reason": tree["reason"], "requirement": None}]


def test_tampered_root_is_rejected(world):
    lockfile = three_levels(world)
    tamper(world, "app", "1.0")
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("REJECTED", "HASH_MISMATCH") and tree["nodes"] == []


def test_network_loss_on_a_leaf_is_unresolved(world):
    lockfile = three_levels(world)
    world.index.routes[registry_url("leaf", "2.0")] = TransportError("timed out")
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("UNRESOLVED", "REGISTRY_UNAVAILABLE")
    assert tree["problems"][0]["node"] == "leaf==2.0"


def test_rejected_wins_over_unresolved(world):
    world.add("app", "1.0", requires=["aaa", "zzz"])
    world.add("zzz", "1.0")
    world.index.routes[registry_url("aaa", "1.0")] = TransportError("timed out")
    tamper(world, "zzz", "1.0")
    tree = world.tree("app", "1.0", lock("aaa==1.0", "zzz==1.0"))
    assert outcome(tree) == ("REJECTED", "HASH_MISMATCH")
    assert [(problem["node"], problem["result"]) for problem in tree["problems"]] == [
        ("aaa==1.0", "UNRESOLVED"), ("zzz==1.0", "REJECTED")]


def test_leaf_wheel_whose_metadata_names_another_package_is_rejected(world):
    world.add("app", "1.0", requires=["leaf"])
    world.add("leaf", "1.0", metadata="Metadata-Version: 2.1\nName: other\nVersion: 1.0\n")
    tree = world.tree("app", "1.0", lock("leaf==1.0"))
    assert outcome(tree) == ("REJECTED", "METADATA_MISMATCH")
    assert tree["problems"][0]["stage"] == "metadata"


def test_leaf_wheel_without_metadata_is_unresolved(world):
    world.add("app", "1.0", requires=["leaf"])
    world.add("leaf", "1.0", metadata=False)
    assert outcome(world.tree("app", "1.0", lock("leaf==1.0"))) == ("UNRESOLVED", "METADATA_MISSING")


# --- lockfile hash, Requires-Python, budget ------------------------------------------------------------------

def test_lockfile_hash_that_differs_from_the_downloaded_file_is_unresolved(world):
    world.add("app", "1.0", requires=["leaf"])
    world.add("leaf", "1.0")
    tree = world.tree("app", "1.0", lock("leaf==1.0", leaf="0" * 64))
    assert outcome(tree) == ("UNRESOLVED", "LOCKFILE_HASH_MISMATCH")
    assert tree["problems"][0]["node"] == "leaf==1.0"


def test_lockfile_hash_that_matches_is_recorded(world):
    world.add("app", "1.0", requires=["leaf"])
    leaf = world.add("leaf", "1.0")
    tree = world.tree("app", "1.0", lock("leaf==1.0", leaf=sha256_file(leaf).upper()))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert tree["nodes"][1]["lockfile_sha256"] == sha256_file(leaf)
    assert tree["nodes"][0]["lockfile_sha256"] is None


def test_wheel_that_needs_a_newer_python_is_unresolved(world):
    world.add("app", "1.0", metadata="Metadata-Version: 2.1\nName: app\nVersion: 1.0\nRequires-Python: >=3.99\n")
    tree = world.tree("app", "1.0", None)
    assert outcome(tree) == ("UNRESOLVED", "PYTHON_INCOMPATIBLE")


def test_unparseable_requires_python_is_unresolved(world):
    world.add("app", "1.0", metadata="Metadata-Version: 2.1\nName: app\nVersion: 1.0\nRequires-Python: whatever\n")
    assert outcome(world.tree("app", "1.0", None)) == ("UNRESOLVED", "PYTHON_INCOMPATIBLE")


def test_node_budget(world, monkeypatch):
    lockfile = three_levels(world)
    monkeypatch.setattr(dep_tree, "MAX_NODES", 2)
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("UNRESOLVED", "TREE_BUDGET")
    assert len(world.fetched()) == 2


def test_invalid_root_is_unresolved(world):
    assert outcome(world.tree("app", "not a version", None)) == ("UNRESOLVED", "INVALID_REQUEST")
    assert outcome(world.tree(None, "1.0", None)) == ("UNRESOLVED", "INVALID_REQUEST")


def test_every_result_has_the_same_keys(world):
    lockfile = three_levels(world)
    good = world.tree("app", "1.0", lockfile)
    bad = world.tree("app", "1.0", [])
    assert set(good) == set(bad)


# --- one node per release, however the version is written (plan step 10) ---------------------------------------

def test_the_same_release_written_two_ways_is_one_node(world):
    """`app==1.0` is asked for; the lockfile, which pins the way back from `b`, says `1.0.0`."""
    world.add("app", "1.0", requires=["b==2"])
    world.add("b", "2", requires=["app>=1"])
    tree = world.tree("app", "1.0", lock("app==1.0.0", "b==2"))
    assert outcome(tree) == ("OK", "TREE_BUILT")
    assert [(node["name"], node["version"]) for node in tree["nodes"]] == [("app", "1.0"), ("b", "2")]
    assert sorted((edge["parent"], edge["child"]) for edge in tree["edges"]) == [("app==1.0", "b==2"), ("b==2", "app==1.0")]
    # Before this rule `app==1.0.0` was a second node and was asked for again.
    assert world.index.calls.count(registry_url("app", "1.0")) == 1 and registry_url("app", "1.0.0") not in world.index.calls


def test_subtree_digest_does_not_depend_on_how_a_version_is_written(tmp_path):
    def run(directory, requested, locked):
        world = World(directory)
        world.add("app", "1.0", requires=["b==2"])
        world.add("b", "2", requires=["app>=1"])
        # The registry answers for every spelling of the release, as PyPI does.
        world.index.routes[registry_url("app", "1.0.0")] = world.index.routes[registry_url("app", "1.0")]
        return world.tree("app", requested, lock(f"app=={locked}", "b==2"))

    first, second = run(tmp_path / "x", "1.0", "1.0"), run(tmp_path / "y", "1.0.0", "1")
    assert outcome(first) == outcome(second) == ("OK", "TREE_BUILT")
    assert first["root"]["version"] != second["root"]["version"]
    assert first["subtree_digest"] == second["subtree_digest"]
    one = dep_tree.subtree_digest(("a", "1.0"), [("a", "1.0", "f" * 64)], [("a", "1.0", "a", "1.0")])
    assert one == dep_tree.subtree_digest(("a", "1"), [("a", "1.0.0", "f" * 64)], [("a", "1.0.0", "a", "1")])
    assert one != dep_tree.subtree_digest(("a", "1.1"), [("a", "1.1", "f" * 64)], [("a", "1.1", "a", "1.1")])


# --- the evidence of a node that could not be used (plan step 11) ---------------------------------------------

def test_failed_node_keeps_the_download_result_as_evidence(world):
    lockfile = three_levels(world)
    world.index.routes[world.index.add("leaf", "2.0", world.wheels["leaf"])["urls"][0]["url"]] = b"not the bytes the registry describes"
    tree = world.tree("app", "1.0", lockfile)
    assert outcome(tree) == ("REJECTED", "HASH_MISMATCH")
    failure, = tree["failed_nodes"]
    assert failure["node"] == "leaf==2.0" and failure["metadata"] is None
    assert failure["artifact"]["rule"] == "HASH_MISMATCH" and failure["artifact"]["path"].endswith(".rejected")
    assert failure["artifact"]["sha256"] == sha256_file(failure["artifact"]["path"]) != failure["artifact"]["registry_sha256"]
