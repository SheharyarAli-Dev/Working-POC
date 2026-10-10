"""C3 fetch PyPI release metadata and verify the artifact SHA-256 (plan step 4). All tests are offline."""
import hashlib
import json

import pytest
from packaging.tags import Tag

from backend.cavr import pypi_client
from backend.cavr.pypi_client import TransportError, fetch_artifact, registry_url, select_wheel
from backend.cavr.requirement_gate import evaluate_requirement
from test_cavr_support import (
    PYPDF_SHA256,
    PYPDF_WHEEL,
    FakeIndex,
    build_wheel,
    file_entry,
    pypdf_registry_response,
    registry_response,
    sha256_file,
)

PYPDF_URL = registry_url("pypdf", "6.19.0")


def outcome(result):
    return result["result"], result["rule"]


def one_release(tmp_path, name="demo", version="1.0", **wheel_args):
    """An index with one tmp-built wheel. Returns (index, wheel path, registry response)."""
    wheel = build_wheel(tmp_path / "built", name, version, **wheel_args)
    index = FakeIndex()
    response = index.add(name, version, wheel)
    return index, wheel, response


def serve(index, name, version, response):
    index.routes[registry_url(name, version)] = json.dumps(response).encode()


def quarantined(tmp_path):
    directory = tmp_path / "quarantine"
    return sorted(p.name for p in directory.iterdir()) if directory.exists() else []


# --- the real pypdf wheel against the recorded registry response -----------------

def test_real_pypdf_wheel_matches_the_recorded_registry_digest(tmp_path):
    index = FakeIndex()
    index.add_pypdf()
    result = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("OK", "HASH_MATCH")
    assert result["sha256"] == result["registry_sha256"] == PYPDF_SHA256
    assert result["filename"] == "pypdf-6.19.0-py3-none-any.whl"
    assert result["size"] == result["registry_size"] == PYPDF_WHEEL.stat().st_size == 395480
    assert result["registry_url"] == "https://pypi.org/pypi/pypdf/6.19.0/json"
    assert result["url"].startswith("https://files.pythonhosted.org/packages/")
    # The digest in the result is the digest of the file that is now on disk.
    assert sha256_file(result["path"]) == PYPDF_SHA256
    assert quarantined(tmp_path) == ["pypdf-6.19.0-py3-none-any.whl"]
    assert index.calls == [PYPDF_URL, result["url"]]


def test_one_flipped_byte_is_rejected(tmp_path):
    index = FakeIndex()
    response = index.add_pypdf()
    url = response["urls"][0]["url"]
    data = bytearray(index.routes[url])
    data[len(data) // 2] ^= 0x01
    index.routes[url] = bytes(data)
    result = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("REJECTED", "HASH_MISMATCH")
    assert result["registry_sha256"] == PYPDF_SHA256
    assert result["sha256"] == hashlib.sha256(bytes(data)).hexdigest() != PYPDF_SHA256
    assert result["size"] == 395480
    # The tampered file is kept as evidence, but not under a name a later stage would open as a wheel.
    assert quarantined(tmp_path) == ["pypdf-6.19.0-py3-none-any.whl.rejected"]
    assert result["path"].endswith(".rejected")
    assert sha256_file(result["path"]) == result["sha256"]


def test_truncated_download_is_rejected(tmp_path):
    index = FakeIndex()
    response = index.add_pypdf()
    url = response["urls"][0]["url"]
    index.routes[url] = index.routes[url][:-1]
    result = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("REJECTED", "HASH_MISMATCH")
    assert (result["size"], result["registry_size"]) == (395479, 395480)


def test_name_is_canonicalised_for_the_registry_url(tmp_path):
    index = FakeIndex()
    index.add_pypdf()
    result = fetch_artifact("PyPDF", "6.19.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("OK", "HASH_MATCH")
    assert result["name"] == "pypdf"
    assert index.calls[0] == PYPDF_URL


def test_second_fetch_replaces_the_quarantined_file(tmp_path):
    index = FakeIndex()
    index.add_pypdf()
    first = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine", transport=index)
    second = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine", transport=index)
    assert first["path"] == second["path"] and outcome(second) == ("OK", "HASH_MATCH")
    assert quarantined(tmp_path) == ["pypdf-6.19.0-py3-none-any.whl"]


# --- tmp-built wheels --------------------------------------------------------------

def test_tmp_built_wheel_matches(tmp_path):
    index, wheel, _ = one_release(tmp_path)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("OK", "HASH_MATCH")
    assert result["sha256"] == sha256_file(wheel) == sha256_file(result["path"])


def test_registry_digest_of_another_file_is_rejected(tmp_path):
    index, wheel, response = one_release(tmp_path)
    response["urls"][0]["digests"]["sha256"] = "0" * 64
    serve(index, "demo", "1.0", response)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("REJECTED", "HASH_MISMATCH")
    assert result["sha256"] == sha256_file(wheel)


def test_version_is_compared_as_a_version_not_as_text(tmp_path):
    index, _, _ = one_release(tmp_path, version="1.0")
    index.routes[registry_url("demo", "1.0.0")] = index.routes[registry_url("demo", "1.0")]
    assert outcome(fetch_artifact("demo", "1.0.0", tmp_path / "quarantine", transport=index)) == ("OK", "HASH_MATCH")


# --- invalid request -> UNRESOLVED, nothing asked from the network ---------------------

@pytest.mark.parametrize("name, version", [
    ("", "1.0"),
    ("demo", ""),
    ("../demo", "1.0"),
    ("demo/x", "1.0"),
    ("demo", "not a version"),
    ("demo", "1.0/../2.0"),
    ("demo", ">=1.0"),
    ("demo", "1.*"),
    (None, "1.0"),
    ("demo", None),
    ("demo", 1.0),
])
def test_invalid_request_is_unresolved_without_any_network_call(tmp_path, name, version):
    index = FakeIndex()
    result = fetch_artifact(name, version, tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "INVALID_REQUEST")
    assert index.calls == [] and quarantined(tmp_path) == []


def test_local_version_is_unresolved_even_though_the_gate_permits_it(tmp_path):
    # Deferred from the batch 1-3 review: `a==1.0+local` satisfies the allowlist entry `a==1.0`.
    policy = {"approved_requirements": ["demo==1.0"], "denied_packages": []}
    assert evaluate_requirement("demo==1.0+local", policy)["result"] == "PERMITTED"
    index, _, _ = one_release(tmp_path)
    result = fetch_artifact("demo", "1.0+local", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "INVALID_REQUEST")
    assert "local version" in result["reason"]
    assert index.calls == []


# --- registry unavailable or unusable -> UNRESOLVED ---------------------------------

def test_timeout_reading_the_registry_is_unresolved(tmp_path):
    index = FakeIndex()
    index.routes[registry_url("demo", "1.0")] = TransportError("timed out")
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_UNAVAILABLE")
    assert "timed out" in result["reason"]
    assert result["sha256"] is None and result["path"] is None
    assert quarantined(tmp_path) == []


def test_unknown_release_is_unresolved(tmp_path):
    result = fetch_artifact("demo", "9.9", tmp_path / "quarantine", transport=FakeIndex())
    assert outcome(result) == ("UNRESOLVED", "RELEASE_NOT_FOUND")


def test_transport_that_fails_with_an_os_error_is_unresolved(tmp_path):
    index = FakeIndex()
    index.routes[registry_url("demo", "1.0")] = OSError("network is unreachable")
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("UNRESOLVED", "REGISTRY_UNAVAILABLE")


@pytest.mark.parametrize("body", [
    b"<html>not json</html>",
    b"",
    b"[]",
    b"null",
    b'{"info": {"name": "demo", "version": "1.0"}}',
    b'{"info": {"name": "demo", "version": "1.0"}, "urls": {}}',
    b'{"info": [], "urls": []}',
    b'{"info": {"name": "demo", "version": "1.0"}, "urls": ["x"]}',
    b'{"info": {"name": "other", "version": "1.0"}, "urls": []}',
    b'{"info": {"name": "demo", "version": "2.0"}, "urls": []}',
    b'{"info": {"name": "demo", "version": "?"}, "urls": []}',
    b'{"info": {"name": 5, "version": "1.0"}, "urls": []}',
    b"\xff\xfe",
])
def test_unusable_registry_response_is_unresolved(tmp_path, body):
    index = FakeIndex()
    index.routes[registry_url("demo", "1.0")] = body
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_INVALID")
    assert index.downloads() == []


def test_oversized_registry_response_is_unresolved(tmp_path, monkeypatch):
    index, _, _ = one_release(tmp_path)
    monkeypatch.setattr(pypi_client, "MAX_REGISTRY_BYTES", 50)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_INVALID")
    assert index.downloads() == []


# --- yanked, no wheel -> UNRESOLVED -----------------------------------------------

def test_yanked_release_is_unresolved(tmp_path):
    index, _, response = one_release(tmp_path)
    response["info"]["yanked"] = True
    response["info"]["yanked_reason"] = "broken upload"
    serve(index, "demo", "1.0", response)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "YANKED")
    assert "broken upload" in result["reason"]
    assert index.downloads() == []


def test_yanked_file_is_unresolved(tmp_path):
    index, _, response = one_release(tmp_path)
    response["urls"][0]["yanked"] = True
    serve(index, "demo", "1.0", response)
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("UNRESOLVED", "YANKED")
    assert index.downloads() == []


@pytest.mark.parametrize("yanked", [None, "false", 0])
def test_yanked_flag_that_is_not_exactly_false_is_unresolved(tmp_path, yanked):
    index, _, response = one_release(tmp_path)
    response["info"]["yanked"] = yanked
    serve(index, "demo", "1.0", response)
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("UNRESOLVED", "YANKED")


def test_sdist_only_release_is_unresolved(tmp_path):
    sdist = tmp_path / "demo-1.0.tar.gz"
    sdist.write_bytes(b"not really a tarball; never opened")
    index = FakeIndex()
    serve(index, "demo", "1.0", registry_response("demo", "1.0", [file_entry(sdist, packagetype="sdist")]))
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "NO_WHEEL")
    assert result["files_listed"] == ["demo-1.0.tar.gz"]
    assert index.downloads() == []


def test_release_with_no_files_is_unresolved(tmp_path):
    index = FakeIndex()
    serve(index, "demo", "1.0", registry_response("demo", "1.0", []))
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("UNRESOLVED", "NO_WHEEL")


def test_only_incompatible_platform_wheels_is_unresolved(tmp_path):
    index, _, _ = one_release(tmp_path, tag="cp27-cp27m-win32")
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "NO_COMPATIBLE_WHEEL")
    assert index.downloads() == []


# --- wheel selection -------------------------------------------------------------------

def test_select_wheel_takes_the_best_ranked_compatible_tag(tmp_path):
    names = ["demo-1.0-cp27-cp27m-win32.whl", "demo-1.0-py3-none-any.whl", "demo-1.0-cp99-cp99-linux_x86_64.whl"]
    wheels = [build_wheel(tmp_path, "demo", "1.0", tag=name[len("demo-1.0-"):-len(".whl")]) for name in names]
    entries = [file_entry(wheel) for wheel in wheels]
    supported = [Tag("cp99", "cp99", "linux_x86_64"), Tag("py3", "none", "any")]
    chosen, problem = select_wheel(entries, "demo", "1.0", supported)
    assert problem is None and chosen["filename"] == "demo-1.0-cp99-cp99-linux_x86_64.whl"
    chosen, problem = select_wheel(list(reversed(entries)), "demo", "1.0", supported[1:])
    assert chosen["filename"] == "demo-1.0-py3-none-any.whl"
    chosen, problem = select_wheel(entries, "demo", "1.0", [Tag("cp1", "cp1", "plan9")])
    assert chosen is None and problem[0] == "NO_COMPATIBLE_WHEEL"


@pytest.mark.parametrize("filename", [
    "../demo-1.0-py3-none-any.whl",
    "sub/demo-1.0-py3-none-any.whl",
    "sub\\demo-1.0-py3-none-any.whl",
    "other-1.0-py3-none-any.whl",
    "demo-2.0-py3-none-any.whl",
    "demo-1.0.whl",
    "demo.whl",
    5,
])
def test_wheel_entry_with_a_bad_filename_is_unresolved(tmp_path, filename):
    index, _, response = one_release(tmp_path)
    response["urls"][0]["filename"] = filename
    serve(index, "demo", "1.0", response)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_INVALID")
    assert index.downloads() == [] and quarantined(tmp_path) == []
    assert not (tmp_path / "demo-1.0-py3-none-any.whl").exists()


@pytest.mark.parametrize("url", [
    "http://files.pythonhosted.org/packages/test/demo-1.0-py3-none-any.whl",
    "https://example.invalid/demo-1.0-py3-none-any.whl",
    "https://files.pythonhosted.org.example.invalid/demo-1.0-py3-none-any.whl",
    "https://user@files.pythonhosted.org/demo-1.0-py3-none-any.whl",
    "https://files.pythonhosted.org:8443/demo-1.0-py3-none-any.whl",
    "file:///etc/passwd",
    "",
    None,
])
def test_file_url_outside_the_pypi_file_host_is_unresolved(tmp_path, url):
    index, wheel, response = one_release(tmp_path)
    response["urls"][0]["url"] = url
    serve(index, "demo", "1.0", response)
    if isinstance(url, str):
        index.routes[url] = wheel.read_bytes()
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "URL_NOT_ALLOWED")
    assert index.calls == [registry_url("demo", "1.0")]


@pytest.mark.parametrize("digests", [None, {}, {"md5": "x"}, {"sha256": "abc"}, {"sha256": "Z" * 64}, {"sha256": 5}])
def test_missing_or_malformed_registry_digest_is_unresolved(tmp_path, digests):
    index, _, response = one_release(tmp_path)
    response["urls"][0]["digests"] = digests
    serve(index, "demo", "1.0", response)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_DIGEST_MISSING")
    assert index.downloads() == []


def test_uppercase_registry_digest_still_matches(tmp_path):
    index, _, response = one_release(tmp_path)
    response["urls"][0]["digests"]["sha256"] = response["urls"][0]["digests"]["sha256"].upper()
    serve(index, "demo", "1.0", response)
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("OK", "HASH_MATCH")


# --- size cap and download failures -> UNRESOLVED, nothing left behind ---------------------

def test_declared_size_over_the_cap_is_unresolved_before_downloading(tmp_path):
    index, _, _ = one_release(tmp_path)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index, max_bytes=10)
    assert outcome(result) == ("UNRESOLVED", "TOO_LARGE")
    assert index.downloads() == [] and quarantined(tmp_path) == []


def test_stream_longer_than_the_cap_is_cut_off_and_unresolved(tmp_path):
    # The registry says the file is small; the server sends more than the cap.
    index, wheel, response = one_release(tmp_path)
    response["urls"][0]["size"] = 5
    serve(index, "demo", "1.0", response)
    index.chunk_size = 16
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index, max_bytes=64)
    assert outcome(result) == ("UNRESOLVED", "TOO_LARGE")
    assert wheel.stat().st_size > 64
    assert quarantined(tmp_path) == []


@pytest.mark.parametrize("size", [None, "12", -1, 1.5, True])
def test_registry_size_that_is_not_a_whole_number_is_unresolved(tmp_path, size):
    index, _, response = one_release(tmp_path)
    response["urls"][0]["size"] = size
    serve(index, "demo", "1.0", response)
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("UNRESOLVED", "REGISTRY_INVALID")
    assert index.downloads() == []


def test_timeout_during_the_download_is_unresolved_and_leaves_no_file(tmp_path):
    index, wheel, response = one_release(tmp_path)
    data = wheel.read_bytes()

    class CutOff(FakeIndex):
        def stream(self, url):
            if url != response["urls"][0]["url"]:
                yield from super().stream(url)
                return
            self.calls.append(url)
            yield data[:10]
            raise TransportError("read timed out")

    cut = CutOff()
    cut.routes = index.routes
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=cut)
    assert outcome(result) == ("UNRESOLVED", "DOWNLOAD_FAILED")
    assert "read timed out" in result["reason"]
    assert result["sha256"] is None and result["path"] is None
    assert quarantined(tmp_path) == []


def test_missing_file_on_the_file_host_is_unresolved(tmp_path):
    index, _, response = one_release(tmp_path)
    del index.routes[response["urls"][0]["url"]]
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("UNRESOLVED", "DOWNLOAD_FAILED")
    assert quarantined(tmp_path) == []


def test_download_slower_than_the_deadline_is_unresolved(tmp_path, monkeypatch):
    index, _, _ = one_release(tmp_path)
    index.chunk_size = 8
    # The clock stands still while the registry is read, then jumps 50 seconds per call.
    ticks = iter(range(0, 100000, 50))
    monkeypatch.setattr(pypi_client.time, "monotonic", lambda: next(ticks) if index.downloads() else 0)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index, deadline_seconds=120)
    assert outcome(result) == ("UNRESOLVED", "DOWNLOAD_FAILED")
    assert "deadline" in result["reason"]
    assert quarantined(tmp_path) == []


def test_quarantine_that_cannot_be_created_is_unresolved(tmp_path):
    index, _, _ = one_release(tmp_path)
    blocker = tmp_path / "quarantine"
    blocker.write_text("a file where the directory should be")
    result = fetch_artifact("demo", "1.0", blocker, transport=index)
    assert outcome(result) == ("UNRESOLVED", "DOWNLOAD_FAILED")


# --- result shape ------------------------------------------------------------------------

def test_every_result_has_the_same_keys(tmp_path):
    index, _, _ = one_release(tmp_path)
    good = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    bad = fetch_artifact("demo", "bad version", tmp_path / "quarantine", transport=index)
    missing = fetch_artifact("demo", "9.9", tmp_path / "quarantine", transport=index)
    assert set(good) == set(bad) == set(missing)
    assert good["ecosystem"] == "PyPI"


def test_recorded_response_is_the_real_registry_shape():
    # Guards the helper: the recorded file must keep the fields the client reads.
    response = pypdf_registry_response()
    wheel = next(entry for entry in response["urls"] if entry["packagetype"] == "bdist_wheel")
    assert wheel["digests"]["sha256"] == PYPDF_SHA256 == sha256_file(PYPDF_WHEEL)
    assert response["info"]["yanked"] is False


# --- items deferred from the batch 4-8 review, handled in plan step 11 ----------------------------------------

def test_registry_listing_the_same_wheel_twice_is_unresolved_not_a_crash(tmp_path):
    index, wheel, response = one_release(tmp_path)
    response["urls"].append(dict(response["urls"][0]))
    serve(index, "demo", "1.0", response)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_INVALID") and "more than once" in result["reason"]
    assert index.downloads() == []


def test_wheel_filename_with_a_nul_byte_is_unresolved_not_a_crash(tmp_path):
    index, wheel, response = one_release(tmp_path)
    response["urls"][0]["filename"] = "demo-1.0-py3-none-any\x00.whl"
    serve(index, "demo", "1.0", response)
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_INVALID") and index.downloads() == []


@pytest.mark.parametrize("name, version", [("demo\n", "1.0"), ("demo", "1.0\n"), ("demo\n\n", "1.0")])
def test_name_or_version_with_a_trailing_newline_is_not_a_request(tmp_path, name, version):
    index, _, _ = one_release(tmp_path)
    # The version check already ignores surrounding white space (packaging does); the name check must not.
    expected = ("OK", "HASH_MATCH") if name == "demo" else ("UNRESOLVED", "INVALID_REQUEST")
    assert outcome(fetch_artifact(name, version, tmp_path / "quarantine", transport=index)) == expected


def test_good_file_from_an_earlier_run_does_not_stay_beside_a_rejected_one(tmp_path):
    index, wheel, response = one_release(tmp_path)
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("OK", "HASH_MATCH")
    assert quarantined(tmp_path) == [wheel.name]
    index.routes[response["urls"][0]["url"]] = wheel.read_bytes() + b"tampered"
    assert outcome(fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=index)) == ("REJECTED", "HASH_MISMATCH")
    assert quarantined(tmp_path) == [wheel.name + ".rejected"]


def http_transport(handler):
    import httpx
    return pypi_client.HttpxTransport(timeout=1.0, transport=httpx.MockTransport(handler))


def test_httpx_transport_streams_a_200_body():
    import httpx
    body = bytes(range(256)) * 1000
    transport = http_transport(lambda request: httpx.Response(200, content=body))
    assert b"".join(transport.stream("https://pypi.org/pypi/demo/1.0/json")) == body


@pytest.mark.parametrize("status", [301, 302, 403, 404, 500])
def test_httpx_transport_does_not_follow_redirects_and_refuses_other_statuses(status):
    import httpx
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(status, headers={"Location": "https://example.invalid/elsewhere"}, content=b"body")

    with pytest.raises(TransportError) as raised:
        list(http_transport(handler).stream("https://pypi.org/pypi/demo/1.0/json"))
    assert raised.value.status == status and seen == ["https://pypi.org/pypi/demo/1.0/json"]


def test_httpx_transport_turns_network_errors_into_transport_errors(tmp_path):
    import httpx

    def handler(request):
        raise httpx.ConnectError("network is unreachable")

    with pytest.raises(TransportError) as raised:
        list(http_transport(handler).stream("https://pypi.org/pypi/demo/1.0/json"))
    assert raised.value.status is None
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=http_transport(handler))
    assert outcome(result) == ("UNRESOLVED", "REGISTRY_UNAVAILABLE")
    result = fetch_artifact("demo", "1.0", tmp_path / "quarantine", transport=http_transport(lambda request: httpx.Response(404)))
    assert outcome(result) == ("UNRESOLVED", "RELEASE_NOT_FOUND")
