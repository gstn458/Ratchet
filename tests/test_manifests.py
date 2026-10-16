"""Dependency manifests: the parsing the goldens under tests/fixtures/manifests
do not reach on their own."""

import json

import pytest

import ratchet


def scan(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    found = ratchet.scan_manifest(str(path))
    return [(f.algorithm, f.line) for f in found], [lib[1:] for lib in found.libraries]


def test_manifest_names():
    for name in ("requirements.txt", "requirements-dev.txt", "requirements_test.txt", "pyproject.toml",
                 "Pipfile", "setup.cfg", "go.mod", "package.json", "pom.xml", "build.gradle", "build.gradle.kts"):
        assert ratchet.is_manifest(name), name
    for name in ("package-lock.json", "go.sum", "poetry.lock", "yarn.lock", "Pipfile.lock", "requirements.in",
                 "setup.py", "dev-requirements.txt"):
        assert not ratchet.is_manifest(name), name


@pytest.mark.parametrize("ecosystem, name, key", [
    ("pypi", "PyNaCl", "pynacl"),
    ("pypi", "py_jwt", None),
    ("pypi", "PyJWT", "pyjwt"),
    ("pypi", "Ed25519", "ed25519"),
    ("go", "github.com/golang-jwt/jwt/v5", "github.com/golang-jwt/jwt"),
    ("go", "github.com/golang-jwt/jwt", "github.com/golang-jwt/jwt"),
    ("go", "golang.org/x/crypto/v2", "golang.org/x/crypto"),
    ("maven", "org.bouncycastle:bcpkix-jdk18on", "org.bouncycastle:*"),
    ("maven", "com.nimbusds:nimbus-jose-jwt", "com.nimbusds:nimbus-jose-jwt"),
    ("maven", "com.nimbusds:other", None),
    ("npm", "@noble/ed25519", "@noble/ed25519"),
    ("npm", "MD5", None),   # npm names are lower case; this is not the md5 package
])
def test_library_keys(ecosystem, name, key):
    assert ratchet.library_key(ecosystem, name) == key


def test_purls():
    assert ratchet.purl("npm", "@noble/ed25519") == "pkg:npm/%40noble/ed25519"
    assert ratchet.purl("go", "github.com/golang-jwt/jwt/v5") == "pkg:golang/github.com/golang-jwt/jwt/v5"
    assert ratchet.purl("maven", "org.bouncycastle:bcprov-jdk18on") == "pkg:maven/org.bouncycastle/bcprov-jdk18on"
    assert ratchet.purl("pypi", "pynacl") == "pkg:pypi/pynacl"


def test_go_indirect_and_replace_lines(tmp_path):
    text = ("module m\n\nrequire (\n\tgolang.org/x/crypto v0.1.0 // indirect\n)\n"
            "replace filippo.io/edwards25519 => ../fork\n")
    assert scan(tmp_path, "go.mod", text) == ([], [])


def test_package_json_scripts_and_other_objects_are_not_dependencies(tmp_path):
    doc = {"name": "x", "scripts": {"md5": "node md5.js"}, "config": {"tweetnacl": True},
           "peerDependencies": {"node-rsa": "^1"}}
    text = json.dumps(doc, indent=2)
    algorithms, libraries = scan(tmp_path, "package.json", text)
    assert algorithms == [("RSA", 10)]
    assert libraries == [("npm", "node-rsa", "node-rsa")]


def test_setup_cfg(tmp_path):
    text = ("[metadata]\nname = x\n\n[options]\ninstall_requires =\n    rsa>=4\n    six\n"
            "python_requires = >=3.9\n\n[options.extras_require]\nsig = ed25519\n")
    algorithms, _ = scan(tmp_path, "setup.cfg", text)
    assert algorithms == [("RSA", 6), ("Ed25519", 11)]


def test_pipfile(tmp_path):
    text = "[packages]\nPyNaCl = '*'\n\n[requires]\npython_version = '3.12'\n"
    algorithms, _ = scan(tmp_path, "Pipfile", text)
    assert algorithms == [("Ed25519", 2), ("X25519", 2)]


def test_gradle_kotlin(tmp_path):
    text = 'dependencies {\n    implementation("org.bouncycastle:bcprov-jdk18on:1.78")\n}\n'
    assert scan(tmp_path, "build.gradle.kts", text) == (
        [], [("maven", "org.bouncycastle:*", "org.bouncycastle:bcprov-jdk18on")])


def test_dependencies_never_gate(tmp_path):
    (tmp_path / "requirements.txt").write_text("rsa\necdsa\n")
    scan_ = ratchet.walk(str(tmp_path))
    assert ratchet.ci_gate_count(scan_) == 0
    assert {r["level"] for r in ratchet.build_sarif(scan_)["runs"][0]["results"]} == {"note"}


def test_libraries_are_cyclonedx_library_components(tmp_path, cbom_validator):
    (tmp_path / "requirements.txt").write_text("cryptography\nrsa\n")
    doc = ratchet.build_cbom(ratchet.walk(str(tmp_path)), str(tmp_path))
    libraries = {c["name"]: c for c in doc["components"] if c["type"] == "library"}
    assert set(libraries) == {"cryptography", "rsa"}
    assert libraries["rsa"]["purl"] == "pkg:pypi/rsa"
    props = {p["name"]: p["value"] for p in libraries["cryptography"]["properties"]}
    assert props["ratchet:implements"] == "general"
    assert props["ratchet:library_source"] == "https://pypi.org/project/cryptography/"
    assert [c["name"] for c in doc["components"]] == sorted(c["name"] for c in doc["components"])
    assert list(cbom_validator.iter_errors(doc)) == []


def test_a_registry_without_a_library_table_reads_no_manifests(tmp_path, monkeypatch):
    # Registries before 2026.10.5 have no libraries table.
    monkeypatch.setattr(ratchet, "LIBRARIES", {})
    (tmp_path / "requirements.txt").write_text("rsa\n")
    scan_ = ratchet.walk(str(tmp_path), jobs=1)
    assert scan_.findings == [] and scan_.libraries == []


def test_maven_property_names_fall_back_to_the_group(tmp_path):
    text = ("<project><dependencies><dependency><groupId>org.bouncycastle</groupId>"
            "<artifactId>${bcprov.artifactId}</artifactId></dependency></dependencies></project>\n")
    assert scan(tmp_path, "pom.xml", text) == ([], [("maven", "org.bouncycastle:*", "org.bouncycastle:*")])
    assert ratchet.purl("maven", "org.bouncycastle:*") == "pkg:maven/org.bouncycastle"
