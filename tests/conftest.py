import io
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
SCHEMA_DIR = REPO_ROOT / "tests" / "schema" / "cyclonedx-1.6.2"

sys.path.insert(0, str(REPO_ROOT))

import ratchet  # noqa: E402

# Fields that legitimately differ between two runs over the same tree.
# Everything else in the CBOM must be byte-identical.
VOLATILE = {
    ("serialNumber",): "urn:uuid:00000000-0000-0000-0000-000000000000",
    ("metadata", "timestamp"): "1970-01-01T00:00:00+00:00",
}


def pytest_addoption(parser):
    parser.addoption(
        "--update-golden",
        action="store_true",
        help="rewrite expected.cbom.json and expected.report.txt from current output",
    )


@pytest.fixture
def update_golden(request):
    return request.config.getoption("--update-golden")


def normalise(cbom):
    for path, value in VOLATILE.items():
        node = cbom
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return cbom


def dumps(cbom):
    return json.dumps(cbom, indent=2) + "\n"


def fixture_options(root):
    """Scan options for a fixture, from an optional options.json beside it,
    e.g. {"include_vendored": true}."""
    path = Path(root) / "options.json"
    return json.loads(path.read_text()) if path.exists() else {}


def scan(root):
    """Scan a fixture the way the CLI does, from inside it, so paths are relative.

    Returns (normalised CBOM dict, terminal report text).
    """
    options = fixture_options(root)
    old = os.getcwd()
    os.chdir(root)
    try:
        result = ratchet.walk(".", **options)
        cbom = normalise(ratchet.build_cbom(result, "."))
        out = io.StringIO()
        with redirect_stdout(out):
            ratchet.report(result, ".")
    finally:
        os.chdir(old)
    return cbom, out.getvalue()


def fixture_dirs():
    """Every tests/fixtures/<group>/<case>/ directory is one scan root.

    Discovery is by layout, not by the presence of goldens, so a new fixture
    with no expected output fails instead of being silently skipped.
    """
    return sorted(p for p in FIXTURES.glob("*/*") if p.is_dir())


def fixture_id(path):
    return str(path.relative_to(FIXTURES))


@pytest.fixture(scope="session")
def cbom_validator():
    import jsonschema
    from referencing import Registry, Resource

    schemas = [json.loads(p.read_text()) for p in sorted(SCHEMA_DIR.glob("*.schema.json"))]
    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in schemas
    )
    bom = next(s for s in schemas if s["$id"].endswith("bom-1.6.schema.json"))
    return jsonschema.Draft7Validator(
        bom, registry=registry, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER
    )
