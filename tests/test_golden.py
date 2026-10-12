"""Golden-file tests: each directory under tests/fixtures is a scan root.

A fixture directory holds small source files plus the expected output of
scanning it: expected.cbom.json (timestamp and serialNumber normalised) and
expected.report.txt. Regenerate after an intended change with

    pytest tests/test_golden.py --update-golden

and review the diff. The diff is the change.
"""

import pytest

from conftest import dumps, fixture_dirs, fixture_id, scan


def test_fixtures_exist():
    # Guards against a glob or layout change silently collecting nothing.
    assert len(fixture_dirs()) >= 30


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_golden(root, update_golden):
    cbom, report = scan(root)
    cbom_file = root / "expected.cbom.json"
    report_file = root / "expected.report.txt"

    if update_golden:
        cbom_file.write_text(dumps(cbom))
        report_file.write_text(report)
        return

    assert dumps(cbom) == cbom_file.read_text()
    assert report == report_file.read_text()

