"""go_lex against a reference implementation.

go_lex copies plain code in runs between quotes, slashes and line breaks.
reference_go_lex below is the lexer it replaced, which walked one character
at a time: slow, but simple enough to check by reading. The two must agree on
every input, including the odd ones: unterminated literals, escapes before a
line break, comment markers inside strings.
"""

import random

import pytest

import ratchet
from conftest import FIXTURES


def reference_go_lex(text):
    """The original lexer, one character at a time."""
    code, strings = [], []
    line_code, line_strings = [], []
    i, n = 0, len(text)
    state = None  # None, "block" (/* */) or "raw" (`...`)
    raw, raw_line = [], 0

    def end_line():
        code.append("".join(line_code))
        strings.append(line_strings[:])
        line_code.clear()
        line_strings.clear()

    while i < n:
        c = text[i]
        if c == "\n":
            if state == "raw":
                raw.append(c)
            end_line()
            i += 1
        elif state == "block":
            if text.startswith("*/", i):
                state = None
                line_code.append(" ")
                i += 2
            else:
                i += 1
        elif state == "raw":
            if c == "`":
                state = None
                line_code.append("``")
                # Attributed to the line the literal opens on.
                if raw_line == len(code):
                    line_strings.append("".join(raw))
                else:
                    strings[raw_line].append("".join(raw))
                i += 1
            else:
                raw.append(c)
                i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            state = "block"
            i += 2
        elif c == "`":
            state = "raw"
            raw, raw_line = [], len(code)
            i += 1
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if c == '"':
                line_strings.append(text[i + 1:j])
            line_code.append(c + c)
            i = j + 1
        else:
            line_code.append(c)
            i += 1
    end_line()
    return code, strings


TRICKY = [
    "", "x", "/", "//", "/*", "*/", "`", '"', "'", "\\",
    'a := "x // not a comment" // comment\nb',
    "s := `raw\nstill raw` + t",
    'r := \'"\'; q := "\\"" // escaped quote',
    '"unterminated\nnext line',
    '"escaped newline \\\nstill string"',
    "/* block\nspanning */ code",
    "/* never closed\n",
    "`never closed\n",
    "x / y /* c */ / z",
]


@pytest.mark.parametrize("text", TRICKY)
def test_tricky_inputs(text):
    assert ratchet.go_lex(text) == reference_go_lex(text)


def test_random_inputs():
    rng = random.Random(20261015)
    pieces = ['"', "'", "`", "/", "*", "\\", "\n", "a", " ", "//", "/*", "*/", "rsa."]
    for _ in range(20000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 30)))
        assert ratchet.go_lex(text) == reference_go_lex(text), repr(text)


def test_go_fixtures():
    for path in sorted(FIXTURES.rglob("*.go")):
        text = "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines())
        assert ratchet.go_lex(text) == reference_go_lex(text), path
