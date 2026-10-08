"""Every directory entry of compound files, as olefile reads them.

An oracle for tests/compound.rs: olefile (BSD-licensed, not part of this
crate) is installed in a virtual environment, never vendored. One line per
entry reached from the root: file (from tests/fixtures/), path (the names
from the root's down, joined by '/', characters outside printable ASCII as
\\u{hex}), type, size, creation and modification FILETIMEs (0 when not set).

    python3 -m venv /tmp/olefile && /tmp/olefile/bin/pip install olefile==0.47
    /tmp/olefile/bin/python3 -I tests/fixtures/oracle/olefile_tree.py \
        tests/fixtures/compound/plaso/Document.doc \
        tests/fixtures/jumplist/*/*.automaticDestinations-ms \
        > tests/fixtures/oracle/olefile.tsv
"""
import sys

import olefile


def escaped(name):
    return "".join(c if " " <= c <= "~" else "\\u{%x}" % ord(c) for c in name)


def walk(path, entry, lines):
    lines.append((path, entry))
    for kid in entry.kids:
        walk(path + "/" + escaped(kid.name), kid, lines)


def main():
    for name in sys.argv[1:]:
        ole = olefile.OleFileIO(name)
        lines = []
        walk(escaped(ole.root.name), ole.root, lines)
        label = name.split("tests/fixtures/", 1)[-1]
        for path, e in sorted(lines, key=lambda line: line[0]):
            fields = [label, path, e.entry_type, e.size, e.createTime, e.modifyTime]
            print("\t".join(str(field) for field in fields))


main()
