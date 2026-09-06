#!/usr/bin/env python3
"""Unit tests for fix_api_imports.py.

Runs under plain CPython 3 -- no Ghidra required:
    python3 tests/test_fix_api_imports.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fix_api_imports as fai

MODULES = {"decomp_utils", "datatype_utils", "loopfinder"}
PKG = "ghidra_api"


def rewrite(source, in_package=False):
    """Rewritten source, or the original when nothing changed."""
    result = fai.rewrite_source(source, MODULES, PKG, in_package)
    return source if result is None else result


def warnings_for(source, in_package=True):
    collected = []
    fai.rewrite_source(source, MODULES, PKG, in_package, collected.append)
    return collected


class TestOutsidePackage(unittest.TestCase):
    def test_from_import(self):
        self.assertEqual(rewrite("from decomp_utils import DecompUtils\n"),
                         "from ghidra_api.decomp_utils import DecompUtils\n")

    def test_star_import(self):
        self.assertEqual(rewrite("from decomp_utils import *\n"),
                         "from ghidra_api.decomp_utils import *\n")

    def test_plain_import_keeps_binding(self):
        # `import ghidra_api.decomp_utils` alone would rebind the name to
        # `ghidra_api`, breaking every use site.
        self.assertEqual(rewrite("import decomp_utils\n"),
                         "import ghidra_api.decomp_utils as decomp_utils\n")

    def test_plain_import_preserves_alias(self):
        self.assertEqual(rewrite("import decomp_utils as du\n"),
                         "import ghidra_api.decomp_utils as du\n")

    def test_multi_clause_import(self):
        self.assertEqual(rewrite("import os, decomp_utils, sys\n"),
                         "import os, ghidra_api.decomp_utils as decomp_utils, sys\n")

    def test_parenthesized_and_continued(self):
        self.assertEqual(rewrite("from decomp_utils import (\n    A,\n    B,\n)\n"),
                         "from ghidra_api.decomp_utils import (\n    A,\n    B,\n)\n")
        self.assertEqual(rewrite("from decomp_utils import \\\n    A\n"),
                         "from ghidra_api.decomp_utils import \\\n    A\n")

    def test_indented_import(self):
        self.assertEqual(rewrite("def f():\n    from loopfinder import L\n"),
                         "def f():\n    from ghidra_api.loopfinder import L\n")


class TestLeftAlone(unittest.TestCase):
    def test_docstring_comment_and_string(self):
        src = ('"""from decomp_utils import X"""\n'
               "# from decomp_utils import X\n"
               's = "from decomp_utils import X"\n')
        self.assertIsNone(fai.rewrite_source(src, MODULES, PKG))

    def test_already_prefixed(self):
        self.assertIsNone(fai.rewrite_source(
            "from ghidra_api.decomp_utils import X\n", MODULES, PKG))

    def test_explicit_relative(self):
        self.assertIsNone(fai.rewrite_source(
            "from . import decomp_utils\nfrom .decomp_utils import X\n", MODULES, PKG))

    def test_similar_names(self):
        self.assertIsNone(fai.rewrite_source(
            "from decomp_utils_extra import X\nfrom mypkg.decomp_utils import Y\n",
            MODULES, PKG))

    def test_untargeted_module(self):
        self.assertIsNone(fai.rewrite_source("import os\nfrom sys import path\n",
                                             MODULES, PKG))


class TestInsidePackage(unittest.TestCase):
    def test_from_import_becomes_relative(self):
        self.assertEqual(rewrite("from decomp_utils import DecompUtils\n", True),
                         "from .decomp_utils import DecompUtils\n")

    def test_plain_import_becomes_from_dot_import(self):
        self.assertEqual(rewrite("import decomp_utils\n", True),
                         "from . import decomp_utils\n")

    def test_alias_preserved(self):
        self.assertEqual(rewrite("import decomp_utils as du\n", True),
                         "from . import decomp_utils as du\n")

    def test_several_siblings_on_one_line(self):
        self.assertEqual(rewrite("import decomp_utils, datatype_utils\n", True),
                         "from . import decomp_utils, datatype_utils\n")

    def test_mixed_clause_is_split(self):
        self.assertEqual(rewrite("import os, decomp_utils, sys\n", True),
                         "import os, sys\nfrom . import decomp_utils\n")

    def test_split_preserves_indentation(self):
        self.assertEqual(rewrite("def f():\n    import os, decomp_utils\n", True),
                         "def f():\n    import os\n    from . import decomp_utils\n")

    def test_compound_line_falls_back_to_absolute(self):
        # Splitting `try: import x` across lines would break the try block.
        src = "try: import decomp_utils\nexcept ImportError: pass\n"
        self.assertEqual(rewrite(src, True),
                         "try: import ghidra_api.decomp_utils as decomp_utils\n"
                         "except ImportError: pass\n")

    def test_compound_line_warns(self):
        warns = warnings_for("try: import decomp_utils\nexcept ImportError: pass\n")
        self.assertEqual(len(warns), 1)
        self.assertIn("line 1", warns[0])
        self.assertIn("decomp_utils", warns[0])

    def test_clean_rewrite_does_not_warn(self):
        self.assertEqual(warnings_for("import decomp_utils\n"), [])


class TestLineHandling(unittest.TestCase):
    def test_form_feed_does_not_shift_offsets(self):
        # str.splitlines() breaks on \x0c but the Python lexer does not;
        # using it here corrupted every edit after the form feed.
        src = "import os\n\x0c\nfrom decomp_utils import X\nV = 1\n"
        self.assertEqual(rewrite(src),
                         "import os\n\x0c\nfrom ghidra_api.decomp_utils import X\nV = 1\n")

    def test_other_unicode_line_boundaries(self):
        for ch in ("\x0b", "\x1c", "\x1d", "\x1e", "\x85", " ", " "):
            src = "s = '%s'\nfrom decomp_utils import X\n" % ch
            self.assertEqual(rewrite(src),
                             "s = '%s'\nfrom ghidra_api.decomp_utils import X\n" % ch,
                             "offset desync on %r" % ch)

    def test_crlf_preserved(self):
        self.assertEqual(rewrite("from decomp_utils import X\r\n"),
                         "from ghidra_api.decomp_utils import X\r\n")

    def test_split_lines_matches_tokenize_rows(self):
        self.assertEqual(fai.split_lines("a\n\x0cb\n"), ["a\n", "\x0cb\n"])
        self.assertEqual(fai.split_lines("a\r\nb"), ["a\r\n", "b"])
        self.assertEqual(fai.split_lines(""), [])

    def test_no_trailing_newline(self):
        self.assertEqual(rewrite("from decomp_utils import X"),
                         "from ghidra_api.decomp_utils import X")


class TestIdempotency(unittest.TestCase):
    def test_second_pass_is_a_noop(self):
        for src, in_pkg in (("from decomp_utils import X\n", False),
                            ("import decomp_utils\n", False),
                            ("from decomp_utils import X\n", True),
                            ("import os, decomp_utils\n", True)):
            once = rewrite(src, in_pkg)
            self.assertIsNone(fai.rewrite_source(once, MODULES, PKG, in_pkg),
                              "not idempotent: %r" % src)


class TestDiscovery(unittest.TestCase):
    def test_discovers_real_package(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        found = fai.discover_modules(os.path.join(root, "ghidra_api"))
        self.assertIn("decomp_utils", found)
        self.assertNotIn("__init__", found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
