"""Packaging metadata that a reader (or pip) would actually trust.

The values here are small and easy to get wrong in a way nobody notices until
someone installs the package: a placeholder author, a URL to a repository that
does not exist, a license mentioned in three places and present in none.
"""

import os
import re
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(_ROOT, name), encoding="utf-8") as handle:
        return handle.read()


class TestPackaging(unittest.TestCase):
    def test_the_license_file_the_metadata_points_at_exists(self):
        pyproject = _read("pyproject.toml")
        self.assertIn('license = {file = "LICENSE"}', pyproject,
                      "the metadata must point at a file, not at a label")
        self.assertTrue(os.path.exists(os.path.join(_ROOT, "LICENSE")))
        self.assertIn("MIT License", _read("LICENSE"))

    def test_no_placeholder_author_or_url_survives(self):
        pyproject = _read("pyproject.toml")
        for placeholder in ("Your Name", "your.email@example.com",
                            "github.com/username"):
            self.assertNotIn(placeholder, pyproject)

    def test_one_version_in_three_places_and_they_agree(self):
        """pyproject, meson and __version__ are three claims about one number.

        None of them can read the others without a build step, so the test is
        the only thing that keeps them honest.
        """
        pyproject = re.search(r'^version = "([^"]+)"', _read("pyproject.toml"),
                              re.MULTILINE)
        meson = re.search(r"version:\s*'([^']+)'", _read("meson.build"))
        init = re.search(r'__version__ = "([^"]+)"',
                         _read(os.path.join("src", "pydbg", "__init__.py")))
        self.assertIsNotNone(pyproject)
        self.assertIsNotNone(meson)
        self.assertIsNotNone(init)
        self.assertEqual(pyproject.group(1), meson.group(1))
        self.assertEqual(pyproject.group(1), init.group(1))

    def test_the_dev_extra_can_build_and_test_the_project(self):
        pyproject = _read("pyproject.toml")
        for needed in ("meson", "ninja", "cython", "pytest", "capstone"):
            self.assertIn(needed, pyproject)

    def test_requires_python_matches_the_syntax_in_use(self):
        """PEP 604 unions and dataclass(slots=True) are 3.10 or newer."""
        self.assertIn('requires-python = ">=3.10"', _read("pyproject.toml"))


class TestInstrumentIsOptional(unittest.TestCase):
    """Instrumentation is an optional build, not a core dependency.

    The backend links LLVM 22 statically, which pip cannot install. What the
    metadata can express is the Python-side dependency (capstone, needed to
    size the trampoline); the native toolchain is selected with -Dllvm-config
    and must not be spelled as a machine path in the build or the docs.
    """

    def test_the_instrument_extra_carries_its_python_dependency(self):
        self.assertIn('instrument = ["capstone>=5.0"]', _read("pyproject.toml"))

    def test_the_llvm_backend_has_no_hardcoded_toolchain_path(self):
        meson = _read(os.path.join("src", "pydbg", "instrument",
                                   "llvm_backend", "meson.build"))
        self.assertNotIn("C:/Users", meson)
        self.assertNotIn("C:\\Users", meson)
        self.assertNotIn("fs.exists", meson,
                         "the prebuilt search was removed; llvm-config comes "
                         "from -Dllvm-config or PATH")
        self.assertIn("-Dllvm-config", meson)

    def test_active_docs_do_not_ship_a_developer_machine_path(self):
        for name in ("README.md", "docs/architecture.md",
                     "docs/KNOWN_ISSUES.md"):
            self.assertNotIn("C:/Users/", _read(name), name)
            self.assertNotIn("C:\\Users\\", _read(name), name)


if __name__ == "__main__":
    unittest.main()
