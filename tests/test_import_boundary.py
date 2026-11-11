"""The import boundary: static analysis must not need the Windows extension.

ADR-0001. The failure this guards against is quiet: everything works on the
machine the extension was built on, and `import pydbg.analysis` fails on any
other — which is most of them, for a package whose analysis half reads files.
"""

import subprocess
import sys
import unittest

_EXTENSION_FREE_IMPORT = '''
import sys
import pydbg
assert "pydbg._pydbg" not in sys.modules, "import pydbg pulled in _pydbg"
assert pydbg.__version__
assert pydbg.analyze_file is not None
print("package import is extension-free")
'''

_ANALYSIS_WITHOUT_EXTENSION = '''
import sys

class BlockExtension:
    """Make `pydbg._pydbg` unimportable, like a machine that never built it."""

    def find_spec(self, name, path=None, target=None):
        if name == "pydbg._pydbg":
            raise ImportError("blocked for the test")
        return None

sys.meta_path.insert(0, BlockExtension())

from pydbg.analysis import StaticAnalyzer, analyze_file   # noqa: F401
assert "pydbg._pydbg" not in sys.modules, "analysis dragged the extension in"
print("analysis importable without the extension")
'''


class TestImportBoundary(unittest.TestCase):
    def _run(self, code):
        return subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True, timeout=180)

    def test_importing_the_package_does_not_load_the_extension(self):
        done = self._run(_EXTENSION_FREE_IMPORT)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("extension-free", done.stdout)

    def test_analysis_works_with_the_extension_blocked(self):
        done = self._run(_ANALYSIS_WITHOUT_EXTENSION)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("without the extension", done.stdout)

    def test_the_debugger_is_still_reachable_lazily(self):
        from pydbg import Debugger
        self.assertTrue(callable(Debugger))

    def test_an_unknown_name_still_raises_attribute_error(self):
        import pydbg
        with self.assertRaises(AttributeError):
            pydbg.no_such_thing
