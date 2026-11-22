"""#82 — model.py is the leaf of the analysis package, and stays one.

The defect was not a crash. A `from .owners import ...` inside a method works,
which is exactly why `AnalysisResult` accumulated twenty-four of them: the
record could reach any collaborator it liked, so it did, and model.py ended up
with a reverse dependency on eight sibling modules while claiming to be the
bottom layer. What was wrong was the direction of the arrow. Only a structural
check keeps it pointed the other way, because every individual call still
works.
"""

import ast
import importlib.util
import pathlib
import sys
import unittest

MODEL_PATH = (pathlib.Path(__file__).resolve().parents[1]
              / "src" / "pydbg" / "analysis" / "model.py")
_STDLIB = {"__future__", "dataclasses", "enum", "typing"}

# The four lookups that read the result's own reference index. Everything else
# is a free function in the module that owns the decision.
_KEPT_METHODS = {"callers_of", "data_refs_of", "ref_kinds_of", "xrefs_of"}


class TestModelIsALeaf(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(MODEL_PATH.read_text(encoding="utf-8"))

    def test_no_import_inside_a_function(self):
        """A method-body import is how the arrow to a sibling was hidden."""
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    self.fail(f"{MODEL_PATH.name}:{child.lineno} imports "
                              f"inside {node.name}()")

    def test_runtime_imports_are_the_standard_library_only(self):
        """TYPE_CHECKING imports are for a reader, not a dependency."""
        imported = set()
        for statement in self.tree.body:
            if isinstance(statement, ast.If):
                self.assertIsInstance(
                    statement.test, ast.Name,
                    "model.py has a module-level conditional import that is "
                    "not the TYPE_CHECKING block")
                self.assertEqual(statement.test.id, "TYPE_CHECKING")
                continue
            if isinstance(statement, ast.ImportFrom):
                imported.add(statement.module)
            elif isinstance(statement, ast.Import):
                imported.update(alias.name for alias in statement.names)
        self.assertEqual(imported, _STDLIB)

    def test_the_module_loads_without_the_package(self):
        """The real dependency graph has no edge to a sibling at all.

        Executing model.py outside the package succeeds only while it imports
        nothing analysis-local; a single module-level sibling import would
        fail here with ModuleNotFoundError.
        """
        spec = importlib.util.spec_from_file_location("pydbg_model_leaf",
                                                      MODEL_PATH)
        module = importlib.util.module_from_spec(spec)
        # dataclasses reads the defining module out of sys.modules to resolve
        # string annotations, so the module has to be registered while it runs.
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(spec.name, None)
        self.assertTrue(hasattr(module, "AnalysisResult"))


class TestResultSurface(unittest.TestCase):
    """The record keeps its index lookups and nothing that needs a partner."""

    def test_only_the_index_lookups_remain(self):
        from pydbg.analysis.model import AnalysisResult
        methods = {name for name, value in vars(AnalysisResult).items()
                   if not name.startswith("_") and callable(value)}
        self.assertEqual(methods, _KEPT_METHODS)

    def test_every_moved_method_is_gone(self):
        from pydbg.analysis.model import AnalysisResult
        moved = (
            "render_summary", "render_functions", "render_xrefs",
            "render_coverage", "render_stats", "render_listing",
            "render_indirect_sites", "render_xref_gaps", "render_names",
            "render_structures", "render_attribution",
            "ref_kinds", "xrefs_are_complete", "indirect_call_sites",
            "call_graph_is_complete", "references_of",
            "owner_of", "function_of", "container_of", "boundary_of",
            "classify_range", "receiver_of", "value_set_of",
            "narrow_value_set", "names", "label", "accesses", "structures",
            "attribution", "scan", "scan_section", "scan_text", "cfg_of",
        )
        for name in moved:
            self.assertFalse(hasattr(AnalysisResult, name), name)


if __name__ == "__main__":
    unittest.main()
