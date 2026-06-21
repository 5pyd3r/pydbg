"""Tests for AnalysisWorkbench."""

import os
import struct
import tempfile
import unittest


class TestAnalysisWorkbench(unittest.TestCase):
    """Tests for AnalysisWorkbench."""

    def test_init(self):
        """Constructor stores target path and initializes fields to None."""
        from pydbg.analysis.workbench import AnalysisWorkbench

        wb = AnalysisWorkbench("test.exe")
        self.assertEqual(wb._target, "test.exe")
        self.assertIsNone(wb._dbg)
        self.assertIsNone(wb._stealth)
        self.assertIsNone(wb._interceptor)
        self.assertIsNone(wb._tracer)
        self.assertIsNone(wb._pe)

    def test_setup_creates_debugger(self):
        """setup() creates a Debugger and optionally an AntiAware."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.core.debugger import Debugger
        from pydbg.stealth.anti_aware import AntiAware

        wb = AnalysisWorkbench("test.exe")

        # With stealth=True (default)
        wb.setup(stealth=True)
        self.assertIsInstance(wb._dbg, Debugger)
        self.assertIsInstance(wb._stealth, AntiAware)

        # With stealth=False
        wb2 = AnalysisWorkbench("test.exe")
        wb2.setup(stealth=False)
        self.assertIsInstance(wb2._dbg, Debugger)
        self.assertIsNone(wb2._stealth)

    def test_load_pe_static(self):
        """load_and_analyze_pe parses kernel32.dll and returns correct fields."""
        from pydbg.analysis.workbench import AnalysisWorkbench

        kernel32 = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll"
        )
        if not os.path.exists(kernel32):
            self.skipTest("kernel32.dll not found")

        wb = AnalysisWorkbench(kernel32)
        info = wb.load_and_analyze_pe()

        self.assertIn("machine", info)
        self.assertIn("entry_point", info)
        self.assertIn("image_base", info)
        self.assertIn("sections", info)
        self.assertIn("imports", info)
        self.assertIn("exports", info)
        self.assertIsInstance(info["sections"], list)
        self.assertGreater(len(info["sections"]), 0)
        # kernel32 definitely has exports
        self.assertGreater(len(info["exports"]), 0)
        export_names = [e["name"] for e in info["exports"] if e["name"]]
        self.assertIn("GetProcAddress", export_names)
        self.assertIn("LoadLibraryA", export_names)

    def test_extract_resources_from_pe(self):
        """extract_resources finds resources from a synthetic PE with .rsrc."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.pe import PE
        from tests.test_resource import build_pe_with_resources

        pe_data, expected_data = build_pe_with_resources()
        wb = AnalysisWorkbench("dummy.exe")
        wb._pe = PE(pe_data)

        # Test returning ResourceEntry list (no output_dir)
        entries = wb.extract_resources()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].type_id, 10)
        self.assertEqual(entries[0].type_name, "RT_RCDATA")
        self.assertEqual(entries[0].name_id, 100)
        self.assertEqual(entries[0].data_size, 16)

        # Test extracting to directory
        out_dir = os.path.join(tempfile.gettempdir(), "test_wb_resources")
        try:
            paths = wb.extract_resources(out_dir)
            self.assertIsInstance(paths, list)
            self.assertGreater(len(paths), 0)
            for p in paths:
                self.assertTrue(os.path.exists(p))
        finally:
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_setup_interception(self):
        """setup_interception returns an APIInterceptor with preset hooks registered."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.intercept.api_hook import APIInterceptor

        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)

        interceptor = wb.setup_interception("ddraw")
        self.assertIsInstance(interceptor, APIInterceptor)
        self.assertIs(wb._interceptor, interceptor)

        # Verify no calls yet
        calls = interceptor.get_calls()
        self.assertEqual(calls, [])

    def test_setup_interception_without_setup_raises(self):
        """setup_interception raises RuntimeError if setup() was not called."""
        from pydbg.analysis.workbench import AnalysisWorkbench

        wb = AnalysisWorkbench("test.exe")
        with self.assertRaises(RuntimeError):
            wb.setup_interception("ddraw")

    def test_setup_interception_invalid_preset(self):
        """setup_interception raises ValueError for unknown preset."""
        from pydbg.analysis.workbench import AnalysisWorkbench

        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        with self.assertRaises(ValueError):
            wb.setup_interception("nonexistent_preset")

    def test_generate_report(self):
        """generate_report writes a Markdown file with expected sections."""
        from pydbg.analysis.workbench import AnalysisWorkbench

        kernel32 = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll"
        )
        if not os.path.exists(kernel32):
            self.skipTest("kernel32.dll not found")

        wb = AnalysisWorkbench(kernel32)

        with tempfile.TemporaryDirectory() as tmp_dir:
            report_path = os.path.join(tmp_dir, "report.md")
            wb.generate_report(report_path)

            self.assertTrue(os.path.exists(report_path))
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("# Analysis Report", content)
            self.assertIn("## PE Information", content)
            self.assertIn("## Sections", content)
            self.assertIn("## Imports", content)
            self.assertIn("## Exports", content)
            self.assertIn("## Resources", content)
            self.assertIn("kernel32.dll", content)

    def test_generate_report_creates_dirs(self):
        """generate_report creates intermediate directories."""
        from pydbg.analysis.workbench import AnalysisWorkbench

        kernel32 = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll"
        )
        if not os.path.exists(kernel32):
            self.skipTest("kernel32.dll not found")

        wb = AnalysisWorkbench(kernel32)

        with tempfile.TemporaryDirectory() as tmp_dir:
            nested = os.path.join(tmp_dir, "sub", "dir", "report.md")
            wb.generate_report(nested)
            self.assertTrue(os.path.exists(nested))


class TestGameAnalyzer(unittest.TestCase):
    """Tests for GameAnalyzer."""

    def test_init(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer

        wb = AnalysisWorkbench("test.exe")
        ga = GameAnalyzer(wb)
        self.assertIs(ga._wb, wb)

    def test_analyze_game_loop_no_process(self):
        """Should return empty result when no process is running."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer

        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)
        result = ga.analyze_game_loop()
        self.assertIn("messages", result)
        self.assertEqual(result["messages"], [])

    def test_analyze_rendering_pipeline_no_process(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer

        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)
        result = ga.analyze_rendering_pipeline()
        self.assertIn("surfaces", result)

    def test_analyze_input_handling_no_process(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer

        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)
        result = ga.analyze_input_handling()
        self.assertIn("key_map", result)


if __name__ == "__main__":
    unittest.main()
