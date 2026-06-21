"""Tests for pydbg.intercept — APIInterceptor, APICall, CallGraphBuilder, and Presets."""

import json
import os
import tempfile
import unittest

from pydbg.intercept.api_hook import APICall, APIInterceptor
from pydbg.intercept.call_graph import CallEdge, CallGraphBuilder
from pydbg.intercept.presets import (
    DDRAW_API_PRESET,
    DDRAW_HRESULTS,
    DDRAW_VTABLE_METHODS,
    DSOUND_API_PRESET,
    WIN32_API_PRESET,
    decode_hresult,
    load_preset,
)


class TestAPICall(unittest.TestCase):

    def test_dataclass(self):
        """APICall fields are stored and accessible."""
        call = APICall(
            timestamp=1000,
            tid=42,
            module="kernel32.dll",
            function="CreateFileW",
            args=[0x1000, 0x2000],
            decoded_args={"lpFileName": "C:\\test.txt"},
            return_value=0xABCD,
            decoded_return="HANDLE",
            call_stack=[0x401000, 0x401100],
        )
        self.assertEqual(call.timestamp, 1000)
        self.assertEqual(call.tid, 42)
        self.assertEqual(call.module, "kernel32.dll")
        self.assertEqual(call.function, "CreateFileW")
        self.assertEqual(call.args, [0x1000, 0x2000])
        self.assertEqual(call.decoded_args, {"lpFileName": "C:\\test.txt"})
        self.assertEqual(call.return_value, 0xABCD)
        self.assertEqual(call.decoded_return, "HANDLE")
        self.assertEqual(call.call_stack, [0x401000, 0x401100])

    def test_dataclass_defaults(self):
        """APICall default values for optional fields."""
        call = APICall(timestamp=0, tid=1, module="mod", function="func")
        self.assertEqual(call.args, [])
        self.assertEqual(call.decoded_args, {})
        self.assertEqual(call.return_value, 0)
        self.assertEqual(call.decoded_return, "")
        self.assertEqual(call.call_stack, [])


class TestAPIInterceptor(unittest.TestCase):

    def test_init(self):
        """APIInterceptor initializes with empty state."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        interceptor = APIInterceptor(session)
        self.assertEqual(interceptor._hooks, {})
        self.assertEqual(interceptor._calls, [])
        self.assertEqual(interceptor._decoders, {})
        self.assertEqual(interceptor._original_addrs, {})

    def test_register_decoder(self):
        """register_decoder stores a decoder for a module/function pair."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        interceptor = APIInterceptor(session)

        def my_decoder(args):
            return {"arg0": hex(args[0])}

        interceptor.register_decoder("kernel32.dll", "CreateFileW", my_decoder)
        key = ("kernel32.dll", "createfilew")
        self.assertIn(key, interceptor._decoders)
        self.assertIs(interceptor._decoders[key], my_decoder)

    def test_record_call_manually(self):
        """record_call appends an APICall and applies decoder if registered."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        interceptor = APIInterceptor(session)

        def decoder(args):
            return {"hObject": hex(args[0])}

        interceptor.register_decoder("kernel32.dll", "CloseHandle", decoder)

        call = APICall(
            timestamp=100,
            tid=5,
            module="kernel32.dll",
            function="CloseHandle",
            args=[0xDEAD],
        )
        interceptor.record_call(call)

        self.assertEqual(len(interceptor._calls), 1)
        recorded = interceptor._calls[0]
        self.assertEqual(recorded.module, "kernel32.dll")
        self.assertEqual(recorded.function, "CloseHandle")
        self.assertEqual(recorded.args, [0xDEAD])
        self.assertEqual(recorded.decoded_args, {"hObject": "0xdead"})

    def test_export_json(self):
        """export_json writes valid JSON with recorded calls."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        interceptor = APIInterceptor(session)

        interceptor.record_call(APICall(
            timestamp=1, tid=1, module="m", function="f", args=[1, 2],
        ))
        interceptor.record_call(APICall(
            timestamp=2, tid=2, module="m", function="g",
            return_value=99, decoded_return="ok",
        ))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            interceptor.export_json(tmp_path)
            with open(tmp_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["function"], "f")
            self.assertEqual(data[1]["return_value"], 99)
            self.assertEqual(data[1]["decoded_return"], "ok")
        finally:
            os.unlink(tmp_path)

    def test_get_calls_filter(self):
        """get_calls filters by module, function, and tid."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        interceptor = APIInterceptor(session)

        interceptor.record_call(APICall(
            timestamp=1, tid=1, module="kernel32.dll", function="CreateFileW",
        ))
        interceptor.record_call(APICall(
            timestamp=2, tid=2, module="kernel32.dll", function="CloseHandle",
        ))
        interceptor.record_call(APICall(
            timestamp=3, tid=1, module="user32.dll", function="MessageBoxW",
        ))

        # Filter by module
        calls = interceptor.get_calls(module="kernel32.dll")
        self.assertEqual(len(calls), 2)

        # Filter by function
        calls = interceptor.get_calls(function="CloseHandle")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].tid, 2)

        # Filter by tid
        calls = interceptor.get_calls(tid=1)
        self.assertEqual(len(calls), 2)

        # Combined filter
        calls = interceptor.get_calls(module="kernel32.dll", tid=1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].function, "CreateFileW")

        # No results
        calls = interceptor.get_calls(module="ntdll.dll")
        self.assertEqual(len(calls), 0)


class TestCallGraphBuilder(unittest.TestCase):

    def test_init(self):
        builder = CallGraphBuilder()
        self.assertEqual(builder._edges, {})
        self.assertEqual(builder._nodes, {})

    def test_add_call(self):
        builder = CallGraphBuilder()
        builder.add_call(0x1000, 0x2000, 100, 200)

        self.assertEqual(len(builder._edges), 1)
        edge = builder._edges[(0x1000, 0x2000)]
        self.assertEqual(edge.caller, 0x1000)
        self.assertEqual(edge.callee, 0x2000)
        self.assertEqual(edge.count, 1)
        self.assertEqual(edge.total_time, 100)

        self.assertIn(0x1000, builder._nodes)
        self.assertIn(0x2000, builder._nodes)
        self.assertEqual(builder._nodes[0x1000]['count'], 1)
        self.assertEqual(builder._nodes[0x1000]['first_seen'], 100)
        self.assertEqual(builder._nodes[0x2000]['count'], 1)

    def test_edge_count_aggregation(self):
        builder = CallGraphBuilder()
        builder.add_call(0x1000, 0x2000, 100, 200)
        builder.add_call(0x1000, 0x2000, 300, 500)
        builder.add_call(0x1000, 0x3000, 600, 700)

        edge1 = builder._edges[(0x1000, 0x2000)]
        self.assertEqual(edge1.count, 2)
        self.assertEqual(edge1.total_time, 300)

        edge2 = builder._edges[(0x1000, 0x3000)]
        self.assertEqual(edge2.count, 1)
        self.assertEqual(edge2.total_time, 100)

        # caller node should have count = 3 (called 3 times total)
        self.assertEqual(builder._nodes[0x1000]['count'], 3)
        # first_seen should remain from the first call
        self.assertEqual(builder._nodes[0x1000]['first_seen'], 100)

    def test_export_json(self):
        builder = CallGraphBuilder()
        builder.add_call(0x1000, 0x2000, 100, 200)
        builder.add_call(0x1000, 0x3000, 300, 500)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            path = f.name

        try:
            builder.export_json(path)
            with open(path, 'r') as f:
                data = json.load(f)

            self.assertIn('nodes', data)
            self.assertIn('edges', data)
            self.assertEqual(len(data['nodes']), 3)
            self.assertEqual(len(data['edges']), 2)
            self.assertEqual(data['edges'][0]['caller'], 0x1000)
        finally:
            os.unlink(path)

    def test_export_dot(self):
        builder = CallGraphBuilder()
        builder.add_call(0x1000, 0x2000, 100, 200)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.dot', delete=False) as f:
            path = f.name

        try:
            builder.export_dot(path)
            with open(path, 'r') as f:
                content = f.read()

            self.assertIn('digraph callgraph {', content)
            self.assertIn('0x1000', content)
            self.assertIn('0x2000', content)
            self.assertIn('->', content)
            self.assertTrue(content.strip().endswith('}'))
        finally:
            os.unlink(path)

    def test_get_hot_paths(self):
        builder = CallGraphBuilder()
        # Add calls with varying durations
        builder.add_call(0x1000, 0x2000, 0, 500)   # 500
        builder.add_call(0x2000, 0x3000, 0, 1000)  # 1000
        builder.add_call(0x3000, 0x4000, 0, 2000)  # 2000
        builder.add_call(0x4000, 0x5000, 0, 100)   # 100

        hot = builder.get_hot_paths(top_n=2)
        self.assertEqual(len(hot), 2)
        self.assertEqual(hot[0]['callee'], 0x4000)  # highest total_time
        self.assertEqual(hot[0]['total_time'], 2000)
        self.assertEqual(hot[1]['callee'], 0x3000)
        self.assertEqual(hot[1]['total_time'], 1000)

        # top_n larger than edge count returns all edges
        hot_all = builder.get_hot_paths(top_n=100)
        self.assertEqual(len(hot_all), 4)


class TestPresets(unittest.TestCase):

    def test_load_ddraw_preset(self):
        preset = load_preset("ddraw")
        self.assertIn("DirectDrawCreate", preset)
        self.assertIn("DirectDrawCreateEx", preset)
        self.assertEqual(preset["DirectDrawCreate"]["dll"], "ddraw.dll")
        self.assertEqual(preset["DirectDrawCreate"]["ret_type"], "hresult")
        self.assertEqual(preset["DirectDrawCreate"]["convention"], "stdcall")
        self.assertEqual(len(preset["DirectDrawCreate"]["params"]), 3)
        self.assertEqual(len(preset["DirectDrawCreateEx"]["params"]), 4)

    def test_ddraw_vtable_methods(self):
        dd_vtable = DDRAW_VTABLE_METHODS["IDirectDraw"]
        self.assertEqual(len(dd_vtable), 23)
        self.assertEqual(dd_vtable[0], "QueryInterface")
        self.assertEqual(dd_vtable[22], "WaitForVerticalBlank")

        surface_vtable = DDRAW_VTABLE_METHODS["IDirectDrawSurface"]
        self.assertEqual(len(surface_vtable), 32)
        self.assertEqual(surface_vtable[0], "QueryInterface")
        self.assertEqual(surface_vtable[31], "Unlock")

    def test_ddraw_hresult_decode(self):
        self.assertEqual(decode_hresult(0x00000000), "DD_OK")
        self.assertEqual(decode_hresult(0x8876014A), "DDERR_INVALIDPARAMS")
        result = decode_hresult(0xDEADBEEF)
        self.assertEqual(result, "0xDEADBEEF")

    def test_load_dsound_preset(self):
        preset = load_preset("dsound")
        self.assertIn("DirectSoundCreate", preset)
        self.assertIn("DirectSoundCreate8", preset)
        self.assertEqual(preset["DirectSoundCreate"]["dll"], "dsound.dll")
        self.assertEqual(preset["DirectSoundCreate8"]["ret_type"], "hresult")
        self.assertEqual(len(preset["DirectSoundCreate"]["params"]), 3)
        self.assertEqual(len(preset["DirectSoundCreate8"]["params"]), 3)

    def test_load_win32_preset(self):
        preset = load_preset("win32")
        expected = [
            "CreateWindowExA", "CreateWindowExW",
            "PeekMessageA", "PeekMessageW",
            "GetMessageA", "GetMessageW",
            "DispatchMessageA",
            "timeGetTime",
            "IsDebuggerPresent",
        ]
        for name in expected:
            self.assertIn(name, preset, f"{name} missing from WIN32_API_PRESET")
        self.assertEqual(preset["CreateWindowExA"]["dll"], "user32.dll")
        self.assertEqual(preset["CreateWindowExW"]["dll"], "user32.dll")
        self.assertEqual(preset["timeGetTime"]["dll"], "winmm.dll")
        self.assertEqual(preset["IsDebuggerPresent"]["dll"], "kernel32.dll")
        self.assertEqual(len(preset["CreateWindowExA"]["params"]), 12)
        self.assertEqual(preset["timeGetTime"]["params"], [])

    def test_unknown_preset_raises(self):
        with self.assertRaises(ValueError) as ctx:
            load_preset("nonexistent")
        self.assertIn("nonexistent", str(ctx.exception))
        self.assertIn("Available:", str(ctx.exception))


class TestAPIInterceptorExportCSV(unittest.TestCase):
    """Tests for APIInterceptor.export_csv()."""

    def test_export_csv_creates_file(self):
        """export_csv creates a valid CSV file."""
        import csv
        from pydbg.core.session import DebugSession

        session = DebugSession()
        interceptor = APIInterceptor(session)
        interceptor._calls.append(APICall(
            timestamp=100, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[0],
            decoded_args={}, return_value=0, decoded_return="DD_OK",
            call_stack=[],
        ))
        interceptor._calls.append(APICall(
            timestamp=200, tid=2, module="dsound.dll",
            function="DirectSoundCreate", args=[0],
            decoded_args={}, return_value=0, decoded_return="DS_OK",
            call_stack=[],
        ))

        path = os.path.join(tempfile.gettempdir(), "test_intercept_export.csv")
        interceptor.export_csv(path)
        with open(path, newline='') as f:
            reader = csv.reader(f)
            rows = list(reader)
        # Header + 2 data rows
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0], [
            'timestamp', 'tid', 'module', 'function',
            'args', 'decoded_args', 'return_value', 'decoded_return',
            'call_stack',
        ])
        self.assertEqual(rows[1][3], 'DirectDrawCreate')
        os.unlink(path)

    def test_export_csv_empty(self):
        """export_csv with no calls writes header only."""
        import csv
        from pydbg.core.session import DebugSession

        session = DebugSession()
        interceptor = APIInterceptor(session)
        path = os.path.join(tempfile.gettempdir(), "test_intercept_empty.csv")
        interceptor.export_csv(path)
        with open(path, newline='') as f:
            rows = list(csv.reader(f))
        self.assertEqual(len(rows), 1)  # header only
        os.unlink(path)


class TestAPIInterceptorClear(unittest.TestCase):
    """Tests for APIInterceptor.clear()."""

    def test_clear_empties_calls(self):
        """clear() removes all recorded calls."""
        from pydbg.core.session import DebugSession

        session = DebugSession()
        interceptor = APIInterceptor(session)
        interceptor._calls.append(APICall(
            timestamp=100, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[],
            decoded_args={}, return_value=0, decoded_return="",
            call_stack=[],
        ))
        self.assertEqual(len(interceptor.get_calls()), 1)
        interceptor.clear()
        self.assertEqual(len(interceptor.get_calls()), 0)

    def test_clear_idempotent(self):
        """clear() can be called multiple times safely."""
        from pydbg.core.session import DebugSession

        session = DebugSession()
        interceptor = APIInterceptor(session)
        interceptor.clear()
        interceptor.clear()
        self.assertEqual(len(interceptor.get_calls()), 0)


class TestCallGraphBuilderClear(unittest.TestCase):
    """Tests for CallGraphBuilder.clear()."""

    def test_clear_empties_graph(self):
        """clear() removes all nodes and edges."""
        cg = CallGraphBuilder()
        cg.add_call(0x401000, 0x402000, 100, 110)
        cg.add_call(0x401000, 0x403000, 200, 210)
        self.assertEqual(len(cg.build_graph()['edges']), 2)
        cg.clear()
        graph = cg.build_graph()
        self.assertEqual(len(graph['edges']), 0)
        self.assertEqual(len(graph['nodes']), 0)

    def test_clear_idempotent(self):
        """clear() can be called multiple times safely."""
        cg = CallGraphBuilder()
        cg.clear()
        cg.clear()
        self.assertEqual(len(cg.build_graph()['edges']), 0)


if __name__ == "__main__":
    unittest.main()
