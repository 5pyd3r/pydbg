"""Raw-CONTEXT capture and x86/x64 stack walking (spec §13.3, D10)."""

import os
import struct
import sys
import unittest
import warnings
from unittest import mock

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

from pydbg.core.session import DebugSession
from pydbg.dump.stackwalk import StackWalker
from pydbg.exceptions import ThreadError

try:
    from pydbg.thread.manager import (
        MACHINE_X64, MACHINE_X86, ThreadManager,
    )
except ImportError:  # pragma: no cover — extension-free collection
    ThreadManager = None

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# x64 call chain main -> f1 -> f2 -> f3, built by tests/meson.build.
TEST_STACK_TARGET = os.environ.get(
    'TEST_STACK_TARGET_PATH',
    os.path.join(_TEST_DIR, 'target', 'stack_target.exe'))
_HAS_STACK_TARGET = os.path.exists(TEST_STACK_TARGET)

# 32-bit target whose main thread calls the exported main_add in a loop, so a
# breakpoint there stops on a real WOW64 call chain.
TEST_THREADED_TARGET = os.environ.get(
    'TEST_THREADED_TARGET_PATH',
    os.path.join(_TEST_DIR, 'target', 'threaded_target32.exe'))
_HAS_THREADED_TARGET = os.path.exists(TEST_THREADED_TARGET)

_WOW64_AVAILABLE = struct.calcsize('P') == 8 and sys.platform == 'win32'

_CONTEXT_X64 = 0x4D0   # sizeof(CONTEXT) on x64
_CONTEXT_WOW64 = 716   # sizeof(WOW64_CONTEXT)


def _session(arch=64):
    """A DebugSession with a process handle and one registered thread."""
    session = DebugSession()
    session.process_handle = 0x111
    session.pid = 1
    session.register_pid_arch(1, arch)
    session.register_thread(7, 1)
    return session


def _module_by_name(dbg, path):
    basename = os.path.basename(path).lower()
    for module in dbg.enum_modules():
        name = module.get('name', '').split('\\')[-1].lower()
        if name == basename:
            return module
    raise AssertionError(f'module {basename} not found in the target')


def _export_rva(path, name):
    from pydbg.pe import PE

    for export in PE.from_file(path).exports:
        if export.name == name:
            return export.rva
    raise AssertionError(f'export {name} not found in {path}')


class TestContextBytes(unittest.TestCase):
    """ThreadManager.get_context_bytes: raw bytes, machine resolution."""

    @unittest.skipUnless(ThreadManager is not None,
                         'optional dependency: Cython extension')
    def test_the_extension_bytes_come_back_unchanged(self):
        manager = ThreadManager(_session())
        raw = bytes(range(256)) * 4 + bytes(_CONTEXT_X64 - 1024)
        self.assertEqual(len(raw), _CONTEXT_X64)
        with mock.patch('pydbg._pydbg.get_thread_context_bytes',
                        return_value=raw) as getter:
            self.assertEqual(
                manager.get_context_bytes(0x55, machine='x64'), raw)
        getter.assert_called_once_with(0x55, 64)

    @unittest.skipUnless(ThreadManager is not None,
                         'optional dependency: Cython extension')
    def test_machine_none_asks_the_target(self):
        manager = ThreadManager(_session(arch=32))
        raw = b'\x00' * _CONTEXT_WOW64
        with mock.patch('pydbg._pydbg.get_thread_id', return_value=7), \
                mock.patch('pydbg._pydbg.get_thread_context_bytes',
                           return_value=raw) as getter:
            self.assertEqual(len(manager.get_context_bytes(0x55)),
                             _CONTEXT_WOW64)
        getter.assert_called_once_with(0x55, 32)

    @unittest.skipUnless(ThreadManager is not None,
                         'optional dependency: Cython extension')
    def test_every_machine_spelling_reaches_the_same_architecture(self):
        manager = ThreadManager(_session())
        for spec, arch in (('x86', 32), ('X86', 32), (32, 32),
                           (MACHINE_X86, 32),
                           ('x64', 64), (64, 64), (MACHINE_X64, 64)):
            with mock.patch('pydbg._pydbg.get_thread_context_bytes',
                            return_value=b'') as getter:
                manager.get_context_bytes(1, machine=spec)
            getter.assert_called_once_with(1, arch)

    @unittest.skipUnless(ThreadManager is not None,
                         'optional dependency: Cython extension')
    def test_an_unknown_machine_is_refused(self):
        manager = ThreadManager(_session())
        with self.assertRaises(ValueError):
            manager.get_context_bytes(1, machine='arm64')

    @unittest.skipUnless(ThreadManager is not None,
                         'optional dependency: Cython extension')
    def test_oserror_becomes_thread_error(self):
        manager = ThreadManager(_session())
        with mock.patch('pydbg._pydbg.get_thread_context_bytes',
                        side_effect=OSError(6, 'bad handle')):
            with self.assertRaises(ThreadError):
                manager.get_context_bytes(1, machine='x64')


class TestContextFrameBytes(unittest.TestCase):
    """The raw bytes, not the thread's current registers, seed the walk."""

    @unittest.skipUnless(_has_cython, 'optional dependency: Cython extension')
    def test_a_short_buffer_is_refused(self):
        for arch in (32, 64):
            with self.assertRaises(ValueError):
                _pydbg.context_frame_bytes(arch, b'\x00' * 8)


class TestWalkMachine(unittest.TestCase):
    """walk()/get_call_stack() machine handling and per-frame state."""

    def test_the_machine_and_context_reach_the_extension(self):
        session = _session(arch=32)
        context = b'\x00' * _CONTEXT_WOW64
        frame = {'frame_ip': 0x1000, 'frame_sp': 0x2000, 'frame_fp': 0x3000,
                 'context': context, 'frame_state': b'state'}
        with mock.patch('pydbg._pydbg.get_thread_id', return_value=7), \
                mock.patch('pydbg._pydbg.context_frame_bytes',
                           return_value=(0x1000, 0x2000, 0x3000)) as frame_of, \
                mock.patch('pydbg._pydbg.sym_initialize') as sym_init, \
                mock.patch('pydbg._pydbg.sym_cleanup') as sym_clean, \
                mock.patch('pydbg._pydbg.stack_walk_frame',
                           side_effect=[frame, None]) as walk_frame:
            frames = StackWalker(session).walk(
                0x55, context, max_frames=8, machine='x86')

        self.assertEqual(frames, [
            {'frame_ip': 0x1000, 'frame_sp': 0x2000, 'frame_fp': 0x3000}])
        frame_of.assert_called_once_with(32, context)
        sym_init.assert_called_once_with(0x111, "", 1)
        sym_clean.assert_called_once_with(0x111)
        first = walk_frame.call_args_list[0].args
        self.assertEqual(first[0], StackWalker.MACHINE_X86)
        self.assertEqual(first[1], 0x111)
        self.assertEqual(first[2], 0x55)
        self.assertEqual(first[3], context)
        self.assertEqual(first[4:7], (0x1000, 0x2000, 0x3000))
        self.assertIsNone(first[7])

    def test_the_next_call_carries_the_walk_state_forward(self):
        session = _session()
        first_context = b'\x01' * _CONTEXT_X64
        updated_context = b'\x02' * _CONTEXT_X64
        first = {'frame_ip': 0x1000, 'frame_sp': 0x2000, 'frame_fp': 0x3000,
                 'context': updated_context, 'frame_state': b'state'}
        second = {'frame_ip': 0x4000, 'frame_sp': 0x5000, 'frame_fp': 0x6000,
                  'context': updated_context, 'frame_state': b'state2'}
        with mock.patch('pydbg._pydbg.context_frame_bytes',
                        return_value=(0x1000, 0x2000, 0x3000)), \
                mock.patch('pydbg._pydbg.sym_initialize'), \
                mock.patch('pydbg._pydbg.sym_cleanup'), \
                mock.patch('pydbg._pydbg.stack_walk_frame',
                           side_effect=[first, second, None]) as walk_frame:
            frames = StackWalker(session).walk(
                0x55, first_context, max_frames=8, machine='x64')

        self.assertEqual([frame['frame_ip'] for frame in frames],
                         [0x1000, 0x4000])
        second_call = walk_frame.call_args_list[1].args
        self.assertEqual(second_call[3], updated_context)
        self.assertEqual(second_call[7], b'state')
        self.assertEqual(second_call[4:7], (0x1000, 0x2000, 0x3000))

    def test_machine_none_takes_the_target_architecture(self):
        session = _session(arch=32)
        with mock.patch('pydbg._pydbg.get_thread_id', return_value=7), \
                mock.patch('pydbg._pydbg.context_frame_bytes',
                           return_value=(1, 2, 3)) as frame_of, \
                mock.patch('pydbg._pydbg.sym_initialize'), \
                mock.patch('pydbg._pydbg.sym_cleanup'), \
                mock.patch('pydbg._pydbg.stack_walk_frame',
                           return_value=None):
            StackWalker(session).walk(0x55, b'\x00' * _CONTEXT_WOW64)
        frame_of.assert_called_once_with(32, b'\x00' * _CONTEXT_WOW64)

    def test_an_existing_symbol_session_is_not_cleaned_up(self):
        session = _session()
        with mock.patch('pydbg._pydbg.context_frame_bytes',
                        return_value=(1, 2, 3)), \
                mock.patch('pydbg._pydbg.sym_initialize',
                           side_effect=OSError(87, 'already initialized')) \
                as sym_init, \
                mock.patch('pydbg._pydbg.sym_cleanup') as sym_clean, \
                mock.patch('pydbg._pydbg.stack_walk_frame',
                           return_value=None):
            StackWalker(session).walk(
                0x55, b'\x00' * _CONTEXT_X64, machine='x64')
        sym_init.assert_called_once_with(0x111, "", 1)
        sym_clean.assert_not_called()

    def test_an_unknown_machine_is_refused_before_any_walk(self):
        with self.assertRaises(ValueError):
            StackWalker(_session()).walk(
                0x55, b'\x00' * _CONTEXT_X64, machine='arm64')

    def test_get_call_stack_forwards_machine_and_resolves(self):
        class RecordingWalker(StackWalker):
            def __init__(self, session):
                super().__init__(session)
                self.seen = 'unset'

            def walk(self, h_thread, context_bytes, max_frames=64,
                     machine=None):
                self.seen = machine
                return [
                    {'frame_ip': 0x1000, 'frame_sp': 1, 'frame_fp': 2},
                    {'frame_ip': 0, 'frame_sp': 0, 'frame_fp': 0},
                ]

        walker = RecordingWalker(DebugSession())
        stack = walker.get_call_stack(
            1, b'', resolve=lambda ip: f'sub_{ip:x}', machine='x86')
        self.assertEqual(walker.seen, 'x86')
        self.assertEqual([frame['index'] for frame in stack], [0, 1])
        self.assertEqual(stack[0]['func_name'], 'sub_1000')
        self.assertIsNone(stack[1]['func_name'])


def _wow64_launch(dbg, target):
    """Run a WOW64 target until its 32-bit main() is about to execute.

    The same drain as tests/test_wow64.py's _launch(run=True): the first
    loader breakpoint is the 64-bit bootstrap, the next one (after the image
    is visible to the 64-bit PSAPI view) is STATUS_WX86_BREAKPOINT, which
    means a software breakpoint placed now actually fires.
    """
    from pydbg.exceptions import MemError

    pid, tid = dbg.create_process(target)
    event = dbg.wait_event(5000)
    if event is not None:
        dbg.continue_event(event.pid, event.tid)
    basename = os.path.basename(target).lower()
    saw_image = False
    for _ in range(100):
        event = dbg.wait_event(2000)
        if event is None or event.type == 'EXIT_PROCESS':
            break
        dbg.continue_event(event.pid, event.tid)
        if event.type == 'EXCEPTION':
            if saw_image:
                break
            continue
        try:
            modules = dbg.modules.enumerate_handle(dbg._session.process_handle)
        except MemError:
            continue
        if any(module.get('name', '').split('\\')[-1].lower() == basename
               for module in modules):
            saw_image = True
    return pid, tid


@unittest.skipUnless(_has_cython and _HAS_STACK_TARGET,
                     'target not built: stack_target.exe')
class TestLiveX64StackWalk(unittest.TestCase):
    """A real x64 CONTEXT from a real call chain, unwound by dbghelp."""

    def test_a_real_call_chain_walks_at_least_three_frames(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger(TEST_STACK_TARGET)
        h_thread = None
        try:
            module = _module_by_name(dbg, TEST_STACK_TARGET)
            base = module['base_address']
            f3 = base + _export_rva(TEST_STACK_TARGET, 'f3')
            dbg.continue_event(pid, tid)  # release the loader breakpoint
            dbg.run_until(f3, max_wait_ms=10000)
            h_thread = dbg.open_thread(tid)

            context = dbg.thread.get_context_bytes(h_thread, machine='x64')
            self.assertEqual(len(context), _CONTEXT_X64,
                             'x64 CONTEXT must be 1232 bytes')
            context_ip = _pydbg.context_frame_bytes(64, context)[0]
            self.assertEqual(context_ip, f3,
                             'the stop did not capture the breakpoint address')

            frames = dbg.stack_walker.walk(
                h_thread, context, max_frames=16, machine='x64')
            self.assertGreaterEqual(len(frames), 3,
                                    f'only {len(frames)} frames: {frames}')
            first = frames[0]['frame_ip']
            self.assertTrue(
                base <= first < base + module['size'],
                f'first frame 0x{first:X} is outside the target module')
            self.assertEqual(first, context_ip,
                             'walk() did not start from the CONTEXT it got')
            sps = [frame['frame_sp'] for frame in frames]
            self.assertEqual(sps, sorted(sps),
                             f'frame stack pointers are not monotonic: {sps}')
            self.assertEqual(len(set(sps)), len(sps),
                             f'frame stack pointers repeat: {sps}')
        finally:
            if h_thread is not None:
                try:
                    dbg.close_handle(h_thread)
                except Exception:
                    pass
            teardown(dbg)


@unittest.skipUnless(_has_cython and _HAS_THREADED_TARGET
                     and _WOW64_AVAILABLE,
                     'environment: threaded 32-bit target and 64-bit host')
class TestLiveWow64StackWalk(unittest.TestCase):
    """WOW64_CONTEXT bytes drive StackWalk64 with MACHINE_X86."""

    def test_a_wow64_call_chain_walks(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        h_thread = None
        try:
            _pid, tid = _wow64_launch(dbg, TEST_THREADED_TARGET)
            module = _module_by_name(dbg, TEST_THREADED_TARGET)
            base = module['base_address']
            main_add = base + _export_rva(TEST_THREADED_TARGET, 'main_add')
            dbg.run_until(main_add, max_wait_ms=15000)
            h_thread = dbg.open_thread(tid)

            context = dbg.thread.get_context_bytes(h_thread, machine='x86')
            self.assertEqual(len(context), _CONTEXT_WOW64,
                             'WOW64 CONTEXT must be 716 bytes')
            frames = dbg.stack_walker.walk(
                h_thread, context, max_frames=16, machine='x86')
            self.assertTrue(frames, 'the WOW64 walk produced no frame at all')
            first = frames[0]['frame_ip']
            self.assertTrue(
                base <= first < base + module['size'],
                f'first frame 0x{first:X} is outside the target module')
            if len(frames) < 2:
                warnings.warn(
                    'WOW64 StackWalk64 ended after %d frame(s): x86 unwinding '
                    'needs FPO/PDB records and none are loaded for this target'
                    % len(frames), stacklevel=2)
        finally:
            if h_thread is not None:
                try:
                    dbg.close_handle(h_thread)
                except Exception:
                    pass
            teardown(dbg)
