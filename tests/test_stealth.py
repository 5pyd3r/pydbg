import unittest

from pydbg.core.session import DebugSession
from pydbg.stealth.anti_aware import AntiAware


class TestAntiAwareInit(unittest.TestCase):
    """AntiAware initialisation with a DebugSession."""

    def test_init_with_session(self):
        session = DebugSession()
        anti = AntiAware(session)
        self.assertIs(anti._s, session)

    def test_init_default_session(self):
        """Default DebugSession has no process_handle — AntiAware still constructs."""
        session = DebugSession()
        anti = AntiAware(session)
        self.assertIsNotNone(anti)

    def test_hide_all_callable(self):
        """hide_all is callable (will use dummy PEB address offline)."""
        session = DebugSession()
        anti = AntiAware(session)
        # With no process_handle, _get_peb_address returns a stub and
        # memory helpers will be skipped or fail gracefully.
        # We only test that the method exists and is callable.
        self.assertTrue(callable(anti.hide_all))

    def test_method_signatures(self):
        """All public methods exist."""
        session = DebugSession()
        anti = AntiAware(session)
        self.assertTrue(callable(anti.patch_peb_being_debugged))
        self.assertTrue(callable(anti.patch_peb_nt_global_flag))
        self.assertTrue(callable(anti.patch_heap_flags))


class TestAntiAwarePEBOffsets(unittest.TestCase):
    """Verify PEB-related constants match the x86/x64 PEB layout."""

    def test_being_debugged_offset(self):
        self.assertEqual(AntiAware.PEB_BEING_DEBUGGED_OFFSET, 0x02)

    def test_nt_global_flag_offset(self):
        self.assertEqual(AntiAware.PEB_NT_GLOBAL_FLAG_OFFSET, 0x68)

    def test_process_heap_offset(self):
        self.assertEqual(AntiAware.PEB_PROCESS_HEAP_OFFSET, 0x18)

    def test_heap_flags_offset(self):
        self.assertEqual(AntiAware.HEAP_FLAGS_OFFSET, 0x40)

    def test_heap_force_flags_offset(self):
        self.assertEqual(AntiAware.HEAP_FORCE_FLAGS_OFFSET, 0x44)


class TestAntiAwareDebugFlagConstants(unittest.TestCase):
    """Verify NtGlobalFlag debug bit values."""

    def test_tail_check(self):
        self.assertEqual(AntiAware.FLG_HEAP_ENABLE_TAIL_CHECK, 0x10)

    def test_free_check(self):
        self.assertEqual(AntiAware.FLG_HEAP_ENABLE_FREE_CHECK, 0x20)

    def test_validate_parameters(self):
        self.assertEqual(AntiAware.FLG_HEAP_VALIDATE_PARAMETERS, 0x40)

    def test_debug_flags_union(self):
        """DEBUG_FLAGS is the OR of all three heap debug flags."""
        expected = 0x10 | 0x20 | 0x40
        self.assertEqual(AntiAware.DEBUG_FLAGS, expected)
        self.assertEqual(AntiAware.DEBUG_FLAGS, 0x70)

    def test_debug_flags_bits_are_disjoint(self):
        """No overlap between the individual flag bits."""
        a = AntiAware.FLG_HEAP_ENABLE_TAIL_CHECK
        b = AntiAware.FLG_HEAP_ENABLE_FREE_CHECK
        c = AntiAware.FLG_HEAP_VALIDATE_PARAMETERS
        self.assertEqual(a & b, 0)
        self.assertEqual(a & c, 0)
        self.assertEqual(b & c, 0)


class TestAntiAwarePEBLookup(unittest.TestCase):
    """Test _get_peb_address offline behaviour."""

    def test_peb_stub_with_no_handle(self):
        """Without a process_handle, returns a dummy address (offline mode)."""
        session = DebugSession()  # process_handle is None
        anti = AntiAware(session)
        peb = anti._get_peb_address()
        self.assertEqual(peb, 0x7FFE_0000)

    def test_peb_stub_with_custom_dummy(self):
        """Session with a non-None but non-live handle still exercises offline path."""
        session = DebugSession(process_handle=0xDEAD)
        anti = AntiAware(session)
        # With a fake handle, reading memory will fail, but we can at
        # least verify the code path exists.  Patch _get_peb_address
        # internals by giving a thread_handle to hit the TEB path.
        # Since this is an offline test, we just verify construction.
        self.assertIsNotNone(anti)


if __name__ == '__main__':
    unittest.main()
