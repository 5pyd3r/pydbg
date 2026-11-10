from ..exceptions import PydbgError


class IATHook:
    """IAT (Import Address Table) hook manager."""

    def __init__(self, session):
        self._s = session
        self._hooks = {}  # (module_name, func_name) -> (iat_rva, original_addr)

    def _ptr_size(self):
        """Return pointer size in bytes for the target process."""
        arch = getattr(self._s, 'target_arch', 64)
        return 8 if arch == 64 else 4

    def set(self, module_name, func_name, new_addr):
        mem = self._get_memory()
        modules = self._get_modules()

        mod = self._find_module(modules, module_name)
        if mod is None:
            raise PydbgError(f"Module '{module_name}' not found")

        iat_addr = self._find_iat_addr(mod, func_name, mem)
        if iat_addr is None:
            raise PydbgError(
                f"Function '{func_name}' not found in IAT of '{module_name}'"
            )

        ptr_sz = self._ptr_size()
        original = int.from_bytes(mem.read(iat_addr, ptr_sz), 'little')
        mem.write(iat_addr, new_addr.to_bytes(ptr_sz, 'little'))

        key = (module_name, func_name)
        self._hooks[key] = (iat_addr, original)
        return original

    def restore(self, module_name, func_name, original_addr=None):
        ptr_sz = self._ptr_size()
        key = (module_name, func_name)
        if key in self._hooks:
            iat_addr, saved_original = self._hooks.pop(key)
            mem = self._get_memory()
            mem.write(iat_addr, saved_original.to_bytes(ptr_sz, 'little'))
        elif original_addr is not None:
            mem = self._get_memory()
            modules = self._get_modules()
            mod = self._find_module(modules, module_name)
            if mod is None:
                raise PydbgError(f"Module '{module_name}' not found")
            iat_addr = self._find_iat_addr(mod, func_name, mem)
            if iat_addr is None:
                raise PydbgError(
                    f"Function '{func_name}' not found in IAT of '{module_name}'"
                )
            mem.write(iat_addr, original_addr.to_bytes(ptr_sz, 'little'))

    def find(self, module_name, func_name):
        mem = self._get_memory()
        modules = self._get_modules()
        mod = self._find_module(modules, module_name)
        if mod is None:
            return None
        iat_addr = self._find_iat_addr(mod, func_name, mem)
        if iat_addr is None:
            return None
        ptr_sz = self._ptr_size()
        return int.from_bytes(mem.read(iat_addr, ptr_sz), 'little')

    def teardown(self):
        """Put every original import address back. Returns [(what, why)].

        Entries that could not be restored are left in _hooks so a later
        teardown() can retry, and so list_hooks() keeps telling the truth.
        """
        problems = []
        for key in list(self._hooks):
            iat_addr = self._hooks[key][0]
            try:
                self.restore(*key)
            except PydbgError as exc:
                problems.append((f"IAT {key[0]}!{key[1]} at 0x{iat_addr:X}",
                                 str(exc)))
        return problems

    def discard(self):
        """Forget the hooks without touching the target (it is gone)."""
        self._hooks.clear()

    def list_hooks(self):
        return dict(self._hooks)

    def _get_memory(self):
        from ..memory.manager import MemoryManager
        return MemoryManager(self._s)

    def _get_modules(self):
        from ..module.resolver import ModuleResolver
        return ModuleResolver(self._s)

    def _find_module(self, modules, module_name):
        name_lower = module_name.lower()
        for m in modules.enumerate():
            if m.get('name', '').lower() == name_lower:
                return m
        return None

    def _find_iat_addr(self, mod, func_name, mem):
        base = mod.get('base_address', 0)
        if base == 0:
            return None

        from ..analysis.process_source import ProcessSource
        from ..pe import PE
        from ..pe.view import LoadedView

        # Parse the live module through the same code path as a file. The
        # previous version read a fixed 64 KiB and swallowed every exception:
        # a module whose import directory sat past that window, or a read that
        # failed, both came back as "this function is not in the IAT" — a
        # confident wrong answer instead of an error.
        pe = PE.from_source(
            ProcessSource(None, base, size=mod.get('size'), reader=mem.read),
            LoadedView())
        wanted = func_name.lower()
        for imp in pe.imports:
            if imp.name and imp.name.lower() == wanted:
                return imp.rva
        return None
